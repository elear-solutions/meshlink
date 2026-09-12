/*
    relay.c -- UDP type-8 relay
    Copyright (C) 2026 Elear Solutions / MeshLink contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "connection.h"
#include "event.h"
#include "list.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "node.h"
#include "protocol.h"
#include "relay.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

typedef struct relay_report_entry {
	char *origin;
	char *destination;
	uint16_t last_budget;
	struct timespec last_report;
	time_t last_traffic_time;
	bool have_reported;
} relay_report_entry_t;

struct relay_devtool_state {
	bool fail_reports;
	uint8_t capture_buf[RELAY_CAPTURE_MAX];
	size_t capture_len;
};

static void relay_report_free(const void *data) {
	relay_report_entry_t *e = (relay_report_entry_t *)data;

	if(!e) {
		return;
	}

	free(e->origin);
	free(e->destination);
	free(e);
}

static void relay_expire_idle(meshlink_handle_t *mesh) {
	if(!mesh->relay_reports) {
		return;
	}

	time_t now = mesh->loop.now.tv_sec;

	for list_each(relay_report_entry_t, e, mesh->relay_reports) {
		if(now >= e->last_traffic_time + RELAY_REPORT_IDLE_SEC) {
			list_delete_node(mesh->relay_reports, list_node);
		}
	}
}

static void relay_report_timeout_handler(event_loop_t *loop, void *data) {
	meshlink_handle_t *mesh = data;

	relay_expire_idle(mesh);
	timeout_set(loop, &mesh->relay_report_timeout, &(struct timespec) {
		RELAY_REPORT_IDLE_SEC, 0
	});
}

void relay_init(meshlink_handle_t *mesh) {
	mesh->relay_reports = list_alloc(relay_report_free);
	timeout_add(&mesh->loop, &mesh->relay_report_timeout, relay_report_timeout_handler, mesh, &(struct timespec) {
		RELAY_REPORT_IDLE_SEC, 0
	});
}

void relay_exit(meshlink_handle_t *mesh) {
	timeout_del(&mesh->loop, &mesh->relay_report_timeout);

	if(mesh->relay_reports) {
		list_delete_list(mesh->relay_reports);
		mesh->relay_reports = NULL;
	}

	free(mesh->relay_devtool);
	mesh->relay_devtool = NULL;
}

bool relay_hop_udp_ready(const node_t *hop) {
	return hop && hop->status.udp_confirmed && hop->status.validkey && !hop->status.temp_udp_confirmed;
}

static size_t relay_prefix_len(const char *origin, const char *destination) {
	return 2 + strlen(origin) + strlen(destination);
}

static bool relay_sub_u32(uint32_t a, uint32_t b, uint32_t *out) {
	if(a < b) {
		return false;
	}

	*out = a - b;
	return true;
}

static bool relay_add_u32(uint32_t a, uint32_t b, uint32_t *out) {
	if(a > UINT32_MAX - b) {
		return false;
	}

	*out = a + b;
	return true;
}

static bool relay_prefix21(const char *origin, const char *destination, uint32_t *out) {
	return relay_add_u32((uint32_t)relay_prefix_len(origin, destination), RELAY_INNER_MIN, out);
}

bool relay_names_unusable(const char *origin, const char *destination) {
	uint32_t prefix21;
	uint32_t need;

	if(!relay_prefix21(origin, destination, &prefix21)) {
		return true;
	}

	if(!relay_add_u32(prefix21, (uint32_t)sizeof(meshlink_packethdr_t) + RELAY_UTCP_HDR + RELAY_MIN_PAYLOAD, &need)) {
		return true;
	}

	return MINMTU < need;
}

void relay_update_destination_transport(meshlink_handle_t *mesh, node_t *dest) {
	if(!dest || !dest->utcp || dest == mesh->self) {
		return;
	}

	if(dest->status.udp_confirmed) {
		uint16_t base = dest->minmtu > MINMTU ? dest->minmtu : MINMTU;
		utcp_set_mtu(dest->utcp, base - sizeof(meshlink_packethdr_t));
		return;
	}

	if(!dest->status.reachable || !dest->nexthop || dest->nexthop == mesh->self) {
		return;
	}

	if(relay_names_unusable(mesh->self->name, dest->name) || !relay_hop_udp_ready(dest->nexthop)) {
		utcp_set_mtu(dest->utcp, MTU - sizeof(meshlink_packethdr_t));
		return;
	}

	uint32_t prefix21;

	if(!relay_prefix21(mesh->self->name, dest->name, &prefix21)) {
		utcp_set_mtu(dest->utcp, MTU - sizeof(meshlink_packethdr_t));
		return;
	}

	uint32_t floor;

	if(!relay_sub_u32(MINMTU, prefix21, &floor)) {
		utcp_set_mtu(dest->utcp, MTU - sizeof(meshlink_packethdr_t));
		return;
	}

	uint32_t last = dest->relay_budget ? dest->relay_budget : floor;
	uint32_t first_base = dest->nexthop->minmtu > MINMTU ? dest->nexthop->minmtu : MINMTU;
	uint32_t first;

	if(!relay_sub_u32(first_base, prefix21, &first)) {
		utcp_set_mtu(dest->utcp, MTU - sizeof(meshlink_packethdr_t));
		return;
	}

	uint32_t budget = last < first ? last : first;
	uint32_t ch;

	if(!relay_sub_u32(budget, (uint32_t)sizeof(meshlink_packethdr_t), &ch) || ch > UINT16_MAX) {
		utcp_set_mtu(dest->utcp, MTU - sizeof(meshlink_packethdr_t));
		return;
	}

	utcp_set_mtu(dest->utcp, (uint16_t)ch);
}

void recompute_relay_dependents(meshlink_handle_t *mesh, node_t *hop) {
	if(!mesh || !hop) {
		return;
	}

	for splay_each(node_t, dest, mesh->nodes) {
		if(dest == hop || dest == mesh->self) {
			continue;
		}

		if(dest->nexthop != hop) {
			continue;
		}

		if(dest->status.udp_confirmed) {
			continue;
		}

		if(!dest->utcp) {
			continue;
		}

		relay_update_destination_transport(mesh, dest);
	}
}

void relay_on_hard_send_error(meshlink_handle_t *mesh, node_t *hop) {
	if(!hop) {
		return;
	}

	hop->status.udp_confirmed = false;
	recompute_relay_dependents(mesh, hop);
	relay_update_destination_transport(mesh, hop);
}

void relay_wake_probes(meshlink_handle_t *mesh, node_t *hop) {
	if(!hop || hop->mtuprobes != 31 || !hop->mtutimeout.cb) {
		return;
	}

	timeout_set(&mesh->loop, &hop->mtutimeout, &(struct timespec) {
		0, 0
	});
	signal_trigger(&mesh->loop, &mesh->datafromapp);
}

void relay_clear_budget_if_nexthop_changed(meshlink_handle_t *mesh, node_t *dest) {
	if(!dest || dest == mesh->self) {
		return;
	}

	if(dest->nexthop != dest->prev_nexthop) {
		dest->relay_budget = 0;
		dest->prev_nexthop = dest->nexthop;
		relay_update_destination_transport(mesh, dest);
	} else {
		dest->prev_nexthop = dest->nexthop;
	}
}

bool relay_encode(const char *origin, const char *destination, const void *inner, size_t inner_len, void *out, size_t *out_len) {
	if(!origin || !destination || !inner || !out || !out_len) {
		return false;
	}

	size_t ol = strlen(origin);
	size_t dl = strlen(destination);

	if(ol > RELAY_NAME_MAX || dl > RELAY_NAME_MAX) {
		return false;
	}

	if(!check_id(origin) || !check_id(destination)) {
		return false;
	}

	size_t total = 2 + ol + dl + inner_len;

	if(total > *out_len) {
		return false;
	}

	uint8_t *p = out;
	p[0] = (uint8_t)ol;
	memcpy(p + 1, origin, ol);
	p[1 + ol] = (uint8_t)dl;
	memcpy(p + 2 + ol, destination, dl);
	memcpy(p + 2 + ol + dl, inner, inner_len);
	*out_len = total;
	return true;
}

static bool relay_decode(const void *data, size_t len, char *origin, size_t origin_size, char *destination, size_t destination_size, const uint8_t **inner, size_t *inner_len) {
	if(!data || !origin || !destination || !inner || !inner_len) {
		return false;
	}

	if(len < 2) {
		return false;
	}

	const uint8_t *p = data;
	uint8_t ol = p[0];

	if((size_t)1 + ol + 1 > len) {
		return false;
	}

	uint8_t dl = p[1 + ol];

	if((size_t)2 + ol + dl + RELAY_INNER_MIN > len) {
		return false;
	}

	if((size_t)ol + 1 > origin_size || (size_t)dl + 1 > destination_size) {
		return false;
	}

	memcpy(origin, p + 1, ol);
	origin[ol] = 0;
	memcpy(destination, p + 2 + ol, dl);
	destination[dl] = 0;
	*inner = p + 2 + ol + dl;
	*inner_len = len - (size_t)(2 + ol + dl);
	return true;
}

bool relay_payload_destination(const void *data, size_t len, char *destination, size_t destination_size) {
	char origin[RELAY_NAME_MAX + 1];
	const uint8_t *inner = NULL;
	size_t inner_len = 0;

	return relay_decode(data, len, origin, sizeof(origin), destination, destination_size, &inner, &inner_len);
}

static int relay_entry_cmp(const relay_report_entry_t *a, const relay_report_entry_t *b) {
	if(a->last_traffic_time != b->last_traffic_time) {
		return a->last_traffic_time < b->last_traffic_time ? -1 : 1;
	}

	int oc = strcmp(a->origin, b->origin);

	if(oc) {
		return oc;
	}

	return strcmp(a->destination, b->destination);
}

static relay_report_entry_t *relay_report_find(meshlink_handle_t *mesh, const char *origin, const char *destination) {
	if(!mesh->relay_reports) {
		return NULL;
	}

	for list_each(relay_report_entry_t, e, mesh->relay_reports) {
		if(!strcmp(e->origin, origin) && !strcmp(e->destination, destination)) {
			return e;
		}
	}

	return NULL;
}

static void relay_evict_lru(meshlink_handle_t *mesh) {
	relay_report_entry_t *victim = NULL;

	for list_each(relay_report_entry_t, c, mesh->relay_reports) {
		if(!victim || relay_entry_cmp(c, victim) < 0) {
			victim = c;
		}
	}

	if(victim) {
		list_delete(mesh->relay_reports, victim);
	}
}

static relay_report_entry_t *relay_report_get(meshlink_handle_t *mesh, const char *origin, const char *destination, bool create, bool require_nodes) {
	relay_expire_idle(mesh);

	relay_report_entry_t *e = relay_report_find(mesh, origin, destination);

	if(e || !create) {
		return e;
	}

	if(require_nodes && (!lookup_node(mesh, origin) || !lookup_node(mesh, destination))) {
		return NULL;
	}

	if(mesh->relay_reports->count >= RELAY_REPORT_MAX) {
		relay_evict_lru(mesh);
	}

	e = xzalloc(sizeof(*e));
	e->origin = xstrdup(origin);
	e->destination = xstrdup(destination);
	list_insert_tail(mesh->relay_reports, e);
	return e;
}

void relay_touch_traffic(meshlink_handle_t *mesh, const char *origin, const char *destination) {
	relay_report_entry_t *e = relay_report_get(mesh, origin, destination, true, true);

	if(e) {
		e->last_traffic_time = mesh->loop.now.tv_sec;
	}
}

static struct relay_devtool_state *relay_devtool_get(meshlink_handle_t *mesh) {
	if(!mesh->relay_devtool) {
		mesh->relay_devtool = xzalloc(sizeof(*mesh->relay_devtool));
	}

	return mesh->relay_devtool;
}

static bool relay_send_report(meshlink_handle_t *mesh, const char *origin_name, struct node_t *dest, uint16_t budget) {
	if(mesh->relay_devtool && mesh->relay_devtool->fail_reports) {
		return send_request(mesh, NULL, NULL, "%d %s %s %d %s %u", REQ_KEY, mesh->self->name, origin_name, REQ_RELAY_MTU, dest->name, (unsigned)budget);
	}

	node_t *origin = lookup_node(mesh, origin_name);

	if(!origin || !origin->nexthop || !origin->nexthop->connection) {
		return false;
	}

	return send_request(mesh, origin->nexthop->connection, NULL, "%d %s %s %d %s %u", REQ_KEY, mesh->self->name, origin->name, REQ_RELAY_MTU, dest->name, (unsigned)budget);
}

static bool relay_within_oversize_cooldown(const struct timespec *now, const struct timespec *last) {
	if(now->tv_sec < last->tv_sec) {
		return true;
	}

	if(now->tv_sec == last->tv_sec) {
		return true;
	}

	if(now->tv_sec > last->tv_sec + RELAY_OVERSIZE_COOLDOWN_SEC) {
		return false;
	}

	/* now.tv_sec == last.tv_sec + cooldown: still inside the second until nsec catches up */
	return now->tv_nsec < last->tv_nsec;
}

void relay_maybe_report(meshlink_handle_t *mesh, const char *origin, struct node_t *dest, bool oversize) {
	if(!dest || dest->nexthop != dest) {
		return;
	}

	if(!relay_hop_udp_ready(dest)) {
		return;
	}

	uint32_t prefix21;

	if(!relay_prefix21(origin, dest->name, &prefix21)) {
		return;
	}

	uint32_t base = dest->minmtu > MINMTU ? dest->minmtu : MINMTU;
	uint32_t budget;

	if(!relay_sub_u32(base, prefix21, &budget) || budget > UINT16_MAX) {
		return;
	}

	relay_report_entry_t *e = relay_report_get(mesh, origin, dest->name, true, true);

	if(!e) {
		return;
	}

	e->last_traffic_time = mesh->loop.now.tv_sec;

	bool changed = !e->have_reported || e->last_budget != (uint16_t)budget;

	if(oversize && !changed && e->have_reported && relay_within_oversize_cooldown(&mesh->loop.now, &e->last_report)) {
		return;
	}

	if(!changed && !oversize && e->have_reported) {
		return;
	}

	if(relay_send_report(mesh, origin, dest, (uint16_t)budget)) {
		e->last_budget = (uint16_t)budget;
		e->last_report = mesh->loop.now;
		e->have_reported = true;
	}
}

void relay_notify_minmtu_change(meshlink_handle_t *mesh, node_t *dest) {
	if(!dest || dest->nexthop != dest || !mesh->relay_reports) {
		return;
	}

	relay_expire_idle(mesh);

	for list_each(relay_report_entry_t, e, mesh->relay_reports) {
		if(!strcmp(e->destination, dest->name)) {
			relay_maybe_report(mesh, e->origin, dest, false);
		}
	}
}

bool relay_send_meta_req_sptps(meshlink_handle_t *mesh, const char *origin, node_t *dest, const void *inner, size_t inner_len) {
	if(!dest || !dest->nexthop || !dest->nexthop->connection || !inner || !inner_len) {
		return false;
	}

	char buf[inner_len * 4 / 3 + 5];
	b64encode(inner, buf, (int)inner_len);
	return send_request(mesh, dest->nexthop->connection, NULL, "%d %s %s %d %s", REQ_KEY, origin, dest->name, REQ_SPTPS, buf);
}

bool relay_handle_record(meshlink_handle_t *mesh, node_t *from, const void *data, uint16_t len) {
	char origin_name[RELAY_NAME_MAX + 1];
	char dest_name[RELAY_NAME_MAX + 1];
	const uint8_t *inner = NULL;
	size_t inner_len = 0;

	if(!relay_decode(data, len, origin_name, sizeof(origin_name), dest_name, sizeof(dest_name), &inner, &inner_len)) {
		return true;
	}

	if(!check_id(origin_name) || !check_id(dest_name)) {
		return true;
	}

	node_t *origin = lookup_node(mesh, origin_name);
	node_t *dest = lookup_node(mesh, dest_name);

	if(!origin || !dest) {
		return true;
	}

	if(origin == mesh->self) {
		return true;
	}

	if(dest == mesh->self) {
		if(!origin->status.validkey || !origin->sptps.state) {
			return true;
		}

		if(origin == from) {
			uint8_t copy[inner_len];
			memcpy(copy, inner, inner_len);
			(void)sptps_receive_relay_inner(&origin->sptps, copy, inner_len);
		} else {
			(void)sptps_receive_relay_inner(&origin->sptps, inner, inner_len);
		}

		return true;
	}

	if(!dest->status.reachable || !dest->nexthop || dest->nexthop == mesh->self || dest->nexthop == from) {
		return true;
	}

	node_t *out = dest->nexthop;

	if(!relay_hop_udp_ready(out)) {
		if(!out->connection) {
			return true;
		}

		relay_send_meta_req_sptps(mesh, origin_name, dest, inner, inner_len);
		return true;
	}

	uint16_t limit = out->minmtu > MINMTU ? out->minmtu : MINMTU;

	if((uint32_t)len > limit) {
		relay_touch_traffic(mesh, origin_name, dest_name);

		if(out == dest) {
			relay_maybe_report(mesh, origin_name, dest, true);
		}

		return true;
	}

	if(out == dest) {
		relay_maybe_report(mesh, origin_name, dest, false);
	} else {
		relay_touch_traffic(mesh, origin_name, dest_name);
	}

	sptps_send_record(&out->sptps, PKT_RELAY_SPTPS, data, len);
	return true;
}

bool relay_handle_req_relay_mtu(meshlink_handle_t *mesh, connection_t *c, const char *request, node_t *from) {
	char dest_name[MAX_STRING_SIZE];
	unsigned budget = 0;

	if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING " %u", dest_name, &budget) != 2) {
		return true;
	}

	if(!check_id(dest_name)) {
		return true;
	}

	node_t *dest = lookup_node(mesh, dest_name);

	if(!dest) {
		return true;
	}

	/* AC20: accept only from dest's current META nexthop. Phase 1 is one hop (AC24). */
	if(from != dest->nexthop || from->connection != c || dest->status.udp_confirmed) {
		return true;
	}

	uint32_t prefix21;
	uint32_t lo, hi;

	if(!relay_prefix21(mesh->self->name, dest->name, &prefix21)
	                || !relay_sub_u32(MINMTU, prefix21, &lo)
	                || !relay_sub_u32(MTU, prefix21, &hi)) {
		return true;
	}

	if(budget < lo || budget > hi || budget > UINT16_MAX) {
		return true;
	}

	dest->relay_budget = (uint16_t)budget;
	logger(mesh, MESHLINK_DEBUG, "Got REQ_RELAY_MTU from %s for %s: %u", from->name, dest->name, (unsigned)dest->relay_budget);
	relay_update_destination_transport(mesh, dest);
	return true;
}

static bool relay_capture_send(void *handle, uint8_t type, const void *data, size_t len) {
	(void)type;
	node_t *n = handle;
	meshlink_handle_t *mesh = n->mesh;
	struct relay_devtool_state *dt = relay_devtool_get(mesh);

	if(len > sizeof(dt->capture_buf)) {
		return false;
	}

	memcpy(dt->capture_buf, data, len);
	dt->capture_len = len;
	return true;
}

bool relay_inject_inner(meshlink_handle_t *mesh, node_t *dest, uint8_t type) {
	if(!dest || !dest->sptps.outstate) {
		return false;
	}

	uint8_t dummy[32];
	memset(dummy, 0, sizeof(dummy));

	struct relay_devtool_state *dt = relay_devtool_get(mesh);
	send_data_t saved = dest->sptps.send_data;
	dt->capture_len = 0;
	dest->sptps.send_data = relay_capture_send;

	bool ok;

	if(type >= SPTPS_HANDSHAKE) {
		ok = sptps_send_record_raw(&dest->sptps, type, dummy, sizeof(dummy));
	} else {
		ok = sptps_send_record(&dest->sptps, type, dummy, sizeof(dummy));
	}

	dest->sptps.send_data = saved;

	if(!ok || !dt->capture_len) {
		return false;
	}

	if(dest->status.udp_confirmed) {
		return false;
	}

	if(dest->nexthop && relay_hop_udp_ready(dest->nexthop)) {
		uint8_t wrapped[MAXSIZE];
		size_t wlen = sizeof(wrapped);

		if(!relay_encode(mesh->self->name, dest->name, dt->capture_buf, dt->capture_len, wrapped, &wlen)) {
			return false;
		}

		return sptps_send_record(&dest->nexthop->sptps, PKT_RELAY_SPTPS, wrapped, (uint16_t)wlen);
	}

	return relay_send_meta_req_sptps(mesh, mesh->self->name, dest, dt->capture_buf, dt->capture_len);
}

void relay_devtool_clear_reports(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->relay_reports) {
		return;
	}

	list_delete_list(mesh->relay_reports);
	mesh->relay_reports = list_alloc(relay_report_free);
}

bool relay_devtool_seed_report(meshlink_handle_t *mesh, const char *origin, const char *destination, unsigned age_sec, bool have_reported) {
	if(!mesh || !mesh->relay_reports || !origin || !destination) {
		return false;
	}

	relay_report_entry_t *e = relay_report_get(mesh, origin, destination, true, false);

	if(!e) {
		return false;
	}

	e->last_traffic_time = mesh->loop.now.tv_sec - (time_t)age_sec;
	e->have_reported = have_reported;
	e->last_report.tv_sec = have_reported ? e->last_traffic_time : 0;
	e->last_report.tv_nsec = 0;
	return true;
}

bool relay_devtool_has_report(meshlink_handle_t *mesh, const char *origin, const char *destination) {
	if(!mesh || !origin || !destination) {
		return false;
	}

	return relay_report_find(mesh, origin, destination) != NULL;
}

bool relay_devtool_have_reported(meshlink_handle_t *mesh, const char *origin, const char *destination) {
	if(!mesh || !origin || !destination) {
		return false;
	}

	relay_report_entry_t *e = relay_report_find(mesh, origin, destination);
	return e && e->have_reported;
}

size_t relay_devtool_report_count(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->relay_reports) {
		return 0;
	}

	return mesh->relay_reports->count;
}

bool relay_devtool_fill_reports(meshlink_handle_t *mesh, size_t count, unsigned age_sec, bool have_reported) {
	if(!mesh) {
		return false;
	}

	for(size_t i = 0; i < count; i++) {
		char origin[8];
		snprintf(origin, sizeof(origin), "f%04u", (unsigned)i);

		if(!relay_devtool_seed_report(mesh, origin, "x", age_sec, have_reported)) {
			return false;
		}
	}

	return true;
}

void relay_devtool_fail_reports(meshlink_handle_t *mesh, bool fail) {
	if(mesh) {
		relay_devtool_get(mesh)->fail_reports = fail;
	}
}

bool relay_devtool_handle_aliased(meshlink_handle_t *mesh, node_t *from, const void *data, uint16_t len) {
	if(!mesh || !from || !data || !from->sptps.decrypted_buffer) {
		return false;
	}

	if(len > from->sptps.decrypted_buffer_len) {
		char *nbuf = realloc(from->sptps.decrypted_buffer, len);

		if(!nbuf) {
			return false;
		}

		from->sptps.decrypted_buffer = nbuf;
		from->sptps.decrypted_buffer_len = len;
	}

	memcpy(from->sptps.decrypted_buffer, data, len);
	return relay_handle_record(mesh, from, from->sptps.decrypted_buffer, len);
}

bool relay_devtool_send_meta_sptps(meshlink_handle_t *mesh, node_t *dest, uint8_t type, const void *data, size_t len) {
	if(!mesh || !dest || !dest->sptps.outstate) {
		return false;
	}

	struct relay_devtool_state *dt = relay_devtool_get(mesh);
	send_data_t saved = dest->sptps.send_data;
	dt->capture_len = 0;
	dest->sptps.send_data = relay_capture_send;

	bool ok;

	if(type >= SPTPS_HANDSHAKE) {
		ok = sptps_send_record_raw(&dest->sptps, type, data, (uint16_t)len);
	} else {
		ok = sptps_send_record(&dest->sptps, type, data, (uint16_t)len);
	}

	dest->sptps.send_data = saved;

	if(!ok || !dt->capture_len) {
		return false;
	}

	return relay_send_meta_req_sptps(mesh, mesh->self->name, dest, dt->capture_buf, dt->capture_len);
}
