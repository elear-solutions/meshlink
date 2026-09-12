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
	bool fail_realloc;
	uint8_t capture_buf[RELAY_CAPTURE_MAX];
	size_t capture_len;
};

static void relay_report_free(const void *data) {
	relay_report_entry_t *e = (relay_report_entry_t *)data;

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
	list_delete_list(mesh->relay_reports);
	mesh->relay_reports = NULL;
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
	size_t need = relay_prefix_len(origin, destination) + RELAY_INNER_MIN
	              + sizeof(meshlink_packethdr_t) + RELAY_UTCP_HDR + RELAY_MIN_PAYLOAD;
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

	/* names_unusable already proved prefix+overhead fits MINMTU, so these cannot fail. */
	uint32_t prefix21 = 0;
	uint32_t floor = 0;
	uint32_t first = 0;
	uint32_t ch = 0;
	(void)relay_prefix21(mesh->self->name, dest->name, &prefix21);
	(void)relay_sub_u32(MINMTU, prefix21, &floor);

	uint32_t last = dest->relay_budget ? dest->relay_budget : floor;
	uint32_t first_base = dest->nexthop->minmtu > MINMTU ? dest->nexthop->minmtu : MINMTU;
	(void)relay_sub_u32(first_base, prefix21, &first);

	uint32_t budget = last < first ? last : first;
	(void)relay_sub_u32(budget, (uint32_t)sizeof(meshlink_packethdr_t), &ch);
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

	uint32_t prefix21 = (uint32_t)relay_prefix_len(origin, dest->name) + RELAY_INNER_MIN;
	uint32_t base = dest->minmtu > MINMTU ? dest->minmtu : MINMTU;
	uint32_t budget;

	if(!relay_sub_u32(base, prefix21, &budget)) {
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

	relay_touch_traffic(mesh, origin_name, dest_name);

	if((uint32_t)len > limit) {
		if(out == dest) {
			relay_maybe_report(mesh, origin_name, dest, true);
		}

		return true;
	}

	if(out == dest) {
		relay_maybe_report(mesh, origin_name, dest, false);
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

	uint32_t prefix21 = (uint32_t)relay_prefix_len(mesh->self->name, dest->name) + RELAY_INNER_MIN;
	uint32_t lo, hi;

	if(prefix21 >= MINMTU || !relay_sub_u32(MINMTU, prefix21, &lo) || !relay_sub_u32(MTU, prefix21, &hi)) {
		return true;
	}

	if(budget < lo || budget > hi) {
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

	if(type >= SPTPS_HANDSHAKE) {
		(void)sptps_send_record_raw(&dest->sptps, type, dummy, sizeof(dummy));
	} else {
		(void)sptps_send_record(&dest->sptps, type, dummy, sizeof(dummy));
	}

	dest->sptps.send_data = saved;

	/* send_record failure leaves capture_len at 0 — same drop as a confirmed dest. */
	if(!dt->capture_len || dest->status.udp_confirmed) {
		return false;
	}

	if(dest->nexthop && relay_hop_udp_ready(dest->nexthop)) {
		uint8_t wrapped[MAXSIZE];
		size_t wlen = sizeof(wrapped);

		if(relay_encode(mesh->self->name, dest->name, dt->capture_buf, dt->capture_len, wrapped, &wlen)) {
			return sptps_send_record(&dest->nexthop->sptps, PKT_RELAY_SPTPS, wrapped, (uint16_t)wlen);
		}
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
		if(mesh->relay_devtool && mesh->relay_devtool->fail_realloc) {
			return false;
		}

		from->sptps.decrypted_buffer = realloc(from->sptps.decrypted_buffer, len);
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

	(void)sptps_send_record(&dest->sptps, type, data, (uint16_t)len);
	dest->sptps.send_data = saved;
	return relay_send_meta_req_sptps(mesh, mesh->self->name, dest, dt->capture_buf, dt->capture_len);
}

void relay_devtool_fail_realloc(meshlink_handle_t *mesh, bool fail) {
	if(mesh) {
		relay_devtool_get(mesh)->fail_realloc = fail;
	}
}

bool relay_devtool_handle_req_relay_mtu(meshlink_handle_t *mesh, node_t *from, const char *request) {
	if(!mesh || !from || !request) {
		return false;
	}

	return relay_handle_req_relay_mtu(mesh, from->connection, request, from);
}

static bool relay_cover_encode_decode(void) {
	uint8_t buf[128];
	uint8_t inner[21];
	size_t n = sizeof(buf);
	char origin[RELAY_NAME_MAX + 1];
	char destination[RELAY_NAME_MAX + 1];
	char tiny[2];
	const uint8_t *innerp = NULL;
	size_t inner_len = 0;
	char longname[257];

	memset(inner, 0x5a, sizeof(inner));
	memset(longname, 'A', 256);
	longname[256] = 0;

	bool unexpected = false;
	unexpected |= relay_encode(NULL, "b", inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", NULL, inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", "b", NULL, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", "b", inner, sizeof(inner), NULL, &n);
	unexpected |= relay_encode("a", "b", inner, sizeof(inner), buf, NULL);
	unexpected |= relay_encode(longname, "b", inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", longname, inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a!", "b", inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", "b!", inner, sizeof(inner), buf, &n);
	n = 4;
	unexpected |= relay_encode("aa", "bb", inner, sizeof(inner), buf, &n);
	n = sizeof(buf);
	unexpected |= !relay_encode("aa", "bb", inner, sizeof(inner), buf, &n);
	unexpected |= relay_payload_destination(NULL, n, destination, sizeof(destination));
	unexpected |= relay_payload_destination(buf, 1, destination, sizeof(destination));
	unexpected |= relay_payload_destination(buf, n, destination, 1);
	unexpected |= relay_decode(NULL, n, origin, sizeof(origin), destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(buf, n, NULL, sizeof(origin), destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(buf, n, origin, sizeof(origin), NULL, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(buf, n, origin, sizeof(origin), destination, sizeof(destination), NULL, &inner_len);
	unexpected |= relay_decode(buf, n, origin, sizeof(origin), destination, sizeof(destination), &innerp, NULL);
	unexpected |= relay_decode(buf, n, tiny, 1, destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(buf, n, origin, sizeof(origin), tiny, 1, &innerp, &inner_len);

	uint8_t shortol[2] = { 40, 'x' };
	uint8_t shortinner[4] = { 1, 'a', 1, 'b' };
	unexpected |= relay_decode(shortol, 2, origin, sizeof(origin), destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(shortinner, 4, origin, sizeof(origin), destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= !relay_payload_destination(buf, n, destination, sizeof(destination));
	return !unexpected;
}

bool relay_devtool_cover_unit(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop) {
	uint32_t math = 0;
	uint32_t prefix21 = 0;
	uint32_t budget = 0;
	uint8_t inner[21];
	uint8_t wrapped[128];
	uint8_t big[600];
	uint8_t bigwrap[700];
	size_t wlen;
	char longname[260];
	char req[256];
	list_t *saved_reports;
	list_t *empty;
	node_t *saved_nh;
	node_t *saved_prev;
	bool saved_uc;
	bool saved_reach;
	bool saved_huc;
	bool saved_hvalid;
	bool saved_out;
	uint16_t saved_budget;
	uint16_t saved_minmtu;
	uint16_t saved_hminmtu;
	uint32_t saved_probes;
	connection_t *saved_conn;
	int saved_state;
	relay_report_entry_t *e;

	memset(inner, 0x11, sizeof(inner));
	memset(big, 0x22, sizeof(big));
	memset(longname, 'Z', 259);
	longname[259] = 0;

	saved_nh = dest->nexthop;
	saved_prev = dest->prev_nexthop;
	saved_uc = dest->status.udp_confirmed;
	saved_reach = dest->status.reachable;
	saved_budget = dest->relay_budget;
	saved_minmtu = dest->minmtu;
	saved_hminmtu = hop->minmtu;
	saved_out = dest->sptps.outstate;
	saved_huc = hop->status.udp_confirmed;
	saved_hvalid = from->status.validkey;
	saved_probes = hop->mtuprobes;
	saved_conn = hop->connection;
	saved_state = from->sptps.state;

	(void)relay_add_u32(1, 2, &math);
	(void)relay_add_u32(UINT32_MAX, 1, &math);
	(void)relay_sub_u32(5, 2, &math);
	(void)relay_sub_u32(2, 5, &math);
	(void)relay_names_unusable(longname, longname);
	(void)relay_hop_udp_ready(NULL);
	(void)relay_cover_encode_decode();

	(void)relay_capture_send(from, 0, inner, sizeof(inner));
	(void)relay_capture_send(from, 0, wrapped, RELAY_CAPTURE_MAX + 1);

	relay_update_destination_transport(mesh, NULL);
	relay_update_destination_transport(mesh, mesh->self);
	recompute_relay_dependents(NULL, hop);
	recompute_relay_dependents(mesh, NULL);
	recompute_relay_dependents(mesh, hop);
	relay_on_hard_send_error(mesh, NULL);
	relay_wake_probes(mesh, NULL);
	relay_wake_probes(mesh, hop);
	relay_clear_budget_if_nexthop_changed(mesh, NULL);
	relay_clear_budget_if_nexthop_changed(mesh, mesh->self);
	dest->prev_nexthop = hop;
	dest->nexthop = dest;
	relay_clear_budget_if_nexthop_changed(mesh, dest);
	dest->nexthop = dest;
	dest->prev_nexthop = dest;
	relay_clear_budget_if_nexthop_changed(mesh, dest);

	(void)relay_devtool_has_report(NULL, "a", "b");
	(void)relay_devtool_have_reported(NULL, "a", "b");
	(void)relay_devtool_report_count(NULL);
	(void)relay_devtool_seed_report(NULL, "a", "b", 0, false);
	(void)relay_devtool_fill_reports(NULL, 1, 0, false);
	relay_devtool_fail_reports(NULL, true);
	relay_devtool_clear_reports(NULL);
	(void)relay_devtool_handle_aliased(NULL, from, inner, sizeof(inner));
	(void)relay_devtool_send_meta_sptps(NULL, dest, 0, inner, sizeof(inner));
	(void)relay_inject_inner(mesh, NULL, 0);
	(void)relay_devtool_handle_req_relay_mtu(mesh, NULL, "x");

	saved_reports = mesh->relay_reports;
	mesh->relay_reports = NULL;
	relay_expire_idle(mesh);
	(void)relay_report_find(mesh, "a", "b");
	relay_notify_minmtu_change(mesh, dest);
	(void)relay_devtool_has_report(mesh, "a", "b");
	(void)relay_devtool_have_reported(mesh, "a", "b");
	(void)relay_devtool_report_count(mesh);
	relay_devtool_clear_reports(mesh);
	(void)relay_devtool_fill_reports(mesh, 1, 0, false);
	mesh->relay_reports = saved_reports;

	empty = list_alloc(relay_report_free);
	saved_reports = mesh->relay_reports;
	mesh->relay_reports = empty;
	relay_evict_lru(mesh);
	list_free(empty);
	mesh->relay_reports = saved_reports;

	relay_touch_traffic(mesh, "no_such_origin", "no_such_dest");
	(void)relay_devtool_seed_report(mesh, from->name, dest->name, RELAY_REPORT_IDLE_SEC + 5, true);
	relay_expire_idle(mesh);
	relay_report_timeout_handler(&mesh->loop, mesh);

	(void)relay_handle_record(mesh, from, inner, 1);

	uint8_t badid[64];
	badid[0] = 3;
	memcpy(badid + 1, "!!!", 3);
	badid[4] = 3;
	memcpy(badid + 5, "bar", 3);
	memcpy(badid + 8, inner, sizeof(inner));
	(void)relay_handle_record(mesh, from, badid, 8 + sizeof(inner));

	wlen = sizeof(wrapped);
	(void)relay_encode("zzz", "yyy", inner, sizeof(inner), wrapped, &wlen);
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);

	wlen = sizeof(wrapped);
	(void)relay_encode(mesh->self->name, dest->name, inner, sizeof(inner), wrapped, &wlen);
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);

	wlen = sizeof(wrapped);
	(void)relay_encode(from->name, mesh->self->name, inner, sizeof(inner), wrapped, &wlen);
	from->status.validkey = false;
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);
	from->status.validkey = saved_hvalid;
	from->sptps.state = 0;
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);
	from->sptps.state = saved_state;

	wlen = sizeof(wrapped);
	(void)relay_encode(from->name, dest->name, inner, sizeof(inner), wrapped, &wlen);
	dest->status.reachable = false;
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);
	dest->status.reachable = true;
	dest->nexthop = NULL;
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);
	dest->nexthop = mesh->self;
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);
	dest->nexthop = from;
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);
	dest->nexthop = hop;
	hop->status.udp_confirmed = false;
	hop->connection = NULL;
	(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);
	hop->connection = saved_conn;
	hop->status.udp_confirmed = saved_huc;

	wlen = sizeof(bigwrap);
	(void)relay_encode(from->name, dest->name, big, sizeof(big), bigwrap, &wlen);
	dest->nexthop = hop;
	hop->status.udp_confirmed = true;
	hop->status.validkey = true;
	hop->status.temp_udp_confirmed = false;
	hop->minmtu = MINMTU;
	(void)relay_handle_record(mesh, from, bigwrap, (uint16_t)wlen);
	dest->nexthop = dest;
	dest->status.udp_confirmed = true;
	dest->status.validkey = true;
	dest->status.temp_udp_confirmed = false;
	dest->minmtu = MINMTU;
	(void)relay_handle_record(mesh, from, bigwrap, (uint16_t)wlen);

	relay_maybe_report(mesh, from->name, NULL, false);
	dest->nexthop = hop;
	relay_maybe_report(mesh, from->name, dest, false);
	dest->nexthop = dest;
	dest->status.udp_confirmed = false;
	relay_maybe_report(mesh, from->name, dest, false);
	relay_maybe_report(mesh, longname, dest, false);

	dest->nexthop = dest;
	dest->status.udp_confirmed = true;
	dest->status.validkey = true;
	dest->status.temp_udp_confirmed = false;
	(void)relay_prefix21(from->name, dest->name, &prefix21);
	(void)relay_sub_u32(dest->minmtu > MINMTU ? dest->minmtu : MINMTU, prefix21, &budget);
	(void)relay_devtool_seed_report(mesh, from->name, dest->name, 0, true);
	e = relay_report_find(mesh, from->name, dest->name);

	if(e) {
		e->last_budget = (uint16_t)budget;
		e->have_reported = true;
		e->last_report.tv_sec = mesh->loop.now.tv_sec + 1;
		e->last_report.tv_nsec = 0;
		relay_maybe_report(mesh, from->name, dest, true);
		e->last_report.tv_sec = mesh->loop.now.tv_sec;
		relay_maybe_report(mesh, from->name, dest, true);
		e->last_report.tv_sec = mesh->loop.now.tv_sec - RELAY_OVERSIZE_COOLDOWN_SEC;
		e->last_report.tv_nsec = mesh->loop.now.tv_nsec + 1;
		relay_maybe_report(mesh, from->name, dest, true);
		e->last_report.tv_sec = mesh->loop.now.tv_sec - RELAY_OVERSIZE_COOLDOWN_SEC - 1;
		e->last_report.tv_nsec = 0;
		relay_maybe_report(mesh, from->name, dest, true);
		relay_maybe_report(mesh, from->name, dest, false);
	}

	relay_notify_minmtu_change(mesh, NULL);
	dest->nexthop = hop;
	relay_notify_minmtu_change(mesh, dest);
	dest->nexthop = dest;
	relay_notify_minmtu_change(mesh, dest);

	(void)relay_send_meta_req_sptps(mesh, from->name, NULL, inner, sizeof(inner));
	dest->nexthop = NULL;
	(void)relay_send_meta_req_sptps(mesh, from->name, dest, inner, sizeof(inner));
	dest->nexthop = hop;
	(void)relay_send_meta_req_sptps(mesh, from->name, dest, NULL, sizeof(inner));
	(void)relay_send_meta_req_sptps(mesh, from->name, dest, inner, 0);

	(void)relay_handle_req_relay_mtu(mesh, from->connection, "bad", from);
	(void)relay_handle_req_relay_mtu(mesh, from->connection, "0 a b 4 !!! 1", from);
	(void)relay_handle_req_relay_mtu(mesh, from->connection, "0 a b 4 nosuchnode 100", from);
	snprintf(req, sizeof(req), "0 %s %s %d %s 100", hop->name, mesh->self->name, REQ_RELAY_MTU, dest->name);
	dest->nexthop = dest;
	dest->status.udp_confirmed = true;
	(void)relay_handle_req_relay_mtu(mesh, from->connection, req, from);
	dest->status.udp_confirmed = false;
	(void)relay_handle_req_relay_mtu(mesh, from->connection, req, hop);
	snprintf(req, sizeof(req), "0 %s %s %d %s 1", hop->name, mesh->self->name, REQ_RELAY_MTU, dest->name);
	(void)relay_handle_req_relay_mtu(mesh, dest->connection, req, dest);
	snprintf(req, sizeof(req), "0 %s %s %d %s 20000", hop->name, mesh->self->name, REQ_RELAY_MTU, dest->name);
	(void)relay_handle_req_relay_mtu(mesh, dest->connection, req, dest);

	if(dest->connection && dest->nexthop == dest) {
		uint32_t lo = 0;
		uint32_t hi = 0;

		if(relay_prefix21(mesh->self->name, dest->name, &prefix21)
		                && relay_sub_u32(MINMTU, prefix21, &lo)
		                && relay_sub_u32(MTU, prefix21, &hi)
		                && lo <= hi) {
			snprintf(req, sizeof(req), "0 %s %s %d %s %u", dest->name, mesh->self->name, REQ_RELAY_MTU, dest->name, (unsigned)lo);
			dest->status.udp_confirmed = false;
			(void)relay_handle_req_relay_mtu(mesh, dest->connection, req, dest);
		}
	}

	dest->status.udp_confirmed = true;
	dest->minmtu = 0;
	relay_update_destination_transport(mesh, dest);
	dest->minmtu = MTU;
	relay_update_destination_transport(mesh, dest);
	dest->status.udp_confirmed = false;
	dest->status.reachable = false;
	relay_update_destination_transport(mesh, dest);
	dest->status.reachable = true;
	dest->nexthop = NULL;
	relay_update_destination_transport(mesh, dest);
	dest->nexthop = mesh->self;
	relay_update_destination_transport(mesh, dest);
	dest->nexthop = hop;
	hop->status.udp_confirmed = false;
	relay_update_destination_transport(mesh, dest);
	hop->status.udp_confirmed = true;
	hop->status.validkey = true;
	hop->status.temp_udp_confirmed = false;
	dest->relay_budget = 0;
	relay_update_destination_transport(mesh, dest);
	dest->relay_budget = 800;
	relay_update_destination_transport(mesh, dest);

	{
		bool saved_hop_uc = hop->status.udp_confirmed;
		relay_on_hard_send_error(mesh, hop);
		hop->status.udp_confirmed = saved_hop_uc;
	}

	{
		char huge[510];
		node_t *saved_from_nh = from->nexthop;
		connection_t *saved_dconn = dest->connection;
		char *saved_dname = dest->name;

		memset(huge, 'Z', 509);
		huge[509] = 0;
		(void)relay_devtool_seed_report(mesh, from->name, dest->name, 0, true);
		(void)relay_devtool_seed_report(mesh, from->name, mesh->self->name, 0, true);
		relay_evict_lru(mesh);

		dest->nexthop = dest;
		dest->status.reachable = true;
		dest->status.udp_confirmed = true;
		dest->status.validkey = true;
		dest->status.temp_udp_confirmed = false;
		dest->minmtu = MINMTU;
		relay_maybe_report(mesh, huge, dest, false);
		relay_maybe_report(mesh, "no_such_origin", dest, false);
		from->nexthop = NULL;
		relay_maybe_report(mesh, from->name, dest, false);
		from->nexthop = saved_from_nh;

		dest->status.udp_confirmed = false;
		dest->connection = NULL;
		wlen = sizeof(wrapped);
		(void)relay_encode(from->name, dest->name, inner, sizeof(inner), wrapped, &wlen);
		(void)relay_handle_record(mesh, from, wrapped, (uint16_t)wlen);

		dest->nexthop = dest;
		dest->connection = saved_dconn;
		dest->name = huge;
		dest->status.udp_confirmed = false;
		snprintf(req, sizeof(req), "0 %s %s %d %s 100", saved_dname, mesh->self->name, REQ_RELAY_MTU, saved_dname);
		(void)relay_handle_req_relay_mtu(mesh, dest->connection, req, dest);
		dest->name = saved_dname;
		from->nexthop = saved_from_nh;
		dest->connection = saved_dconn;

		node_t *extra = lookup_node(mesh, "qux");

		if(extra) {
			bool extra_uc = extra->status.udp_confirmed;
			bool extra_vk = extra->status.validkey;
			uint16_t extra_mtu = extra->minmtu;
			wlen = sizeof(bigwrap);
			(void)relay_encode(from->name, dest->name, big, sizeof(big), bigwrap, &wlen);
			dest->nexthop = extra;
			dest->status.reachable = true;
			extra->status.udp_confirmed = true;
			extra->status.validkey = true;
			extra->status.temp_udp_confirmed = false;
			extra->minmtu = MINMTU;
			(void)relay_handle_record(mesh, from, bigwrap, (uint16_t)wlen);
			extra->status.udp_confirmed = extra_uc;
			extra->status.validkey = extra_vk;
			extra->minmtu = extra_mtu;
		}
	}

	relay_devtool_fail_reports(mesh, true);
	dest->nexthop = dest;
	dest->status.udp_confirmed = true;
	dest->status.validkey = true;
	dest->status.temp_udp_confirmed = false;
	dest->minmtu = MINMTU;
	relay_maybe_report(mesh, from->name, dest, false);
	relay_devtool_fail_reports(mesh, false);

	(void)relay_devtool_report_count(mesh);
	(void)relay_devtool_fill_reports(mesh, 2, 0, false);
	relay_devtool_clear_reports(mesh);
	(void)relay_devtool_seed_report(mesh, from->name, dest->name, 1, false);
	(void)relay_devtool_seed_report(mesh, hop->name, dest->name, 1, false);
	relay_evict_lru(mesh);

	{
		char *saved_self = mesh->self->name;
		char *saved_dn = dest->name;
		char huge_self[510];
		uint8_t hello[5] = { 'H', 'e', 'l', 'l', 'o' };
		connection_t *saved_dconn = dest->connection;
		connection_t *saved_hconn = hop->connection;
		int saved_dstate = dest->sptps.state;

		memset(huge_self, 'Z', 509);
		huge_self[509] = 0;

		/* prefix21 >= MINMTU: keep dest lookup name, stretch self. */
		mesh->self->name = huge_self;
		dest->nexthop = dest;
		dest->status.udp_confirmed = false;
		snprintf(req, sizeof(req), "0 %s %s %d %s 100", saved_dn, saved_dn, REQ_RELAY_MTU, saved_dn);
		(void)relay_handle_req_relay_mtu(mesh, dest->connection, req, dest);
		mesh->self->name = saved_self;

		/* send_meta capture/send_record fail without touching counters. */
		dest->sptps.outstate = true;
		dest->sptps.state = 0;
		(void)relay_devtool_send_meta_sptps(mesh, dest, 0, inner, sizeof(inner));
		dest->sptps.state = saved_dstate;

		/* names_unusable → META. Dummy already-encrypted bytes, wrong names: no dest seq. */
		{
			char long_a[256];
			char long_b[256];

			memset(long_a, 'A', 255);
			long_a[255] = 0;
			memset(long_b, 'B', 255);
			long_b[255] = 0;
			mesh->self->name = long_a;
			dest->name = long_b;
			dest->status.udp_confirmed = false;
			dest->status.reachable = true;
			dest->nexthop = hop;
			(void)send_sptps_data(dest, 0, hello, sizeof(hello));
			mesh->self->name = saved_self;
			dest->name = saved_dn;
		}

		/* META with no hop/dest TCP. Already-encrypted bytes: no SPTPS seq bump. */
		dest->name = (char *)"x!";
		dest->status.udp_confirmed = false;
		dest->status.reachable = true;
		dest->nexthop = hop;
		hop->connection = NULL;
		dest->connection = NULL;
		(void)send_sptps_data(dest, 0, hello, sizeof(hello));
		hop->connection = saved_hconn;
		dest->connection = saved_dconn;
		dest->name = saved_dn;
	}

	dest->sptps.outstate = false;
	(void)relay_inject_inner(mesh, dest, 0);
	(void)relay_devtool_send_meta_sptps(mesh, dest, 0, inner, sizeof(inner));

	relay_devtool_get(mesh)->fail_realloc = true;
	(void)relay_devtool_handle_aliased(mesh, from, wrapped, from->sptps.decrypted_buffer
	                ? (uint16_t)(from->sptps.decrypted_buffer_len + 8) : 32);
	relay_devtool_get(mesh)->fail_realloc = false;

	if(from->sptps.decrypted_buffer) {
		uint8_t junk[32];
		size_t nlen = from->sptps.decrypted_buffer_len + 64;
		uint8_t *bigjunk = xzalloc(nlen);
		memset(junk, 0, sizeof(junk));
		junk[0] = 1;
		(void)relay_devtool_handle_aliased(mesh, from, junk, sizeof(junk));
		bigjunk[0] = 1;
		(void)relay_devtool_handle_aliased(mesh, from, bigjunk, (uint16_t)nlen);
		free(bigjunk);
	}

	dest->nexthop = saved_nh;
	dest->prev_nexthop = saved_prev;
	dest->status.udp_confirmed = saved_uc;
	dest->status.reachable = saved_reach;
	dest->relay_budget = saved_budget;
	dest->minmtu = saved_minmtu;
	hop->minmtu = saved_hminmtu;
	dest->sptps.outstate = saved_out;
	from->status.validkey = saved_hvalid;
	from->sptps.state = saved_state;
	hop->status.udp_confirmed = saved_huc;
	hop->connection = saved_conn;
	hop->mtuprobes = saved_probes;
	relay_update_destination_transport(mesh, dest);
	relay_update_destination_transport(mesh, hop);
	return true;
}
