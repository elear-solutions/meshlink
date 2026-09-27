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
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "protocol.h"
#include "relay.h"
#include "relay_devtool.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

void relay_report_free(const void *data) {
	relay_report_entry_t *e = (relay_report_entry_t *)data;

	free(e->origin);
	free(e->destination);
	free(e);
}

void relay_expire_idle(meshlink_handle_t *mesh) {
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

void relay_report_timeout_handler(event_loop_t *loop, void *data) {
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
	}

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

bool relay_sub_u32(uint32_t a, uint32_t b, uint32_t *out) {
	if(a < b) {
		return false;
	}

	*out = a - b;
	return true;
}

bool relay_add_u32(uint32_t a, uint32_t b, uint32_t *out) {
	if(a > UINT32_MAX - b) {
		return false;
	}

	*out = a + b;
	return true;
}

bool relay_prefix21(const char *origin, const char *destination, uint32_t *out) {
	return relay_add_u32((uint32_t)relay_prefix_len(origin, destination), RELAY_INNER_MIN, out);
}

bool relay_names_unusable(const char *origin, const char *destination) {
	size_t need = relay_prefix_len(origin, destination) + RELAY_INNER_MIN
	              + sizeof(meshlink_packethdr_t) + RELAY_UTCP_HDR + RELAY_MIN_PAYLOAD;
	return MINMTU < need;
}

uint16_t relay_fixed_channel_mtu(meshlink_handle_t *mesh, const node_t *dest) {
	uint32_t direct_floor = 0;

	/* MINMTU is the smallest payload any validated UDP path may carry, so the
	   floor stays valid on META and before PMTU settles. Live channels raise
	   above it in channel_refresh_mtu(). */
	if(!relay_sub_u32(MINMTU, (uint32_t)sizeof(meshlink_packethdr_t), &direct_floor)) {
		return 0;
	}

	if(!mesh || !dest || relay_names_unusable(mesh->self->name, dest->name)) {
		return (uint16_t)direct_floor;
	}

	/* This pair can be relayed, so reserve the type-8 prefix too. names_unusable
	   already proved the result leaves room for a UTCP header plus one byte. */
	uint32_t prefix21 = 0;
	uint32_t floor = 0;
	uint32_t ch = 0;

	if(!relay_prefix21(mesh->self->name, dest->name, &prefix21)
	                || !relay_sub_u32(MINMTU, prefix21, &floor)
	                || !relay_sub_u32(floor, (uint32_t)sizeof(meshlink_packethdr_t), &ch)
	                || ch <= RELAY_UTCP_HDR) {
		return (uint16_t)direct_floor;
	}

	return (uint16_t)ch;
}

static bool relay_is_confirmed_send_dest(const node_t *hop, const sockaddr_t *sa) {
	return hop && sa && !sockaddrcmp(sa, &hop->address);
}

void relay_fill_port_mismatch(const sockaddr_t *src, sockaddr_t *dst) {
	if(!src || !dst) {
		return;
	}

	*dst = *src;

	if(dst->sa.sa_family == AF_INET) {
		dst->in.sin_port ^= htons(0x8000);
	} else if(dst->sa.sa_family == AF_INET6) {
		dst->in6.sin6_port ^= htons(0x8000);
	} else {
		memset(dst, 0, sizeof *dst);
		dst->sa.sa_family = AF_INET;
		dst->in.sin_port = htons(1);
	}
}

void relay_fill_host_mismatch(const sockaddr_t *src, sockaddr_t *dst) {
	if(!src || !dst) {
		return;
	}

	*dst = *src;

	if(dst->sa.sa_family == AF_INET) {
		dst->in.sin_addr.s_addr ^= htonl(1);
	} else if(dst->sa.sa_family == AF_INET6) {
		dst->in6.sin6_addr.s6_addr[15] ^= 1;
	} else {
		memset(dst, 0, sizeof *dst);
		dst->sa.sa_family = AF_INET;
		dst->in.sin_addr.s_addr = htonl(0x7f000002);
	}
}

void relay_fill_mcast_ff02_1(sockaddr_t *dst) {
	if(!dst) {
		return;
	}

	memset(dst, 0, sizeof *dst);
	dst->in6.sin6_family = AF_INET6;
	dst->in6.sin6_addr.s6_addr[0] = 0xff;
	dst->in6.sin6_addr.s6_addr[1] = 0x02;
	dst->in6.sin6_addr.s6_addr[15] = 0x01;
}

void relay_fill_bcast_ipv4(sockaddr_t *dst) {
	if(!dst) {
		return;
	}

	memset(dst, 0, sizeof *dst);
	dst->in.sin_family = AF_INET;
	dst->in.sin_addr.s_addr = htonl(INADDR_BROADCAST);
}

void relay_on_hard_send_error(meshlink_handle_t *mesh, node_t *hop, const sockaddr_t *sa, int sock) {
	(void)sock;

	if(!mesh || !hop || !sa || !hop->status.udp_confirmed) {
		return;
	}

	if(!relay_is_confirmed_send_dest(hop, sa)) {
		return;
	}

	path_note_udp_demoted_reason(mesh, hop, "hard send error");
}

void relay_clear_budget_if_nexthop_changed(meshlink_handle_t *mesh, node_t *dest) {
	if(!dest || dest == mesh->self) {
		return;
	}

	if(dest->nexthop != dest->prev_nexthop) {
		dest->relay_budget = 0;
		dest->prev_nexthop = dest->nexthop;
		channel_refresh_mtu(mesh, dest);
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

bool relay_decode(const void *data, size_t len, char *origin, size_t origin_size, char *destination, size_t destination_size, const uint8_t **inner, size_t *inner_len) {
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

bool relay_send_outer_record(meshlink_handle_t *mesh, node_t *hop, const char *origin, const char *destination, const void *data, size_t len) {
	if(!mesh || !hop || !data || !len || len > UINT16_MAX) {
		return false;
	}

	hop->relay_send_origin = origin;
	hop->relay_send_dest = destination;
	bool ok = sptps_send_record(&hop->sptps, PKT_RELAY_SPTPS, data, (uint16_t)len);
	hop->relay_send_origin = NULL;
	hop->relay_send_dest = NULL;
	return ok;
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

relay_report_entry_t *relay_report_find(meshlink_handle_t *mesh, const char *origin, const char *destination) {
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

void relay_evict_lru(meshlink_handle_t *mesh) {
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

relay_report_entry_t *relay_report_get(meshlink_handle_t *mesh, const char *origin, const char *destination, bool create, bool require_nodes) {
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

static bool relay_send_report(meshlink_handle_t *mesh, const char *origin_name, struct node_t *dest, uint16_t budget) {
	if(mesh->relay_devtool && mesh->relay_devtool->force_report_null_connection) {
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

bool relay_meta_req_sptps(meshlink_handle_t *mesh, connection_t *c, const char *origin, const char *dest_name, const void *data, size_t len) {
	if(!mesh || !c || !origin || !dest_name || !data || !len) {
		return false;
	}

	char buf[len * 4 / 3 + 5];
	b64encode(data, buf, (int)len);
	return send_request(mesh, c, NULL, "%d %s %s %d %s", REQ_KEY, origin, dest_name, REQ_SPTPS, buf);
}

bool relay_send_meta_req_sptps(meshlink_handle_t *mesh, const char *origin, node_t *dest, const void *inner, size_t inner_len) {
	if(!dest || !dest->nexthop || !dest->nexthop->connection || !inner || !inner_len) {
		return false;
	}

	return relay_meta_req_sptps(mesh, dest->nexthop->connection, origin, dest->name, inner, inner_len);
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

			if(!sptps_receive_relay_inner(&origin->sptps, copy, inner_len)) {
				return true;
			}
		} else if(!sptps_receive_relay_inner(&origin->sptps, inner, inner_len)) {
			return true;
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

		path_tier_t hop_tier = path_select_hop_tier(out, false);
		logger(mesh, MESHLINK_DEBUG, "Path policy: mixed hop %s for %s (%s)", out->name, dest->name, path_tier_name(hop_tier));
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

	relay_send_outer_record(mesh, out, origin_name, dest_name, data, len);
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

	/* Ignore unless sender is dest's current META nexthop on this connection.
	   A confirmed direct route no longer needs the relay budget. A confirmed
	   dest whose active route is still relay (promotion not committed) does. */
	if(from != dest->nexthop || from->connection != c) {
		return true;
	}

	if(dest->status.udp_confirmed && dest->active_route.kind == DATA_ROUTE_DIRECT_UDP) {
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

	/* Accepted vpn-packet budget. UDP-relay channels grow and shrink with it. */
	dest->relay_budget = (uint16_t)budget;
	channel_refresh_mtu(mesh, dest);
	logger(mesh, MESHLINK_DEBUG, "Got REQ_RELAY_MTU from %s for %s: %u", from->name, dest->name, (unsigned)dest->relay_budget);
	return true;
}
