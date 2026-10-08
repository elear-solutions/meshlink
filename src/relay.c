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
#include "connection_policy.h"
#include "crypto.h"
#include "path_liveness.h"
#include "path_probe.h"
#include "event.h"
#include "list.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "path_plpmtu.h"
#include "path_policy.h"
#include "protocol.h"
#include "relay.h"
#include "relay_devtool.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

static void relay_hop_timer(event_loop_t *loop, void *data) {
	relay_hop_tick(loop->data, data);
}

static void relay_hop_arm(meshlink_handle_t *mesh, node_t *n) {
	path_timer_arm_ms(mesh, &n->relay_hop.timer, relay_hop_timer, n, RELAY_HOP_TICK_MS + (int)prng(mesh, RELAY_HOP_TICK_JITTER_MS));
}

bool relay_hop_demanded(const meshlink_handle_t *mesh, const node_t *n) {
	return mesh && n && path_ms_between(&mesh->loop.now, &n->relay_hop.demand_until) > 0;
}

void relay_hop_demoted(meshlink_handle_t *mesh, node_t *n) {
	if(!n || !n->relay_hop.confirmed) {
		return;
	}
	n->relay_hop.confirmed = false;
	n->relay_hop.nonce = 0;
	n->relay_hop.retry_at = mesh->loop.now;
	n->relay_hop.retry_at.tv_sec += RELAY_HOP_RETRY_SEC;
	path_scheduler_cancel(mesh, n, PATH_TX_RELAY_HOP);
}

void relay_hop_stop(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}
	bool owned = n->relay_hop.confirmed;
	timeout_del(&mesh->loop, &n->relay_hop.timer);
	path_scheduler_cancel(mesh, n, PATH_TX_RELAY_HOP);
	n->relay_hop.nonce = 0;
	n->relay_hop.confirmed = false;
	n->relay_hop.attempts = 0;
	n->relay_hop.session_id = 0;
	n->relay_hop.network_epoch = 0;
	memset(&n->relay_hop.demand_until, 0, sizeof n->relay_hop.demand_until);
	memset(&n->relay_hop.candidate, 0, sizeof n->relay_hop.candidate);
	memset(&n->relay_hop.retry_at, 0, sizeof n->relay_hop.retry_at);
	if(owned) {
		path_plpmtu_stop(mesh, n);
		path_liveness_stop(mesh, n);
		path_keepalive_stop(mesh, n);
		n->status.udp_confirmed = false;
	}
}

static void relay_hop_preempt(meshlink_handle_t *mesh, node_t *n, path_transaction_type_t type) {
	(void)type;
	/* Retain attempts and deadline; reacquire admission before another send. */
	relay_hop_arm(mesh, n);
}

static void relay_hop_send(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	node_t *n = req->node;
	path_copy_sockaddr(&n->probe_dest_override, &n->relay_hop.candidate);
	n->probe_dest_override_active = true;
	n->udp_send_result = RELAY_UDP_UNREADY;
	net_probe_sched_send(mesh, req);
	n->probe_dest_override_active = false;
	if(n->udp_send_result == RELAY_UDP_SENT) {
		n->relay_hop.attempts++;
		n->relay_hop.challenges_sent++;
		n->relay_hop.last_sent_at = mesh->loop.now;
	}
}

void relay_hop_tick(meshlink_handle_t *mesh, node_t *n) {
	relay_hop_t *p = &n->relay_hop;
	if(!relay_hop_demanded(mesh, n) || !n->status.reachable || n->status.blacklisted
	                || (p->session_id && (p->session_id != n->session_id || p->network_epoch != mesh->lan_network_epoch))) {
		relay_hop_stop(mesh, n);
		return;
	}
	relay_hop_arm(mesh, n);
	if(!n->status.validkey) {
		path_peer_ensure_udp_key(mesh, n);
		return;
	}
	if(p->nonce && path_ms_between(&p->deadline, &mesh->loop.now) >= 0) {
		p->nonce = 0;
		p->failures++;
		p->retry_at = mesh->loop.now;
		p->retry_at.tv_sec += RELAY_HOP_RETRY_SEC;
		path_scheduler_cancel(mesh, n, PATH_TX_RELAY_HOP);
	}
	if(p->confirmed) { path_plpmtu_verify_relay_due(mesh, n); }
	if(!p->nonce) {
		sockaddr_t candidate;
		if(!path_get_fresh_relay_udp_observation(mesh, n, &candidate)) {
			return;
		}
		bool same = p->candidate.sa.sa_family && !sockaddrcmp(&candidate, &p->candidate);
		if((p->confirmed && !sockaddrcmp(&candidate, &p->confirmed_endpoint))
		                || (same && path_ms_between(&mesh->loop.now, &p->retry_at) > 0)) {
			return;
		}
		p->candidate = candidate;
		p->session_id = n->session_id;
		p->network_epoch = mesh->lan_network_epoch;
		p->attempts = 0;
		p->nonce = path_probe_fresh_nonce();
		p->deadline = mesh->loop.now;
		p->deadline.tv_sec += RELAY_HOP_DEADLINE_SEC;
	}
	if(p->attempts >= RELAY_HOP_MAX_ATTEMPTS || (p->attempts && path_ms_between(&p->last_sent_at, &mesh->loop.now) < RELAY_HOP_PROBE_GAP_MS)) {
		return;
	}
	path_sched_txn_t *txn = path_scheduler_begin_transaction(mesh, n, PATH_TXN_RELAY_HOP, PATH_TX_RELAY_HOP, relay_hop_preempt);
	if(!txn) {
		p->admission_delays++;
		return;
	}
	path_probe_request_t req = {
		.node = n, .length = PROBE_FIXED_LEN, .priority = PATH_TX_RELAY_HOP,
		.send = relay_hop_send, .probe_kind = PROBE_KIND_ECHO_REQUEST,
		.probe_purpose = PROBE_PURPOSE_RELAY_HOP, .probe_nonce = p->nonce
	};
	if(path_scheduler_emit_packet(mesh, txn, &req) != PATH_SCHED_SENT) {
		p->admission_delays++;
	}
}

void relay_hop_note_demand(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || n == mesh->self || mesh->self->devclass != DEV_CLASS_BACKBONE || n->status.blacklisted) {
		return;
	}
	/* A packet arriving before the overdue timer is dispatched must not
	   extend expired readiness. The new demand needs a fresh proof. */
	if(n->relay_hop.demand_until.tv_sec && !relay_hop_demanded(mesh, n)) {
		relay_hop_stop(mesh, n);
	}
	n->relay_hop.demand_until = mesh->loop.now;
	n->relay_hop.demand_until.tv_sec += RELAY_HOP_DEMAND_SEC;
	relay_hop_tick(mesh, n);
}

void relay_hop_observe(meshlink_handle_t *mesh, node_t *n) {
	if(relay_hop_demanded(mesh, n)) {
		relay_hop_tick(mesh, n);
	}
}

bool relay_hop_reply(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce) {
	relay_hop_t *p = &n->relay_hop;
	if(!relay_hop_demanded(mesh, n) || !n->status.validkey || !n->status.reachable || n->status.blacklisted
	                || !nonce || nonce != p->nonce || !p->attempts || sockaddrcmp(from, &p->candidate)
	                || p->session_id != n->session_id || p->network_epoch != mesh->lan_network_epoch
	                || path_ms_between(&mesh->loop.now, &p->deadline) <= 0) {
		return false;
	}
	p->nonce = 0;
	p->confirmed = true;
	p->confirmations++;
	p->confirmed_endpoint = p->candidate;
	path_scheduler_cancel(mesh, n, PATH_TX_RELAY_HOP);
	update_node_udp_from(mesh, n, &p->confirmed_endpoint, ADDR_SRC_UDP_REFLEXIVE);
	n->status.udp_confirmed = true;
	/* Deliberately bypass ordinary route promotion and address advertisement. */
	path_plpmtu_on_confirmed(mesh, n);
	path_liveness_on_confirmed(mesh, n);
	path_keepalive_on_confirmed(mesh, n);
	if(mesh->relay_reports) {
		for list_each(relay_report_entry_t, e, mesh->relay_reports) {
			if(!strcmp(e->destination, n->name)) { e->have_reported = false; }
		}
	}
	relay_notify_minmtu_change(mesh, n);
	logger(mesh, MESHLINK_INFO, "Relay UDP output to %s proved", n->name);
	return true;
}

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
	if(mesh->nodes) {
		for splay_each(node_t, n, mesh->nodes) { relay_hop_stop(mesh, n); }
	}
	timeout_del(&mesh->loop, &mesh->relay_report_timeout);

	if(mesh->relay_reports) {
		list_delete_list(mesh->relay_reports);
	}

	mesh->relay_reports = NULL;
	free(mesh->relay_devtool);
	mesh->relay_devtool = NULL;
}

bool relay_hop_udp_ready(const node_t *hop) {
	if(!hop || !hop->status.udp_confirmed || !hop->status.validkey || hop->status.temp_udp_confirmed) {
		return false;
	}
	if(hop->mesh && hop->mesh->self->devclass == DEV_CLASS_BACKBONE) {
		return hop->relay_hop.confirmed && !sockaddrcmp(&hop->address, &hop->relay_hop.confirmed_endpoint);
	}
	return true;
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
	if(!origin || !destination || !out || strlen(origin) > RELAY_NAME_MAX || strlen(destination) > RELAY_NAME_MAX) { return false; }
	return relay_add_u32((uint32_t)relay_prefix_len(origin, destination), RELAY_INNER_MIN, out);
}

bool relay_names_unusable(const char *origin, const char *destination) {
	size_t need = relay_prefix_len(origin, destination) + RELAY_INNER_MIN
	              + sizeof(meshlink_packethdr_t) + RELAY_UTCP_HDR + RELAY_MIN_PAYLOAD;
	return MINMTU < need;
}

uint16_t relay_effective_budget(meshlink_handle_t *mesh, const node_t *dest) {
	uint32_t overhead, first, legacy;
	const node_t *hop = dest->active_route.first_hop;
	if(!hop || !relay_prefix21(mesh->self->name, dest->name, &overhead)
	                || !relay_sub_u32(path_plpmtu_size(hop) ? path_plpmtu_size(hop) : MINMTU, overhead, &first)
	                || !relay_sub_u32(MINMTU, overhead, &legacy)) {
		return 0;
	}
	uint32_t final = dest->relay_budget && hop->connection && dest->nexthop == hop
	                 && dest->relay_budget_connection == hop->connection
	                 ? dest->relay_budget : legacy;
	return (uint16_t)(first < final ? first : final);
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
		dest->relay_budget_connection = NULL;
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
	uint16_t plp = path_plpmtu_size(dest);
	uint32_t base = plp ? plp : MINMTU;
	uint32_t budget;
	node_t *source = lookup_node(mesh, origin);
	/* Older origins treat the final-hop report as the entire route budget.
	   Offer them only the legacy floor: raising their MSS could oversize leg 1.
	   A directly connected 17.8 origin performs the directional clamp itself. */
	if(!source || !source->connection || source->connection->protocol_minor < PROT_MINOR_SPTPS_APP) {
		base = MINMTU;
	}

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

bool relay_meta_app(meshlink_handle_t *mesh, connection_t *c, const char *origin, const char *dest_name, const void *data, size_t len) {
	if(!mesh || !c || !origin || !dest_name || !data || !len || len > MAXSIZE) {
		return false;
	}
	if(c->protocol_minor < PROT_MINOR_SPTPS_APP) {
		return relay_meta_req_sptps(mesh, c, origin, dest_name, data, len);
	}
	char buf[len * 4 / 3 + 5];
	b64encode(data, buf, (int)len);
	return send_request(mesh, c, NULL, "%d %s %s %d %s", REQ_KEY, origin, dest_name, REQ_SPTPS_APP, buf);
}

static bool relay_fallback(meshlink_handle_t *mesh, node_t *out, const char *origin, node_t *dest, const void *inner, size_t len, relay_udp_result_t reason);

bool relay_handle_meta_app(meshlink_handle_t *mesh, connection_t *c, node_t *origin, node_t *dest, const char *request) {
	if(!c || c->protocol_minor < PROT_MINOR_SPTPS_APP || !origin || !dest
	                || origin == mesh->self || origin->status.blacklisted || dest->status.blacklisted) {
		return true;
	}
	char encoded[MAX_STRING_SIZE], extra;
	if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING " %c", encoded, &extra) != 1) {
		return true;
	}
	size_t encoded_len = strlen(encoded);
	if(encoded_len % 4 == 1) { return true; }
	/* b64decode historically accepts junk. Require the wire alphabet here. */
	for(size_t i = 0; i < encoded_len; i++) {
		if(!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", encoded[i])) {
			return true;
		}
	}
	int len = b64decode(encoded, encoded, encoded_len);
	if(len < RELAY_INNER_MIN) {
		return true;
	}
	if(dest == mesh->self) {
		if(!origin->status.validkey || !origin->sptps.instate) {
			return true;
		}
		origin->status.in_req_sptps = true;
		bool ok = sptps_receive_relay_inner(&origin->sptps, encoded, len);
		origin->status.in_req_sptps = false;
		(void)ok;
		return true; /* authentication/replay rejection is a quiet drop */
	}
	if(!c->node || c->node->status.blacklisted || !dest->nexthop || dest->nexthop == mesh->self
	                || dest->nexthop == c->node || !dest->status.reachable) {
		return true;
	}
	uint8_t wrapped[MAXSIZE];
	size_t wrapped_len = sizeof wrapped;
	if(!relay_encode(origin->name, dest->name, encoded, len, wrapped, &wrapped_len)) {
		/* META can carry an inner record whose relay wrapper cannot fit. */
		relay_touch_traffic(mesh, origin->name, dest->name);
		relay_hop_note_demand(mesh, dest->nexthop);
		if(dest->nexthop == dest) { relay_maybe_report(mesh, origin->name, dest, true); }
		relay_fallback(mesh, dest->nexthop, origin->name, dest, encoded, len, RELAY_UDP_OVERSIZE);
		return true;
	}
	return relay_handle_record(mesh, c->node, wrapped, (uint16_t)wrapped_len);
}

static bool relay_fallback(meshlink_handle_t *mesh, node_t *out, const char *origin, node_t *dest, const void *inner, size_t len, relay_udp_result_t reason) {
	out->relay_hop.meta_fallbacks++;
	if((unsigned)reason < 7) {
		out->relay_hop.fallback_reason[reason]++;
	}
	static const char *const reasons[] = {"unready", "sent", "oversize", "no socket", "would block", "EMSGSIZE", "hard send error"};
	logger(mesh, MESHLINK_DEBUG, "Relay META fallback via %s for %s: %s", out->name, dest->name,
	       (unsigned)reason < 7 ? reasons[reason] : "unknown send result");
	return relay_send_meta_req_sptps(mesh, origin, dest, inner, len);
}

void relay_invalidate_connection(meshlink_handle_t *mesh, node_t *hop) {
	if(!mesh || !hop || !mesh->nodes) {
		return;
	}
	for splay_each(node_t, dest, mesh->nodes) {
		if(dest->nexthop == hop) {
			dest->relay_budget = 0;
			dest->relay_budget_connection = NULL;
			channel_refresh_mtu(mesh, dest);
		}
	}
	if(mesh->relay_reports) {
		for list_each(relay_report_entry_t, e, mesh->relay_reports) {
			node_t *origin = lookup_node(mesh, e->origin);
			if(origin && origin->nexthop == hop) { e->have_reported = false; }
		}
	}
}

bool relay_send_meta_req_sptps(meshlink_handle_t *mesh, const char *origin, node_t *dest, const void *inner, size_t inner_len) {
	if(!dest || !dest->nexthop || !dest->nexthop->connection || !inner || !inner_len) {
		return false;
	}

	return relay_meta_app(mesh, dest->nexthop->connection, origin, dest->name, inner, inner_len);
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

	if(!origin || !dest || origin->status.blacklisted || dest->status.blacklisted || from->status.blacklisted) {
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
	relay_touch_traffic(mesh, origin_name, dest_name);
	relay_hop_note_demand(mesh, out);

	if(!relay_hop_udp_ready(out) || out->devtool_force_meta) {
		relay_fallback(mesh, out, origin_name, dest, inner, inner_len, RELAY_UDP_UNREADY);
		return true;
	}

	uint16_t plp = path_plpmtu_size(out);
	uint16_t limit = plp ? plp : MINMTU;
	if((uint32_t)len > limit) {
		if(out == dest) { relay_maybe_report(mesh, origin_name, dest, true); }
		relay_fallback(mesh, out, origin_name, dest, inner, inner_len, RELAY_UDP_OVERSIZE);
		return true;
	}
	if(out == dest) { relay_maybe_report(mesh, origin_name, dest, false); }
	/* Pin the proved endpoint across wrapping and socket selection. */
	path_copy_sockaddr(&out->app_udp_override, &out->address);
	out->app_udp_override_active = true;
	out->udp_send_result = RELAY_UDP_UNREADY;
	bool sent = relay_send_outer_record(mesh, out, origin_name, dest_name, data, len);
	out->app_udp_override_active = false;
	if(!sent) {
		relay_fallback(mesh, out, origin_name, dest, inner, inner_len, out->udp_send_result);
	}
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
	dest->relay_budget_connection = c;
	channel_refresh_mtu(mesh, dest);
	logger(mesh, MESHLINK_DEBUG, "Got REQ_RELAY_MTU from %s for %s: %u", from->name, dest->name, (unsigned)dest->relay_budget);
	return true;
}
