/*
    path_liveness.c -- path liveness, idle keepalive, local discovery
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include <string.h>

#include "crypto.h"
#include "event.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "path_liveness.h"
#include "path_plpmtu.h"
#include "path_policy.h"
#include "path_probe.h"
#include "path_scheduler.h"
#include "protocol.h"
#include "relay.h"

static bool same_ip_portless(const sockaddr_t *a, const sockaddr_t *b);

bool path_local_discovery_did_broadcast(const meshlink_handle_t *mesh) {
	return mesh && mesh->discovery_did_broadcast;
}

uint64_t path_probe_fresh_nonce(void) {
	uint64_t nonce = 0;

	do {
		randomize(&nonce, sizeof nonce);
	} while(!nonce);

	return nonce;
}

int64_t path_ms_between(const struct timespec *from, const struct timespec *to) {
	return (int64_t)(to->tv_sec - from->tv_sec) * 1000
	       + (to->tv_nsec - from->tv_nsec) / 1000000;
}

void path_timer_arm_ms(meshlink_handle_t *mesh, timeout_t *t, timeout_cb_t cb, void *data, int ms) {
	struct timespec tv = {
		.tv_sec = ms / 1000,
		.tv_nsec = (long)(ms % 1000) * 1000000L
	};

	if(ms < 1) {
		tv.tv_sec = 0;
		tv.tv_nsec = 1000000L;
	}

	if(t->cb) {
		timeout_set(&mesh->loop, t, &tv);
	} else {
		timeout_add(&mesh->loop, t, cb, data, &tv);
	}

	/* The mesh thread drops mesh->mutex around pselect. A timer inserted
	   off-thread is invisible until something wakes the loop. */
	if(mesh->threadstarted && mesh->loop.pipefd[1] != -1 && !pthread_equal(mesh->thread, pthread_self())) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

void path_timer_disarm(meshlink_handle_t *mesh, timeout_t *t) {
	if(t->cb) {
		timeout_del(&mesh->loop, t);
	}
}

#define fresh_nonce path_probe_fresh_nonce
#define ms_between path_ms_between
#define arm_ms path_timer_arm_ms
#define disarm path_timer_disarm

static int ping_interval(const meshlink_handle_t *mesh, const node_t *n) {
	int interval = mesh->dev_class_traits[n->devclass].pinginterval;

	return interval > 0 ? interval : PATH_LIVENESS_INTERVAL_SEC;
}

static int ping_timeout(const meshlink_handle_t *mesh, const node_t *n) {
	int timeout = mesh->dev_class_traits[n->devclass].pingtimeout;

	return timeout > 0 ? timeout : PATH_LIVENESS_FALLBACK_PING_TIMEOUT_SEC;
}

static int try_gap_ms(const meshlink_handle_t *mesh, const node_t *n) {
	int gap = ping_timeout(mesh, n) * 1000 / PATH_LIVENESS_TRIES;

	return gap < PATH_LIVENESS_TRY_GAP_FLOOR_MS ? PATH_LIVENESS_TRY_GAP_FLOOR_MS : gap;
}

static bool emit_echo(meshlink_handle_t *mesh, node_t *n, uint8_t purpose, uint64_t nonce, bool broadcast, path_transaction_priority_t prio) {
	path_probe_request_t req;
	path_sched_admit_t admit;

	memset(&req, 0, sizeof req);
	req.node = n;
	req.length = PROBE_FIXED_LEN;
	req.broadcast = broadcast;
	req.priority = prio;
	req.send = net_probe_sched_send;
	req.probe_kind = PROBE_KIND_ECHO_REQUEST;
	req.probe_purpose = purpose;
	req.probe_nonce = nonce;
	admit = path_scheduler_emit_packet(mesh, NULL, &req);
	return admit == PATH_SCHED_SENT;
}

static void liveness_timer(event_loop_t *loop, void *data);
static void keepalive_timer(event_loop_t *loop, void *data);
static void discovery_timer(event_loop_t *loop, void *data);

bool path_liveness_outstanding(const node_t *n) {
	return n && n->liveness.state == LIVENESS_PROBING;
}

void path_liveness_stop(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	disarm(mesh, &n->liveness.timer);
	n->liveness.state = LIVENESS_IDLE;
	n->liveness.nonce = 0;
	n->liveness.tries = 0;
	path_scheduler_cancel(mesh, n, PATH_TX_LIVENESS);
}

static void keepalive_apply_pending(meshlink_handle_t *mesh, node_t *n) {
	uint32_t gap = n->keepalive.pending_gap_ms;
	int64_t age = ms_between(&n->keepalive.pending_since, &mesh->loop.now);

	if(gap && n->keepalive.pending_since.tv_sec
	                && gap >= n->keepalive.interval_ms
	                && age >= 0 && age <= (int64_t)PATH_KEEPALIVE_EXPIRY_CONFIRM_SEC * 1000
	                && same_ip_portless(&n->keepalive.pending_ip, &n->address)) {
		uint32_t shrunk = (uint64_t)gap * PATH_KEEPALIVE_SHRINK_PCT / 100;

		if(shrunk < n->keepalive.interval_ms) {
			if(shrunk < PATH_KEEPALIVE_FLOOR_MS) {
				shrunk = PATH_KEEPALIVE_FLOOR_MS;
			}

			n->keepalive.interval_ms = shrunk;
			n->keepalive.expiries++;
			n->status.dirty = true;
			path_plpmtu_remember_keepalive(mesh, n);
			if(n != mesh->backbone_udp.node) {
				arm_ms(mesh, &n->keepalive.timer, keepalive_timer, n, (int)shrunk);
			}
			logger(mesh, MESHLINK_INFO, "UDP keepalive interval for %s set to %ums after idle expiry", n->name, shrunk);
		}

		/* Restart the hourly grow even when the interval is already at the
		   floor and 60% of this gap would not shrink it further. */
		n->keepalive.last_grow_at = mesh->loop.now;
	}

	n->keepalive.pending_gap_ms = 0;
}

void path_liveness_on_confirmed(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || !n->status.udp_confirmed) {
		return;
	}

	if(n == mesh->backbone_udp.node) {
		path_liveness_stop(mesh, n);
		return;
	}

	n->liveness.gave_up = false;
	n->liveness.state = LIVENESS_PARKED;
	n->liveness.tries = 0;
	n->liveness.nonce = 0;
	arm_ms(mesh, &n->liveness.timer, liveness_timer, n, ping_interval(mesh, n) * 1000);
}

void path_liveness_tick(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	if(!n->status.udp_confirmed || !n->status.validkey || n == mesh->backbone_udp.node
	                || !path_liveness_probe_warranted(mesh, n)) {
		path_liveness_stop(mesh, n);
		return;
	}

	if(n->liveness.state != LIVENESS_PROBING && path_plpmtu_probe_recent(mesh, n)) {
		arm_ms(mesh, &n->liveness.timer, liveness_timer, n, PATH_PLPMTU_LIVENESS_GUARD_MS);
		return;
	}

	if(n->liveness.state != LIVENESS_PROBING) {
		n->liveness.state = LIVENESS_PROBING;
		n->liveness.tries = 0;
		n->liveness.nonce = fresh_nonce();
		n->liveness.first_try_at = mesh->loop.now;
	}

	/* All tries have to be sent. A 1s pingtimeout cannot fit three 500ms
	   gaps, and a scheduler denial is not silence from the peer. */
	if(n->liveness.tries >= PATH_LIVENESS_TRIES) {
		if(path_rebind_try_rescue(mesh, n)) {
			arm_ms(mesh, &n->liveness.timer, liveness_timer, n, PATH_REBIND_PROBE_GAP_MS);
			return;
		}

		n->liveness.giveups++;
		n->liveness.gave_up = true;
		logger(mesh, MESHLINK_INFO, "%s did not respond to UDP ping", n->name);
		path_liveness_stop(mesh, n);
		n->liveness.gave_up = true;
		path_note_udp_demoted_reason(mesh, n, "liveness give-up");
		return;
	}

	if(emit_echo(mesh, n, PROBE_PURPOSE_LIVENESS, n->liveness.nonce, false, PATH_TX_LIVENESS)) {
		n->liveness.probes_sent++;
		n->keepalive.last_probe_at = mesh->loop.now;

		if(n->liveness.tries) {
			n->liveness.retries++;
		}

		n->liveness.tries++;
	}

	arm_ms(mesh, &n->liveness.timer, liveness_timer, n, try_gap_ms(mesh, n));
}

static void liveness_timer(event_loop_t *loop, void *data) {
	path_liveness_tick(loop->data, data);
}

static bool from_confirmed(const node_t *n, const sockaddr_t *from) {
	return from && n->address.sa.sa_family && !sockaddrcmp(from, &n->address);
}

void path_liveness_observe_reply(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce, uint8_t purpose) {
	bool mine;

	if(!mesh || !n || n->liveness.state != LIVENESS_PROBING) {
		return;
	}

	if(!from_confirmed(n, from)) {
		return;
	}

	mine = nonce && nonce == n->liveness.nonce && purpose == PROBE_PURPOSE_LIVENESS;

	/* SIZE_ACK callers pass PURPOSE_NONE. A reply from another port never counts. */
	if(!mine && purpose != PROBE_PURPOSE_SUSPECT && purpose != PROBE_PURPOSE_REBIND
	                && purpose != PROBE_PURPOSE_NONE && purpose != PROBE_PURPOSE_PROMOTION
	                && purpose != PROBE_PURPOSE_PUNCH) {
		return;
	}

	if(!mine && !nonce) {
		return;
	}

	n->liveness.state = LIVENESS_PARKED;
	n->liveness.nonce = 0;
	n->liveness.tries = 0;
	n->liveness.gave_up = false;
	path_scheduler_cancel(mesh, n, PATH_TX_LIVENESS);
	arm_ms(mesh, &n->liveness.timer, liveness_timer, n, ping_interval(mesh, n) * 1000);
}

void path_liveness_observe_peer_request(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from) {
	int wait;

	if(!mesh || !n || !mesh->self || n->liveness.state == LIVENESS_IDLE) {
		return;
	}

	if(!from_confirmed(n, from)) {
		return;
	}

	if(!mesh_self_name_is_greater(mesh->self->name, n->name)) {
		return;
	}

	/* The lesser name owns the window. Yield even if our own probe is in flight. */
	n->liveness.state = LIVENESS_PARKED;
	n->liveness.nonce = 0;
	n->liveness.tries = 0;
	n->liveness.gave_up = false;
	path_scheduler_cancel(mesh, n, PATH_TX_LIVENESS);
	wait = ping_interval(mesh, n) + ping_timeout(mesh, n) + 1;
	arm_ms(mesh, &n->liveness.timer, liveness_timer, n, wait * 1000);
}

static bool same_ip_portless(const sockaddr_t *a, const sockaddr_t *b) {
	sockaddr_t aa, bb;

	if(!a || !b || !a->sa.sa_family || !b->sa.sa_family || a->sa.sa_family != b->sa.sa_family) {
		return false;
	}

	path_copy_sockaddr(&aa, a);
	path_copy_sockaddr(&bb, b);

	if(aa.sa.sa_family == AF_INET) {
		aa.in.sin_port = 0;
		bb.in.sin_port = 0;
	} else if(aa.sa.sa_family == AF_INET6) {
		aa.in6.sin6_port = 0;
		bb.in6.sin6_port = 0;
	}

	return !sockaddrcmp(&aa, &bb);
}

static bool keepalive_eligible(const meshlink_handle_t *mesh, const node_t *n) {
	int64_t since_rx;

	if(!n->status.udp_confirmed || !n->status.validkey || n == mesh->self) {
		return false;
	}

	if(n == mesh->backbone_udp.node) {
		return false;
	}

	if(relay_hop_demanded(mesh, n) || path_peer_udp_demanded(mesh, n)) {
		return true;
	}

	if(mesh->backbone.node == mesh->self || !n->keepalive.last_rx_at.tv_sec) {
		return false;
	}

	since_rx = ms_between(&n->keepalive.last_rx_at, &mesh->loop.now);
	return since_rx >= 0 && since_rx <= (int64_t)PATH_KEEPALIVE_PEER_DEMAND_SEC * 1000;
}

void path_keepalive_stop(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	disarm(mesh, &n->keepalive.timer);
	path_scheduler_cancel(mesh, n, PATH_TX_KEEPALIVE);
}

void path_keepalive_on_confirmed(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	if(!n->keepalive.interval_ms) {
		n->keepalive.interval_ms = n == mesh->backbone_udp.node
		                           ? PATH_KEEPALIVE_BACKBONE_INITIAL_MS
		                           : PATH_KEEPALIVE_INITIAL_MS;
	}
	if(!n->keepalive.last_grow_at.tv_sec) {
		n->keepalive.last_grow_at = mesh->loop.now;
	}
	if(!n->keepalive.last_tx_at.tv_sec) {
		/* Confirmation bounds the initial gap even if its outbound probe
		   preceded assignment of the confirmed endpoint. */
		n->keepalive.last_tx_at = mesh->loop.now;
	}

	arm_ms(mesh, &n->keepalive.timer, keepalive_timer, n, (int)n->keepalive.interval_ms);
}

void path_keepalive_note_tx(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *to) {
	uint32_t interval;
	int64_t gap;

	if(!mesh || !n || !n->status.udp_confirmed || n->status.temp_udp_confirmed || !from_confirmed(n, to)) {
		return;
	}

	interval = n->keepalive.interval_ms ? n->keepalive.interval_ms
	           : n == mesh->backbone_udp.node ? PATH_KEEPALIVE_BACKBONE_INITIAL_MS : PATH_KEEPALIVE_INITIAL_MS;
	gap = n->keepalive.last_tx_at.tv_sec ? ms_between(&n->keepalive.last_tx_at, &mesh->loop.now) : 0;
	if(gap >= PATH_KEEPALIVE_FLOOR_MS) {
		logger(mesh, MESHLINK_DEBUG, "UDP outbound idle gap for %s: %lldms (keepalive %ums)", n->name, (long long)gap, interval);
	}

	/* A silence at the remote end says nothing about our own NAT. Save our
	   outbound idle gap; learn only if the peer subsequently observes our
	   source port changing. Short gaps must not manufacture an idle expiry. */
	if(gap >= interval && gap >= PATH_KEEPALIVE_FLOOR_MS && gap <= UINT32_MAX) {
		n->keepalive.pending_gap_ms = (uint32_t)gap;
		n->keepalive.pending_since = mesh->loop.now;
		path_copy_sockaddr(&n->keepalive.pending_ip, &n->address);
	}

	n->keepalive.last_tx_at = mesh->loop.now;

	if(n != mesh->backbone_udp.node) {
		arm_ms(mesh, &n->keepalive.timer, keepalive_timer, n, (int)(n->keepalive.interval_ms ? n->keepalive.interval_ms : PATH_KEEPALIVE_INITIAL_MS));
	}
}

void path_keepalive_note_rx(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	n->keepalive.last_rx_at = mesh->loop.now;

	if(!n->keepalive.timer.cb && keepalive_eligible(mesh, n)) {
		path_keepalive_on_confirmed(mesh, n);
	}
}

void path_keepalive_observe_local_endpoint(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, const sockaddr_t *endpoint) {
	bool known;
	bool remapped;
	bool oversized;
	int64_t age;

	if(!mesh || !n || !endpoint || !n->status.udp_confirmed || !n->status.validkey || !from_confirmed(n, from)
	                || (endpoint->sa.sa_family != AF_INET && endpoint->sa.sa_family != AF_INET6)) {
		return;
	}

	known = n->keepalive.local_endpoint.sa.sa_family
	        && n->keepalive.local_endpoint_epoch == mesh->lan_network_epoch
	        && !sockaddrcmp(&n->keepalive.local_endpoint_peer, from);
	remapped = known && same_ip_portless(&n->keepalive.local_endpoint, endpoint)
	           && sockaddrcmp(&n->keepalive.local_endpoint, endpoint);
	age = ms_between(&n->plpmtu.last_oversize_sent_at, &mesh->loop.now);
	oversized = n->plpmtu.last_oversize_sent_at.tv_sec
	            && age >= 0 && age <= (int64_t)PATH_KEEPALIVE_EXPIRY_CONFIRM_SEC * 1000;

	if(remapped) {
		logger(mesh, MESHLINK_DEBUG, "UDP source port changed for %s: idle evidence %ums, recent oversize %d",
		       n->name, n->keepalive.pending_gap_ms, oversized);
		path_plpmtu_note_local_remap(mesh, n);

		if(!oversized) {
			keepalive_apply_pending(mesh, n);
		}
	}

	/* An unchanged endpoint proves that this idle gap survived. An IP or
	   network change starts a new observation baseline, not an expiry. */
	n->keepalive.pending_gap_ms = 0;
	path_copy_sockaddr(&n->keepalive.local_endpoint, endpoint);
	path_copy_sockaddr(&n->keepalive.local_endpoint_peer, from);
	n->keepalive.local_endpoint_epoch = mesh->lan_network_epoch;
}

static uint32_t keepalive_interval(meshlink_handle_t *mesh, node_t *n, uint32_t cap) {
	uint32_t interval = n->keepalive.interval_ms ? n->keepalive.interval_ms : cap;

	if(n->keepalive.last_grow_at.tv_sec
	                && mesh->loop.now.tv_sec - n->keepalive.last_grow_at.tv_sec >= PATH_KEEPALIVE_GROW_SEC) {
		uint32_t grown = (uint64_t)interval * PATH_KEEPALIVE_GROW_PCT / 100;

		if(grown > cap) {
			grown = cap;
		}

		if(grown > interval) {
			n->keepalive.interval_ms = grown;
			interval = grown;
			n->status.dirty = true;
			path_plpmtu_remember_keepalive(mesh, n);
		}

		n->keepalive.last_grow_at = mesh->loop.now;
	}
	return interval;
}

void path_keepalive_tick(meshlink_handle_t *mesh, node_t *n) {
	path_probe_request_t req;
	int64_t idle;
	int jitter;
	uint32_t interval;

	if(!mesh || !n) {
		return;
	}

	if(!keepalive_eligible(mesh, n)) {
		path_keepalive_stop(mesh, n);
		return;
	}

	if(path_plpmtu_probe_recent(mesh, n)) {
		arm_ms(mesh, &n->keepalive.timer, keepalive_timer, n, PATH_PLPMTU_LIVENESS_GUARD_MS);
		return;
	}

	interval = keepalive_interval(mesh, n, PATH_KEEPALIVE_INITIAL_MS);

	idle = n->keepalive.last_tx_at.tv_sec ? ms_between(&n->keepalive.last_tx_at, &mesh->loop.now) : (int64_t)interval;

	if(idle < (int64_t)interval) {
		arm_ms(mesh, &n->keepalive.timer, keepalive_timer, n, (int)((int64_t)interval - idle));
		return;
	}

	memset(&req, 0, sizeof req);
	req.node = n;
	req.length = PROBE_FIXED_LEN;
	req.priority = PATH_TX_KEEPALIVE;
	req.send = net_probe_sched_send;
	req.probe_kind = PROBE_KIND_KEEPALIVE;
	req.probe_purpose = PROBE_PURPOSE_NONE;
	req.probe_nonce = 0;

	if(path_scheduler_emit_packet(mesh, NULL, &req) == PATH_SCHED_SENT) {
		n->keepalive.sent++;
		n->keepalive.last_probe_at = mesh->loop.now;
	}

	jitter = (int)interval * PATH_KEEPALIVE_JITTER_PCT / 100;
	arm_ms(mesh, &n->keepalive.timer, keepalive_timer, n, (int)interval + (jitter ? (int)prng(mesh, (uint64_t)(2 * jitter + 1)) - jitter : 0));
}

static void keepalive_timer(event_loop_t *loop, void *data) {
	path_keepalive_tick(loop->data, data);
}

uint32_t path_keepalive_backbone_interval_ms(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || !n->keepalive.interval_ms) {
		return PATH_KEEPALIVE_BACKBONE_INITIAL_MS;
	}

	return keepalive_interval(mesh, n, PATH_KEEPALIVE_BACKBONE_INITIAL_MS);
}

void path_local_discovery_stop(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	disarm(mesh, &n->local_discovery.timer);
	n->local_discovery.active = false;
	n->local_discovery.nonce = 0;
}

void path_local_discovery_start(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || n->status.udp_confirmed) {
		return;
	}

	n->local_discovery.active = true;
	n->local_discovery.exhausted = false;
	n->local_discovery.tries = 0;
	n->local_discovery.nonce = fresh_nonce();
	arm_ms(mesh, &n->local_discovery.timer, discovery_timer, n, 0);
}

bool path_local_discovery_accept(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce, uint8_t purpose) {
	sockaddr_t ep;

	if(!mesh || !n || !from || n->status.udp_confirmed || !n->local_discovery.active) {
		return false;
	}

	if(purpose != PROBE_PURPOSE_LOCAL_DISCOVERY || !nonce || nonce != n->local_discovery.nonce) {
		return false;
	}

	if(!path_address_is_local(from)) {
		return false;
	}

	path_copy_sockaddr(&ep, from);
	update_node_udp_from(mesh, n, &ep, ADDR_SRC_UDP_REFLEXIVE);
	n->status.udp_confirmed = true;

	if(n->address.sa.sa_family != AF_UNSPEC) {
		node_add_recent_address_cap(mesh, n, &n->address, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP);
	}

	path_local_discovery_stop(mesh, n);
	path_note_udp_confirmed(mesh, n);
	return true;
}

void path_local_discovery_tick(meshlink_handle_t *mesh, node_t *n) {
	bool broadcast;

	if(!mesh || !n || !n->local_discovery.active || n->status.udp_confirmed) {
		path_local_discovery_stop(mesh, n);
		return;
	}

	if(n->local_discovery.tries >= PATH_LOCAL_DISCOVERY_TRIES) {
		n->local_discovery.exhausted = true;
		n->local_discovery.active = false;
		path_local_discovery_stop(mesh, n);

		if(n->status.want_udp && n->nexthop && n->nexthop->connection) {
			send_request(mesh, n->nexthop->connection, NULL, "%d %s %s . -1 -1 -1 0", ANS_KEY, mesh->self->name, n->name);
			n->status.want_udp = false;
		}

		return;
	}

	broadcast = n->local_discovery.tries < PATH_LOCAL_DISCOVERY_BROADCAST_TRIES && n->prevedge;
	bool sent = emit_echo(mesh, n, PROBE_PURPOSE_LOCAL_DISCOVERY, n->local_discovery.nonce, broadcast, PATH_TX_LIVENESS);
	mesh->discovery_did_broadcast = sent && broadcast;
	if(sent) {
		n->local_discovery.tries++;
	}
	arm_ms(mesh, &n->local_discovery.timer, discovery_timer, n, PATH_LOCAL_DISCOVERY_REARM_MS);
}

static void discovery_timer(event_loop_t *loop, void *data) {
	path_local_discovery_tick(loop->data, data);
}
