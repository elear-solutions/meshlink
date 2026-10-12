/*
    path_plpmtu_cover.c -- PLPMTU, liveness, keepalive and probe wire cover
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <time.h>

#include "connection_policy.h"
#include "edge.h"
#include "local_network.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "packmsg.h"
#include "path_liveness.h"
#include "path_plpmtu.h"
#include "path_policy.h"
#include "path_probe.h"
#include "path_scheduler.h"
#include "relay.h"

#define CHECK(cond) do { \
		if(!(cond)) { \
			logger(mesh, MESHLINK_ERROR, "path_plpmtu_cover_unit failed: %s", #cond); \
			goto done; \
		} \
	} while(0)

#define EXPECT_ECHO(tap, node, broadcast_flag, dest_sa) do { \
		CHECK((tap).count >= 1); \
		CHECK((tap).last.probe_kind == PROBE_KIND_ECHO_REQUEST); \
		CHECK((tap).last.probe_purpose == PROBE_PURPOSE_LOCAL_DISCOVERY); \
		CHECK((tap).last.length == PROBE_FIXED_LEN); \
		CHECK((tap).last.probe_nonce == (node).local_discovery.nonce); \
		CHECK((tap).last.broadcast == (broadcast_flag)); \
		CHECK(!sockaddrcmp(&(tap).last.dest, &(dest_sa))); \
	} while(0)

static uint16_t cover_pmtu_seen;

static void cover_pmtu_cb(meshlink_handle_t *mesh, meshlink_node_t *node, uint16_t pmtu) {
	(void)mesh;
	(void)node;
	cover_pmtu_seen = pmtu;
}

static sockaddr_t v4(uint32_t host, uint16_t port) {
	sockaddr_t sa;

	memset(&sa, 0, sizeof sa);
	sa.in.sin_family = AF_INET;
	sa.in.sin_addr.s_addr = htonl(host);
	sa.in.sin_port = htons(port);
	return sa;
}

static void advance_ms(meshlink_handle_t *mesh, int ms) {
	mesh->loop.now.tv_sec += ms / 1000;
	mesh->loop.now.tv_nsec += (long)(ms % 1000) * 1000000L;

	if(mesh->loop.now.tv_nsec >= 1000000000L) {
		mesh->loop.now.tv_sec++;
		mesh->loop.now.tv_nsec -= 1000000000L;
	}
}

static void plant_confirmed_udp_peer(node_t *n, meshlink_handle_t *mesh, const char *name, uint32_t ip) {
	memset(n, 0, sizeof *n);
	n->name = (char *)name;
	n->mesh = mesh;
	n->devclass = DEV_CLASS_STATIONARY;
	n->status.udp_confirmed = true;
	n->status.validkey = true;
	n->status.reachable = true;
	n->devtool_force_meta = true;
	n->peer_udp.channel_count = 1;
	n->keepalive.interval_ms = PATH_KEEPALIVE_INITIAL_MS;
	n->address = v4(ip, 9);
}

static void stop_peer_path_activity(meshlink_handle_t *mesh, node_t *n) {
	path_plpmtu_stop(mesh, n);
	path_liveness_stop(mesh, n);
	path_keepalive_stop(mesh, n);
	path_local_discovery_stop(mesh, n);
	path_scheduler_cancel_node(mesh, n);
	timeout_del(&mesh->loop, &n->punch_timer);
	timeout_del(&mesh->loop, &n->promotion_timer);
	timeout_del(&mesh->loop, &n->rebind_timer);
	timeout_del(&mesh->loop, &n->suspect_validation.timer);
	timeout_del(&mesh->loop, &n->plpmtu.timer);
	timeout_del(&mesh->loop, &n->liveness.timer);
	timeout_del(&mesh->loop, &n->keepalive.timer);
	timeout_del(&mesh->loop, &n->local_discovery.timer);
}

static bool lose_outstanding(meshlink_handle_t *mesh, node_t *n) {
	int i;

	for(i = 0; i < PATH_PLPMTU_MAX_PROBES; i++) {
		advance_ms(mesh, PATH_PLPMTU_PROBE_TIMEOUT_MS);
		path_plpmtu_tick(mesh, n);
		advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
		path_plpmtu_tick(mesh, n);
	}

	return n->plpmtu.probe_size == 0;
}

static int cache_slot(const node_t *n, uint32_t host) {
	uint32_t be = htonl(host);
	int i;

	for(i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		if(n->mtu_cache[i].family == AF_INET && !memcmp(n->mtu_cache[i].addr, &be, 4)) {
			return i;
		}
	}

	return -1;
}

static bool plpmtu_cover(meshlink_handle_t *mesh) {
	node_t n;
	node_t hop;
	node_t dest;
	int slot;
	sockaddr_t other;
	meshlink_node_pmtu_cb_t saved_cb = mesh->node_pmtu_cb;
	char *saved_ext = mesh->self->external_ip_address;
	node_t *saved_bb = mesh->backbone_udp.node;
	uint16_t held;
	uint32_t hits;
	int i;
	bool ok = false;

	memset(&hop, 0, sizeof hop);
	memset(&dest, 0, sizeof dest);
	plant_confirmed_udp_peer(&n, mesh, "plpmtu-peer", 0xcb00710a);
	CHECK(mesh->self);
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_BASE);
	CHECK(n.plpmtu.size == PATH_PLPMTU_BASE);
	CHECK(!n.plpmtu.probe_size);

	n.active_route.kind = DATA_ROUTE_DIRECT_UDP;
	CHECK(channel_compute_mtu(mesh, &n) == PATH_PLPMTU_BASE - sizeof(meshlink_packethdr_t));

	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1259);

	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce ^ 1, n.plpmtu.probe_size);
	other = n.address;
	other.in.sin_port = htons(10);
	path_plpmtu_observe_ack(mesh, &n, &other, n.plpmtu.probe_nonce, n.plpmtu.probe_size);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, 64);
	CHECK(n.plpmtu.probe_size == 1259);
	CHECK(n.plpmtu.size == PATH_PLPMTU_BASE);

	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, n.plpmtu.probe_size);
	CHECK(n.plpmtu.size == 1259);
	CHECK(!n.plpmtu.probe_size);

	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1339);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, n.plpmtu.probe_size);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1379);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, n.plpmtu.probe_size);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1399);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, n.plpmtu.probe_size);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1419);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, n.plpmtu.probe_size);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1431);
	CHECK(lose_outstanding(mesh, &n));
	CHECK(n.plpmtu.state == PLPMTU_COMPLETE);
	CHECK(n.plpmtu.size == 1419);
	CHECK(n.plpmtu.largest_failed == 1431);
	CHECK(n.plpmtu.probes_lost == 3);
	CHECK(n.plpmtu.raise_at.tv_sec == mesh->loop.now.tv_sec + PATH_PLPMTU_RAISE_SEC);

	mesh->loop.now.tv_sec = n.plpmtu.raise_at.tv_sec;
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1431);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, n.plpmtu.probe_size);
	CHECK(n.plpmtu.size == 1431);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == MTU);

	/* EMSGSIZE pulls the settled size under the failed payload. */
	n.plpmtu.size = 1419;
	n.plpmtu.probe_size = 0;
	mesh->node_pmtu_cb = cover_pmtu_cb;
	cover_pmtu_seen = 0;
	path_plpmtu_note_emsgsize(mesh, &n, 1400);
	CHECK(n.plpmtu.size == 1399);
	CHECK(n.plpmtu.largest_failed == 1400);
	CHECK(n.plpmtu.emsgsize >= 1);
	CHECK(cover_pmtu_seen == 1399);

	/* A base probe that dies three times is an error, and the raise retries it. */
	stop_peer_path_activity(mesh, &n);
	memset(&n.plpmtu, 0, sizeof n.plpmtu);
	memset(n.mtu_cache, 0, sizeof n.mtu_cache);
	n.status.udp_confirmed = true;
	n.plpmtu.state = PLPMTU_BASE;
	n.plpmtu.size = PATH_PLPMTU_BASE;
	n.plpmtu.probe_size = PATH_PLPMTU_BASE;
	n.plpmtu.probe_tries = PATH_PLPMTU_MAX_PROBES - 1;
	n.plpmtu.probe_sent_at = mesh->loop.now;
	advance_ms(mesh, PATH_PLPMTU_PROBE_TIMEOUT_MS);
	path_plpmtu_tick(mesh, &n);
	advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_ERROR);
	CHECK(n.plpmtu.size == MINMTU);
	mesh->loop.now.tv_sec = n.plpmtu.raise_at.tv_sec;
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_BASE);
	CHECK(n.plpmtu.probe_size == PATH_PLPMTU_BASE);

	/* Same IP inside the trust window restores COMPLETE and sends nothing. */
	stop_peer_path_activity(mesh, &n);
	memset(&n.plpmtu, 0, sizeof n.plpmtu);
	memset(n.mtu_cache, 0, sizeof n.mtu_cache);
	n.status.udp_confirmed = true;
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.size = 1419;
	n.plpmtu.largest_failed = 1431;
	n.plpmtu.path_ip = n.address;
	n.plpmtu.path_ip.in.sin_port = 0;
	n.plpmtu.path_net_fp = path_local_network_fp(mesh);
	path_plpmtu_stop(mesh, &n);
	n.status.udp_confirmed = true;
	n.status.dirty = false;
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_COMPLETE);
	CHECK(n.plpmtu.size == 1419);
	CHECK(!n.plpmtu.probe_size);
	CHECK(n.plpmtu.cache_hits == 1);

	/* Same bytes stored again are not a material change. */
	n.status.dirty = false;
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.size = 1419;
	n.plpmtu.largest_failed = 1431;
	n.plpmtu.path_ip = n.address;
	n.plpmtu.path_ip.in.sin_port = 0;
	path_plpmtu_stop(mesh, &n);
	CHECK(!n.status.dirty);

	slot = cache_slot(&n, 0xcb00710a);
	CHECK(slot >= 0);
	n.mtu_cache[slot].updated_at = time(NULL) - PATH_PLPMTU_TRUST_SEC - 5;
	n.status.udp_confirmed = true;
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_VERIFY);
	CHECK(n.plpmtu.size == PATH_PLPMTU_BASE);
	CHECK(n.plpmtu.probe_size == 1419);
	CHECK(lose_outstanding(mesh, &n));
	CHECK(n.plpmtu.state == PLPMTU_SEARCHING);
	CHECK(n.plpmtu.size == PATH_PLPMTU_BASE);
	CHECK(n.plpmtu.largest_failed == 1419);
	advance_ms(mesh, PATH_PLPMTU_STEP_GAP_MS);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1259);

	/* Four addresses, then a fifth drops the oldest. */
	stop_peer_path_activity(mesh, &n);
	memset(n.mtu_cache, 0, sizeof n.mtu_cache);
	memset(&n.plpmtu, 0, sizeof n.plpmtu);

	for(i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		n.address = v4(0x0a000001 + i, 9);
		n.status.udp_confirmed = true;
		path_plpmtu_on_confirmed(mesh, &n);
		n.plpmtu.size = PATH_PLPMTU_BASE;
		path_plpmtu_stop(mesh, &n);
		slot = cache_slot(&n, 0x0a000001 + i);
		CHECK(slot >= 0);
		n.mtu_cache[slot].updated_at = 10 + i;
	}

	n.address = v4(0x0a000001 + PATH_MTU_CACHE_ENTRIES, 9);
	n.status.udp_confirmed = true;
	path_plpmtu_on_confirmed(mesh, &n);
	n.plpmtu.size = PATH_PLPMTU_BASE;
	path_plpmtu_stop(mesh, &n);
	CHECK(cache_slot(&n, 0x0a000001) < 0);
	CHECK(cache_slot(&n, 0x0a000001 + PATH_MTU_CACHE_ENTRIES) >= 0);

	/* A different local network fingerprint ignores the entry. */
	char network_a[] = "203.0.113.9 1";
	char network_b[] = "198.51.100.9 1";
	mesh->self->external_ip_address = network_a;
	n.address = v4(0xcb00710a, 9);
	memset(n.mtu_cache, 0, sizeof n.mtu_cache);
	memset(&n.plpmtu, 0, sizeof n.plpmtu);
	n.status.udp_confirmed = true;
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.size = 1399;
	n.plpmtu.path_ip = n.address;
	n.plpmtu.path_ip.in.sin_port = 0;
	n.plpmtu.path_net_fp = path_local_network_fp(mesh);
	path_plpmtu_stop(mesh, &n);
	mesh->self->external_ip_address = network_b;
	n.status.udp_confirmed = true;
	hits = n.plpmtu.cache_hits;
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_BASE);
	CHECK(n.plpmtu.cache_hits == hits);

	/* No search probe while liveness is in flight or inside the guard. */
	n.liveness.state = LIVENESS_PROBING;
	n.plpmtu.probe_size = 0;
	path_plpmtu_tick(mesh, &n);
	CHECK(!n.plpmtu.probe_size);
	n.liveness.state = LIVENESS_PARKED;
	n.liveness.first_try_at = mesh->loop.now;
	path_plpmtu_tick(mesh, &n);
	CHECK(!n.plpmtu.probe_size);
	advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
	n.liveness.state = LIVENESS_IDLE;
	n.keepalive.last_probe_at = mesh->loop.now;
	path_plpmtu_tick(mesh, &n);
	CHECK(!n.plpmtu.probe_size);
	advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
	n.keepalive.last_tx_at.tv_sec = 0;
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1259);

	/* Idle peers are not searched. The backbone node is. */
	stop_peer_path_activity(mesh, &n);
	memset(&n.plpmtu, 0, sizeof n.plpmtu);
	memset(n.mtu_cache, 0, sizeof n.mtu_cache);
	n.peer_udp.channel_count = 0;
	n.status.udp_confirmed = true;
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_DISABLED);
	mesh->backbone_udp.node = &n;
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_BASE);
	CHECK(n.plpmtu.size == PATH_PLPMTU_BASE);
	mesh->backbone_udp.node = saved_bb;

	/* Before a final-hop report arrives, relay MSS keeps the legacy floor. */
	plant_confirmed_udp_peer(&hop, mesh, "mtu-hop", 0xcb007120);
	plant_confirmed_udp_peer(&dest, mesh, "d", 0xcb007121);
	hop.status.udp_confirmed = true;
	hop.plpmtu.state = PLPMTU_COMPLETE;
	hop.plpmtu.size = PATH_PLPMTU_BASE;
	dest.active_route.kind = DATA_ROUTE_RELAY;
	dest.active_route.relay_carrier = RELAY_CARRIER_UDP;
	dest.active_route.first_hop = &hop;
	{
		uint32_t prefix21 = 0;

		CHECK(relay_prefix21(mesh->self->name, dest.name, &prefix21));
		CHECK(!relay_names_unusable(mesh->self->name, dest.name));
		held = (uint16_t)(MINMTU - prefix21 - sizeof(meshlink_packethdr_t));
		CHECK(channel_compute_mtu(mesh, &dest) == held);
	}

	/* Hostile: a local remap inside the window holds the size and backs off. */
	stop_peer_path_activity(mesh, &n);
	memset(&n.plpmtu, 0, sizeof n.plpmtu);
	n.status.udp_confirmed = true;
	n.peer_udp.channel_count = 1;
	n.plpmtu.state = PLPMTU_SEARCHING;
	n.plpmtu.size = 1399;
	n.plpmtu.last_oversize_sent_at = mesh->loop.now;
	path_plpmtu_note_local_remap(mesh, &n);
	CHECK(n.plpmtu.hostile);
	CHECK(n.plpmtu.size == 1399);
	CHECK(n.plpmtu.state == PLPMTU_COMPLETE);
	CHECK(n.plpmtu.raise_at.tv_sec - mesh->loop.now.tv_sec == 1200);
	n.plpmtu.last_oversize_sent_at = mesh->loop.now;
	path_plpmtu_note_local_remap(mesh, &n);
	CHECK(n.plpmtu.raise_at.tv_sec - mesh->loop.now.tv_sec == 2400);
	n.plpmtu.raise_backoff = 16;
	n.plpmtu.last_oversize_sent_at = mesh->loop.now;
	path_plpmtu_note_local_remap(mesh, &n);
	CHECK(n.plpmtu.raise_at.tv_sec - mesh->loop.now.tv_sec == PATH_PLPMTU_RAISE_MAX_SEC);

	/* Two large suspect sends plus a clear drop a black hole back to base. */
	n.plpmtu.hostile = false;
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.size = 1419;
	n.plpmtu.probe_size = 0;
	n.plpmtu.bh_evidence = 0;
	n.plpmtu.bh_first_at.tv_sec = 0;
	n.plpmtu.black_holes = 0;
	path_plpmtu_note_large_suspect_send(mesh, &n, 1300);
	path_plpmtu_note_large_suspect_send(mesh, &n, 1300);
	path_plpmtu_note_suspect_cleared(mesh, &n);
	CHECK(n.plpmtu.bh_verifying);
	CHECK(n.plpmtu.probe_size == 1419);
	CHECK(lose_outstanding(mesh, &n));
	CHECK(n.plpmtu.size == PATH_PLPMTU_BASE);
	CHECK(n.plpmtu.largest_failed == 1419);
	CHECK(n.plpmtu.black_holes == 1);

	ok = true;

done:
	mesh->node_pmtu_cb = saved_cb;
	mesh->self->external_ip_address = saved_ext;
	mesh->backbone_udp.node = saved_bb;
	stop_peer_path_activity(mesh, &n);
	stop_peer_path_activity(mesh, &hop);
	stop_peer_path_activity(mesh, &dest);
	return ok;
}

/* Regression: scheduler starvation must neither queue a stale size probe nor
   consume a try; deferred verification must retain its intended size. */
static bool plpmtu_admission_cover(meshlink_handle_t *mesh) {
	node_t n;
	node_t blocker;
	uint64_t nonce;
	uint32_t sent;
	unsigned queued = mesh->probe_queue->count;
	unsigned saved_max = mesh->probe_max_transactions;
	bool ok = false;

	memset(&blocker, 0, sizeof blocker);
	plant_confirmed_udp_peer(&n, mesh, "plpmtu-admission", 0xcb007130);
	path_plpmtu_on_confirmed(mesh, &n);
	path_scheduler_set_budget(mesh, 0, 100, 8);
	path_plpmtu_tick(mesh, &n);
	CHECK(mesh->probe_queue->count == queued);
	CHECK(!n.plpmtu.probe_size && !n.plpmtu.probe_nonce && n.plpmtu.pending_size == 1259);
	CHECK(!n.plpmtu.probes_sent && !n.plpmtu.probe_tries);
	CHECK(!n.plpmtu.last_oversize_sent_at.tv_sec);

	path_scheduler_set_budget(mesh, 100, 100, 8);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1259 && n.plpmtu.probe_nonce);
	CHECK(n.plpmtu.probes_sent == 1);
	nonce = n.plpmtu.probe_nonce;
	advance_ms(mesh, PATH_PLPMTU_PROBE_TIMEOUT_MS);
	path_scheduler_set_budget(mesh, 0, 100, 8);
	path_plpmtu_tick(mesh, &n);
	CHECK(mesh->probe_queue->count == queued);
	CHECK(n.plpmtu.probe_nonce == nonce && n.plpmtu.probe_size == 1259);
	CHECK(!n.plpmtu.probe_tries && n.plpmtu.probes_sent == 1);
	/* A late reply is still accepted after admission denied its retry. */
	path_plpmtu_observe_ack(mesh, &n, &n.address, nonce, 1259);
	CHECK(n.plpmtu.size == 1259);

	path_scheduler_set_budget(mesh, 100, 100, 8);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1339);
	sent = n.plpmtu.probes_sent;
	advance_ms(mesh, PATH_PLPMTU_PROBE_TIMEOUT_MS);
	n.liveness.state = LIVENESS_PROBING;
	n.keepalive.last_probe_at = mesh->loop.now;
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probes_sent == sent && !n.plpmtu.probe_tries);
	n.liveness.state = LIVENESS_IDLE;
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probes_sent == sent);
	advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.recovery_nonce && n.plpmtu.probes_sent == sent && !n.plpmtu.probe_tries);
	advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probes_sent == sent + 1 && n.plpmtu.probe_tries == 1);
	/* Reverse timer order: health probes defer after an actual size send. */
	path_liveness_tick(mesh, &n);
	CHECK(n.liveness.state != LIVENESS_PROBING && !n.liveness.probes_sent);
	n.keepalive.last_tx_at.tv_sec = 0;
	path_keepalive_tick(mesh, &n);
	CHECK(!n.keepalive.sent);
	advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
	path_liveness_tick(mesh, &n);
	CHECK(n.liveness.probes_sent == 1);
	path_liveness_stop(mesh, &n);
	advance_ms(mesh, PATH_PLPMTU_PROBE_TIMEOUT_MS);
	path_plpmtu_tick(mesh, &n);
	advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probes_sent == sent + 2 && n.plpmtu.probe_tries == 2);
	advance_ms(mesh, PATH_PLPMTU_PROBE_TIMEOUT_MS);
	path_plpmtu_tick(mesh, &n);
	advance_ms(mesh, PATH_PLPMTU_LIVENESS_GUARD_MS);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_COMPLETE && n.plpmtu.probes_lost == 3);
	CHECK(n.plpmtu.probes_sent == sent + 2);

	/* A full transaction pool must defer the first size probe too. */
	stop_peer_path_activity(mesh, &n);
	plant_confirmed_udp_peer(&n, mesh, "plpmtu-admission", 0xcb007130);
	plant_confirmed_udp_peer(&blocker, mesh, "probe-slot-blocker", 0xcb007131);
	path_scheduler_set_budget(mesh, 100, 100, 1);
	CHECK(path_scheduler_begin_transaction(mesh, &blocker, PATH_TXN_SUSPECT,
	                PATH_TX_ACTIVE_ROUTE_RECOVERY, path_transaction_preempt));
	path_plpmtu_on_confirmed(mesh, &n);
	path_plpmtu_tick(mesh, &n);
	CHECK(!n.plpmtu.probe_nonce && !n.plpmtu.probes_sent && !n.plpmtu.probe_size);
	path_scheduler_end_type(mesh, &blocker, PATH_TXN_SUSPECT);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1259 && n.plpmtu.probes_sent == 1);

	/* Black-hole verification must keep the current size when deferred. */
	n.plpmtu.size = 1399;
	n.liveness.state = LIVENESS_PROBING;
	path_plpmtu_note_large_suspect_send(mesh, &n, 1300);
	path_plpmtu_note_large_suspect_send(mesh, &n, 1300);
	path_plpmtu_note_suspect_cleared(mesh, &n);
	CHECK(n.plpmtu.bh_verifying && n.plpmtu.pending_size == 1399);
	CHECK(!n.plpmtu.probe_nonce && !n.plpmtu.probe_size);
	n.liveness.state = LIVENESS_IDLE;
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1399);

	/* ERROR recovery is guarded too, even though it sends the base size. */
	path_plpmtu_pause(mesh, &n);
	n.plpmtu.state = PLPMTU_ERROR;
	n.plpmtu.size = MINMTU;
	n.plpmtu.bh_verifying = false;
	n.plpmtu.largest_failed = PATH_PLPMTU_BASE;
	n.plpmtu.raise_at = mesh->loop.now;
	n.liveness.state = LIVENESS_PROBING;
	sent = n.plpmtu.probes_sent;
	path_plpmtu_tick(mesh, &n);
	CHECK(!n.plpmtu.probe_size && n.plpmtu.pending_size == PATH_PLPMTU_BASE);
	CHECK(n.plpmtu.probes_sent == sent);
	n.liveness.state = LIVENESS_IDLE;
	/* Backbone health windows also block all size sends. */
	node_t *saved_bb = mesh->backbone_udp.node;
	uint64_t saved_nonce = mesh->backbone_udp.liveness_nonce;
	mesh->backbone_udp.node = &n;
	mesh->backbone_udp.liveness_nonce = 1;
	path_plpmtu_tick(mesh, &n);
	bool deferred = !n.plpmtu.probe_size && n.plpmtu.probes_sent == sent;
	mesh->backbone_udp.node = saved_bb;
	mesh->backbone_udp.liveness_nonce = saved_nonce;
	CHECK(deferred);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == PATH_PLPMTU_BASE);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, PATH_PLPMTU_BASE);
	CHECK(!n.plpmtu.largest_failed && !n.plpmtu.raise_backoff);
	ok = true;

done:
	stop_peer_path_activity(mesh, &n);
	stop_peer_path_activity(mesh, &blocker);
	path_scheduler_set_budget(mesh, 1000, 1000, saved_max);
	return ok;
}

static bool plpmtu_cache_raise_cover(meshlink_handle_t *mesh) {
	node_t n;
	int slot;
	bool ok = false;

	plant_confirmed_udp_peer(&n, mesh, "cached-mtu-raise", 0xcb007132);
	path_plpmtu_on_confirmed(mesh, &n);
	n.plpmtu.size = 1399;
	n.plpmtu.largest_failed = 1419;
	n.plpmtu.hostile = true;
	n.plpmtu.raise_backoff = 5;
	n.keepalive.interval_ms = 5000;
	path_plpmtu_stop(mesh, &n);
	slot = cache_slot(&n, 0xcb007132);
	CHECK(slot >= 0);
	n.mtu_cache[slot].updated_at = time(NULL) - PATH_PLPMTU_TRUST_SEC - 1;
	n.keepalive.interval_ms = PATH_KEEPALIVE_INITIAL_MS;
	n.liveness.state = LIVENESS_PROBING;
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_VERIFY && !n.plpmtu.probe_nonce);
	CHECK(n.plpmtu.size == PATH_PLPMTU_BASE && n.plpmtu.pending_size == 1399);
	CHECK(n.keepalive.interval_ms == 5000);
	n.liveness.state = LIVENESS_IDLE;
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.probe_size == 1399);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, 1399);
	CHECK(n.plpmtu.hostile && n.plpmtu.largest_failed == 1419 && n.plpmtu.raise_backoff == 5);
	CHECK(n.mtu_cache[slot].flags == (PATH_MTU_CACHE_HOSTILE | PATH_MTU_CACHE_KEEPALIVE_V2));
	CHECK(n.mtu_cache[slot].largest_failed == 1419 && n.mtu_cache[slot].raise_backoff == 5);
	CHECK(n.mtu_cache[slot].keepalive_ms == 5000);

	/* A local MTU limit cancels a deferred cached target before admission. */
	path_plpmtu_stop(mesh, &n);
	n.mtu_cache[slot].updated_at = time(NULL) - PATH_PLPMTU_TRUST_SEC - 1;
	n.liveness.state = LIVENESS_PROBING;
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(n.plpmtu.pending_size == 1399);
	path_plpmtu_note_emsgsize(mesh, &n, 1300);
	CHECK(!n.plpmtu.pending_size && n.plpmtu.largest_failed == 1300);
	n.liveness.state = LIVENESS_IDLE;
	/* Restore this cache fixture for the independent loss case. */
	n.plpmtu.size = 1399;
	n.plpmtu.largest_failed = 1419;

	/* Verification losses tighten the bound and retain unrelated lessons. */
	path_plpmtu_stop(mesh, &n);
	n.mtu_cache[slot].updated_at = time(NULL) - PATH_PLPMTU_TRUST_SEC - 1;
	path_plpmtu_on_confirmed(mesh, &n);
	CHECK(lose_outstanding(mesh, &n));
	CHECK(n.plpmtu.size == PATH_PLPMTU_BASE && n.plpmtu.largest_failed == 1399);
	CHECK(n.plpmtu.hostile && n.plpmtu.raise_backoff == 5 && n.keepalive.interval_ms == 5000);

	/* First failure waits 10 minutes; failed raises double up to the cap. */
	stop_peer_path_activity(mesh, &n);
	plant_confirmed_udp_peer(&n, mesh, "cached-mtu-raise", 0xcb007132);
	path_plpmtu_on_confirmed(mesh, &n);
	path_plpmtu_tick(mesh, &n);
	CHECK(lose_outstanding(mesh, &n));
	CHECK(n.plpmtu.raise_at.tv_sec - mesh->loop.now.tv_sec == PATH_PLPMTU_RAISE_SEC);
	for(int round = 1; round <= 8; round++) {
		mesh->loop.now = n.plpmtu.raise_at;
		path_plpmtu_tick(mesh, &n);
		CHECK(n.plpmtu.probe_size == 1259);
		CHECK(lose_outstanding(mesh, &n));
		int expected = PATH_PLPMTU_RAISE_SEC << round;
		if(expected > PATH_PLPMTU_RAISE_MAX_SEC) {
			expected = PATH_PLPMTU_RAISE_MAX_SEC;
		}
		CHECK(n.plpmtu.raise_at.tv_sec - mesh->loop.now.tv_sec == expected);
	}
	mesh->loop.now = n.plpmtu.raise_at;
	path_plpmtu_tick(mesh, &n);
	path_plpmtu_observe_ack(mesh, &n, &n.address, n.plpmtu.probe_nonce, 1259);
	CHECK(n.plpmtu.size == 1259 && !n.plpmtu.raise_backoff);
	path_plpmtu_tick(mesh, &n);
	CHECK(lose_outstanding(mesh, &n));
	CHECK(n.plpmtu.raise_at.tv_sec - mesh->loop.now.tv_sec == PATH_PLPMTU_RAISE_SEC);
	/* ICMP failures follow the same backoff without inventing packet loss. */
	mesh->loop.now = n.plpmtu.raise_at;
	path_plpmtu_tick(mesh, &n);
	path_plpmtu_note_emsgsize(mesh, &n, n.plpmtu.probe_size);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_COMPLETE && n.plpmtu.raise_backoff == 1);
	CHECK(n.plpmtu.raise_at.tv_sec - mesh->loop.now.tv_sec == 2 * PATH_PLPMTU_RAISE_SEC);
	ok = true;

done:
	stop_peer_path_activity(mesh, &n);
	return ok;
}

/* No application UDP is available before promotion. A missed size request
   must itself make the new NAT mapping visible, including on the backbone. */
static bool plpmtu_recovery_cover(meshlink_handle_t *mesh) {
	node_t n;
	vpn_packet_t packet;
	sockaddr_t local = v4(0xc0000201, 5000);
	node_t *saved_bb = mesh->backbone_udp.node;
	bool saved_confirmed = mesh->backbone_udp.confirmed;
	uint64_t saved_nonce = mesh->backbone_udp.liveness_nonce;
	unsigned saved_max = mesh->probe_max_transactions;
	bool ok = false;

	memset(&n, 0, sizeof n);
	for(int backbone = 0; backbone < 2; backbone++) {
		plant_confirmed_udp_peer(&n, mesh, "plpmtu-recovery", 0xcb007133);
		if(backbone) {
			mesh->backbone_udp.node = &n;
			mesh->backbone_udp.confirmed = true;
			mesh->backbone_udp.liveness_nonce = 0;
		}
		n.plpmtu.state = PLPMTU_SEARCHING;
		n.plpmtu.size = 1431;
		n.plpmtu.path_ip = n.address;
		n.plpmtu.path_ip.in.sin_port = 0;
		path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
		path_scheduler_set_budget(mesh, 100, 100, 8);
		path_plpmtu_tick(mesh, &n);
		CHECK(n.plpmtu.probe_size == 1451 && n.plpmtu.probes_sent == 1);
		uint64_t size_nonce = n.plpmtu.probe_nonce;
		advance_ms(mesh, PATH_PLPMTU_PROBE_TIMEOUT_MS);
		path_scheduler_set_budget(mesh, 0, 100, 8);
		path_plpmtu_tick(mesh, &n);
		CHECK(!n.plpmtu.recovery_nonce && !n.plpmtu.probe_tries && !mesh->probe_queue->count);
		path_scheduler_set_budget(mesh, 100, 100, 8);
		path_plpmtu_tick(mesh, &n);
		CHECK(n.plpmtu.recovery_nonce && n.plpmtu.probe_nonce == size_nonce);
		CHECK(n.plpmtu.probes_sent == 1 && !n.plpmtu.probe_tries);
		path_plpmtu_tick(mesh, &n);
		CHECK(n.plpmtu.probes_sent == 1);

		memset(&packet, 0, sizeof packet);
		packet.len = PROBE_FIXED_LEN;
		packet.data[0] = PROBE_KIND_ECHO_REPLY;
		packet.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_PLPMTU_RECOVERY;
		uint64_t nonce = n.plpmtu.recovery_nonce ^ 1;
		memcpy(packet.data + PROBE_NONCE_OFFSET, &nonce, sizeof nonce);
		local.in.sin_port = htons(5100 + backbone);
		path_probe_write_endpoint(packet.data, &local);
		n.devtool_force_meta = false;
		n.last_udp_from = n.address;
		probe_record_h(mesh, &n, &packet, packet.len);
		CHECK(!n.plpmtu.hostile);
		nonce = n.plpmtu.recovery_nonce;
		memcpy(packet.data + PROBE_NONCE_OFFSET, &nonce, sizeof nonce);
		n.last_udp_from.in.sin_port = htons(9999);
		probe_record_h(mesh, &n, &packet, packet.len);
		CHECK(!n.plpmtu.hostile);
		n.last_udp_from = n.address;
		probe_record_h(mesh, &n, &packet, packet.len);
		CHECK(n.plpmtu.hostile && n.plpmtu.hostile_marks == 1);
		CHECK(n.plpmtu.size == 1431 && n.plpmtu.state == PLPMTU_COMPLETE);
		CHECK(!n.plpmtu.probe_nonce && !n.plpmtu.recovery_nonce);
		CHECK(!n.keepalive.expiries && n.keepalive.interval_ms == PATH_KEEPALIVE_INITIAL_MS);
		probe_record_h(mesh, &n, &packet, packet.len);
		CHECK(n.plpmtu.hostile_marks == 1);
		path_plpmtu_observe_ack(mesh, &n, &n.address, size_nonce, 1451);
		CHECK(n.plpmtu.size == 1431);
		stop_peer_path_activity(mesh, &n);
	}
	ok = true;

done:
	mesh->backbone_udp.node = saved_bb;
	mesh->backbone_udp.confirmed = saved_confirmed;
	mesh->backbone_udp.liveness_nonce = saved_nonce;
	stop_peer_path_activity(mesh, &n);
	path_scheduler_set_budget(mesh, 1000, 1000, saved_max);
	return ok;
}

static void set_lan_snapshot(meshlink_handle_t *mesh);

static bool liveness_admission_cover(meshlink_handle_t *mesh) {
	node_t n;
	unsigned saved_max = mesh->probe_max_transactions;
	uint64_t sent = mesh->probe_budget.optional_packets_sent;
	bool ok = false;

	plant_confirmed_udp_peer(&n, mesh, "liveness-budget", 0xcb007134);
	path_liveness_on_confirmed(mesh, &n);
	path_scheduler_set_budget(mesh, 0, 100, 8);
	for(int i = 0; i < 10; i++) {
		path_liveness_tick(mesh, &n);
		advance_ms(mesh, 2000);
	}
	CHECK(!n.liveness.tries && !n.liveness.probes_sent && !n.liveness.giveups);
	CHECK(mesh->probe_budget.optional_packets_sent == sent && !mesh->probe_queue->count);
	path_scheduler_set_budget(mesh, 100, 100, 8);
	path_scheduler_drain(mesh);
	CHECK(mesh->probe_budget.optional_packets_sent == sent);
	path_liveness_tick(mesh, &n);
	CHECK(n.liveness.tries == 1 && n.liveness.probes_sent == 1);
	CHECK(mesh->probe_budget.optional_packets_sent == sent + 1);
	path_liveness_observe_reply(mesh, &n, &n.address, n.liveness.nonce, PROBE_PURPOSE_LIVENESS);
	path_scheduler_drain(mesh);
	CHECK(n.liveness.state == LIVENESS_PARKED && !mesh->probe_queue->count);
	CHECK(mesh->probe_budget.optional_packets_sent == sent + 1);
	for(int i = 0; i < PATH_LIVENESS_TRIES; i++) {
		path_liveness_tick(mesh, &n);
		advance_ms(mesh, 2000);
	}
	CHECK(n.liveness.tries == PATH_LIVENESS_TRIES && n.liveness.probes_sent == 4);
	CHECK(mesh->probe_budget.optional_packets_sent == sent + 4 && !mesh->probe_queue->count);
	path_liveness_tick(mesh, &n);
	CHECK(n.liveness.giveups == 1);
	path_scheduler_drain(mesh);
	CHECK(mesh->probe_budget.optional_packets_sent == sent + 4);
	/* Local discovery shares the timer-owned liveness priority. Denial
	   must not exhaust its finite probe ladder either. */
	n.status.udp_confirmed = false;
	set_lan_snapshot(mesh);
	n.address = v4(0xc0a80114, 9);
	n.address_source = ADDR_SRC_DISCOVERY;
	n.address_cap = PATH_CAP_BOTH;
	path_local_discovery_start(mesh, &n);
	path_scheduler_set_budget(mesh, 0, 100, 8);
	for(int i = 0; i < PATH_LOCAL_DISCOVERY_TRIES + 2; i++) {
		path_local_discovery_tick(mesh, &n);
		advance_ms(mesh, 1000);
	}
	CHECK(n.local_discovery.active && !n.local_discovery.exhausted && !n.local_discovery.tries);
	CHECK(!mesh->probe_queue->count && mesh->probe_budget.optional_packets_sent == sent + 4);
	path_scheduler_set_budget(mesh, 100, 100, 8);
	path_scheduler_drain(mesh);
	CHECK(mesh->probe_budget.optional_packets_sent == sent + 4);
	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.tries == 1 && mesh->probe_budget.optional_packets_sent == sent + 5);
	ok = true;

done:
	stop_peer_path_activity(mesh, &n);
	local_network_set_snapshot(mesh, NULL, 0);
	path_scheduler_set_budget(mesh, 1000, 1000, saved_max);
	return ok;
}

static bool liveness_cover(meshlink_handle_t *mesh) {
	node_t n;
	node_t low;
	sockaddr_t other;
	node_t *saved_bb = mesh->backbone_udp.node;
	char lower[128];
	char higher[128];
	time_t parked_until;
	int wait;
	bool ok = false;

	memset(&low, 0, sizeof low);
	plant_confirmed_udp_peer(&n, mesh, "liveness-peer", 0xcb00710b);
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.size = 1419;
	path_liveness_on_confirmed(mesh, &n);
	CHECK(n.liveness.state == LIVENESS_PARKED);
	path_liveness_tick(mesh, &n);
	CHECK(n.liveness.state == LIVENESS_PROBING);
	CHECK(n.liveness.probes_sent == 1);
	CHECK(n.liveness.nonce);

	path_liveness_observe_reply(mesh, &n, &n.address, n.liveness.nonce, PROBE_PURPOSE_LIVENESS);
	CHECK(n.liveness.state == LIVENESS_PARKED);
	CHECK(!n.liveness.gave_up);

	path_liveness_tick(mesh, &n);
	path_liveness_tick(mesh, &n);
	CHECK(n.liveness.retries == 1);
	path_liveness_observe_reply(mesh, &n, &n.address, n.liveness.nonce, PROBE_PURPOSE_LIVENESS);
	CHECK(n.liveness.state == LIVENESS_PARKED);
	CHECK(!n.liveness.gave_up);

	path_liveness_tick(mesh, &n);
	other = n.address;
	other.in.sin_port = htons(99);
	path_liveness_observe_reply(mesh, &n, &other, n.liveness.nonce, PROBE_PURPOSE_LIVENESS);
	CHECK(n.liveness.state == LIVENESS_PROBING);
	path_liveness_observe_reply(mesh, &n, &n.address, 0x111, PROBE_PURPOSE_PUNCH);
	CHECK(n.liveness.state == LIVENESS_PARKED);
	path_liveness_observe_reply(mesh, &n, &n.address, 0x222, PROBE_PURPOSE_SUSPECT);
	CHECK(n.liveness.state == LIVENESS_PARKED);

	path_liveness_tick(mesh, &n);
	path_liveness_observe_reply(mesh, &n, &n.address, 0x333, PROBE_PURPOSE_REBIND);
	CHECK(n.liveness.state == LIVENESS_PARKED);
	path_liveness_tick(mesh, &n);
	path_liveness_observe_reply(mesh, &n, &n.address, 0x444, PROBE_PURPOSE_NONE);
	CHECK(n.liveness.state == LIVENESS_PARKED);

	n.liveness.state = LIVENESS_PROBING;
	n.liveness.tries = PATH_LIVENESS_TRIES;
	n.liveness.nonce = 1;
	n.udp_rebind.challenge_active = true;
	n.udp_rebind.challenge_nonce = 7;
	n.udp_rebind.challenge_attempts = 0;
	n.udp_rebind.challenge_deadline = mesh->loop.now;
	n.udp_rebind.challenge_deadline.tv_sec += 60;
	n.udp_rebind.challenge_network_epoch = mesh->lan_network_epoch;
	n.liveness.giveups = 0;
	path_liveness_tick(mesh, &n);
	CHECK(!n.liveness.gave_up);
	CHECK(n.liveness.timer.cb);
	n.udp_rebind.challenge_active = false;
	path_liveness_tick(mesh, &n);
	CHECK(n.liveness.gave_up);
	CHECK(n.plpmtu.size == 1419);
	CHECK(n.liveness.giveups == 1);

	/* Greater name parks; the lesser name does not. */
	n.status.udp_confirmed = true;
	n.status.validkey = true;
	n.peer_udp.channel_count = 1;
	n.devtool_force_meta = true;
	snprintf(lower, sizeof lower, "%s", mesh->self->name);
	snprintf(higher, sizeof higher, "%s", mesh->self->name);

	if(lower[0]) {
		lower[0]--;
	}

	{
		size_t hlen = strlen(higher);

		if(hlen + 1 < sizeof higher) {
			higher[hlen] = 'z';
			higher[hlen + 1] = '\0';
		}
	}
	plant_confirmed_udp_peer(&low, mesh, lower, 0xcb00710b);
	low.status.udp_confirmed = true;
	path_liveness_on_confirmed(mesh, &low);
	wait = mesh->dev_class_traits[DEV_CLASS_STATIONARY].pinginterval;
	wait = wait > 0 ? wait : PATH_LIVENESS_INTERVAL_SEC;
	wait += (mesh->dev_class_traits[DEV_CLASS_STATIONARY].pingtimeout > 0
	         ? mesh->dev_class_traits[DEV_CLASS_STATIONARY].pingtimeout : 5) + 1;
	path_liveness_observe_peer_request(mesh, &low, &low.address);
	CHECK(low.liveness.state == LIVENESS_PARKED);
	parked_until = low.liveness.timer.tv.tv_sec;
	CHECK(parked_until - mesh->loop.now.tv_sec >= wait - 1);

	low.name = higher;
	path_liveness_observe_peer_request(mesh, &low, &low.address);
	CHECK(low.liveness.timer.tv.tv_sec == parked_until);

	/* No demand, and never the backbone node. */
	stop_peer_path_activity(mesh, &n);
	plant_confirmed_udp_peer(&n, mesh, "liveness-peer", 0xcb00710b);
	n.peer_udp.channel_count = 0;
	path_liveness_on_confirmed(mesh, &n);
	path_liveness_tick(mesh, &n);
	CHECK(n.liveness.state == LIVENESS_IDLE);
	CHECK(!n.liveness.timer.cb);
	n.peer_udp.channel_count = 1;
	mesh->backbone_udp.node = &n;
	path_liveness_on_confirmed(mesh, &n);
	CHECK(n.liveness.state == LIVENESS_IDLE);
	CHECK(!n.liveness.timer.cb);
	mesh->backbone_udp.node = saved_bb;

	ok = true;

done:
	mesh->backbone_udp.node = saved_bb;
	stop_peer_path_activity(mesh, &n);
	stop_peer_path_activity(mesh, &low);
	return ok;
}

static bool keepalive_legacy_cache_cover(meshlink_handle_t *mesh) {
	node_t n;
	path_mtu_cache_entry_t entry;
	int slot;
	bool ok = false;

	plant_confirmed_udp_peer(&n, mesh, "keepalive-cache-upgrade", 0xcb007136);
	n.plpmtu.path_ip = n.address;
	n.plpmtu.path_ip.in.sin_port = 0;
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.size = 1431;
	n.plpmtu.largest_failed = 1451;
	n.plpmtu.hostile = true;
	n.keepalive.interval_ms = 5000;
	path_plpmtu_remember_keepalive(mesh, &n);
	slot = cache_slot(&n, 0xcb007136);
	CHECK(slot >= 0);
	entry = n.mtu_cache[slot];
	CHECK(entry.flags & PATH_MTU_CACHE_KEEPALIVE_V2);

	for(int current = 0; current < 2; current++) {
		stop_peer_path_activity(mesh, &n);
		memset(&n.plpmtu, 0, sizeof n.plpmtu);
		n.keepalive.interval_ms = 0;
		n.mtu_cache[slot] = entry;
		if(!current) {
			n.mtu_cache[slot].flags &= ~PATH_MTU_CACHE_KEEPALIVE_V2;
		}
		path_plpmtu_on_confirmed(mesh, &n);
		path_keepalive_on_confirmed(mesh, &n);
		CHECK(n.plpmtu.state == PLPMTU_COMPLETE && n.plpmtu.size == 1431);
		CHECK(n.plpmtu.hostile && n.plpmtu.largest_failed == 1451);
		CHECK(n.plpmtu.cache_hits == 1 && !n.plpmtu.probes_sent);
		CHECK(n.keepalive.interval_ms == (current ? 5000 : PATH_KEEPALIVE_INITIAL_MS));
	}
	ok = true;

done:
	stop_peer_path_activity(mesh, &n);
	return ok;
}

static bool keepalive_default_cover(meshlink_handle_t *mesh) {
	node_t *n = NULL;
	node_t *saved_bb = mesh->backbone_udp.node;
	bool ok = false;

	for(int backbone = 0; backbone < 2; backbone++) {
		n = new_node();
		n->mesh = mesh;
		n->address = v4(0xcb007135, 9);
		n->status.udp_confirmed = true;
		n->status.validkey = true;
		mesh->backbone_udp.node = backbone ? n : NULL;
		path_keepalive_on_confirmed(mesh, n);
		CHECK(n->keepalive.interval_ms == (backbone ? PATH_KEEPALIVE_BACKBONE_INITIAL_MS : PATH_KEEPALIVE_INITIAL_MS));
		CHECK(n->keepalive.last_tx_at.tv_sec == mesh->loop.now.tv_sec);
		/* A restored interval takes precedence over either role's default. */
		n->keepalive.interval_ms = 9000;
		path_keepalive_on_confirmed(mesh, n);
		CHECK(n->keepalive.interval_ms == 9000);
		stop_peer_path_activity(mesh, n);
		free_node(n);
		n = NULL;
	}
	ok = true;

done:
	mesh->backbone_udp.node = saved_bb;
	if(n) {
		stop_peer_path_activity(mesh, n);
		free_node(n);
	}
	return ok;
}

/* Exercise the actual destination-override send path used by probe replies,
   rebind challenges and backbone traffic, without needing an SPTPS session. */
static bool keepalive_probe_tx_cover(meshlink_handle_t *mesh) {
	node_t n;
	uint8_t probe[PROBE_FIXED_LEN] = {0};
	struct timespec last_tx;
	bool ok = false;

	plant_confirmed_udp_peer(&n, mesh, "keepalive-probe-send", 0x7f000001);
	n.probe_dest_override_active = true;
	n.probe_dest_override = n.address;
	n.keepalive.last_tx_at = mesh->loop.now;
	advance_ms(mesh, 15000);
	CHECK(send_sptps_data(&n, PKT_PROBE, probe, sizeof probe));
	CHECK(n.keepalive.last_tx_at.tv_sec == mesh->loop.now.tv_sec);
	CHECK(n.keepalive.last_tx_at.tv_nsec == mesh->loop.now.tv_nsec);
	CHECK(n.keepalive.pending_gap_ms == 15000);
	CHECK(n.keepalive.timer.cb);
	last_tx = n.keepalive.last_tx_at;

	/* Probing another candidate does not refresh the confirmed mapping. */
	n.probe_dest_override.in.sin_port = htons(10);
	advance_ms(mesh, 1000);
	CHECK(send_sptps_data(&n, PKT_PROBE, probe, sizeof probe));
	CHECK(n.keepalive.last_tx_at.tv_sec == last_tx.tv_sec);
	CHECK(n.keepalive.last_tx_at.tv_nsec == last_tx.tv_nsec);
	CHECK(n.keepalive.pending_gap_ms == 15000);

	/* A send failure to the confirmed endpoint is not mapping activity. */
	n.probe_dest_override = n.address;
	for(int sock = 0; sock < mesh->listen_sockets; sock++) {
		if(mesh->listen_socket[sock].sa.sa.sa_family != AF_INET) {
			continue;
		}
		int saved_fd = mesh->listen_socket[sock].udp.fd;
		mesh->listen_socket[sock].udp.fd = -1;
		bool accepted = send_sptps_data(&n, PKT_PROBE, probe, sizeof probe);
		mesh->listen_socket[sock].udp.fd = saved_fd;
		CHECK(!accepted);
		CHECK(n.keepalive.last_tx_at.tv_sec == last_tx.tv_sec);
		CHECK(n.keepalive.last_tx_at.tv_nsec == last_tx.tv_nsec);
		break;
	}

	ok = true;

done:
	update_node_udp(mesh, &n, NULL);
	stop_peer_path_activity(mesh, &n);
	return ok;
}

static bool keepalive_cover(meshlink_handle_t *mesh) {
	node_t n;
	sockaddr_t local = v4(0xc0000201, 5000);
	sockaddr_t other;
	node_t *saved_bb = mesh->backbone_udp.node;
	uint32_t sent;
	bool ok = false;

	plant_confirmed_udp_peer(&n, mesh, "keepalive-peer", 0xcb00710c);
	n.keepalive.last_tx_at = mesh->loop.now;
	path_keepalive_tick(mesh, &n);
	sent = n.keepalive.sent;
	CHECK(n.keepalive.sent == sent);
	advance_ms(mesh, PATH_KEEPALIVE_INITIAL_MS);
	path_keepalive_tick(mesh, &n);
	CHECK(n.keepalive.sent == sent + 1);
	path_keepalive_note_tx(mesh, &n, &n.address);
	path_keepalive_tick(mesh, &n);
	CHECK(n.keepalive.sent == sent + 1);

	n.peer_udp.channel_count = 0;
	n.keepalive.last_rx_at.tv_sec = 0;
	path_keepalive_tick(mesh, &n);
	CHECK(!n.keepalive.timer.cb);
	n.keepalive.last_rx_at = mesh->loop.now;
	path_keepalive_note_rx(mesh, &n);
	CHECK(n.keepalive.timer.cb);
	sent = n.keepalive.sent;
	advance_ms(mesh, (int)n.keepalive.interval_ms);
	path_keepalive_tick(mesh, &n);
	CHECK(n.keepalive.sent == sent + 1);
	advance_ms(mesh, PATH_KEEPALIVE_PEER_DEMAND_SEC * 1000 + 1000);
	path_keepalive_tick(mesh, &n);
	CHECK(!n.keepalive.timer.cb);

	n.peer_udp.channel_count = 1;
	path_keepalive_on_confirmed(mesh, &n);
	CHECK(n.keepalive.timer.cb);

	n.keepalive.interval_ms = PATH_KEEPALIVE_INITIAL_MS;
	n.plpmtu.size = 1419;
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.path_ip = n.address;
	n.plpmtu.path_ip.in.sin_port = 0;
	n.plpmtu.last_oversize_sent_at.tv_sec = 0;
	path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
	n.keepalive.last_tx_at = mesh->loop.now;
	advance_ms(mesh, 6357);
	path_keepalive_note_tx(mesh, &n, &n.address);
	CHECK(!n.keepalive.pending_gap_ms);
	local.in.sin_port = htons(5001);
	path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
	CHECK(n.keepalive.interval_ms == 15000 && !n.keepalive.expiries);

	advance_ms(mesh, 15000);
	path_keepalive_note_tx(mesh, &n, &n.address);
	CHECK(n.keepalive.pending_gap_ms == 15000);
	/* A local give-up and same-IP confirmation do not locate the expired NAT. */
	n.status.udp_confirmed = true;
	path_liveness_on_confirmed(mesh, &n);
	CHECK(n.keepalive.interval_ms == 15000 && !n.keepalive.expiries);
	/* Replies from a different remote endpoint cannot supply evidence. */
	other = n.address;
	other.in.sin_port = htons(100);
	local.in.sin_port = htons(5002);
	path_keepalive_observe_local_endpoint(mesh, &n, &other, &local);
	CHECK(n.keepalive.pending_gap_ms == 15000 && !n.keepalive.expiries);
	path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
	CHECK(n.keepalive.interval_ms == 9000);
	CHECK(n.keepalive.expiries == 1);
	CHECK(cache_slot(&n, 0xcb00710c) >= 0);
	CHECK(n.mtu_cache[cache_slot(&n, 0xcb00710c)].keepalive_ms == 9000);

	/* A raising size ACK keeps the oversize stamp so the endpoint observation is not an idle expiry. */
	n.keepalive.interval_ms = 15000;
	n.keepalive.expiries = 1;
	n.keepalive.pending_gap_ms = 15000;
	n.keepalive.pending_since = mesh->loop.now;
	path_copy_sockaddr(&n.keepalive.pending_ip, &n.address);
	n.plpmtu.state = PLPMTU_SEARCHING;
	n.plpmtu.size = PATH_PLPMTU_BASE;
	n.plpmtu.probe_nonce = 0xabc;
	n.plpmtu.probe_size = PATH_PLPMTU_STEP_1399;
	n.plpmtu.last_oversize_sent_at = mesh->loop.now;
	path_plpmtu_observe_ack(mesh, &n, &n.address, 0xabc, PATH_PLPMTU_STEP_1399);
	CHECK(n.plpmtu.size == PATH_PLPMTU_STEP_1399);
	CHECK(n.plpmtu.last_oversize_sent_at.tv_sec);
	local.in.sin_port = htons(5003);
	path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
	CHECK(n.keepalive.interval_ms == 15000 && n.keepalive.expiries == 1);

	/* A mapping that survives the gap, stale evidence, a new public IP,
	   and an oversize-induced remap must not shorten the idle interval. */
	for(int reason = 0; reason < 6; reason++) {
		n.keepalive.interval_ms = 15000;
		n.keepalive.last_tx_at = mesh->loop.now;
		advance_ms(mesh, 15000);
		path_keepalive_note_tx(mesh, &n, &n.address);
		if(reason == 1) {
			advance_ms(mesh, (PATH_KEEPALIVE_EXPIRY_CONFIRM_SEC + 1) * 1000);
		}
		if(reason == 2) {
			local.in.sin_addr.s_addr = htonl(0xc0000202);
		}
		if(reason == 3) {
			n.plpmtu.last_oversize_sent_at = mesh->loop.now;
		}
		if(reason == 4) {
			n.keepalive.local_endpoint_epoch--;
		}
		if(reason == 5) {
			n.address.in.sin_port = htons(101);
		}
		if(reason) {
			local.in.sin_port = htons(5010 + reason);
		}
		path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
		CHECK(n.keepalive.interval_ms == 15000 && n.keepalive.expiries == 1);
		CHECK(!n.keepalive.pending_gap_ms);
	}
	CHECK(n.plpmtu.hostile);

	n.keepalive.interval_ms = 9000;
	n.keepalive.last_grow_at = mesh->loop.now;
	n.keepalive.last_grow_at.tv_sec -= PATH_KEEPALIVE_GROW_SEC + 1;
	n.keepalive.last_tx_at = mesh->loop.now;
	n.keepalive.last_tx_at.tv_sec -= 20;
	n.peer_udp.channel_count = 1;
	n.status.udp_confirmed = true;
	path_keepalive_tick(mesh, &n);
	CHECK(n.keepalive.interval_ms == 10800);

	/* A confirmed expiry that cannot shrink (gap's 60% is already above the
	   floor) still restarts the grow clock. */
	n.keepalive.interval_ms = PATH_KEEPALIVE_FLOOR_MS;
	n.keepalive.expiries = 1;
	n.keepalive.pending_gap_ms = 0;
	n.keepalive.last_grow_at = mesh->loop.now;
	n.keepalive.last_grow_at.tv_sec -= PATH_KEEPALIVE_GROW_SEC + 1;
	n.plpmtu.last_oversize_sent_at.tv_sec = 0;
	n.status.udp_confirmed = true;
	n.status.validkey = true;
	local = v4(0xc0000201, 5000);
	path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
	n.keepalive.pending_gap_ms = PATH_KEEPALIVE_FLOOR_MS * 3;
	n.keepalive.pending_since = mesh->loop.now;
	path_copy_sockaddr(&n.keepalive.pending_ip, &n.address);
	local.in.sin_port = htons(6100);
	path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
	CHECK(n.keepalive.interval_ms == PATH_KEEPALIVE_FLOOR_MS);
	CHECK(n.keepalive.expiries == 1);
	CHECK(n.keepalive.last_grow_at.tv_sec == mesh->loop.now.tv_sec);

	mesh->backbone_udp.node = &n;
	n.keepalive.interval_ms = PATH_KEEPALIVE_BACKBONE_INITIAL_MS;
	n.keepalive.expiries = 0;
	n.plpmtu.last_oversize_sent_at.tv_sec = 0;
	n.keepalive.last_tx_at = mesh->loop.now;
	advance_ms(mesh, PATH_KEEPALIVE_BACKBONE_INITIAL_MS);
	path_keepalive_note_tx(mesh, &n, &n.address);
	local.in.sin_port = htons(6000);
	path_keepalive_observe_local_endpoint(mesh, &n, &n.address, &local);
	n.status.udp_confirmed = true;
	path_liveness_on_confirmed(mesh, &n);
	CHECK(n.keepalive.interval_ms == PATH_KEEPALIVE_BACKBONE_INITIAL_MS * 60 / 100);
	CHECK(n.keepalive.expiries == 1);
	CHECK(n.liveness.state == LIVENESS_IDLE);
	n.keepalive.last_grow_at.tv_sec -= PATH_KEEPALIVE_GROW_SEC;
	CHECK(path_keepalive_backbone_interval_ms(mesh, &n) == PATH_KEEPALIVE_BACKBONE_INITIAL_MS * 72 / 100);
	CHECK(n.mtu_cache[cache_slot(&n, 0xcb00710c)].keepalive_ms == n.keepalive.interval_ms);
	mesh->backbone_udp_keepalive_sec = PATH_BACKBONE_UDP_KEEPALIVE_SEC;
	CHECK(path_backbone_udp_keepalive_base_sec(mesh) == (int)(n.keepalive.interval_ms / 1000));
	mesh->backbone_udp_keepalive_sec = 2;
	CHECK(path_backbone_udp_keepalive_base_sec(mesh) == 2);
	mesh->backbone_udp_keepalive_sec = PATH_BACKBONE_UDP_KEEPALIVE_SEC;
	CHECK(path_backbone_udp_keepalive_base_sec(mesh) == (int)(n.keepalive.interval_ms / 1000));
	n.keepalive.interval_ms = 0;
	CHECK(path_backbone_udp_keepalive_base_sec(mesh) == PATH_BACKBONE_UDP_KEEPALIVE_SEC);

	ok = true;

done:
	mesh->backbone_udp.node = saved_bb;
	stop_peer_path_activity(mesh, &n);
	return ok;
}

static bool probe_record_and_endpoint_encoding_cover(meshlink_handle_t *mesh) {
	node_t n;
	vpn_packet_t packet;
	sockaddr_t endpoint, decoded;
	uint64_t nonce = 0x1122334455667788ull;
	uint64_t out_before;
	bool ok = false;

	plant_confirmed_udp_peer(&n, mesh, "probe-record-peer", 0xcb00710d);
	memset(&packet, 0, sizeof packet);
	packet.data[0] = PROBE_KIND_SIZE_ACK;
	packet.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_NONE;
	memcpy(packet.data + PROBE_NONCE_OFFSET, &nonce, sizeof nonce);
	packet.data[PROBE_ACKLEN_OFFSET] = (uint8_t)(1259 >> 8);
	packet.data[PROBE_ACKLEN_OFFSET + 1] = (uint8_t)1259;
	packet.len = PROBE_FIXED_LEN;
	CHECK(packet.data[0] == PROBE_KIND_SIZE_ACK);
	CHECK(packet.data[PROBE_PURPOSE_OFFSET] == PROBE_PURPOSE_NONE);

	n.devtool_force_meta = false;
	n.plpmtu.probe_nonce = nonce;
	n.plpmtu.probe_size = 1259;
	n.plpmtu.state = PLPMTU_SEARCHING;
	n.plpmtu.size = PATH_PLPMTU_BASE;
	n.last_udp_from = n.address;
	probe_record_h(mesh, &n, &packet, PROBE_FIXED_LEN);
	CHECK(n.plpmtu.size == 1259);

	out_before = n.out_meta;
	packet.data[0] = PROBE_KIND_ECHO_REQUEST;
	packet.len = 1400;
	probe_record_h(mesh, &n, &packet, 1400);
	CHECK(n.out_meta == out_before);

	packet.data[0] = 9;
	packet.len = PROBE_FIXED_LEN;
	probe_record_h(mesh, &n, &packet, PROBE_FIXED_LEN);
	CHECK(n.out_meta == out_before);

	n.keepalive.last_rx_at.tv_sec = 0;
	packet.data[0] = PROBE_KIND_KEEPALIVE;
	probe_record_h(mesh, &n, &packet, PROBE_FIXED_LEN);
	CHECK(n.keepalive.last_rx_at.tv_sec == mesh->loop.now.tv_sec);
	CHECK(n.out_meta == out_before);

	endpoint = v4(0xc0000201, 5000);
	path_probe_write_endpoint(packet.data, &endpoint);
	CHECK(path_probe_read_endpoint(packet.data, &decoded));
	CHECK(!sockaddrcmp(&decoded, &endpoint));
	memset(&endpoint, 0, sizeof endpoint);
	endpoint.in6.sin6_family = AF_INET6;
	endpoint.in6.sin6_port = htons(65535);
	CHECK(inet_pton(AF_INET6, "2001:db8::1234", &endpoint.in6.sin6_addr) == 1);
	path_probe_write_endpoint(packet.data, &endpoint);
	CHECK(path_probe_read_endpoint(packet.data, &decoded));
	CHECK(!sockaddrcmp(&decoded, &endpoint));
	packet.data[PROBE_ENDPOINT_OFFSET] = 0;
	CHECK(!path_probe_read_endpoint(packet.data, &decoded));
	endpoint.in6.sin6_port = 0;
	path_probe_write_endpoint(packet.data, &endpoint);
	CHECK(!path_probe_read_endpoint(packet.data, &decoded));
	memset(&endpoint, 0, sizeof endpoint);
	path_probe_write_endpoint(packet.data, &endpoint);
	CHECK(!path_probe_read_endpoint(packet.data, &decoded));

	ok = true;

done:
	stop_peer_path_activity(mesh, &n);
	return ok;
}

static bool mtu_cache_serialization_cover(meshlink_handle_t *mesh) {
	node_t src;
	node_t dst;
	uint8_t buf[512];
	packmsg_output_t out = {buf, sizeof buf};
	packmsg_input_t in;
	bool ok = false;

	(void)mesh;
	memset(&src, 0, sizeof src);
	memset(&dst, 0, sizeof dst);
	src.mtu_cache[0].family = AF_INET;
	src.mtu_cache[0].addr[0] = 203;
	src.mtu_cache[0].size = 1399;
	src.mtu_cache[0].largest_failed = 1431;
	src.mtu_cache[0].flags = PATH_MTU_CACHE_HOSTILE | PATH_MTU_CACHE_KEEPALIVE_V2;
	src.mtu_cache[0].raise_backoff = 2;
	src.mtu_cache[0].keepalive_ms = 9000;
	src.mtu_cache[0].updated_at = 1000;
	src.mtu_cache[0].net_fp = 42;
	src.mtu_cache[1].family = AF_INET;
	src.mtu_cache[1].size = 10;
	src.mtu_cache[1].addr[0] = 1;

	path_mtu_cache_pack(&src, &out);
	CHECK(packmsg_output_ok(&out));
	in.ptr = buf;
	in.len = packmsg_output_size(&out, buf);
	path_mtu_cache_unpack(&dst, &in);
	CHECK(packmsg_done(&in));
	CHECK(dst.mtu_cache[0].size == 1399);
	CHECK(dst.mtu_cache[0].largest_failed == 1431);
	CHECK(dst.mtu_cache[0].flags == (PATH_MTU_CACHE_HOSTILE | PATH_MTU_CACHE_KEEPALIVE_V2));
	CHECK(dst.mtu_cache[0].keepalive_ms == 9000);
	CHECK(dst.mtu_cache[0].net_fp == 42);
	CHECK(!dst.mtu_cache[1].family);

	in.ptr = buf;
	in.len = 0;
	path_mtu_cache_unpack(&dst, &in);

	ok = true;

done:
	return ok;
}

static local_iface_addr_t iface4(const char *ip, uint8_t prefix, int index, uint32_t flags) {
	local_iface_addr_t a;

	memset(&a, 0, sizeof a);
	a.ifindex = index;
	a.flags = flags;
	a.prefix_len = prefix;
	a.address.in.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &a.address.in.sin_addr);
	return a;
}

static local_iface_addr_t iface6(const char *ip, uint8_t prefix, int index, uint32_t flags, uint32_t scope) {
	local_iface_addr_t a;

	memset(&a, 0, sizeof a);
	a.ifindex = index;
	a.flags = flags;
	a.prefix_len = prefix;
	a.address.in6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ip, &a.address.in6.sin6_addr);
	a.address.in6.sin6_scope_id = scope;
	return a;
}

static sockaddr_t v6(const char *ip, uint16_t port, uint32_t scope) {
	sockaddr_t sa;

	memset(&sa, 0, sizeof sa);
	sa.in6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ip, &sa.in6.sin6_addr);
	sa.in6.sin6_port = htons(port);
	sa.in6.sin6_scope_id = scope;
	return sa;
}

static void set_lan_snapshot(meshlink_handle_t *mesh) {
	local_iface_addr_t addrs[4];

	addrs[0] = iface4("127.0.0.1", 8, 1, IFF_UP | IFF_LOOPBACK);
	addrs[1] = iface4("192.168.1.10", 24, 2, IFF_UP | IFF_BROADCAST | IFF_MULTICAST);
	addrs[2] = iface6("fe80::10", 64, 2, IFF_UP | IFF_MULTICAST, 2);
	addrs[3] = iface6("fd00::10", 64, 2, IFF_UP | IFF_MULTICAST, 0);
	local_network_set_snapshot(mesh, addrs, 4);
}

static void set_cellular_snapshot(meshlink_handle_t *mesh) {
	local_iface_addr_t addrs[2];

	addrs[0] = iface4("127.0.0.1", 8, 1, IFF_UP | IFF_LOOPBACK);
	addrs[1] = iface4("100.64.10.2", 30, 3, IFF_UP | IFF_POINTOPOINT);
	local_network_set_snapshot(mesh, addrs, 2);
}

static bool broadcast_matches(meshlink_handle_t *mesh, const sockaddr_t *near, uint16_t port, const sockaddr_t *expect) {
	sockaddr_t out;

	if(!local_network_broadcast_target(mesh, near, htons(port), &out) || sockaddrcmp(&out, expect)) {
		return false;
	}

	return expect->sa.sa_family != AF_INET6 || out.in6.sin6_scope_id == expect->in6.sin6_scope_id;
}

static void plant_discovery_peer(node_t *n, edge_t *edge, meshlink_handle_t *mesh, const char *name, uint32_t ip, address_source_t src) {
	/* The peer lives on the stack and is reused. A still-armed discovery
	   timer is linked into the event loop by address; zeroing the node
	   first would leave that node in the tree and the next arm aborts. */
	path_local_discovery_stop(mesh, n);
	plant_confirmed_udp_peer(n, mesh, name, ip);
	n->status.udp_confirmed = false;
	n->address_source = src;
	n->address_cap = PATH_CAP_BOTH;
	memset(edge, 0, sizeof *edge);
	edge->address = v4(ip, 7000);
	n->prevedge = edge;
}

static void give_lan_presence(meshlink_handle_t *mesh, node_t *n, uint32_t ip) {
	memset(n->recent, 0, sizeof n->recent);
	n->recent[0] = v4(ip, 7000);
	n->recent_source[0] = ADDR_SRC_DISCOVERY;
	n->recent_cap[0] = PATH_CAP_BOTH;
	n->lan_presence.network_epoch = mesh->lan_network_epoch;
	n->lan_presence.last_discovered_at = mesh->loop.now.tv_sec ? mesh->loop.now.tv_sec : 1;
}

/* A network-change hint: new lan epoch, same interface snapshot. */
static void bump_lan_epoch(meshlink_handle_t *mesh) {
	mesh->lan_network_epoch++;

	if(!mesh->lan_network_epoch) {
		mesh->lan_network_epoch = 1;
	}
}

static bool local_discovery_cover(meshlink_handle_t *mesh) {
	node_t n;
	edge_t edge;
	path_probe_tap_t tap;
	sockaddr_t near;
	sockaddr_t out;
	sockaddr_t expect;
	sockaddr_t bcast;
	sockaddr_t uni;
	local_iface_addr_t one;
	unsigned saved_max = mesh->probe_max_transactions;
	unsigned before;
	uint64_t saved_epoch = mesh->lan_network_epoch;
	uint64_t saved_nonce;
	uint64_t prev_nonce;
	sockaddr_t want_dest;
	int saved_fam[MAXSOCKETS];
	int i;
	int t;
	bool families_saved = false;
	bool ok = false;

	memset(&tap, 0, sizeof tap);
	memset(&n, 0, sizeof n);
	tap.swallow = true;
	tap.result = RELAY_UDP_SENT;
	path_scheduler_set_tap(mesh, &tap);
	path_scheduler_set_budget(mesh, 100, 100, 8);
	CHECK(mesh->listen_sockets > 0);

	/* 1. Directed broadcast from the matching interface, never a limited one. */
	set_lan_snapshot(mesh);
	near = v4(0xc0a80114, 1);
	expect = v4(0xc0a801ff, 7000);
	CHECK(broadcast_matches(mesh, &near, 7000, &expect));
	near = v4(0x0a1401b5, 1);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));
	near = v4(0x7f000001, 1);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));
	near = v4(0xc0a80114, 1);
	CHECK(!local_network_broadcast_target(mesh, &near, 0, &out));

	one = iface4("192.168.5.0", 31, 2, IFF_UP | IFF_BROADCAST | IFF_MULTICAST);
	local_network_set_snapshot(mesh, &one, 1);
	near = v4(0xc0a80501, 1);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));

	one = iface4("10.9.0.1", 24, 2, IFF_UP);
	local_network_set_snapshot(mesh, &one, 1);
	near = v4(0x0a090005, 1);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));

	one = iface4("10.9.0.1", 24, 2, IFF_UP | IFF_BROADCAST | IFF_POINTOPOINT);
	local_network_set_snapshot(mesh, &one, 1);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));

	one = iface4("192.168.1.10", 24, 2, 0);
	local_network_set_snapshot(mesh, &one, 1);
	near = v4(0xc0a80114, 1);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));

	set_lan_snapshot(mesh);
	near = v6("fe80::20", 9, 2);
	expect = v6("ff02::1", 7000, 2);
	CHECK(broadcast_matches(mesh, &near, 7000, &expect));
	near = v6("fe80::20", 9, 0);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));
	near = v6("fd00::20", 9, 0);
	expect = v6("ff02::1", 7000, 2);
	CHECK(broadcast_matches(mesh, &near, 7000, &expect));

	one = iface6("fd00:1::10", 64, 7, IFF_UP | IFF_MULTICAST, 0);
	local_network_set_snapshot(mesh, &one, 1);
	near = v6("fd00:1::20", 9, 0);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));

	set_lan_snapshot(mesh);
	local_network_force_stale(mesh);
	near = v4(0xc0a80114, 1);
	CHECK(!local_network_broadcast_target(mesh, &near, htons(7000), &out));

	/* 2. Current LAN evidence broadcasts three times, then unicasts. */
	set_lan_snapshot(mesh);
	plant_discovery_peer(&n, &edge, mesh, "discovery-lan", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	bcast = v4(0xc0a801ff, 7000);
	uni = v4(0xc0a80114, 9);
	path_local_discovery_start(mesh, &n);
	CHECK(n.local_discovery.active);
	before = tap.count;

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES; t++) {
		bool is_bcast = t < PATH_LOCAL_DISCOVERY_BROADCAST_TRIES;
		sockaddr_t expect_dest = is_bcast ? bcast : uni;

		path_local_discovery_tick(mesh, &n);
		CHECK(tap.count == before + (unsigned)t + 1);
		EXPECT_ECHO(tap, n, is_bcast, expect_dest);
		advance_ms(mesh, 1000);
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.exhausted && !n.local_discovery.active);
	CHECK(n.local_discovery.broadcasts == PATH_LOCAL_DISCOVERY_BROADCAST_TRIES);
	CHECK(n.local_discovery.unicasts == PATH_LOCAL_DISCOVERY_TRIES - PATH_LOCAL_DISCOVERY_BROADCAST_TRIES);
	CHECK(tap.count == before + PATH_LOCAL_DISCOVERY_TRIES);

	/* 3. A graph edge is not locality. A public peer does not get a probe. */
	before = tap.count;
	plant_discovery_peer(&n, &edge, mesh, "discovery-wan", 0xcb007105, ADDR_SRC_EDGE_DIRECT);
	path_local_discovery_start(mesh, &n);
	CHECK(!n.local_discovery.active);
	CHECK(tap.count == before);
	CHECK(n.local_discovery.skips == 1);
	CHECK(n.local_discovery.skip_reason);
	n.local_discovery.active = true;
	path_local_discovery_tick(mesh, &n);
	CHECK(!n.local_discovery.active);
	CHECK(tap.count == before);

	/* 4. Off-link private graph address. */
	before = tap.count;
	plant_discovery_peer(&n, &edge, mesh, "discovery-off", 0x0a1401b5, ADDR_SRC_EDGE_DIRECT);
	path_local_discovery_start(mesh, &n);
	CHECK(!n.local_discovery.active && tap.count == before);

	/* 5. Routed-private backbone evidence never becomes a LAN probe. */
	before = tap.count;
	plant_discovery_peer(&n, &edge, mesh, "discovery-bb", 0x0a1e0102, ADDR_SRC_BACKBONE_PRIVATE);
	n.devclass = DEV_CLASS_BACKBONE;
	path_local_discovery_start(mesh, &n);
	CHECK(!n.local_discovery.active && tap.count == before);
	CHECK(!n.lan_presence.last_discovered_at);

	/* 6. On-link without LAN evidence is unicast only. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-edge", 0xc0a8011e, ADDR_SRC_EDGE_DIRECT);
	uni = v4(0xc0a8011e, 9);
	path_local_discovery_start(mesh, &n);
	CHECK(n.local_discovery.active);
	before = tap.count;

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES; t++) {
		path_local_discovery_tick(mesh, &n);
		CHECK(tap.count == before + (unsigned)t + 1);
		EXPECT_ECHO(tap, n, false, uni);
		advance_ms(mesh, 1000);
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.exhausted);
	CHECK(n.local_discovery.broadcasts == 0);
	CHECK(n.local_discovery.unicasts == PATH_LOCAL_DISCOVERY_TRIES);

	/* 7. A network change drops a peer that left the LAN, and restarts one that did not. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-move", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	path_local_discovery_start(mesh, &n);
	before = tap.count;
	path_local_discovery_tick(mesh, &n);
	CHECK(tap.count == before + 1);
	EXPECT_ECHO(tap, n, true, bcast);
	saved_nonce = n.local_discovery.nonce;
	set_cellular_snapshot(mesh);
	mesh->lan_network_epoch++;

	if(!mesh->lan_network_epoch) {
		mesh->lan_network_epoch = 1;
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(!n.local_discovery.active && tap.count == before + 1);
	set_lan_snapshot(mesh);
	give_lan_presence(mesh, &n, 0xc0a80114);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(n.local_discovery.active);
	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.nonce != saved_nonce && n.local_discovery.tries == 1);
	EXPECT_ECHO(tap, n, true, bcast);
	CHECK(!path_local_discovery_accept(mesh, &n, &n.address, saved_nonce, PROBE_PURPOSE_LOCAL_DISCOVERY));

	/* 8. No usable broadcast carrier does not spend a try. */
	one = iface4("192.168.1.10", 24, 2, IFF_UP);
	local_network_set_snapshot(mesh, &one, 1);
	plant_discovery_peer(&n, &edge, mesh, "discovery-nobcast", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	uni = v4(0xc0a80114, 9);
	path_local_discovery_start(mesh, &n);
	before = tap.count;

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES; t++) {
		path_local_discovery_tick(mesh, &n);
		EXPECT_ECHO(tap, n, false, uni);
		advance_ms(mesh, 1000);
	}

	CHECK(n.local_discovery.broadcasts == 0);
	CHECK(tap.count == before + PATH_LOCAL_DISCOVERY_TRIES);
	stop_peer_path_activity(mesh, &n);

	set_lan_snapshot(mesh);
	plant_discovery_peer(&n, &edge, mesh, "discovery-v6sock", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);

	for(i = 0; i < mesh->listen_sockets && i < MAXSOCKETS; i++) {
		saved_fam[i] = mesh->listen_socket[i].sa.sa.sa_family;
		mesh->listen_socket[i].sa.sa.sa_family = AF_INET6;
	}

	families_saved = true;
	path_local_discovery_start(mesh, &n);
	CHECK(n.local_discovery.active);
	before = tap.count;
	path_local_discovery_tick(mesh, &n);
	EXPECT_ECHO(tap, n, false, uni);
	CHECK(tap.count == before + 1);

	for(i = 0; i < mesh->listen_sockets && i < MAXSOCKETS; i++) {
		mesh->listen_socket[i].sa.sa.sa_family = saved_fam[i];
	}

	families_saved = false;
	stop_peer_path_activity(mesh, &n);

	plant_discovery_peer(&n, &edge, mesh, "discovery-hard", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	tap.result = RELAY_UDP_HARD_ERROR;
	path_local_discovery_start(mesh, &n);
	before = tap.count;
	path_local_discovery_tick(mesh, &n);
	CHECK(tap.count == before + 1);
	CHECK(!n.local_discovery.tries && n.local_discovery.carrier_failures == 1);
	CHECK(n.local_discovery.broadcast_blocked_epoch == mesh->lan_network_epoch);
	tap.result = RELAY_UDP_SENT;
	path_local_discovery_tick(mesh, &n);
	EXPECT_ECHO(tap, n, false, uni);
	CHECK(n.local_discovery.tries == 1);
	stop_peer_path_activity(mesh, &n);

	plant_discovery_peer(&n, &edge, mesh, "discovery-nosock", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	tap.result = RELAY_UDP_NO_SOCKET;
	path_local_discovery_start(mesh, &n);
	path_local_discovery_tick(mesh, &n);
	CHECK(!n.local_discovery.tries && n.local_discovery.carrier_failures == 1);
	tap.result = RELAY_UDP_SENT;
	stop_peer_path_activity(mesh, &n);

	plant_discovery_peer(&n, &edge, mesh, "discovery-block", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	tap.result = RELAY_UDP_WOULD_BLOCK;
	path_local_discovery_start(mesh, &n);
	before = tap.count;
	path_local_discovery_tick(mesh, &n);
	CHECK(tap.count == before + 1 && !n.local_discovery.tries && !n.local_discovery.carrier_failures);
	tap.result = RELAY_UDP_SENT;
	path_local_discovery_tick(mesh, &n);
	EXPECT_ECHO(tap, n, true, bcast);
	CHECK(n.local_discovery.tries == 1);
	stop_peer_path_activity(mesh, &n);

	/* 9. Scheduler denial keeps the ladder on its first broadcast. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-deny", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	path_local_discovery_start(mesh, &n);
	path_scheduler_set_budget(mesh, 0, 100, 8);
	before = tap.count;

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES + 2; t++) {
		path_local_discovery_tick(mesh, &n);
		advance_ms(mesh, 1000);
	}

	CHECK(n.local_discovery.active && !n.local_discovery.exhausted && !n.local_discovery.tries);
	CHECK(tap.count == before);
	path_scheduler_set_budget(mesh, 100, 100, 8);
	path_local_discovery_tick(mesh, &n);
	EXPECT_ECHO(tap, n, true, bcast);
	CHECK(n.local_discovery.tries == 1 && n.local_discovery.broadcasts == 1);

	/* 10. A reply is proof only from an on-link source. */
	stop_peer_path_activity(mesh, &n);
	plant_discovery_peer(&n, &edge, mesh, "discovery-accept", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	path_local_discovery_start(mesh, &n);
	CHECK(n.local_discovery.active);
	near = v4(0x0a1401b5, 9);
	CHECK(!path_local_discovery_accept(mesh, &n, &near, n.local_discovery.nonce, PROBE_PURPOSE_LOCAL_DISCOVERY));
	near = v4(0xc0a80114, 9);
	CHECK(path_local_discovery_accept(mesh, &n, &near, n.local_discovery.nonce, PROBE_PURPOSE_LOCAL_DISCOVERY));
	CHECK(n.status.udp_confirmed && !n.local_discovery.active);

	/* 11. One silent run per epoch, then one more if broadcast becomes possible. */
	stop_peer_path_activity(mesh, &n);
	plant_discovery_peer(&n, &edge, mesh, "discovery-bound", 0xc0a8011e, ADDR_SRC_EDGE_DIRECT);
	path_local_discovery_start(mesh, &n);

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES; t++) {
		path_local_discovery_tick(mesh, &n);
		advance_ms(mesh, 1000);
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.exhausted && !n.local_discovery.active && !n.local_discovery.broadcasts);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(!n.local_discovery.active);
	give_lan_presence(mesh, &n, 0xc0a8011e);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(n.local_discovery.active && n.local_discovery.last_run_broadcast);
	before = tap.count;

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES; t++) {
		path_local_discovery_tick(mesh, &n);

		if(!t) {
			CHECK(tap.last.broadcast && tap.count == before + 1);
		}

		advance_ms(mesh, 1000);
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(!n.local_discovery.active);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(!n.local_discovery.active);

	/* 12. A peer refused for its key starts when the key is ready. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-cold", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	n.status.validkey = false;
	before = tap.count;
	path_local_discovery_start(mesh, &n);
	CHECK(!n.local_discovery.active && n.local_discovery.skips == 1);
	CHECK(n.local_discovery.skip_reason && !strcmp(n.local_discovery.skip_reason, "no valid key"));
	n.status.validkey = true;
	path_local_discovery_on_key_ready(mesh, &n);
	CHECK(n.local_discovery.active && !n.local_discovery.skip_reason && n.local_discovery.runs == 1);
	path_local_discovery_tick(mesh, &n);
	CHECK(tap.count == before + 1);
	EXPECT_ECHO(tap, n, true, bcast);

	plant_discovery_peer(&n, &edge, mesh, "discovery-cold-wan", 0xcb007105, ADDR_SRC_EDGE_DIRECT);
	n.status.validkey = false;
	before = tap.count;
	path_local_discovery_start(mesh, &n);
	n.status.validkey = true;
	path_local_discovery_on_key_ready(mesh, &n);
	CHECK(!n.local_discovery.active && !n.local_discovery.runs && n.local_discovery.skips == 2);
	CHECK(n.local_discovery.skip_reason && !strcmp(n.local_discovery.skip_reason, "no on-link candidate or LAN evidence"));
	CHECK(tap.count == before);

	/* 13. A rekey resumes the ladder and never buys more tries. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-rekey", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	path_local_discovery_start(mesh, &n);
	before = tap.count;
	path_local_discovery_tick(mesh, &n);
	advance_ms(mesh, 1000);
	path_local_discovery_tick(mesh, &n);
	advance_ms(mesh, 1000);
	CHECK(n.local_discovery.tries == 2);

	for(t = 0; t < 5; t++) {
		prev_nonce = n.local_discovery.nonce;
		n.status.validkey = false;
		path_local_discovery_tick(mesh, &n);
		CHECK(!n.local_discovery.active && tap.count == before + 2 + (unsigned)t);
		n.status.validkey = true;
		path_local_discovery_on_key_ready(mesh, &n);
		CHECK(n.local_discovery.active && n.local_discovery.tries == 2 + t);
		CHECK(n.local_discovery.nonce && n.local_discovery.nonce != prev_nonce);
		path_local_discovery_tick(mesh, &n);
		advance_ms(mesh, 1000);
	}

	for(t = 0; t < 2 * PATH_LOCAL_DISCOVERY_TRIES && n.local_discovery.active; t++) {
		path_local_discovery_tick(mesh, &n);
		advance_ms(mesh, 1000);
	}

	CHECK(n.local_discovery.exhausted && n.local_discovery.runs == 1);
	CHECK(tap.count == before + PATH_LOCAL_DISCOVERY_TRIES);
	CHECK(n.local_discovery.broadcasts == PATH_LOCAL_DISCOVERY_BROADCAST_TRIES);
	path_local_discovery_on_key_ready(mesh, &n);
	CHECK(!n.local_discovery.active && tap.count == before + PATH_LOCAL_DISCOVERY_TRIES);

	/* 14. LAN evidence during a unicast ladder adds the broadcast prefix once. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-upgrade", 0xc0a8011e, ADDR_SRC_EDGE_DIRECT);
	uni = v4(0xc0a8011e, 9);
	path_local_discovery_start(mesh, &n);
	before = tap.count;

	for(t = 0; t < 4; t++) {
		path_local_discovery_tick(mesh, &n);
		EXPECT_ECHO(tap, n, false, uni);
		advance_ms(mesh, 1000);
	}

	give_lan_presence(mesh, &n, 0xc0a8011e);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(n.local_discovery.active && n.local_discovery.last_run_broadcast);

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES - 4; t++) {
		bool is_bcast = t < PATH_LOCAL_DISCOVERY_BROADCAST_TRIES;

		want_dest = is_bcast ? bcast : uni;
		path_local_discovery_tick(mesh, &n);
		EXPECT_ECHO(tap, n, is_bcast, want_dest);
		advance_ms(mesh, 1000);
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.exhausted);
	CHECK(n.local_discovery.broadcasts == PATH_LOCAL_DISCOVERY_BROADCAST_TRIES);
	CHECK(n.local_discovery.unicasts == PATH_LOCAL_DISCOVERY_TRIES - PATH_LOCAL_DISCOVERY_BROADCAST_TRIES);
	CHECK(tap.count == before + PATH_LOCAL_DISCOVERY_TRIES);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(!n.local_discovery.active);

	/* Evidence after the last unicast, before the exhausting tick, is the worst
	   case: still bounded by TRIES + BROADCAST_TRIES. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-late", 0xc0a8011e, ADDR_SRC_EDGE_DIRECT);
	path_local_discovery_start(mesh, &n);
	before = tap.count;

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES; t++) {
		path_local_discovery_tick(mesh, &n);
		advance_ms(mesh, 1000);
	}

	CHECK(n.local_discovery.active && n.local_discovery.tries == PATH_LOCAL_DISCOVERY_TRIES);
	give_lan_presence(mesh, &n, 0xc0a8011e);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(n.local_discovery.tries == PATH_LOCAL_DISCOVERY_TRIES - PATH_LOCAL_DISCOVERY_BROADCAST_TRIES);

	for(t = 0; t < PATH_LOCAL_DISCOVERY_BROADCAST_TRIES; t++) {
		path_local_discovery_tick(mesh, &n);
		EXPECT_ECHO(tap, n, true, bcast);
		advance_ms(mesh, 1000);
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.exhausted);
	CHECK(tap.count == before + PATH_LOCAL_DISCOVERY_TRIES + PATH_LOCAL_DISCOVERY_BROADCAST_TRIES);

	/* 15. A reply after a network change but before the tick proves nothing. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-late-reply", 0xc0a80114, ADDR_SRC_DISCOVERY);
	give_lan_presence(mesh, &n, 0xc0a80114);
	path_local_discovery_start(mesh, &n);
	path_local_discovery_tick(mesh, &n);
	prev_nonce = n.local_discovery.nonce;
	bump_lan_epoch(mesh);
	near = v4(0xc0a80114, 9);
	CHECK(!path_local_discovery_accept(mesh, &n, &near, prev_nonce, PROBE_PURPOSE_LOCAL_DISCOVERY));
	CHECK(!n.status.udp_confirmed && n.local_discovery.active);
	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.nonce != prev_nonce && n.local_discovery.tries == 2 && n.local_discovery.runs == 1);
	CHECK(path_local_discovery_accept(mesh, &n, &near, n.local_discovery.nonce, PROBE_PURPOSE_LOCAL_DISCOVERY));
	CHECK(n.status.udp_confirmed && n.local_discovery.confirms == 1);

	/* 16. Hints over unchanged interfaces keep one ladder; a new snapshot starts another. */
	stop_peer_path_activity(mesh, &n);
	plant_discovery_peer(&n, &edge, mesh, "discovery-flap", 0xc0a8011e, ADDR_SRC_EDGE_DIRECT);
	path_local_discovery_start(mesh, &n);
	before = tap.count;

	for(t = 0; t < 2 * PATH_LOCAL_DISCOVERY_TRIES && n.local_discovery.active; t++) {
		path_local_discovery_tick(mesh, &n);
		bump_lan_epoch(mesh);
		advance_ms(mesh, 1000);
	}

	CHECK(n.local_discovery.exhausted && n.local_discovery.runs == 1);
	CHECK(tap.count == before + PATH_LOCAL_DISCOVERY_TRIES);
	bump_lan_epoch(mesh);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(!n.local_discovery.active);
	path_local_discovery_on_key_ready(mesh, &n);
	CHECK(!n.local_discovery.active);
	set_cellular_snapshot(mesh);
	set_lan_snapshot(mesh);
	path_local_discovery_on_lan_evidence(mesh, &n);
	CHECK(n.local_discovery.active && n.local_discovery.runs == 2);

	/* 17. A broadcast-only ladder ends exhausted, also when its carrier fails. */
	plant_discovery_peer(&n, &edge, mesh, "discovery-bonly", 0xcb007105, ADDR_SRC_EDGE_DIRECT);
	give_lan_presence(mesh, &n, 0xc0a80114);
	n.recent_cap[0] = PATH_CAP_META;
	path_local_discovery_start(mesh, &n);
	CHECK(n.local_discovery.active);
	before = tap.count;

	for(t = 0; t < PATH_LOCAL_DISCOVERY_BROADCAST_TRIES; t++) {
		path_local_discovery_tick(mesh, &n);
		EXPECT_ECHO(tap, n, true, bcast);
		advance_ms(mesh, 1000);
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.exhausted && !n.local_discovery.active);
	CHECK(tap.count == before + PATH_LOCAL_DISCOVERY_BROADCAST_TRIES);

	plant_discovery_peer(&n, &edge, mesh, "discovery-bonly-fail", 0xcb007105, ADDR_SRC_EDGE_DIRECT);
	give_lan_presence(mesh, &n, 0xc0a80114);
	n.recent_cap[0] = PATH_CAP_META;
	tap.result = RELAY_UDP_HARD_ERROR;
	path_local_discovery_start(mesh, &n);
	path_local_discovery_tick(mesh, &n);
	tap.result = RELAY_UDP_SENT;
	CHECK(n.local_discovery.exhausted && !n.local_discovery.active);
	CHECK(n.local_discovery.carrier_failures == 1 && !n.local_discovery.tries);

	/* 18. The nonce-zero confirm path refuses an off-link private source too. */
	plant_discovery_peer(&n, &edge, mesh, "legacy-offlink", 0x0a1401b5, ADDR_SRC_EDGE_DIRECT);
	near = v4(0x0a1401b5, 9);
	CHECK(path_try_confirm_udp_probe_reply(mesh, &n, &near, 0));
	CHECK(!n.status.udp_confirmed);

	ok = true;

done:
	if(families_saved) {
		for(i = 0; i < mesh->listen_sockets && i < MAXSOCKETS; i++) {
			mesh->listen_socket[i].sa.sa.sa_family = saved_fam[i];
		}
	}

	path_scheduler_set_tap(mesh, NULL);
	local_network_set_snapshot(mesh, NULL, 0);
	mesh->lan_network_epoch = saved_epoch ? saved_epoch : 1;
	stop_peer_path_activity(mesh, &n);
	path_scheduler_set_budget(mesh, 1000, 1000, saved_max);
	return ok;
}

bool path_plpmtu_cover_unit(meshlink_handle_t *mesh) {
	struct timespec saved_now;
	unsigned char saved_budget[sizeof mesh->probe_budget];
	int saved_class;
	bool ok;

	if(!mesh || !mesh->self) {
		return false;
	}

	saved_now = mesh->loop.now;
	memcpy(saved_budget, &mesh->probe_budget, sizeof saved_budget);
	saved_class = mesh->self->devclass;

	if(!mesh->loop.now.tv_sec) {
		mesh->loop.now.tv_sec = 1700000000;
	}

	path_scheduler_init(mesh);
	mesh->probe_budget.second_tokens = 1000;
	mesh->probe_budget.minute_tokens = 1000;
	mesh->probe_budget.keepalive_tokens = 1000;
	mesh->self->devclass = DEV_CLASS_STATIONARY;

	ok = plpmtu_cover(mesh)
	     && plpmtu_admission_cover(mesh)
	     && plpmtu_cache_raise_cover(mesh)
	     && plpmtu_recovery_cover(mesh)
	     && liveness_admission_cover(mesh)
	     && liveness_cover(mesh)
	     && local_discovery_cover(mesh)
	     && keepalive_legacy_cache_cover(mesh)
	     && keepalive_default_cover(mesh)
	     && keepalive_probe_tx_cover(mesh)
	     && keepalive_cover(mesh)
	     && probe_record_and_endpoint_encoding_cover(mesh)
	     && mtu_cache_serialization_cover(mesh);

	mesh->self->devclass = saved_class;
	memcpy(&mesh->probe_budget, saved_budget, sizeof saved_budget);
	mesh->loop.now = saved_now;
	return ok;
}
