/*
    path_plpmtu_cover.c -- PLPMTU, liveness, keepalive and probe wire cover
    Copyright (C) 2026 Elear Solutions
*/

#include "system.h"

#include <string.h>
#include <time.h>

#include "edge.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
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
			logger(mesh, MESHLINK_ERROR, "path_ws1_cover_unit failed: %s", #cond); \
			goto done; \
		} \
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

static void plant(node_t *n, meshlink_handle_t *mesh, char *name, uint32_t ip) {
	memset(n, 0, sizeof *n);
	n->name = name;
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

static void bury(meshlink_handle_t *mesh, node_t *n) {
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
	plant(&n, mesh, "ws1-plpmtu", 0xcb00710a);
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
	bury(mesh, &n);
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
	CHECK(n.plpmtu.state == PLPMTU_ERROR);
	CHECK(n.plpmtu.size == MINMTU);
	mesh->loop.now.tv_sec = n.plpmtu.raise_at.tv_sec;
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_BASE);
	CHECK(n.plpmtu.probe_size == PATH_PLPMTU_BASE);

	/* Same IP inside the trust window restores COMPLETE and sends nothing. */
	bury(mesh, &n);
	memset(&n.plpmtu, 0, sizeof n.plpmtu);
	memset(n.mtu_cache, 0, sizeof n.mtu_cache);
	n.status.udp_confirmed = true;
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.size = 1419;
	n.plpmtu.largest_failed = 1431;
	n.plpmtu.path_ip = n.address;
	n.plpmtu.path_ip.in.sin_port = 0;
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
	bury(mesh, &n);
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
	mesh->self->external_ip_address = "203.0.113.9 1";
	n.address = v4(0xcb00710a, 9);
	memset(n.mtu_cache, 0, sizeof n.mtu_cache);
	memset(&n.plpmtu, 0, sizeof n.plpmtu);
	n.status.udp_confirmed = true;
	n.plpmtu.state = PLPMTU_COMPLETE;
	n.plpmtu.size = 1399;
	n.plpmtu.path_ip = n.address;
	n.plpmtu.path_ip.in.sin_port = 0;
	path_plpmtu_stop(mesh, &n);
	mesh->self->external_ip_address = "198.51.100.9 1";
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
	bury(mesh, &n);
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

	/* Relay MSS is the hop's PLPMTU minus the type-8 prefix and the header. */
	plant(&hop, mesh, "ws1-hop", 0xcb007120);
	plant(&dest, mesh, "d", 0xcb007121);
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
		held = (uint16_t)(PATH_PLPMTU_BASE - prefix21 - sizeof(meshlink_packethdr_t));
		CHECK(channel_compute_mtu(mesh, &dest) == held);
	}

	/* Hostile: a local remap inside the window holds the size and backs off. */
	bury(mesh, &n);
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
	bury(mesh, &n);
	bury(mesh, &hop);
	bury(mesh, &dest);
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
	plant(&n, mesh, "ws1-admission", 0xcb007130);
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
	CHECK(n.plpmtu.probes_sent == sent + 2 && n.plpmtu.probe_tries == 2);
	advance_ms(mesh, PATH_PLPMTU_PROBE_TIMEOUT_MS);
	path_plpmtu_tick(mesh, &n);
	CHECK(n.plpmtu.state == PLPMTU_COMPLETE && n.plpmtu.probes_lost == 3);
	CHECK(n.plpmtu.probes_sent == sent + 2);

	/* A full transaction pool must defer the first size probe too. */
	bury(mesh, &n);
	plant(&n, mesh, "ws1-admission", 0xcb007130);
	plant(&blocker, mesh, "ws1-blocker", 0xcb007131);
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
	bury(mesh, &n);
	bury(mesh, &blocker);
	path_scheduler_set_budget(mesh, 1000, 1000, saved_max);
	return ok;
}

static bool plpmtu_cache_raise_cover(meshlink_handle_t *mesh) {
	node_t n;
	int slot;
	bool ok = false;

	plant(&n, mesh, "ws1-cache-raise", 0xcb007132);
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
	CHECK(n.mtu_cache[slot].flags == PATH_MTU_CACHE_HOSTILE);
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
	bury(mesh, &n);
	plant(&n, mesh, "ws1-cache-raise", 0xcb007132);
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
	bury(mesh, &n);
	return ok;
}

static bool liveness_cover(meshlink_handle_t *mesh) {
	node_t n;
	node_t low;
	int t;
	sockaddr_t other;
	edge_t edge;
	node_t *saved_bb = mesh->backbone_udp.node;
	char lower[128];
	char higher[128];
	time_t parked_until;
	int wait;
	bool ok = false;

	memset(&low, 0, sizeof low);
	plant(&n, mesh, "ws1-live", 0xcb00710b);
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
	CHECK(n.liveness.state == LIVENESS_PROBING);
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
	plant(&low, mesh, lower, 0xcb00710b);
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
	bury(mesh, &n);
	plant(&n, mesh, "ws1-live", 0xcb00710b);
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

	/* Local discovery: purpose, nonce, local source, then ten tries. */
	bury(mesh, &n);
	plant(&n, mesh, "ws1-disc", 0x7f000001);
	n.status.udp_confirmed = false;
	n.peer_udp.channel_count = 0;
	memset(&edge, 0, sizeof edge);
	n.prevedge = &edge;
	path_local_discovery_start(mesh, &n);
	CHECK(n.local_discovery.active);
	CHECK(!path_local_discovery_accept(mesh, &n, &n.address, n.local_discovery.nonce, PROBE_PURPOSE_NONE));
	CHECK(!path_local_discovery_accept(mesh, &n, &n.address, n.local_discovery.nonce ^ 1, PROBE_PURPOSE_LOCAL_DISCOVERY));
	other = v4(0xcb007199, 9);
	CHECK(!path_local_discovery_accept(mesh, &n, &other, n.local_discovery.nonce, PROBE_PURPOSE_LOCAL_DISCOVERY));
	n.address = v4(0x7f000001, 4000);
	CHECK(path_local_discovery_accept(mesh, &n, &n.address, n.local_discovery.nonce, PROBE_PURPOSE_LOCAL_DISCOVERY));
	CHECK(n.status.udp_confirmed);
	CHECK(!n.local_discovery.active);

	bury(mesh, &n);
	plant(&n, mesh, "ws1-disc", 0x7f000001);
	n.status.udp_confirmed = false;
	n.peer_udp.channel_count = 0;
	n.prevedge = &edge;
	n.status.want_udp = false;
	path_local_discovery_start(mesh, &n);

	for(t = 0; t < PATH_LOCAL_DISCOVERY_TRIES; t++) {
		path_local_discovery_tick(mesh, &n);
		CHECK(path_local_discovery_did_broadcast() == (t < PATH_LOCAL_DISCOVERY_BROADCAST_TRIES));
	}

	path_local_discovery_tick(mesh, &n);
	CHECK(n.local_discovery.exhausted);
	CHECK(!n.local_discovery.active);

	ok = true;

done:
	mesh->backbone_udp.node = saved_bb;
	bury(mesh, &n);
	bury(mesh, &low);
	return ok;
}

static bool keepalive_cover(meshlink_handle_t *mesh) {
	node_t n;
	node_t *saved_bb = mesh->backbone_udp.node;
	uint32_t sent;
	bool ok = false;

	plant(&n, mesh, "ws1-ka", 0xcb00710c);
	n.keepalive.last_tx_at = mesh->loop.now;
	path_keepalive_tick(mesh, &n);
	sent = n.keepalive.sent;
	CHECK(n.keepalive.sent == sent);
	advance_ms(mesh, PATH_KEEPALIVE_INITIAL_MS);
	path_keepalive_tick(mesh, &n);
	CHECK(n.keepalive.sent == sent + 1);
	path_keepalive_note_tx(mesh, &n);
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
	path_keepalive_note_giveup(mesh, &n, 1000);
	CHECK(!n.keepalive.pending_gap_ms);
	path_keepalive_note_giveup(mesh, &n, 15000);
	CHECK(n.keepalive.pending_gap_ms == 15000);
	n.status.udp_confirmed = true;
	path_liveness_on_confirmed(mesh, &n);
	CHECK(n.keepalive.interval_ms == 9000);
	CHECK(n.keepalive.expiries == 1);
	CHECK(cache_slot(&n, 0xcb00710c) >= 0);
	CHECK(n.mtu_cache[cache_slot(&n, 0xcb00710c)].keepalive_ms == 9000);

	n.keepalive.interval_ms = 9000;
	n.keepalive.last_grow_at = mesh->loop.now;
	n.keepalive.last_grow_at.tv_sec -= PATH_KEEPALIVE_GROW_SEC + 1;
	n.keepalive.last_tx_at = mesh->loop.now;
	n.keepalive.last_tx_at.tv_sec -= 20;
	n.peer_udp.channel_count = 1;
	n.status.udp_confirmed = true;
	path_keepalive_tick(mesh, &n);
	CHECK(n.keepalive.interval_ms == 10800);

	mesh->backbone_udp.node = &n;
	n.keepalive.interval_ms = PATH_KEEPALIVE_BACKBONE_INITIAL_MS;
	n.keepalive.expiries = 0;
	path_keepalive_note_giveup(mesh, &n, 15000);
	n.status.udp_confirmed = true;
	path_liveness_on_confirmed(mesh, &n);
	CHECK(n.keepalive.interval_ms == 9000);
	CHECK(n.keepalive.expiries == 1);
	CHECK(n.liveness.state == LIVENESS_IDLE);

	ok = true;

done:
	mesh->backbone_udp.node = saved_bb;
	bury(mesh, &n);
	return ok;
}

static bool wire_cover(meshlink_handle_t *mesh) {
	node_t n;
	vpn_packet_t packet;
	uint64_t nonce = 0x1122334455667788ull;
	uint64_t out_before;
	bool ok = false;

	plant(&n, mesh, "ws1-wire", 0xcb00710d);
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

	ok = true;

done:
	bury(mesh, &n);
	return ok;
}

static bool persist_cover(meshlink_handle_t *mesh) {
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
	src.mtu_cache[0].flags = PATH_MTU_CACHE_HOSTILE;
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
	CHECK(dst.mtu_cache[0].flags == PATH_MTU_CACHE_HOSTILE);
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

bool path_ws1_cover_unit(meshlink_handle_t *mesh) {
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
	     && liveness_cover(mesh)
	     && keepalive_cover(mesh)
	     && wire_cover(mesh)
	     && persist_cover(mesh);

	mesh->self->devclass = saved_class;
	memcpy(&mesh->probe_budget, saved_budget, sizeof saved_budget);
	mesh->loop.now = saved_now;
	return ok;
}
