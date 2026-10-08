/*
    path_plpmtu.c -- per-path packetization-layer MTU
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include <arpa/inet.h>
#include <string.h>

#include "crypto.h"
#include "event.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "packmsg.h"
#include "path_liveness.h"
#include "path_plpmtu.h"
#include "path_probe.h"
#include "path_scheduler.h"
#include "relay.h"

#define fresh_nonce path_probe_fresh_nonce
#define ms_between path_ms_between
#define arm_ms path_timer_arm_ms
#define disarm path_timer_disarm

static const uint16_t path_plpmtu_ladder[] = {
	PATH_PLPMTU_STEP_1259, PATH_PLPMTU_STEP_1339, PATH_PLPMTU_STEP_1379, PATH_PLPMTU_STEP_1399,
	PATH_PLPMTU_STEP_1419, PATH_PLPMTU_STEP_1431, MTU
};

static void ip_only(sockaddr_t *sa) {
	if(!sa) {
		return;
	}

	if(sa->sa.sa_family == AF_INET) {
		sa->in.sin_port = 0;
	} else if(sa->sa.sa_family == AF_INET6) {
		sa->in6.sin6_port = 0;
	}
}

static bool same_ip(const sockaddr_t *a, const sockaddr_t *b) {
	sockaddr_t aa, bb;

	if(!a || !b || !a->sa.sa_family || !b->sa.sa_family) {
		return false;
	}

	path_copy_sockaddr(&aa, a);
	path_copy_sockaddr(&bb, b);
	ip_only(&aa);
	ip_only(&bb);
	return !sockaddrcmp(&aa, &bb);
}

static void cache_key(const sockaddr_t *sa, uint8_t *family, uint8_t addr[16]) {
	memset(addr, 0, 16);
	*family = 0;

	if(!sa) {
		return;
	}

	if(sa->sa.sa_family == AF_INET) {
		*family = AF_INET;
		memcpy(addr, &sa->in.sin_addr, 4);
	} else if(sa->sa.sa_family == AF_INET6) {
		*family = AF_INET6;
		memcpy(addr, &sa->in6.sin6_addr, 16);
	}
}

static bool cache_key_eq(const path_mtu_cache_entry_t *e, uint8_t family, const uint8_t addr[16]) {
	return e->family && e->family == family && !memcmp(e->addr, addr, 16);
}

static void publish(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	channel_refresh_carrier(mesh, n);
	relay_notify_minmtu_change(mesh, n);

	if(mesh->node_pmtu_cb && !n->status.blacklisted) {
		mesh->node_pmtu_cb(mesh, (meshlink_node_t *)n, path_plpmtu_size(n));
	}
}

static int cache_index(const node_t *n, uint8_t family, const uint8_t addr[16]) {
	int i;
	int empty = -1;
	int oldest = 0;

	for(i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		if(cache_key_eq(&n->mtu_cache[i], family, addr)) {
			return i;
		}

		if(!n->mtu_cache[i].family && empty < 0) {
			empty = i;
		}

		if(n->mtu_cache[i].updated_at < n->mtu_cache[oldest].updated_at) {
			oldest = i;
		}
	}

	return empty >= 0 ? empty : oldest;
}

static bool cache_fp_ok(uint32_t entry_fp, uint32_t now_fp) {
	return !entry_fp || !now_fp || entry_fp == now_fp;
}

static path_mtu_cache_entry_t *cache_get(node_t *n, const sockaddr_t *ip, uint32_t now_fp) {
	uint8_t family, addr[16];
	int i;
	time_t now = time(NULL);

	cache_key(ip, &family, addr);

	if(!family) {
		return NULL;
	}

	for(i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		path_mtu_cache_entry_t *e = &n->mtu_cache[i];

		if(!cache_key_eq(e, family, addr)) {
			continue;
		}

		if(e->size < MINMTU || e->size > MTU) {
			return NULL;
		}

		if(e->largest_failed && (e->largest_failed <= e->size || e->largest_failed > MTU)) {
			return NULL;
		}

		if(now - e->updated_at > PATH_PLPMTU_CACHE_MAX_AGE_SEC) {
			return NULL;
		}

		if(!cache_fp_ok(e->net_fp, now_fp)) {
			return NULL;
		}

		return e;
	}

	return NULL;
}

static void cache_store(meshlink_handle_t *mesh, node_t *n) {
	(void)mesh;
	uint8_t family, addr[16];
	int idx;
	path_mtu_cache_entry_t neu;
	path_mtu_cache_entry_t *e;
	bool material;

	if(!n->plpmtu.path_ip.sa.sa_family || n->plpmtu.size < MINMTU) {
		return;
	}

	cache_key(&n->plpmtu.path_ip, &family, addr);
	idx = cache_index(n, family, addr);
	e = &n->mtu_cache[idx];

	memset(&neu, 0, sizeof neu);
	neu.family = family;
	memcpy(neu.addr, addr, 16);
	neu.size = n->plpmtu.size;
	neu.largest_failed = n->plpmtu.largest_failed;
	neu.flags = PATH_MTU_CACHE_KEEPALIVE_V2 | (n->plpmtu.hostile ? PATH_MTU_CACHE_HOSTILE : 0);
	neu.raise_backoff = n->plpmtu.raise_backoff;
	neu.keepalive_ms = n->keepalive.interval_ms;
	neu.updated_at = time(NULL);
	neu.net_fp = n->plpmtu.path_net_fp;

	material = !cache_key_eq(e, family, addr)
	           || e->size != neu.size
	           || e->largest_failed != neu.largest_failed
	           || e->flags != neu.flags
	           || e->raise_backoff != neu.raise_backoff
	           || e->keepalive_ms != neu.keepalive_ms
	           || e->net_fp != neu.net_fp;

	*e = neu;

	if(material) {
		n->status.dirty = true;
	}
}

uint16_t path_plpmtu_size(const node_t *n) {
	if(!n || !n->status.udp_confirmed || n->plpmtu.size < MINMTU) {
		return 0;
	}

	return n->plpmtu.size;
}

uint32_t path_local_network_fp(const meshlink_handle_t *mesh) {
	const char *s;
	const char *end;
	uint32_t h = PATH_PLPMTU_FNV_OFFSET;

	if(!mesh || !mesh->self || !mesh->self->external_ip_address) {
		return 0;
	}

	s = mesh->self->external_ip_address;
	end = strchr(s, ' ');

	if(!end) {
		end = s + strlen(s);
	}

	if(end == s) {
		return 0;
	}

	for(; s < end; s++) {
		h ^= (uint8_t) * s;
		h *= PATH_PLPMTU_FNV_PRIME;
	}

	return h ? h : 1;
}

static uint16_t next_step(const node_t *n) {
	size_t i;

	for(i = 0; i < sizeof path_plpmtu_ladder / sizeof path_plpmtu_ladder[0]; i++) {
		uint16_t step = path_plpmtu_ladder[i];

		if(step <= n->plpmtu.size) {
			continue;
		}

		if(n->plpmtu.largest_failed && step >= n->plpmtu.largest_failed) {
			continue;
		}

		return step;
	}

	return 0;
}

static int raise_sec(const node_t *n) {
	unsigned shift = n->plpmtu.raise_backoff;
	uint64_t sec = PATH_PLPMTU_RAISE_SEC;

	if(shift > 16) {
		shift = 16;
	}

	sec <<= shift;

	if(sec > PATH_PLPMTU_RAISE_MAX_SEC) {
		sec = PATH_PLPMTU_RAISE_MAX_SEC;
	}

	return (int)sec;
}

static void clear_probe(node_t *n) {
	n->plpmtu.pending_size = 0;
	n->plpmtu.probe_size = 0;
	n->plpmtu.probe_nonce = 0;
	n->plpmtu.recovery_nonce = 0;
	n->plpmtu.probe_tries = 0;
}

static void plpmtu_timer(event_loop_t *loop, void *data);

static void arm_maintenance(meshlink_handle_t *mesh, node_t *n) {
	int64_t left = n->plpmtu.raise_at.tv_sec - mesh->loop.now.tv_sec;
	if(relay_hop_demanded(mesh, n)) {
		if(!n->plpmtu.relay_verify_at.tv_sec) {
			n->plpmtu.relay_verify_at = mesh->loop.now;
			n->plpmtu.relay_verify_at.tv_sec += PATH_PLPMTU_RELAY_VERIFY_SEC + prng(mesh, PATH_PLPMTU_RELAY_VERIFY_JITTER_SEC);
		}
		int64_t verify_left = n->plpmtu.relay_verify_at.tv_sec - mesh->loop.now.tv_sec;
		if(verify_left < left) { left = verify_left; }
	}

	if(left < 1) {
		left = 1;
	}

	arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, (int)left * 1000);
}

static void arm_raise(meshlink_handle_t *mesh, node_t *n) {
	n->plpmtu.raise_at = mesh->loop.now;
	n->plpmtu.raise_at.tv_sec += raise_sec(n);
	arm_maintenance(mesh, n);
}

static void settle(meshlink_handle_t *mesh, node_t *n, const char *how) {
	bool verified = n->plpmtu.relay_verifying;
	n->plpmtu.relay_verifying = false;
	n->plpmtu.relay_verified_at = mesh->loop.now;
	n->plpmtu.relay_verify_at = mesh->loop.now;
	n->plpmtu.relay_verify_at.tv_sec += PATH_PLPMTU_RELAY_VERIFY_SEC + prng(mesh, PATH_PLPMTU_RELAY_VERIFY_JITTER_SEC);
	path_scheduler_end_type(mesh, n, PATH_TXN_PLPMTU_SEARCH);
	n->plpmtu.state = PLPMTU_COMPLETE;
	clear_probe(n);
	n->plpmtu.bh_verifying = false;
	n->plpmtu.raising = false;
	cache_store(mesh, n);
	publish(mesh, n);
	logger(mesh, MESHLINK_INFO, "PLPMTU of %s settled at %u (largest failed %u)%s%s",
	       n->name, n->plpmtu.size, n->plpmtu.largest_failed, how ? " " : "", how ? how : "");
	if(verified) { arm_maintenance(mesh, n); } else { arm_raise(mesh, n); }
}

static bool liveness_guard(const meshlink_handle_t *mesh, const node_t *n);

static bool emit_size(meshlink_handle_t *mesh, node_t *n, uint16_t size) {
	path_probe_request_t req;
	path_sched_txn_t *txn = NULL;
	path_sched_admit_t admit;
	uint64_t nonce;
	uint64_t old_nonce = n->plpmtu.probe_nonce;
	uint16_t old_size = n->plpmtu.probe_size;
	struct timespec old_sent_at = n->plpmtu.probe_sent_at;
	struct timespec old_oversize_at = n->plpmtu.last_oversize_sent_at;

	n->plpmtu.pending_size = size;

	if(liveness_guard(mesh, n)) {
		arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_LIVENESS_GUARD_MS);
		return false;
	}

	if(n->plpmtu.state == PLPMTU_SEARCHING || n->plpmtu.state == PLPMTU_VERIFY || n->plpmtu.state == PLPMTU_BASE) {
		txn = path_scheduler_begin_transaction(mesh, n, PATH_TXN_PLPMTU_SEARCH, PATH_TX_PLPMTU_PROBE, path_transaction_preempt);
	}

	if(!txn) {
		if(n->plpmtu.relay_verifying) { n->plpmtu.relay_verify_admission_delays++; }
		arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_PROBE_TIMEOUT_MS);
		return false;
	}

	nonce = fresh_nonce();
	memset(&req, 0, sizeof req);
	req.node = n;
	req.length = size < PROBE_FIXED_LEN ? PROBE_FIXED_LEN : size;
	req.priority = PATH_TX_PLPMTU_PROBE;
	req.send = net_probe_sched_send;
	req.probe_kind = PROBE_KIND_SIZE_REQUEST;
	req.probe_purpose = PROBE_PURPOSE_NONE;
	req.probe_nonce = nonce;

	n->plpmtu.probe_nonce = nonce;
	n->plpmtu.probe_size = req.length;
	n->plpmtu.probe_sent_at = mesh->loop.now;

	if(req.length > n->plpmtu.size) {
		n->plpmtu.last_oversize_sent_at = mesh->loop.now;
	}

	admit = path_scheduler_emit_packet(mesh, txn, &req);

	if(admit != PATH_SCHED_SENT) {
		if(n->plpmtu.relay_verifying) { n->plpmtu.relay_verify_admission_delays++; }
		/* Retain the previous attempt so a late reply can still prove it. */
		n->plpmtu.probe_nonce = old_nonce;
		n->plpmtu.probe_size = old_size;
		n->plpmtu.probe_sent_at = old_sent_at;
		n->plpmtu.last_oversize_sent_at = old_oversize_at;
		arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_PROBE_TIMEOUT_MS);
		return false;
	}

	n->plpmtu.pending_size = 0;
	n->plpmtu.recovery_nonce = 0;
	n->plpmtu.probes_sent++;

	if(req.length > n->plpmtu.size) {
		n->plpmtu.probes_oversize++;
	}

	arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_PROBE_TIMEOUT_MS);
	return true;
}

static bool liveness_guard(const meshlink_handle_t *mesh, const node_t *n) {
	int64_t age;

	if(n->liveness.state == LIVENESS_PROBING
	                || (n == mesh->backbone_udp.node && mesh->backbone_udp.liveness_nonce)) {
		return true;
	}

	if(!n->liveness.first_try_at.tv_sec && !n->keepalive.last_probe_at.tv_sec) {
		return false;
	}

	if(n->liveness.state != LIVENESS_IDLE && n->liveness.first_try_at.tv_sec) {
		age = ms_between(&n->liveness.first_try_at, &mesh->loop.now);

		if(age >= 0 && age < PATH_PLPMTU_LIVENESS_GUARD_MS) {
			return true;
		}
	}

	if(n->keepalive.last_probe_at.tv_sec) {
		age = ms_between(&n->keepalive.last_probe_at, &mesh->loop.now);

		if(age >= 0 && age < PATH_PLPMTU_LIVENESS_GUARD_MS) {
			return true;
		}
	}

	return false;
}

bool path_plpmtu_probe_recent(const meshlink_handle_t *mesh, const node_t *n) {
	int64_t age;

	if(!n->plpmtu.probe_sent_at.tv_sec) {
		return false;
	}

	age = ms_between(&n->plpmtu.probe_sent_at, &mesh->loop.now);
	return age >= 0 && age < PATH_PLPMTU_LIVENESS_GUARD_MS;
}

static void failed_raise(node_t *n) {
	if(n->plpmtu.raising) {
		if(n->plpmtu.raise_backoff < PATH_PLPMTU_RAISE_BACKOFF_CAP) {
			n->plpmtu.raise_backoff++;
		}

		n->plpmtu.raising = false;
	}
}

static void fail_outstanding(meshlink_handle_t *mesh, node_t *n) {
	uint16_t failed = n->plpmtu.probe_size;
	bool base_probe = failed && failed <= PATH_PLPMTU_BASE;
	bool bh = n->plpmtu.bh_verifying;
	uint16_t old = n->plpmtu.size;

	failed_raise(n);
	n->plpmtu.probes_lost += PATH_PLPMTU_MAX_PROBES;
	if(n->plpmtu.relay_verifying) {
		n->plpmtu.relay_verify_failures++;
		n->plpmtu.relay_verifying = false;
	}

	if(!n->plpmtu.largest_failed || failed < n->plpmtu.largest_failed) {
		n->plpmtu.largest_failed = failed;
	}

	clear_probe(n);

	if(base_probe) {
		n->plpmtu.state = PLPMTU_ERROR;
		n->plpmtu.size = MINMTU;
		n->plpmtu.bh_verifying = false;
		path_scheduler_end_type(mesh, n, PATH_TXN_PLPMTU_SEARCH);
		cache_store(mesh, n);
		publish(mesh, n);
		logger(mesh, MESHLINK_INFO, "PLPMTU of %s: base %u not deliverable, using %u", n->name, PATH_PLPMTU_BASE, MINMTU);
		arm_raise(mesh, n);
		return;
	}

	if(bh) {
		n->plpmtu.bh_verifying = false;
		n->plpmtu.black_holes++;
		n->plpmtu.size = PATH_PLPMTU_BASE;
		n->plpmtu.largest_failed = old > PATH_PLPMTU_BASE ? old : failed;
		logger(mesh, MESHLINK_INFO, "PLPMTU of %s: black hole detected, %u -> %u", n->name, old, n->plpmtu.size);
		publish(mesh, n);
		n->plpmtu.state = PLPMTU_SEARCHING;
		arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_STEP_GAP_MS);
		return;
	}

	if(n->plpmtu.state == PLPMTU_VERIFY) {
		n->plpmtu.size = PATH_PLPMTU_BASE;
		n->plpmtu.state = PLPMTU_SEARCHING;
		publish(mesh, n);
		arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_STEP_GAP_MS);
		return;
	}

	n->plpmtu.state = PLPMTU_COMPLETE;
	settle(mesh, n, NULL);
}

void path_plpmtu_verify_relay_due(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || !relay_hop_demanded(mesh, n) || !n->relay_hop.confirmed
	                || !relay_hop_udp_ready(n)
	                || (n->plpmtu.state != PLPMTU_COMPLETE && n->plpmtu.state != PLPMTU_ERROR)
	                || n->plpmtu.probe_size || n->plpmtu.pending_size) {
		return;
	}
	if(!n->plpmtu.relay_verify_at.tv_sec) {
		n->plpmtu.relay_verify_at = mesh->loop.now;
		n->plpmtu.relay_verify_at.tv_sec += PATH_PLPMTU_RELAY_VERIFY_SEC + prng(mesh, PATH_PLPMTU_RELAY_VERIFY_JITTER_SEC);
		return;
	}
	if(ms_between(&mesh->loop.now, &n->plpmtu.relay_verify_at) > 0) { return; }
	/* Check the current usable size, preserving hostile holds and raise_at. */
	n->plpmtu.relay_verify_state = n->plpmtu.state;
	n->plpmtu.relay_verifying = true;
	n->plpmtu.relay_verifications++;
	n->plpmtu.bh_verifying = true;
	n->plpmtu.state = PLPMTU_VERIFY;
	emit_size(mesh, n, n->plpmtu.size);
}

void path_plpmtu_tick(meshlink_handle_t *mesh, node_t *n) {
	uint16_t step;

	if(!mesh || !n || n->plpmtu.state == PLPMTU_DISABLED) {
		return;
	}

	if(!n->status.udp_confirmed || !n->status.validkey) {
		path_plpmtu_pause(mesh, n);
		return;
	}

	if(n != mesh->backbone_udp.node && !path_peer_udp_demanded(mesh, n) && !relay_hop_demanded(mesh, n)) {
		path_plpmtu_pause(mesh, n);
		return;
	}

	if(n->plpmtu.probe_size) {
		if(ms_between(&n->plpmtu.probe_sent_at, &mesh->loop.now) >= PATH_PLPMTU_PROBE_TIMEOUT_MS) {
			if(liveness_guard(mesh, n)) {
				arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_LIVENESS_GUARD_MS);
				return;
			}
			/* A failed large send may have destroyed our NAT mapping. Expose
			   the new port with control traffic, even before direct promotion.
			   Keep the size nonce alive for a late ACK and never queue this
			   timer-owned echo or count it as another size attempt. */
			if(!n->plpmtu.recovery_nonce) {
				path_probe_request_t req;
				memset(&req, 0, sizeof req);
				req.node = n;
				req.length = PROBE_FIXED_LEN;
				req.priority = PATH_TX_PLPMTU_PROBE;
				req.send = net_probe_sched_send;
				req.probe_kind = PROBE_KIND_ECHO_REQUEST;
				req.probe_purpose = PROBE_PURPOSE_PLPMTU_RECOVERY;
				req.probe_nonce = fresh_nonce();

				if(path_scheduler_emit_packet(mesh, NULL, &req) == PATH_SCHED_SENT) {
					n->plpmtu.recovery_nonce = req.probe_nonce;
					n->keepalive.last_probe_at = mesh->loop.now;
					arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_LIVENESS_GUARD_MS);
				} else {
					arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_PROBE_TIMEOUT_MS);
				}

				return;
			}

			n->plpmtu.probe_tries++;

			if(n->plpmtu.probe_tries >= PATH_PLPMTU_MAX_PROBES) {
				fail_outstanding(mesh, n);
			} else if(!emit_size(mesh, n, n->plpmtu.probe_size)) {
				n->plpmtu.probe_tries--;
			}
		}

		return;
	}

	if(n->plpmtu.pending_size) {
		emit_size(mesh, n, n->plpmtu.pending_size);
		return;
	}

	if(n->plpmtu.state == PLPMTU_COMPLETE || n->plpmtu.state == PLPMTU_ERROR) {
		path_plpmtu_verify_relay_due(mesh, n);
		if(n->plpmtu.relay_verifying) { return; }
		if(mesh->loop.now.tv_sec < n->plpmtu.raise_at.tv_sec) {
			arm_maintenance(mesh, n);
			return;
		}

		n->plpmtu.raising = true;

		if(n->plpmtu.state == PLPMTU_ERROR) {
			n->plpmtu.size = PATH_PLPMTU_BASE;
			n->plpmtu.state = PLPMTU_BASE;
			emit_size(mesh, n, PATH_PLPMTU_BASE);
			return;
		}

		if(!n->plpmtu.hostile) {
			n->plpmtu.largest_failed = 0;
		}

		n->plpmtu.state = PLPMTU_SEARCHING;
	}

	step = next_step(n);

	if(!step) {
		settle(mesh, n, NULL);
		return;
	}

	n->plpmtu.state = n->plpmtu.state == PLPMTU_VERIFY ? PLPMTU_VERIFY : PLPMTU_SEARCHING;
	emit_size(mesh, n, step);
}

static void plpmtu_timer(event_loop_t *loop, void *data) {
	path_plpmtu_tick(loop->data, data);
}

void path_plpmtu_pause(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	disarm(mesh, &n->plpmtu.timer);
	if(n->plpmtu.relay_verifying) {
		n->plpmtu.state = n->plpmtu.relay_verify_state;
		n->plpmtu.bh_verifying = false;
	}
	clear_probe(n);
	n->plpmtu.relay_verifying = false;
	path_scheduler_end_type(mesh, n, PATH_TXN_PLPMTU_SEARCH);
}

void path_plpmtu_stop(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	if(n->plpmtu.state != PLPMTU_DISABLED && n->plpmtu.size >= MINMTU) {
		cache_store(mesh, n);
	}

	path_plpmtu_pause(mesh, n);
	memset(&n->plpmtu, 0, sizeof n->plpmtu);
	n->plpmtu.state = PLPMTU_DISABLED;
}

void path_plpmtu_forget(meshlink_handle_t *mesh, node_t *n) {
	if(!n) {
		return;
	}

	path_plpmtu_stop(mesh, n);
	memset(n->mtu_cache, 0, sizeof n->mtu_cache);
	n->status.dirty = true;
}

void path_plpmtu_on_confirmed(meshlink_handle_t *mesh, node_t *n) {
	sockaddr_t ip;
	path_mtu_cache_entry_t *hit;
	uint32_t fp;
	time_t now;

	if(!mesh || !n || !n->status.udp_confirmed || !n->status.validkey) {
		return;
	}

	if(n != mesh->backbone_udp.node && !path_peer_udp_demanded(mesh, n) && !relay_hop_demanded(mesh, n)) {
		return;
	}

	if(!n->address.sa.sa_family) {
		return;
	}

	path_copy_sockaddr(&ip, &n->address);
	ip_only(&ip);
	fp = path_local_network_fp(mesh);

	if(n->plpmtu.state != PLPMTU_DISABLED && same_ip(&n->plpmtu.path_ip, &ip)
	                && cache_fp_ok(n->plpmtu.path_net_fp, fp)) {
		publish(mesh, n);

		if(!n->plpmtu.timer.cb) {
			arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_STEP_GAP_MS);
		}

		return;
	}

	if(n->plpmtu.state != PLPMTU_DISABLED) { cache_store(mesh, n); }
	path_plpmtu_pause(mesh, n);
	memset(&n->plpmtu, 0, sizeof n->plpmtu);
	n->plpmtu.path_ip = ip;
	n->plpmtu.path_net_fp = fp;
	hit = cache_get(n, &ip, fp);
	now = time(NULL);

	if(hit) {
		n->plpmtu.largest_failed = hit->largest_failed;
		n->plpmtu.hostile = hit->flags & PATH_MTU_CACHE_HOSTILE;
		n->plpmtu.raise_backoff = hit->raise_backoff;
		n->plpmtu.cache_hits++;

		/* Older builds attributed remote/oversize recoveries to local idle
		   expiry. Retain their MTU, but relearn the keepalive interval. */
		if((hit->flags & PATH_MTU_CACHE_KEEPALIVE_V2) && hit->keepalive_ms >= PATH_KEEPALIVE_FLOOR_MS) {
			n->keepalive.interval_ms = hit->keepalive_ms;
		}
	}

	if(hit && now - hit->updated_at <= PATH_PLPMTU_TRUST_SEC) {
		n->plpmtu.state = PLPMTU_COMPLETE;
		n->plpmtu.size = hit->size;
		publish(mesh, n);
		logger(mesh, MESHLINK_INFO, "PLPMTU of %s settled at %u (largest failed %u) cached",
		       n->name, n->plpmtu.size, n->plpmtu.largest_failed);
		arm_raise(mesh, n);
		return;
	}

	if(hit) {
		n->plpmtu.state = PLPMTU_VERIFY;
		n->plpmtu.size = PATH_PLPMTU_BASE;
		publish(mesh, n);
		emit_size(mesh, n, hit->size);
		return;
	}

	n->plpmtu.state = PLPMTU_BASE;
	n->plpmtu.size = PATH_PLPMTU_BASE;
	publish(mesh, n);
	arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_STEP_GAP_MS);
}

void path_plpmtu_observe_ack(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce, uint16_t len) {
	uint16_t prev;

	if(!mesh || !n || !from || !n->plpmtu.probe_size || nonce != n->plpmtu.probe_nonce || len != n->plpmtu.probe_size) {
		return;
	}

	if(sockaddrcmp(from, &n->address)) {
		return;
	}

	if(n->plpmtu.raising && !n->plpmtu.hostile) {
		n->plpmtu.raise_backoff = 0;
		n->plpmtu.raising = false;
	}

	/* A delivered size supersedes an older failure at that same bound. */
	if(n->plpmtu.largest_failed && len >= n->plpmtu.largest_failed) {
		n->plpmtu.largest_failed = 0;
	}

	prev = n->plpmtu.size;
	/* Leave last_oversize_sent_at set. The size ACK's endpoint is observed
	   after this returns, and a recent oversized send explains that remap. */
	n->plpmtu.size = len;
	clear_probe(n);
	n->plpmtu.probe_tries = 0;

	if(n->plpmtu.state == PLPMTU_VERIFY || (n->plpmtu.bh_verifying && len >= prev)) {
		n->plpmtu.bh_verifying = false;
		settle(mesh, n, NULL);
		return;
	}

	if(len > prev) {
		logger(mesh, MESHLINK_INFO, "PLPMTU of %s raised to %u", n->name, len);
	}

	publish(mesh, n);
	cache_store(mesh, n);
	n->plpmtu.state = PLPMTU_SEARCHING;
	arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_STEP_GAP_MS);
}

void path_plpmtu_note_emsgsize(meshlink_handle_t *mesh, node_t *n, uint16_t payload) {
	if(!mesh || !n || !payload) {
		return;
	}

	failed_raise(n);
	n->plpmtu.emsgsize++;

	if(!n->plpmtu.largest_failed || payload < n->plpmtu.largest_failed) {
		n->plpmtu.largest_failed = payload;
	}

	if(n->plpmtu.size >= payload) {
		n->plpmtu.size = payload > MINMTU + 1 ? payload - 1 : MINMTU;
		publish(mesh, n);
	}

	if(n->plpmtu.probe_size >= payload || n->plpmtu.pending_size >= payload) {
		clear_probe(n);
		n->plpmtu.state = PLPMTU_SEARCHING;
		arm_ms(mesh, &n->plpmtu.timer, plpmtu_timer, n, PATH_PLPMTU_STEP_GAP_MS);
	}

	logger(mesh, MESHLINK_INFO, "PLPMTU of %s: local MTU limit %u (EMSGSIZE)", n->name, payload);
	cache_store(mesh, n);
}

void path_plpmtu_note_local_remap(meshlink_handle_t *mesh, node_t *n) {
	int64_t age;

	if(!mesh || !n || !n->plpmtu.last_oversize_sent_at.tv_sec) {
		return;
	}

	age = ms_between(&n->plpmtu.last_oversize_sent_at, &mesh->loop.now);

	if(age < 0 || age > PATH_PLPMTU_HOSTILE_WINDOW_MS) {
		return;
	}

	n->plpmtu.hostile = true;
	n->plpmtu.hostile_marks++;

	if(n->plpmtu.raise_backoff < PATH_PLPMTU_RAISE_BACKOFF_CAP) {
		n->plpmtu.raise_backoff++;
	}

	clear_probe(n);
	path_scheduler_end_type(mesh, n, PATH_TXN_PLPMTU_SEARCH);
	n->plpmtu.state = PLPMTU_COMPLETE;
	cache_store(mesh, n);
	logger(mesh, MESHLINK_INFO, "PLPMTU of %s: path is hostile to oversized packets, holding %u for %us",
	       n->name, n->plpmtu.size, raise_sec(n));
	arm_raise(mesh, n);
}

void path_plpmtu_note_large_suspect_send(meshlink_handle_t *mesh, node_t *n, uint16_t payload) {
	int64_t age;

	if(!mesh || !n || payload <= PATH_PLPMTU_BASE || n->plpmtu.state == PLPMTU_DISABLED) {
		return;
	}

	if(!n->plpmtu.bh_first_at.tv_sec) {
		n->plpmtu.bh_first_at = mesh->loop.now;
		n->plpmtu.bh_evidence = 1;
		return;
	}

	age = ms_between(&n->plpmtu.bh_first_at, &mesh->loop.now);

	if(age < 0 || age > (int64_t)PATH_PLPMTU_BH_WINDOW_SEC * 1000) {
		n->plpmtu.bh_first_at = mesh->loop.now;
		n->plpmtu.bh_evidence = 1;
		return;
	}

	if(n->plpmtu.bh_evidence < 255) {
		n->plpmtu.bh_evidence++;
	}
}

void path_plpmtu_note_suspect_cleared(meshlink_handle_t *mesh, node_t *n) {
	int64_t age;

	if(!mesh || !n || n->plpmtu.bh_evidence < PATH_PLPMTU_BH_EVIDENCE || n->plpmtu.bh_verifying) {
		return;
	}

	age = ms_between(&n->plpmtu.bh_first_at, &mesh->loop.now);

	if(age < 0 || age > (int64_t)PATH_PLPMTU_BH_WINDOW_SEC * 1000) {
		n->plpmtu.bh_evidence = 0;
		return;
	}

	n->plpmtu.bh_evidence = 0;
	clear_probe(n);
	n->plpmtu.raising = false;
	n->plpmtu.bh_verifying = true;
	n->plpmtu.state = PLPMTU_SEARCHING;
	emit_size(mesh, n, n->plpmtu.size ? n->plpmtu.size : PATH_PLPMTU_BASE);
}

void path_plpmtu_remember_keepalive(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || n->plpmtu.size < MINMTU || !n->plpmtu.path_ip.sa.sa_family) {
		return;
	}

	cache_store(mesh, n);
}

void path_mtu_cache_pack(const node_t *n, packmsg_output_t *out) {
	uint32_t count = 0;
	int i;

	if(!n || !out) {
		return;
	}

	for(i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		if(n->mtu_cache[i].family) {
			count++;
		}
	}

	packmsg_add_array(out, count);

	for(i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		const path_mtu_cache_entry_t *e = &n->mtu_cache[i];
		uint8_t len = e->family == AF_INET6 ? 16 : 4;

		if(!e->family) {
			continue;
		}

		packmsg_add_bin(out, e->addr, len);
		packmsg_add_uint16(out, e->size);
		packmsg_add_uint16(out, e->largest_failed);
		packmsg_add_uint8(out, e->flags);
		packmsg_add_uint8(out, e->raise_backoff);
		packmsg_add_uint32(out, e->keepalive_ms);
		packmsg_add_int64(out, e->updated_at);
		packmsg_add_uint32(out, e->net_fp);
	}
}

void path_mtu_cache_unpack(node_t *n, packmsg_input_t *in) {
	uint32_t count;
	uint32_t i;
	int slot = 0;

	if(!n || !in || packmsg_done(in) || !packmsg_input_ok(in)) {
		return;
	}

	count = packmsg_get_array(in);

	for(i = 0; i < count; i++) {
		const void *bytes = NULL;
		uint32_t alen;
		path_mtu_cache_entry_t e;

		memset(&e, 0, sizeof e);
		alen = packmsg_get_bin_raw(in, &bytes);
		e.size = packmsg_get_uint16(in);
		e.largest_failed = packmsg_get_uint16(in);
		e.flags = packmsg_get_uint8(in);
		e.raise_backoff = packmsg_get_uint8(in);
		e.keepalive_ms = packmsg_get_uint32(in);
		e.updated_at = packmsg_get_int64(in);
		e.net_fp = packmsg_get_uint32(in);

		if(alen == 4) {
			e.family = AF_INET;
		} else if(alen == 16) {
			e.family = AF_INET6;
		}

		if(!e.family || e.size < MINMTU || e.size > MTU) {
			continue;
		}

		if(e.largest_failed && (e.largest_failed <= e.size || e.largest_failed > MTU)) {
			continue;
		}

		if(bytes && slot < PATH_MTU_CACHE_ENTRIES) {
			memcpy(e.addr, bytes, alen);
			n->mtu_cache[slot++] = e;
		}
	}
}
