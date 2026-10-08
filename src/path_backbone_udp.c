/*
    path_backbone_udp.c -- required backbone UDP relay mapping
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "connection.h"
#include "crypto.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "path_liveness.h"
#include "path_plpmtu.h"
#include "path_policy.h"

#include <string.h>

static void path_backbone_udp_timer(event_loop_t *loop, void *data);
void path_backbone_udp_arm(meshlink_handle_t *mesh, int sec, long nsec);

static uint64_t path_fresh_nonce(void) {
	uint64_t nonce = 0;

	do {
		randomize(&nonce, sizeof nonce);
	} while(!nonce);

	return nonce;
}

static bool path_backbone_udp_same_failed(const backbone_udp_path_t *p, const sockaddr_t *sa) {
	return p->failed_endpoint.sa.sa_family && sa && !sockaddrcmp(&p->failed_endpoint, sa);
}

static bool path_backbone_udp_accept_dest(const node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap, const backbone_udp_path_t *p) {
	if(!sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	if(!path_is_udp_candidate(n, sa, src, cap) || !udp_address_bound(sa)) {
		return false;
	}

	return !path_backbone_udp_same_failed(p, sa);
}

static bool path_pick_backbone_udp_candidate(meshlink_handle_t *mesh, node_t *n, sockaddr_t *out, address_source_t *src_out) {
	backbone_udp_path_t *p;
	int i;

	if(!mesh || !n || !out || !src_out) {
		return false;
	}

	p = &mesh->backbone_udp;

	if(n->connection && n->connection->status.active
	                && !path_meta_is_canonical(n, n->connection)
	                && path_backbone_udp_accept_dest(n, &n->connection->address, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH, p)) {
		path_copy_sockaddr(out, &n->connection->address);
		*src_out = ADDR_SRC_AUTH_DIRECT;
		return true;
	}

	if(n->address.sa.sa_family && n->address_source == ADDR_SRC_UDP_REFLEXIVE
	                && path_backbone_udp_accept_dest(n, &n->address, n->address_source, n->address_cap ? n->address_cap : PATH_CAP_UDP, p)) {
		path_copy_sockaddr(out, &n->address);
		*src_out = ADDR_SRC_UDP_REFLEXIVE;
		return true;
	}

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(n->recent_source[i] != ADDR_SRC_UDP_REFLEXIVE) {
			continue;
		}

		if(path_backbone_udp_accept_dest(n, &n->recent[i], n->recent_source[i], n->recent_cap[i], p)) {
			path_copy_sockaddr(out, &n->recent[i]);
			*src_out = n->recent_source[i];
			return true;
		}
	}

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(n->recent_source[i] == ADDR_SRC_UDP_REFLEXIVE) {
			continue;
		}

		if(path_backbone_udp_accept_dest(n, &n->recent[i], n->recent_source[i], n->recent_cap[i], p)) {
			path_copy_sockaddr(out, &n->recent[i]);
			*src_out = n->recent_source[i];
			return true;
		}
	}

	if(n->address.sa.sa_family
	                && path_backbone_udp_accept_dest(n, &n->address, n->address_source, n->address_cap ? n->address_cap : PATH_CAP_UDP, p)) {
		path_copy_sockaddr(out, &n->address);
		*src_out = n->address_source;
		return true;
	}

	return false;
}

void path_backbone_udp_arm(meshlink_handle_t *mesh, int sec, long nsec) {
	struct timespec when;

	when.tv_sec = sec < 0 ? 0 : sec;
	when.tv_nsec = nsec < 0 ? 0 : nsec;

	if(!mesh->backbone_udp.timer.cb) {
		timeout_add(&mesh->loop, &mesh->backbone_udp.timer, path_backbone_udp_timer, mesh, &when);
	} else {
		timeout_set(&mesh->loop, &mesh->backbone_udp.timer, &when);
	}

	if(mesh->threadstarted && mesh->loop.pipefd[1] != -1 && !pthread_equal(mesh->thread, pthread_self())) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

int path_backbone_udp_keepalive_base_sec(meshlink_handle_t *mesh) {
	node_t *n = mesh ? mesh->backbone_udp.node : NULL;

	/* Devtools shorten tests by setting a non-default keepalive. That override
	   wins over a learned interval. The stock 25s does not. */
	if(mesh && mesh->backbone_udp_keepalive_sec > 0
	                && mesh->backbone_udp_keepalive_sec != PATH_BACKBONE_UDP_KEEPALIVE_SEC) {
		return mesh->backbone_udp_keepalive_sec;
	}

	if(n && n->keepalive.interval_ms) {
		int learned = (int)(path_keepalive_backbone_interval_ms(mesh, n) / 1000);

		return learned > 0 ? learned : 1;
	}

	return PATH_BACKBONE_UDP_KEEPALIVE_SEC;
}

static void path_backbone_udp_arm_keepalive(meshlink_handle_t *mesh) {
	int base = path_backbone_udp_keepalive_base_sec(mesh);
	int span = base / 5;
	int delay;

	if(span < 1) {
		span = 1;
	}

	delay = base - span + (int)prng(mesh, (uint64_t)(2 * span + 1));

	if(delay < 1) {
		delay = 1;
	}

	path_backbone_udp_arm(mesh, delay, 0);
}

static int path_backbone_udp_next_establish(meshlink_handle_t *mesh) {
	static const int ladder[] = {1, 2, 4, 8, 16, PATH_BACKBONE_UDP_ESTABLISH_BACKOFF_MAX};
	backbone_udp_path_t *p = &mesh->backbone_udp;
	size_t n = sizeof ladder / sizeof ladder[0];
	unsigned i = p->establish_step;

	if(i >= n) {
		i = n - 1;
	} else {
		p->establish_step++;
	}

	return ladder[i];
}

static int path_backbone_udp_pingtimeout(meshlink_handle_t *mesh, const node_t *n) {
	int timeout = 5;

	if(n && n->devclass >= 0 && n->devclass < DEV_CLASS_COUNT) {
		timeout = mesh->dev_class_traits[n->devclass].pingtimeout;
	}

	if(timeout < 1) {
		timeout = 1;
	}

	return timeout;
}

static void path_backbone_udp_packet(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	/* A queued backbone request may drain immediately after a size send. */
	if(path_plpmtu_probe_recent(mesh, req->node)) {
		path_backbone_udp_arm(mesh, 0, PATH_PLPMTU_LIVENESS_GUARD_MS * 1000000L);
		return;
	}

	req->node->keepalive.last_probe_at = mesh->loop.now;
	mesh->backbone_udp.liveness_nonce = path_fresh_nonce();
	send_backbone_udp_probe(mesh);
}

static void path_backbone_udp_send(meshlink_handle_t *mesh) {
	path_probe_request_t req;

	if(!mesh->backbone_udp.node) {
		return;
	}

	memset(&req, 0, sizeof req);
	req.node = mesh->backbone_udp.node;
	req.length = PATH_PROMOTION_PROBE_LEN;
	req.priority = PATH_TX_BACKBONE_REQUIRED;
	req.send = path_backbone_udp_packet;
	(void)path_scheduler_emit_packet(mesh, NULL, &req);
}

static bool path_backbone_udp_pick_and_send(meshlink_handle_t *mesh, node_t *n) {
	backbone_udp_path_t *p = &mesh->backbone_udp;
	sockaddr_t dest;
	address_source_t src;

	memset(&dest, 0, sizeof dest);

	if(!path_pick_backbone_udp_candidate(mesh, n, &dest, &src)) {
		return false;
	}

	if(p->endpoint.sa.sa_family && sockaddrcmp(&p->endpoint, &dest)) {
		p->unanswered = 0;
	}

	path_copy_sockaddr(&p->endpoint, &dest);
	p->source = src;
	path_backbone_udp_send(mesh);
	return true;
}

static void path_backbone_udp_timer(event_loop_t *loop, void *data) {
	meshlink_handle_t *mesh = data;
	backbone_udp_path_t *p;
	node_t *n;
	bool just_failed;

	(void)loop;

	if(!mesh) {
		return;
	}

	p = &mesh->backbone_udp;
	n = p->node;

	if(!n || !n->status.reachable || n->devtool_force_meta) {
		p->liveness_nonce = 0;
		path_backbone_udp_arm(mesh, path_backbone_udp_next_establish(mesh), 0);
		return;
	}

	if(!n->status.validkey) {
		path_peer_ensure_udp_key(mesh, n);
		p->liveness_nonce = 0;
		path_backbone_udp_arm(mesh, path_backbone_udp_next_establish(mesh), 0);
		return;
	}

	if(p->confirmed) {
		if(path_plpmtu_probe_recent(mesh, n)) {
			path_backbone_udp_arm(mesh, 0, PATH_PLPMTU_LIVENESS_GUARD_MS * 1000000L);
			return;
		}

		if(p->liveness_nonce) {
			p->unanswered++;

			if(p->unanswered >= PATH_BACKBONE_UDP_KEEPALIVE_MISS) {
				logger(mesh, MESHLINK_INFO, "Backbone UDP keepalive to %s timed out", n->name);
				p->liveness_nonce = 0;
				p->unanswered = 0;

				if(n->status.udp_confirmed) {
					path_note_udp_demoted_reason(mesh, n, "backbone-udp-timeout");
				} else {
					p->confirmed = false;
					memset(&p->confirmed_at, 0, sizeof p->confirmed_at);

					if(p->endpoint.sa.sa_family) {
						path_copy_sockaddr(&p->failed_endpoint, &p->endpoint);
					}

					path_backbone_udp_arm(mesh, path_backbone_udp_next_establish(mesh), 0);
				}

				return;
			}
		}

		path_backbone_udp_send(mesh);
		path_backbone_udp_arm(mesh, path_backbone_udp_pingtimeout(mesh, n), 0);
		return;
	}

	just_failed = false;

	if(p->liveness_nonce) {
		p->unanswered++;

		if(p->unanswered >= PATH_BACKBONE_UDP_ESTABLISH_MISS) {
			if(p->endpoint.sa.sa_family) {
				path_copy_sockaddr(&p->failed_endpoint, &p->endpoint);
			}

			p->liveness_nonce = 0;
			p->unanswered = 0;
			just_failed = true;
			logger(mesh, MESHLINK_INFO, "Backbone UDP dest for %s failed, trying another", n->name);
		}
	}

	if(!path_backbone_udp_pick_and_send(mesh, n)) {
		if(!just_failed && p->failed_endpoint.sa.sa_family) {
			memset(&p->failed_endpoint, 0, sizeof p->failed_endpoint);

			if(path_backbone_udp_pick_and_send(mesh, n)) {
				path_backbone_udp_arm(mesh, PATH_BACKBONE_UDP_ESTABLISH_SEC, 0);
				return;
			}
		}

		path_backbone_udp_arm(mesh, path_backbone_udp_next_establish(mesh), 0);
		return;
	}

	path_backbone_udp_arm(mesh, PATH_BACKBONE_UDP_ESTABLISH_SEC, 0);
}

void path_backbone_udp_stop(meshlink_handle_t *mesh) {
	backbone_udp_path_t *path;
	node_t *node;
	bool owns_active_endpoint;

	if(!mesh) {
		return;
	}

	path = &mesh->backbone_udp;
	node = path->node;
	owns_active_endpoint = node
	                       && path->confirmed
	                       && node->status.udp_confirmed
	                       && node->address.sa.sa_family
	                       && node->address.sa.sa_family != AF_UNKNOWN
	                       && path->endpoint.sa.sa_family
	                       && path->endpoint.sa.sa_family != AF_UNKNOWN
	                       && !sockaddrcmp(&node->address, &path->endpoint);

	if(!path->timer.cb && path->timer.node.data) {
		path->timer.cb = path_backbone_udp_timer;
	}

	timeout_del(&mesh->loop, &path->timer);

	if(node) {
		path_plpmtu_stop(mesh, node);
		path_liveness_stop(mesh, node);
		path_keepalive_stop(mesh, node);
		path_scheduler_cancel(mesh, node, PATH_TX_BACKBONE_REQUIRED);
		path_scheduler_cancel(mesh, node, PATH_TX_LIVENESS);
		path_scheduler_cancel(mesh, node, PATH_TX_PLPMTU_PROBE);
	}

	if(owns_active_endpoint) {
		path_note_udp_demoted_reason(mesh, node, "backbone-udp-stopped");
	}

	memset(path, 0, sizeof *path);
}

void path_backbone_udp_start(meshlink_handle_t *mesh, node_t *bb) {
	if(!mesh || !bb) {
		return;
	}

	if(mesh->backbone_udp.node && mesh->backbone_udp.node != bb) {
		path_backbone_udp_stop(mesh);
	}

	mesh->backbone_udp.node = bb;

	if(!mesh->backbone_udp.timer.cb) {
		path_backbone_udp_arm(mesh, 0, 0);
	}
}

void path_backbone_udp_reset(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || n != mesh->backbone_udp.node) {
		return;
	}

	mesh->backbone_udp.confirmed = false;
	memset(&mesh->backbone_udp.confirmed_at, 0, sizeof mesh->backbone_udp.confirmed_at);
	mesh->backbone_udp.liveness_nonce = 0;
	mesh->backbone_udp.unanswered = 0;
	mesh->backbone_udp.establish_step = 0;

	if(mesh->backbone_udp.timer.cb) {
		path_backbone_udp_arm(mesh, 0, 0);
	}
}

void path_backbone_udp_note_direct(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	backbone_udp_path_t *p;

	if(!mesh || !n || n != mesh->backbone_udp.node || mesh->backbone_udp.confirmed) {
		return;
	}

	p = &mesh->backbone_udp;

	if(!path_backbone_udp_accept_dest(n, sa, src, cap, p)) {
		return;
	}

	if(p->endpoint.sa.sa_family && p->endpoint.sa.sa_family != AF_UNKNOWN
	                && !sockaddrcmp(&p->endpoint, sa)) {
		return;
	}

	if(!p->establish_step && p->liveness_nonce) {
		return;
	}

	p->establish_step = 0;

	if(p->timer.cb) {
		path_backbone_udp_arm(mesh, 0, 0);
	}
}

void path_backbone_udp_observe_reply(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce, const sockaddr_t *observed) {
	backbone_udp_path_t *p;

	if(!mesh || !n || n != mesh->backbone_udp.node || !from || !nonce || n->devtool_force_meta) {
		return;
	}

	p = &mesh->backbone_udp;

	if(!p->liveness_nonce || nonce != p->liveness_nonce || sockaddrcmp(from, &p->endpoint)) {
		return;
	}

	p->unanswered = 0;
	p->liveness_nonce = 0;
	p->last_authenticated_reply = mesh->loop.now;
	update_node_udp_from(mesh, n, &p->endpoint, p->source);

	if(!p->confirmed) {
		p->confirmed = true;
		p->confirmed_at = mesh->loop.now;
		p->establish_step = 0;
		n->status.udp_confirmed = true;

		if(n->address.sa.sa_family != AF_UNSPEC) {
			node_add_recent_address_cap(mesh, n, &n->address, p->source, PATH_CAP_UDP);
		}

		path_note_udp_confirmed(mesh, n);
		logger(mesh, MESHLINK_INFO, "Backbone UDP mapping to %s confirmed", n->name);
	}

	if(observed) {
		path_keepalive_observe_local_endpoint(mesh, n, from, observed);
	}
	path_backbone_udp_arm_keepalive(mesh);
}
