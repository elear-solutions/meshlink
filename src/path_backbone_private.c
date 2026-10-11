/*
    path_backbone_private.c -- authenticated backbone private endpoints
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "connection.h"
#include "connection_policy.h"
#include "crypto.h"
#include "local_network.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "net_upgrade.h"
#include "netutl.h"
#include "node.h"
#include "path_backbone_private.h"
#include "path_policy.h"
#include "protocol.h"
#include "xalloc.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static bool timespec_due(const struct timespec *now, const struct timespec *when) {
	if(!when->tv_sec && !when->tv_nsec) {
		return true;
	}

	if(now->tv_sec != when->tv_sec) {
		return now->tv_sec > when->tv_sec;
	}

	return now->tv_nsec >= when->tv_nsec;
}

static struct timespec ahead(const struct timespec *now, int sec) {
	struct timespec t = *now;

	if(sec < 1) {
		sec = 1;
	}

	t.tv_sec += sec;
	return t;
}

static const int query_ladder[] = {1, 2, 5, 10, 30, 120};

static uint8_t ladder_last(void) {
	return (uint8_t)(sizeof query_ladder / sizeof query_ladder[0] - 1);
}

static int ladder_base(uint8_t step) {
	if(step >= sizeof query_ladder / sizeof query_ladder[0]) {
		step = ladder_last();
	}

	return query_ladder[step];
}

static int ladder_delay(meshlink_handle_t *mesh, uint8_t step) {
	int base = ladder_base(step);
	unsigned pct = 80 + (unsigned)prng(mesh, 41);
	int delay = base * (int)pct / 100;

	return delay > 0 ? delay : 1;
}

static bool set_expired(const meshlink_handle_t *mesh) {
	const backbone_private_t *p = &mesh->bb_private;

	if(!p->expires_at.tv_sec && !p->expires_at.tv_nsec) {
		return p->count == 0 && !p->empty;
	}

	return timespec_due(&mesh->loop.now, &p->expires_at);
}

static bool direct_from_node(const connection_t *c, const node_t *from) {
	return c && from && from->connection == c && c->node == from;
}

static void remember_state(bb_private_endpoint_t *dst, const bb_private_endpoint_t *src) {
	dst->meta_state = src->meta_state;
	dst->udp_state = src->udp_state;
	dst->meta_failures = src->meta_failures;
	dst->udp_failures = src->udp_failures;
	dst->meta_retry_at = src->meta_retry_at;
	dst->udp_retry_at = src->udp_retry_at;
}

static bool private_udp_up(const meshlink_handle_t *mesh, const node_t *n) {
	return n == mesh->backbone_udp.node
	       && mesh->backbone_udp.confirmed
	       && mesh->backbone_udp.source == ADDR_SRC_BACKBONE_PRIVATE
	       && path_backbone_private_vouches(mesh, n, &mesh->backbone_udp.endpoint);
}

static bool private_meta_up(const meshlink_handle_t *mesh, const node_t *n) {
	return n && n->connection && n->connection->status.active && n->connection->status.private_carrier
	       && path_backbone_private_vouches(mesh, n, &n->connection->address);
}

static bool bind_is_wildcard(const sockaddr_t *sa) {
	if(!sa) {
		return false;
	}

	if(sa->sa.sa_family == AF_INET) {
		return sa->in.sin_addr.s_addr == INADDR_ANY;
	}

	if(sa->sa.sa_family == AF_INET6) {
		return IN6_IS_ADDR_UNSPECIFIED(&sa->in6.sin6_addr);
	}

	return false;
}

static uint64_t publish_hash(const bb_private_endpoint_t *eps, size_t count) {
	uint64_t h = 1469598103934665603ULL;
	size_t i;
	const uint8_t *b;
	size_t n;

	for(i = 0; i < count; i++) {
		b = (const uint8_t *)&eps[i].sa;
		n = sizeof eps[i].sa;

		while(n--) {
			h ^= *b++;
			h *= 1099511628211ULL;
		}

		h ^= eps[i].cap;
		h *= 1099511628211ULL;
	}

	return h;
}

static void publish_notify(meshlink_handle_t *mesh) {
	if(!mesh->connections || !mesh->self) {
		return;
	}

	for list_each(connection_t, c, mesh->connections) {
		if(!c->status.bb_private_queried || !c->node || !c->status.active) {
			continue;
		}

		if(c->protocol_minor < PROT_MINOR_BACKBONE_PRIVATE) {
			continue;
		}

		send_request(mesh, c, NULL, "%d %s %s %d %" PRIu32 " %" PRIu32,
		             REQ_KEY, mesh->self->name, c->node->name, REQ_BACKBONE_PRIVATE_CHANGED,
		             mesh->self->session_id, mesh->bb_private.publish_revision);
	}
}

static size_t publish_collect(meshlink_handle_t *mesh, bb_private_endpoint_t *out, size_t max) {
	size_t n = 0;
	int i;

	for(i = 0; i < mesh->listen_sockets && n < max; i++) {
		listen_socket_t *ls = &mesh->listen_socket[i];
		path_cap_t cap = PATH_CAP_NONE;
		sockaddr_t addrs[BB_PRIVATE_MAX];
		size_t found;
		size_t a;
		uint16_t port;

		if(ls->tcp.cb && ls->tcp.fd >= 0) {
			cap |= PATH_CAP_META;
		}

		if(ls->udp.cb && ls->udp.fd >= 0) {
			cap |= PATH_CAP_UDP;
		}

		if(!cap) {
			continue;
		}

		port = ls->sa.sa.sa_family == AF_INET6 ? ls->sa.in6.sin6_port : ls->sa.in.sin_port;
		found = local_network_private_publishable(mesh, ls->sa.sa.sa_family, addrs, BB_PRIVATE_MAX);

		for(a = 0; a < found && n < max; a++) {
			size_t k;
			bool dup = false;

			if(!bind_is_wildcard(&ls->sa) && sockaddrcmp_noport(&ls->sa, &addrs[a])) {
				continue;
			}

			if(ls->sa.sa.sa_family == AF_INET) {
				addrs[a].in.sin_port = port;
			} else {
				addrs[a].in6.sin6_port = port;
			}

			for(k = 0; k < n; k++) {
				if(!sockaddrcmp(&out[k].sa, &addrs[a])) {
					out[k].cap |= cap;
					dup = true;
					break;
				}
			}

			if(dup) {
				continue;
			}

			memset(&out[n], 0, sizeof out[n]);
			out[n].sa = addrs[a];
			out[n].cap = cap;
			n++;
		}
	}

	return n;
}

void path_backbone_private_publish_refresh(meshlink_handle_t *mesh) {
	bb_private_endpoint_t next[BB_PRIVATE_MAX];
	size_t count;
	uint64_t hash;

	if(!mesh || !mesh->self || !connection_policy_is_backbone(mesh, mesh->self)) {
		return;
	}

	count = publish_collect(mesh, next, BB_PRIVATE_MAX);
	hash = publish_hash(next, count);

	if(hash == mesh->bb_private.publish_hash && mesh->bb_private.publish_revision) {
		return;
	}

	mesh->bb_private.publish_hash = hash;
	mesh->bb_private.publish_revision++;

	if(!mesh->bb_private.publish_revision) {
		mesh->bb_private.publish_revision = 1;
	}

	publish_notify(mesh);
}

bool path_backbone_private_knows(const meshlink_handle_t *mesh, const sockaddr_t *sa) {
	size_t i;

	if(!mesh || !sa) {
		return false;
	}

	for(i = 0; i < mesh->bb_private.count; i++) {
		if(!sockaddrcmp(&mesh->bb_private.endpoints[i].sa, sa)) {
			return true;
		}
	}

	return false;
}

bool path_backbone_private_vouches(const meshlink_handle_t *mesh, const node_t *n, const sockaddr_t *sa) {
	size_t i;

	if(!mesh || !n || !sa || !connection_policy_is_backbone(mesh, n)) {
		return false;
	}

	if(!mesh->bb_private.session_id || mesh->bb_private.session_id != n->session_id) {
		return false;
	}

	if(mesh->bb_private.network_epoch != (uint32_t)mesh->lan_network_epoch) {
		return false;
	}

	if(set_expired(mesh)) {
		return false;
	}

	for(i = 0; i < mesh->bb_private.count; i++) {
		if(!sockaddrcmp(&mesh->bb_private.endpoints[i].sa, sa)) {
			return true;
		}
	}

	return false;
}

bool path_backbone_private_has_unproven_meta(const meshlink_handle_t *mesh, const node_t *n) {
	size_t i;

	if(!mesh || !n) {
		return false;
	}

	for(i = 0; i < mesh->bb_private.count; i++) {
		const bb_private_endpoint_t *e = &mesh->bb_private.endpoints[i];

		if(!(e->cap & PATH_CAP_META) || e->meta_state == BB_EP_PROVEN) {
			continue;
		}

		if(!timespec_due(&mesh->loop.now, &e->meta_retry_at)) {
			continue;
		}

		/* This host already owns the address. Connecting to it is a hairpin
		   onto our own listener, not a remote private path. */
		if(local_network_is_own_address(mesh, &e->sa)) {
			continue;
		}

		if(path_backbone_private_vouches(mesh, n, &e->sa)) {
			return true;
		}
	}

	return false;
}

bool path_backbone_private_pick_meta(meshlink_handle_t *mesh, node_t *n, sockaddr_t *out) {
	size_t i;

	if(!mesh || !n || !out) {
		return false;
	}

	for(i = 0; i < mesh->bb_private.count; i++) {
		bb_private_endpoint_t *e = &mesh->bb_private.endpoints[i];

		if(!(e->cap & PATH_CAP_META) || e->meta_state == BB_EP_PROVEN) {
			continue;
		}

		if(!timespec_due(&mesh->loop.now, &e->meta_retry_at)) {
			continue;
		}

		if(!path_backbone_private_vouches(mesh, n, &e->sa)) {
			continue;
		}

		if(local_network_is_own_address(mesh, &e->sa)) {
			continue;
		}

		if(n->connection && !sockaddrcmp(&n->connection->address, &e->sa)) {
			continue;
		}

		e->meta_state = BB_EP_VALIDATING;
		*out = e->sa;
		return true;
	}

	return false;
}

static bb_private_endpoint_t *find_endpoint(meshlink_handle_t *mesh, const sockaddr_t *sa) {
	size_t i;

	if(!sa) {
		return NULL;
	}

	for(i = 0; i < mesh->bb_private.count; i++) {
		if(!sockaddrcmp(&mesh->bb_private.endpoints[i].sa, sa)) {
			return &mesh->bb_private.endpoints[i];
		}
	}

	return NULL;
}

static int cooldown_sec(uint8_t failures) {
	int sec = BB_PRIVATE_COOLDOWN_MIN;
	uint8_t i;

	for(i = 1; i < failures && sec < BB_PRIVATE_COOLDOWN_MAX; i++) {
		sec *= 2;
	}

	if(sec > BB_PRIVATE_COOLDOWN_MAX) {
		sec = BB_PRIVATE_COOLDOWN_MAX;
	}

	return sec;
}

void path_backbone_private_note_meta_failure(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa) {
	bb_private_endpoint_t *e;

	if(!mesh) {
		return;
	}

	e = find_endpoint(mesh, sa);

	if(e) {
		if(e->meta_failures < 255) {
			e->meta_failures++;
		}

		e->meta_state = BB_EP_FAILED;
		e->meta_retry_at = ahead(&mesh->loop.now, cooldown_sec(e->meta_failures));
	}

	(void)n;
	mesh->bb_private.next_query_at = mesh->loop.now;
	mesh->bb_private.query_id = 0;
}

/* The member is already metaconnected to this vouched listener. Probing it
   again has no second socket to cut over to, and the sweep would retry forever. */
static void note_live_private_meta(meshlink_handle_t *mesh, node_t *n) {
	connection_t *c;
	bb_private_endpoint_t *e;

	if(!mesh || !n) {
		return;
	}

	c = n->connection;

	if(!c || !c->status.active || c->status.private_carrier) {
		return;
	}

	e = find_endpoint(mesh, &c->address);

	if(!e || !(e->cap & PATH_CAP_META) || !path_backbone_private_vouches(mesh, n, &e->sa)) {
		return;
	}

	c->status.private_carrier = true;
	path_backbone_private_note_meta_proven(mesh, n, &e->sa);
}

void path_backbone_private_note_meta_proven(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa) {
	bb_private_endpoint_t *e;

	if(!mesh) {
		return;
	}

	e = find_endpoint(mesh, sa);

	if(e) {
		e->meta_state = BB_EP_PROVEN;
		e->meta_failures = 0;
		memset(&e->meta_retry_at, 0, sizeof e->meta_retry_at);
	}

	mesh->bb_private.ever_proven = true;
	(void)n;
}

bool path_backbone_private_meta_superseded(const meshlink_handle_t *mesh, const node_t *n) {
	const connection_t *c;

	if(!mesh || !n || !connection_policy_is_backbone(mesh, n)) {
		return false;
	}

	c = n->connection;

	return c && c->status.active && c->status.private_carrier
	       && !path_backbone_private_vouches(mesh, n, &c->address);
}

void path_backbone_private_on_session_change(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || !connection_policy_is_backbone(mesh, n)) {
		return;
	}

	memset(&mesh->bb_private, 0, sizeof mesh->bb_private);
	path_backbone_udp_clear_candidate(mesh);
}

/* Ranking already puts proven private carriers first, so PREFER_PRIVATE never
   withholds public. PRIVATE_ONLY allows public data only until this backbone
   session has proven a private carrier: bootstrap and session recovery. */
bool path_backbone_private_public_data_allowed(const meshlink_handle_t *mesh, const node_t *n) {
	if(!mesh || !n || !connection_policy_is_backbone(mesh, n)) {
		return true;
	}

	if(mesh->backbone_path_policy != MESHLINK_BACKBONE_PATH_PRIVATE_ONLY) {
		return true;
	}

	return !mesh->bb_private.ever_proven;
}

bool path_backbone_private_fill_udp(const meshlink_handle_t *mesh, const node_t *n, sockaddr_t *out) {
	if(!mesh || !n || !out || n != mesh->backbone_udp.node) {
		return false;
	}

	if(!mesh->backbone_udp.confirmed || mesh->backbone_udp.source != ADDR_SRC_BACKBONE_PRIVATE) {
		return false;
	}

	if(mesh->backbone_udp.endpoint.sa.sa_family == AF_UNSPEC) {
		return false;
	}

	*out = mesh->backbone_udp.endpoint;
	return true;
}

bool path_backbone_private_fill_meta(const meshlink_handle_t *mesh, const node_t *n) {
	const connection_t *c;

	if(!mesh || !n || !connection_policy_is_backbone(mesh, n)) {
		return false;
	}

	c = n->connection;

	return c && c->status.active && c->status.private_carrier && !path_meta_is_canonical(n, c);
}

static void member_send(meshlink_handle_t *mesh, node_t *bb) {
	uint64_t id;

	if(!bb->connection || bb->connection->protocol_minor < PROT_MINOR_BACKBONE_PRIVATE) {
		return;
	}

	if(!mesh->self) {
		return;
	}

	do {
		randomize(&id, sizeof id);
	} while(!id);

	/* The reply can be handled inside send_request. The id has to be visible first. */
	mesh->bb_private.query_id = id;
	mesh->bb_private.changed_pending = false;

	if(!send_request(mesh, bb->connection, NULL, "%d %s %s %d %" PRIu64,
	                 REQ_KEY, mesh->self->name, bb->name, REQ_BACKBONE_PRIVATE, id)) {
		if(mesh->bb_private.query_id == id) {
			mesh->bb_private.query_id = 0;
		}

		/* The route tick would otherwise send again on the next pass.
		   Wait out this ladder step, and climb it, without keeping an id
		   for a request that never left. */
		if(mesh->bb_private.ladder_step < ladder_last()) {
			mesh->bb_private.ladder_step++;
		}

		mesh->bb_private.query_hold = true;
		mesh->bb_private.next_query_at = ahead(&mesh->loop.now, ladder_delay(mesh, mesh->bb_private.ladder_step));
		logger(mesh, MESHLINK_INFO, "Backbone private query to %s was not sent", bb->name);
		return;
	}

	bb->connection->status.bb_private_asked = true;
	logger(mesh, MESHLINK_INFO, "Backbone private query %" PRIu64 " to %s", id, bb->name);

	if(mesh->bb_private.query_id == id) {
		mesh->bb_private.query_hold = false;
		mesh->bb_private.next_query_at = ahead(&mesh->loop.now, ladder_delay(mesh, mesh->bb_private.ladder_step));
	}
}

static bool set_current(const meshlink_handle_t *mesh, const node_t *n) {
	return !set_expired(mesh)
	       && mesh->bb_private.network_epoch == (uint32_t)mesh->lan_network_epoch
	       && mesh->bb_private.session_id == n->session_id;
}

/* Queries stop while a private carrier is healthy and its set is current. */
static void member_query_tick(meshlink_handle_t *mesh, node_t *n) {
	bool current = set_current(mesh, n);
	/* The backbone pushes CHANGED only on connections that asked. */
	bool asked = n->connection->status.bb_private_asked;

	if(asked && current && !mesh->bb_private.changed_pending && (private_udp_up(mesh, n) || private_meta_up(mesh, n))) {
		mesh->bb_private.query_hold = false;
		return;
	}

	/* A failed write armed this. A stale set still asks at once once it expires. */
	if(mesh->bb_private.query_hold) {
		if(!timespec_due(&mesh->loop.now, &mesh->bb_private.next_query_at)) {
			return;
		}

		mesh->bb_private.query_hold = false;
	}

	/* A new connection asks at once. So does a set from another network or
	   session, which vouches for nothing, unless a query is already out. */
	if(asked && (current || mesh->bb_private.query_id) && !timespec_due(&mesh->loop.now, &mesh->bb_private.next_query_at)) {
		return;
	}

	/* The in-flight query on this connection timed out. */
	if(asked && mesh->bb_private.query_id) {
		if(mesh->bb_private.ladder_step < ladder_last()) {
			mesh->bb_private.ladder_step++;
		}

		mesh->bb_private.query_id = 0;
	}

	if(mesh->bb_private.empty) {
		mesh->bb_private.ladder_step = ladder_last();
	}

	member_send(mesh, n);
}

/* Each transport validates on its own schedule, whatever the other one does.
   PROVEN describes the live carrier; once that carrier is down the endpoint
   has to be proven again, or a transient outage would end private use. */
static void member_validate_tick(meshlink_handle_t *mesh, node_t *n) {
	bool udp_up = private_udp_up(mesh, n);
	bool meta_up = private_meta_up(mesh, n);
	size_t i;

	for(i = 0; i < mesh->bb_private.count; i++) {
		bb_private_endpoint_t *e = &mesh->bb_private.endpoints[i];

		if(!meta_up && e->meta_state == BB_EP_PROVEN) {
			e->meta_state = BB_EP_IDLE;
		}

		if(udp_up) {
			continue;
		}

		if(e->udp_state == BB_EP_PROVEN) {
			e->udp_state = BB_EP_IDLE;
		}

		if((e->cap & PATH_CAP_UDP)
		                && timespec_due(&mesh->loop.now, &e->udp_retry_at)
		                && path_backbone_private_vouches(mesh, n, &e->sa)
		                && !local_network_is_own_address(mesh, &e->sa)) {
			path_backbone_udp_note_private(mesh, n, &e->sa);
		}
	}

	/* A superseded private carrier no longer vouches, so it is not "up" here. */
	if(!meta_up && path_backbone_private_has_unproven_meta(mesh, n)) {
		try_upgrade_probe(mesh, n);
	}
}

void path_backbone_private_tick(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || n == mesh->self || !connection_policy_is_backbone(mesh, n)) {
		return;
	}

	note_live_private_meta(mesh, n);

	if(!n->connection || !n->connection->status.active || !n->status.reachable) {
		return;
	}

	member_query_tick(mesh, n);
	member_validate_tick(mesh, n);
}

bool path_backbone_private_handle_request(meshlink_handle_t *mesh, connection_t *c, node_t *from, const char *request) {
	uint64_t query_id = 0;
	bb_private_endpoint_t eps[BB_PRIVATE_MAX];
	size_t count;
	char line[MAXBUFSIZE];
	size_t used;
	size_t i;
	int wrote;

	(void)request;

	if(!mesh || !c || !from || !direct_from_node(c, from)) {
		return true;
	}

	if(!mesh->self || !connection_policy_is_backbone(mesh, mesh->self)) {
		return true;
	}

	if(c->protocol_minor < PROT_MINOR_BACKBONE_PRIVATE) {
		return true;
	}

	if(sscanf(request, "%*d %*s %*s %*d %" SCNu64, &query_id) != 1 || !query_id) {
		return true;
	}

	if(c->bb_private_reply_at && mesh->loop.now.tv_sec < c->bb_private_reply_at) {
		return true;
	}

	/* Refresh before marking this connection queried. Otherwise the first
	   publish notifies it with CHANGED, which clears the in-flight query
	   before the ANS in the same burst is accepted. */
	path_backbone_private_publish_refresh(mesh);
	c->status.bb_private_queried = true;
	c->bb_private_reply_at = mesh->loop.now.tv_sec + BB_PRIVATE_REPLY_MIN_SEC;
	count = publish_collect(mesh, eps, BB_PRIVATE_MAX);
	logger(mesh, MESHLINK_INFO, "Backbone private reply to %s query %" PRIu64 " endpoints %zu inventory %zu",
	       from->name, query_id, count, mesh->local_network.count);

	wrote = snprintf(line, sizeof line, "%d %s %s %d %" PRIu64 " %" PRIu32 " %" PRIu32 " %d %zu",
	                 REQ_KEY, mesh->self->name, from->name, ANS_BACKBONE_PRIVATE,
	                 query_id, mesh->self->session_id, mesh->bb_private.publish_revision,
	                 BB_PRIVATE_LIFETIME_SEC, count);

	if(wrote < 0 || (size_t)wrote >= sizeof line) {
		return true;
	}

	used = (size_t)wrote;

	for(i = 0; i < count; i++) {
		char *host = NULL;
		char *port = NULL;

		sockaddr2str(&eps[i].sa, &host, &port);

		if(!host || !port) {
			free(host);
			free(port);
			return true;
		}

		wrote = snprintf(line + used, sizeof line - used, " %s %s %u", host, port, (unsigned)eps[i].cap);
		free(host);
		free(port);

		if(wrote < 0 || (size_t)wrote >= sizeof line - used) {
			return true;
		}

		used += (size_t)wrote;
	}

	send_request(mesh, c, NULL, "%s", line);
	return true;
}

bool path_backbone_private_handle_answer(meshlink_handle_t *mesh, connection_t *c, node_t *from, const char *request) {
	uint64_t query_id = 0;
	uint32_t session_id = 0;
	uint32_t revision = 0;
	int lifetime = 0;
	int count = 0;
	int consumed = 0;
	bb_private_endpoint_t next[BB_PRIVATE_MAX];
	bb_private_endpoint_t previous[BB_PRIVATE_MAX];
	size_t previous_count;
	int i;
	const char *cursor;

	if(!mesh || !c || !from || !request || !direct_from_node(c, from)) {
		return true;
	}

	if(!connection_policy_is_backbone(mesh, from) || c != from->connection) {
		return true;
	}

	if(sscanf(request, "%*d %*s %*s %*d %" SCNu64 " %" SCNu32 " %" SCNu32 " %d %d %n",
	                &query_id, &session_id, &revision, &lifetime, &count, &consumed) < 5) {
		return true;
	}

	if(!mesh->bb_private.query_id || query_id != mesh->bb_private.query_id) {
		logger(mesh, MESHLINK_DEBUG, "Backbone private answer from %s dropped: query %" PRIu64 " in-flight %" PRIu64,
		       from->name, query_id, mesh->bb_private.query_id);
		return true;
	}

	logger(mesh, MESHLINK_INFO, "Backbone private answer from %s session %" PRIu32 " revision %" PRIu32 " endpoints %d",
	       from->name, session_id, revision, count);

	if(session_id != from->session_id) {
		return true;
	}

	if(mesh->bb_private.session_id && session_id != mesh->bb_private.session_id) {
		return true;
	}

	if(mesh->bb_private.session_id == session_id && mesh->bb_private.revision && revision < mesh->bb_private.revision) {
		return true;
	}

	if(count < 0 || count > BB_PRIVATE_MAX || lifetime <= 0) {
		return true;
	}

	memset(next, 0, sizeof next);
	cursor = request + consumed;

	for(i = 0; i < count; i++) {
		char host[MAX_STRING_SIZE];
		char port[64];
		unsigned cap = 0;
		int used = 0;
		sockaddr_t sa;

		if(sscanf(cursor, " " MAX_STRING " %63s %u %n", host, port, &cap, &used) < 3 || used <= 0) {
			return true;
		}

		sa = str2sockaddr(host, port);

		if(sa.sa.sa_family == AF_UNSPEC || sa.sa.sa_family == AF_UNKNOWN) {
			return true;
		}

		next[i].sa = sa;
		next[i].cap = (path_cap_t)(cap & PATH_CAP_BOTH);
		cursor += used;
	}

	previous_count = mesh->bb_private.count;
	memcpy(previous, mesh->bb_private.endpoints, sizeof previous);

	for(i = 0; i < count; i++) {
		size_t p;

		for(p = 0; p < previous_count; p++) {
			if(!sockaddrcmp(&previous[p].sa, &next[i].sa)) {
				remember_state(&next[i], &previous[p]);
				break;
			}
		}
	}

	memcpy(mesh->bb_private.endpoints, next, sizeof next);
	mesh->bb_private.count = (size_t)count;
	mesh->bb_private.session_id = session_id;
	mesh->bb_private.revision = revision;
	mesh->bb_private.network_epoch = (uint32_t)mesh->lan_network_epoch;
	mesh->bb_private.expires_at = ahead(&mesh->loop.now, lifetime);
	mesh->bb_private.empty = count == 0;
	mesh->bb_private.query_id = 0;
	mesh->bb_private.changed_pending = false;
	note_live_private_meta(mesh, from);

	if(count == 0) {
		mesh->bb_private.ladder_step = ladder_last();
		mesh->bb_private.next_query_at = ahead(&mesh->loop.now, ladder_base(ladder_last()));
	} else {
		mesh->bb_private.ladder_step = 0;
		mesh->bb_private.next_query_at = mesh->bb_private.expires_at;
	}

	return true;
}

bool path_backbone_private_handle_changed(meshlink_handle_t *mesh, connection_t *c, node_t *from, const char *request) {
	uint32_t session_id = 0;
	uint32_t revision = 0;

	if(!mesh || !c || !from || !direct_from_node(c, from)) {
		return true;
	}

	if(!connection_policy_is_backbone(mesh, from)) {
		return true;
	}

	if(sscanf(request, "%*d %*s %*s %*d %" SCNu32 " %" SCNu32, &session_id, &revision) != 2) {
		return true;
	}

	if(session_id != from->session_id) {
		return true;
	}

	if(mesh->bb_private.session_id == session_id && revision <= mesh->bb_private.revision) {
		return true;
	}

	mesh->bb_private.changed_pending = true;
	mesh->bb_private.query_id = 0;
	memset(&mesh->bb_private.next_query_at, 0, sizeof mesh->bb_private.next_query_at);
	return true;
}

bool path_backbone_private_test_offer(meshlink_handle_t *mesh, connection_t *c, node_t *from, uint64_t query_id, uint32_t session_id, uint32_t revision, int lifetime, const sockaddr_t *sa, path_cap_t cap) {
	char line[MAXBUFSIZE];
	char *host = NULL;
	char *port = NULL;
	const char *from_name = from && from->name ? from->name : "bb";
	const char *self_name = mesh->self ? mesh->self->name : "me";

	if(sa) {
		sockaddr2str(sa, &host, &port);

		if(!host || !port) {
			free(host);
			free(port);
			return false;
		}

		snprintf(line, sizeof line, "%d %s %s %d %" PRIu64 " %" PRIu32 " %" PRIu32 " %d 1 %s %s %u",
		         REQ_KEY, from_name, self_name, ANS_BACKBONE_PRIVATE,
		         query_id, session_id, revision, lifetime, host, port, (unsigned)cap);
	} else {
		snprintf(line, sizeof line, "%d %s %s %d %" PRIu64 " %" PRIu32 " %" PRIu32 " %d 0",
		         REQ_KEY, from_name, self_name, ANS_BACKBONE_PRIVATE,
		         query_id, session_id, revision, lifetime);
	}

	free(host);
	free(port);
	return path_backbone_private_handle_answer(mesh, c, from, line);
}
