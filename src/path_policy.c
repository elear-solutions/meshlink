/*
    path_policy.c -- validated-path ranking and address provenance
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "adns.h"
#include "connection.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "net_upgrade.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "protocol.h"
#include "xalloc.h"

/* source_trust ranks: AUTH_DIRECT is highest, UNKNOWN is legacy-weak, others 0. */
#define SOURCE_TRUST_AUTH_DIRECT 7
#define SOURCE_TRUST_DISCOVERY   6
#define SOURCE_TRUST_EXTERNAL    5
#define SOURCE_TRUST_HINT        4
#define SOURCE_TRUST_EDGE        3
#define SOURCE_TRUST_UNKNOWN     1
#define SOURCE_TRUST_NONE        0

typedef struct canonical_adns_req {
	uint32_t gen;
	char name[];
} canonical_adns_req_t;

static void path_note_canonical_resolve_failed(meshlink_handle_t *mesh, node_t *n);
static void path_on_canonical_resolved(meshlink_handle_t *mesh, node_t *n);

/* Split "host port" into host and port. copy is xstrdup'd; caller frees it. */
static bool split_canonical_address(const char *canonical, char **copy, char **host, char **port) {
	char *space;

	if(!canonical || !copy || !host || !port) {
		return false;
	}

	*copy = xstrdup(canonical);
	space = strchr(*copy, ' ');

	if(!space || !space[1]) {
		free(*copy);
		*copy = NULL;
		return false;
	}

	*space++ = 0;
	*host = *copy;
	*port = space;
	return true;
}

const char *address_source_name(address_source_t src) {
	switch(src) {
	case ADDR_SRC_AUTH_DIRECT:
		return "auth-direct";

	case ADDR_SRC_DISCOVERY:
		return "discovery";

	case ADDR_SRC_HINT:
		return "hint";

	case ADDR_SRC_EXTERNAL:
		return "external";

	case ADDR_SRC_EDGE_DIRECT:
		return "edge-direct";

	case ADDR_SRC_CANONICAL:
		return "canonical";

	case ADDR_SRC_INDIRECT:
		return "indirect";

	case ADDR_SRC_UDP_REFLEXIVE:
		return "udp-reflexive";

	case ADDR_SRC_UNKNOWN:
	default:
		return "unknown";
	}
}

const char *path_tier_name(path_tier_t tier) {
	switch(tier) {
	case PATH_TIER_DIRECT_LOCAL_UDP:
		return "direct-local-udp";

	case PATH_TIER_DIRECT_WAN_UDP:
		return "direct-wan-udp";

	case PATH_TIER_RELAY_UDP:
		return "relay-udp";

	case PATH_TIER_META_DIRECT:
		return "meta-direct";

	case PATH_TIER_META_CANONICAL:
		return "meta-canonical";

	case PATH_TIER_NONE:
	default:
		return "none";
	}
}

const char *meta_dial_tier_name(meta_dial_tier_t tier) {
	return tier == META_DIAL_CANONICAL ? "canonical" : "direct";
}

const char *path_cap_name(path_cap_t cap) {
	switch(cap & PATH_CAP_BOTH) {
	case PATH_CAP_BOTH:
		return "meta+udp";

	case PATH_CAP_META:
		return "meta";

	case PATH_CAP_UDP:
		return "udp";

	default:
		return "none";
	}
}

path_cap_t path_default_cap(address_source_t src) {
	switch(src) {
	case ADDR_SRC_UDP_REFLEXIVE:
	case ADDR_SRC_UNKNOWN:
		return PATH_CAP_UDP;

	case ADDR_SRC_CANONICAL:
	case ADDR_SRC_INDIRECT:
		return PATH_CAP_META;

	default:
		return PATH_CAP_BOTH;
	}
}

void path_copy_sockaddr(sockaddr_t *dst, const sockaddr_t *src) {
	size_t len = 0;

	if(!dst) {
		return;
	}

	memset(dst, 0, sizeof * dst);

	if(!src) {
		return;
	}

	if(src->sa.sa_family == AF_INET) {
		len = sizeof(struct sockaddr_in);
	} else if(src->sa.sa_family == AF_INET6) {
		len = sizeof(struct sockaddr_in6);
	} else {
		return;
	}

	memcpy(dst, src, len);
}

bool path_source_is_direct(address_source_t src) {
	switch(src) {
	case ADDR_SRC_AUTH_DIRECT:
	case ADDR_SRC_DISCOVERY:
	case ADDR_SRC_HINT:
	case ADDR_SRC_EXTERNAL:
	case ADDR_SRC_EDGE_DIRECT:
	case ADDR_SRC_UNKNOWN: /* legacy host config without provenance: still dialable once canonical is known */
		return true;

	default:
		return false;
	}
}

static bool canonical_to_sockaddr(const char *canonical, sockaddr_t *out) {
	char *copy = NULL;
	char *host = NULL;
	char *port = NULL;
	bool ok;

	if(!canonical || !out) {
		return false;
	}

	if(!split_canonical_address(canonical, &copy, &host, &port)) {
		return false;
	}

	ok = host_port_to_sockaddr(host, port, out);
	free(copy);
	return ok;
}

bool path_canonical_is_hostname(const node_t *n) {
	sockaddr_t parsed;

	if(!n || !n->canonical_address || !n->canonical_address[0]) {
		return false;
	}

	return !canonical_to_sockaddr(n->canonical_address, &parsed);
}

bool path_canonical_unresolved(const node_t *n) {
	if(!path_canonical_is_hostname(n)) {
		return false;
	}

	return n->canonical_sa_count == 0;
}

static const sockaddr_t *canonical_at(const node_t *n, int i) {
	if(!n || i < 0 || i >= n->canonical_sa_count || i >= MAX_CANONICAL_SA) {
		return NULL;
	}

	if(i == 0) {
		return &n->canonical_sa;
	}

	return &n->canonical_extra[i - 1];
}

bool path_is_direct_candidate(const node_t *n, const sockaddr_t *sa, address_source_t src) {
	if(!n || !sa || !path_source_is_direct(src)) {
		return false;
	}

	if(path_address_matches_canonical(n, sa)) {
		return false;
	}

	/* HINT/UNKNOWN cannot stand in for a hostname canonical that has not been
	   tried yet (or is still in flight). After a resolve failure, backoff is
	   set and a later application hint is allowed to fall through. AUTH_DIRECT
	   and DISCOVERY stay eligible so a real local peer is not blocked. */
	if((src == ADDR_SRC_UNKNOWN || src == ADDR_SRC_HINT)
	                && path_canonical_is_hostname(n)
	                && n->canonical_sa_count == 0
	                && n->canonical_resolve_backoff == 0) {
		return false;
	}

	/* EDGE_DIRECT + NLB-IP + another port is the hybrid hole. Peer-advertised
	   AUTH/EXTERNAL/DISCOVERY on the same public IP is allowed. */
	if(src == ADDR_SRC_EDGE_DIRECT && path_address_shares_canonical_ip(n, sa)) {
		return false;
	}

	return true;
}

bool path_is_meta_candidate(const node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	if(!(cap & PATH_CAP_META)) {
		return false;
	}

	/* A reflexive slot that later gained META stays eligible; it must not
	   inherit HINT's unresolved-hostname block. INDIRECT/CANONICAL never walk. */
	if(src == ADDR_SRC_UDP_REFLEXIVE) {
		return n && sa && !path_address_matches_canonical(n, sa);
	}

	return path_is_direct_candidate(n, sa, src);
}

bool path_is_udp_candidate(const node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	if(!n || !sa || !(cap & PATH_CAP_UDP)) {
		return false;
	}

	if(src == ADDR_SRC_CANONICAL || src == ADDR_SRC_INDIRECT) {
		return false;
	}

	if(path_address_matches_canonical(n, sa)) {
		return false;
	}

	return true;
}

bool path_tier_better(path_tier_t a, path_tier_t b) {
	return a < b;
}

bool path_address_is_local(const sockaddr_t *sa) {
	if(!sa) {
		return false;
	}

	if(sa->sa.sa_family == AF_INET) {
		const uint32_t a = ntohl(sa->in.sin_addr.s_addr);

		if((a & 0xff000000) == 0x7f000000) {
			return true; /* 127.0.0.0/8 */
		}

		if((a & 0xff000000) == 0x0a000000) {
			return true; /* 10.0.0.0/8 */
		}

		if((a & 0xfff00000) == 0xac100000) {
			return true; /* 172.16.0.0/12 */
		}

		if((a & 0xffff0000) == 0xc0a80000) {
			return true; /* 192.168.0.0/16 */
		}

		if((a & 0xffff0000) == 0xa9fe0000) {
			return true; /* 169.254.0.0/16 */
		}

		return false;
	}

	if(sa->sa.sa_family == AF_INET6) {
		if(IN6_IS_ADDR_LOOPBACK(&sa->in6.sin6_addr) || IN6_IS_ADDR_LINKLOCAL(&sa->in6.sin6_addr) || IN6_IS_ADDR_SITELOCAL(&sa->in6.sin6_addr)) {
			return true;
		}

		/* fc00::/7 unique local */
		if((sa->in6.sin6_addr.s6_addr[0] & 0xfe) == 0xfc) {
			return true;
		}
	}

	return false;
}

path_tier_t path_udp_tier_for(const sockaddr_t *sa, address_source_t src) {
	if(src == ADDR_SRC_DISCOVERY || path_address_is_local(sa)) {
		return PATH_TIER_DIRECT_LOCAL_UDP;
	}

	return PATH_TIER_DIRECT_WAN_UDP;
}

void path_clear_canonical_endpoints(node_t *n) {
	if(!n) {
		return;
	}

	memset(&n->canonical_sa, 0, sizeof n->canonical_sa);
	memset(n->canonical_extra, 0, sizeof n->canonical_extra);
	n->canonical_sa_count = 0;
}

void path_refresh_canonical_endpoint(node_t *n) {
	if(!n) {
		return;
	}

	path_clear_canonical_endpoints(n);

	if(canonical_to_sockaddr(n->canonical_address, &n->canonical_sa)) {
		n->canonical_sa_count = 1;
	}
}

bool path_assign_canonical_address(node_t *n, char *canonical_address) {
	if(!n) {
		free(canonical_address);
		return false;
	}

	if(n->canonical_address && canonical_address && !strcmp(n->canonical_address, canonical_address)) {
		free(canonical_address);
		return false;
	}

	free(n->canonical_address);
	n->canonical_address = canonical_address;
	path_reset_canonical_resolve(n);
	path_refresh_canonical_endpoint(n);
	return true;
}

void path_set_canonical_sockaddr(node_t *n, const sockaddr_t *sa) {
	if(!n || !sa) {
		return;
	}

	path_clear_canonical_endpoints(n);
	path_copy_sockaddr(&n->canonical_sa, sa);

	if(n->canonical_sa.sa.sa_family == AF_INET || n->canonical_sa.sa.sa_family == AF_INET6) {
		n->canonical_sa_count = 1;
	}
}

bool path_add_canonical_endpoint(node_t *n, const sockaddr_t *sa) {
	sockaddr_t copy;

	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	if(path_address_matches_canonical(n, sa)) {
		return false;
	}

	path_copy_sockaddr(&copy, sa);

	if(copy.sa.sa_family != AF_INET && copy.sa.sa_family != AF_INET6) {
		return false;
	}

	if(n->canonical_sa_count >= MAX_CANONICAL_SA) {
		return false;
	}

	if(n->canonical_sa_count == 0) {
		n->canonical_sa = copy;
		n->canonical_sa_count = 1;
		return true;
	}

	n->canonical_extra[n->canonical_sa_count - 1] = copy;
	n->canonical_sa_count++;
	return true;
}

bool path_address_matches_canonical(const node_t *n, const sockaddr_t *sa) {
	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	for(int i = 0; i < n->canonical_sa_count; i++) {
		const sockaddr_t *canon = canonical_at(n, i);

		if(canon && !sockaddrcmp(sa, canon)) {
			return true;
		}
	}

	sockaddr_t parsed;

	if(n->canonical_address && canonical_to_sockaddr(n->canonical_address, &parsed) && !sockaddrcmp(sa, &parsed)) {
		return true;
	}

	return false;
}

bool path_address_shares_canonical_ip(const node_t *n, const sockaddr_t *sa) {
	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	for(int i = 0; i < n->canonical_sa_count; i++) {
		const sockaddr_t *canon = canonical_at(n, i);

		if(canon && !sockaddrcmp_noport(sa, canon)) {
			return true;
		}
	}

	sockaddr_t parsed;

	if(n->canonical_address && canonical_to_sockaddr(n->canonical_address, &parsed) && !sockaddrcmp_noport(sa, &parsed)) {
		return true;
	}

	return false;
}

bool path_canonical_host_matches(const node_t *n, const char *host, const char *serv) {
	char *copy = NULL;
	char *canon_host = NULL;
	char *canon_port = NULL;
	bool ok = false;

	if(!n || !n->canonical_address || !host || !serv) {
		return false;
	}

	if(!split_canonical_address(n->canonical_address, &copy, &canon_host, &canon_port)) {
		return false;
	}

	ok = !strcmp(canon_host, host) && !strcmp(canon_port, serv);
	free(copy);
	return ok;
}

static void path_apply_canonical_resolution(node_t *n, const struct addrinfo *ai) {
	if(!n) {
		return;
	}

	path_clear_canonical_endpoints(n);

	for(const struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
		if(!aip->ai_addr) {
			continue;
		}

		path_add_canonical_endpoint(n, (const sockaddr_t *)aip->ai_addr);
	}
}

struct addrinfo *path_canonical_addrinfo(const node_t *n) {
	struct addrinfo *ai = NULL;
	struct addrinfo *tail = NULL;

	if(!n) {
		return NULL;
	}

	for(int i = 0; i < n->canonical_sa_count; i++) {
		const sockaddr_t *sa = canonical_at(n, i);
		struct addrinfo *nai = sockaddr_to_stream_addrinfo(sa);

		if(!nai) {
			continue;
		}

		if(!ai) {
			ai = nai;
		} else {
			tail->ai_next = nai;
		}

		tail = nai;
	}

	return ai;
}

static void canonical_resolve_cb(meshlink_handle_t *mesh, char *host, char *serv, void *data, struct addrinfo *ai, int err) {
	canonical_adns_req_t *req = data;
	node_t *n = lookup_node(mesh, req->name);
	bool match;
	bool usable;

	if(!n || n->canonical_resolve_gen != req->gen) {
		if(ai) {
			freeaddrinfo(ai);
		}

		free(host);
		free(serv);

		if(n && !n->canonical_resolve_pending) {
			outgoing_on_canonical_reset(mesh, n);
		}

		free(req);
		return;
	}

	match = path_canonical_host_matches(n, host, serv);
	usable = match && ai && ai->ai_addr;

	n->canonical_resolve_pending = false;

	if(usable) {
		path_apply_canonical_resolution(n, ai);
		n->canonical_resolve_backoff = 0;
		n->canonical_resolve_next = 0;
		path_on_canonical_resolved(mesh, n);
	} else if(match) {
		path_note_canonical_resolve_failed(mesh, n);
	}

	outgoing_on_canonical_resolved(mesh, n, ai, err, usable, host, serv);
	free(req);
}

void path_reset_canonical_resolve(node_t *n) {
	if(!n) {
		return;
	}

	n->canonical_resolve_gen = 0;
	n->canonical_resolve_pending = false;
	n->canonical_resolve_backoff = 0;
	n->canonical_resolve_next = 0;
}

void path_request_canonical_resolve(meshlink_handle_t *mesh, node_t *n) {
	canonical_adns_req_t *req;
	char *copy = NULL;
	char *host = NULL;
	char *port = NULL;
	size_t namelen;

	if(!mesh || !n || !n->name || !path_canonical_is_hostname(n)) {
		return;
	}

	if(n->canonical_resolve_pending) {
		return;
	}

	if(!mesh->adns_signal.cb) {
		return;
	}

	if(n->canonical_resolve_next && mesh->loop.now.tv_sec < n->canonical_resolve_next) {
		return;
	}

	if(!split_canonical_address(n->canonical_address, &copy, &host, &port)) {
		return;
	}

	namelen = strlen(n->name) + 1;
	req = xzalloc(sizeof(*req) + namelen);
	memcpy(req->name, n->name, namelen);
	req->gen = ++mesh->canonical_resolve_seq;

	if(!req->gen) {
		req->gen = ++mesh->canonical_resolve_seq;
	}

	n->canonical_resolve_gen = req->gen;
	n->canonical_resolve_pending = true;
	adns_queue(mesh, xstrdup(host), xstrdup(port), canonical_resolve_cb, req, CANONICAL_RESOLVE_TIMEOUT);
	free(copy);
}

static void path_note_canonical_resolve_failed(meshlink_handle_t *mesh, node_t *n) {
	if(!n) {
		return;
	}

	if(n->canonical_resolve_backoff) {
		n->canonical_resolve_backoff *= 2;

		if(n->canonical_resolve_backoff > CANONICAL_RESOLVE_BACKOFF_MAX) {
			n->canonical_resolve_backoff = CANONICAL_RESOLVE_BACKOFF_MAX;
		}
	} else {
		n->canonical_resolve_backoff = CANONICAL_RESOLVE_BACKOFF_MIN;
	}

	if(mesh) {
		n->canonical_resolve_next = mesh->loop.now.tv_sec + n->canonical_resolve_backoff;
		logger(mesh, MESHLINK_WARNING, "Canonical resolve for %s failed; next try in %d seconds", n->name, n->canonical_resolve_backoff);
	}
}

void path_persist_node(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || !n->status.dirty) {
		return;
	}

	if(!node_write_config(mesh, n, false)) {
		logger(mesh, MESHLINK_DEBUG, "Could not persist path policy state for %s", n->name);
	}
}

void path_reclassify_active_meta(meshlink_handle_t *mesh, node_t *n) {
	connection_t *c;

	if(!mesh || !n || !(c = n->connection) || !c->status.active) {
		return;
	}

	if(path_address_matches_canonical(n, &c->address)) {
		if(!c->status.via_canonical) {
			path_mark_meta_dial(c, true);
			path_log_meta(mesh, n, &c->address, "reclassified canonical");
		}

		if(c->edge && !(c->edge->options & OPTION_INDIRECT)) {
			c->edge->options |= OPTION_INDIRECT;
			send_add_edge(mesh, mesh->everyone, c->edge, 0);
			graph(mesh);
		}

		return;
	}

	if(!path_canonical_unresolved(n) && !path_meta_is_canonical(n, c)) {
		path_learn_address_cap(mesh, n, &c->address, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH);
	}
}

static void path_on_canonical_resolved(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	path_sanitize_recent(mesh, n);
	path_reclassify_active_meta(mesh, n);
	path_persist_node(mesh, n);
	try_upgrade_probe(mesh, n);
}

void path_migrate_legacy_caps(node_t *n) {
	if(!n) {
		return;
	}

	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(n->recent_cap[i]) {
			continue;
		}

		switch(n->recent_source[i]) {
		case ADDR_SRC_AUTH_DIRECT:
		case ADDR_SRC_DISCOVERY:
		case ADDR_SRC_HINT:
		case ADDR_SRC_EXTERNAL:
		case ADDR_SRC_EDGE_DIRECT:
			n->recent_cap[i] = PATH_CAP_BOTH;
			break;

		default:
			n->recent_cap[i] = PATH_CAP_UDP;
			break;
		}
	}
}

static int source_trust(address_source_t src) {
	switch(src) {
	case ADDR_SRC_AUTH_DIRECT:
		return SOURCE_TRUST_AUTH_DIRECT;

	case ADDR_SRC_UDP_REFLEXIVE:
		return SOURCE_TRUST_UNKNOWN;

	case ADDR_SRC_DISCOVERY:
		return SOURCE_TRUST_DISCOVERY;

	case ADDR_SRC_EXTERNAL:
		return SOURCE_TRUST_EXTERNAL;

	case ADDR_SRC_HINT:
		return SOURCE_TRUST_HINT;

	case ADDR_SRC_EDGE_DIRECT:
		return SOURCE_TRUST_EDGE;

	case ADDR_SRC_UNKNOWN:
		return SOURCE_TRUST_UNKNOWN;

	default:
		return SOURCE_TRUST_NONE;
	}
}

static int recent_count(const node_t *n) {
	int i;

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
	}

	return i;
}

static bool reject_canonical(meshlink_handle_t *mesh, const node_t *n, const sockaddr_t *sa, address_source_t src) {
	if(!path_address_matches_canonical(n, sa) && src != ADDR_SRC_CANONICAL) {
		return false;
	}

	path_log_candidate(mesh, n, sa, src, PATH_CAP_NONE, "rejected canonical");
	return true;
}

static void recent_store_front(node_t *n, int i, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	address_source_t keep = src;
	path_cap_t keep_cap = cap;

	if(i >= 0) {
		if(source_trust(n->recent_source[i]) >= source_trust(src)) {
			keep = n->recent_source[i];
		}

		keep_cap = (path_cap_t)(n->recent_cap[i] | cap);
	}

	if(i < 0) {
		i = recent_count(n);

		if(i >= MAX_RECENT) {
			i = MAX_RECENT - 1;
		}
	}

	if(i > 0) {
		memmove(n->recent + 1, n->recent, (size_t)i * sizeof(*n->recent));
		memmove(n->recent_source + 1, n->recent_source, (size_t)i * sizeof(*n->recent_source));
		memmove(n->recent_cap + 1, n->recent_cap, (size_t)i * sizeof(*n->recent_cap));
	}

	memcpy(n->recent, sa, SALEN(sa->sa));
	n->recent_source[0] = keep;
	n->recent_cap[0] = keep_cap;
	n->status.dirty = true;
}

bool path_learn_address_cap(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	if(src == ADDR_SRC_INDIRECT || reject_canonical(mesh, n, sa, src)) {
		return false;
	}

	int i;

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], sa)) {
			path_cap_t merged = (path_cap_t)(n->recent_cap[i] | cap);

			if(i == 0 && source_trust(src) <= source_trust(n->recent_source[0]) && merged == n->recent_cap[0]) {
				return false;
			}

			recent_store_front(n, i, sa, src, cap);
			path_log_candidate(mesh, n, sa, n->recent_source[0], n->recent_cap[0], "updated");
			return true;
		}
	}

	recent_store_front(n, -1, sa, src, cap);
	path_log_candidate(mesh, n, sa, src, cap, "learned");
	return true;
}

bool path_learn_address(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src) {
	return path_learn_address_cap(mesh, n, sa, src, path_default_cap(src));
}

bool path_learn_address_fallback_cap(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	if(reject_canonical(mesh, n, sa, src)) {
		return false;
	}

	int i;

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], sa)) {
			path_cap_t merged = (path_cap_t)(n->recent_cap[i] | cap);
			bool changed = false;

			if(source_trust(src) > source_trust(n->recent_source[i])) {
				n->recent_source[i] = src;
				changed = true;
			}

			if(merged != n->recent_cap[i]) {
				n->recent_cap[i] = merged;
				changed = true;
			}

			if(changed) {
				n->status.dirty = true;
			}

			return changed;
		}
	}

	if(i == 0 || i >= MAX_RECENT) {
		return false;
	}

	memcpy(&n->recent[i], sa, SALEN(sa->sa));
	n->recent_source[i] = src;
	n->recent_cap[i] = cap;
	n->status.dirty = true;
	path_log_candidate(mesh, n, sa, src, cap, "fallback");
	return true;
}

bool path_learn_address_fallback(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src) {
	return path_learn_address_fallback_cap(mesh, n, sa, src, path_default_cap(src));
}

void path_clear_recent(node_t *n) {
	if(!n) {
		return;
	}

	memset(n->recent, 0, sizeof n->recent);
	memset(n->recent_source, 0, sizeof n->recent_source);
	memset(n->recent_cap, 0, sizeof n->recent_cap);
	n->status.dirty = true;
}

void path_plant_recent(node_t *n, const sockaddr_t *sa) {
	int i;

	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return;
	}

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], sa)) {
			recent_store_front(n, i, sa, ADDR_SRC_UNKNOWN, PATH_CAP_UDP);
			n->recent_source[0] = ADDR_SRC_UNKNOWN;
			n->recent_cap[0] = PATH_CAP_UDP;
			return;
		}
	}

	recent_store_front(n, -1, sa, ADDR_SRC_UNKNOWN, PATH_CAP_UDP);
	n->recent_source[0] = ADDR_SRC_UNKNOWN;
	n->recent_cap[0] = PATH_CAP_UDP;
}

bool path_sanitize_recent(meshlink_handle_t *mesh, node_t *n) {
	if(!n) {
		return false;
	}

	if(n->canonical_sa_count == 0) {
		path_refresh_canonical_endpoint(n);
	}

	bool changed = false;
	sockaddr_t kept[MAX_RECENT];
	address_source_t kept_src[MAX_RECENT];
	path_cap_t kept_cap[MAX_RECENT];
	int out = 0;

	memset(kept, 0, sizeof kept);
	memset(kept_src, 0, sizeof kept_src);
	memset(kept_cap, 0, sizeof kept_cap);

	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(path_address_matches_canonical(n, &n->recent[i]) || n->recent_source[i] == ADDR_SRC_CANONICAL) {
			path_log_candidate(mesh, n, &n->recent[i], n->recent_source[i], n->recent_cap[i], "sanitized");
			changed = true;
			continue;
		}

		kept[out] = n->recent[i];
		kept_src[out] = n->recent_source[i];
		kept_cap[out] = n->recent_cap[i];
		out++;
	}

	if(changed) {
		memcpy(n->recent, kept, sizeof kept);
		memcpy(n->recent_source, kept_src, sizeof kept_src);
		memcpy(n->recent_cap, kept_cap, sizeof kept_cap);
		n->status.dirty = true;
	}

	return changed;
}

bool path_best_direct_meta(const node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out) {
	if(!n || !out) {
		return false;
	}

	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!path_is_meta_candidate(n, &n->recent[i], n->recent_source[i], n->recent_cap[i])) {
			continue;
		}

		if(skip && !sockaddrcmp(&n->recent[i], skip)) {
			continue;
		}

		path_copy_sockaddr(out, &n->recent[i]);

		if(src_out) {
			*src_out = n->recent_source[i];
		}

		return true;
	}

	return false;
}

bool path_has_direct_meta_candidate(const node_t *n, const sockaddr_t *skip) {
	sockaddr_t sa;
	return path_best_direct_meta(n, skip, &sa, NULL);
}

bool path_meta_is_canonical(const node_t *n, const connection_t *c) {
	if(!c) {
		return false;
	}

	if(c->status.via_canonical) {
		return true;
	}

	return n && path_address_matches_canonical(n, &c->address);
}

void path_mark_meta_dial(connection_t *c, bool canonical) {
	if(!c) {
		return;
	}

	c->status.via_canonical = canonical;
	c->status.meta_dial_tier = canonical ? META_DIAL_CANONICAL : META_DIAL_DIRECT;
}

const char *path_upgrade_ineligible_reason(meshlink_handle_t *mesh, const node_t *n) {
	const connection_t *c;

	if(!n) {
		return "no-node";
	}

	c = n->connection;

	if(!c || !c->status.active) {
		return "no-active-meta";
	}

	if(!c->outgoing) {
		return "not-initiator";
	}

	if(!path_meta_is_canonical(n, c)) {
		return "already-direct";
	}

	if(n->upgrade_probe) {
		return "probe-in-flight";
	}

	if(n->status.blacklisted) {
		return "blacklisted";
	}

	if(!path_has_direct_meta_candidate(n, &c->address)) {
		return "no-direct-candidate";
	}

	if(mesh && mesh->loop.now.tv_sec < n->upgrade_next_try) {
		return "backoff";
	}

	return NULL;
}

static bool hop_udp_ready(const node_t *hop) {
	return hop && hop->status.udp_confirmed && hop->status.validkey && !hop->status.temp_udp_confirmed;
}

path_tier_t path_select_hop_tier(const node_t *hop, bool meta_in) {
	if(!hop) {
		return PATH_TIER_NONE;
	}

	if(!meta_in && hop_udp_ready(hop)) {
		return PATH_TIER_RELAY_UDP;
	}

	if(!hop->connection || !hop->connection->status.active) {
		return PATH_TIER_NONE;
	}

	if(path_meta_is_canonical(hop, hop->connection)) {
		return PATH_TIER_META_CANONICAL;
	}

	return PATH_TIER_META_DIRECT;
}

path_tier_t path_select_destination_tier(const node_t *dest, bool meta_in) {
	if(!dest) {
		return PATH_TIER_NONE;
	}

	if(!meta_in && hop_udp_ready(dest)) {
		return dest->udp_tier == PATH_TIER_DIRECT_LOCAL_UDP ? PATH_TIER_DIRECT_LOCAL_UDP : PATH_TIER_DIRECT_WAN_UDP;
	}

	if(dest->nexthop && dest->nexthop != dest) {
		return path_select_hop_tier(dest->nexthop, meta_in);
	}

	return path_select_hop_tier(dest, meta_in);
}

bool path_udp_should_probe_local(meshlink_handle_t *mesh, const node_t *n, sockaddr_t *out) {
	sockaddr_t sa;
	sockaddr_t *dest = out ? out : &sa;

	if(!mesh || !n || !n->status.udp_confirmed || n->udp_tier != PATH_TIER_DIRECT_WAN_UDP) {
		return false;
	}

	if(mesh->loop.now.tv_sec < n->udp_local_probe_next) {
		return false;
	}

	return path_pick_local_udp_candidate(mesh, n, dest);
}

void path_schedule_local_udp_probe(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	n->udp_local_probe_next = mesh->loop.now.tv_sec + UDP_LOCAL_PROBE_SEC;
}

bool path_pick_local_udp_candidate(meshlink_handle_t *mesh, const node_t *n, sockaddr_t *out) {
	(void)mesh;

	if(!n || !out) {
		return false;
	}

	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!path_is_udp_candidate(n, &n->recent[i], n->recent_source[i], n->recent_cap[i])) {
			continue;
		}

		if(!path_is_direct_candidate(n, &n->recent[i], n->recent_source[i]) && n->recent_source[i] != ADDR_SRC_UDP_REFLEXIVE) {
			continue;
		}

		if(n->address.sa.sa_family != AF_UNSPEC && !sockaddrcmp(&n->recent[i], &n->address)) {
			continue;
		}

		if(path_udp_tier_for(&n->recent[i], n->recent_source[i]) != PATH_TIER_DIRECT_LOCAL_UDP) {
			continue;
		}

		if(!udp_address_bound(&n->recent[i])) {
			continue;
		}

		*out = n->recent[i];
		return true;
	}

	if(n->catta_address.sa.sa_family != AF_UNSPEC && path_address_is_local(&n->catta_address)
	                && (n->address.sa.sa_family == AF_UNSPEC || sockaddrcmp(&n->catta_address, &n->address))) {
		*out = n->catta_address;
		return true;
	}

	return false;
}

void path_note_udp_confirmed(meshlink_handle_t *mesh, node_t *n) {
	if(!n) {
		return;
	}

	address_source_t src = ADDR_SRC_AUTH_DIRECT;

	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], &n->address)) {
			src = n->recent_source[i];
			break;
		}
	}

	path_tier_t was = n->udp_tier;
	n->udp_tier = path_udp_tier_for(&n->address, src);
	n->udp_local_probe_next = 0;

	if(was != n->udp_tier) {
		path_log_transition(mesh, n, was, n->udp_tier, "udp confirmed");
	}
}

void path_note_udp_demoted(meshlink_handle_t *mesh, node_t *n) {
	path_tier_t was;

	if(!n || !n->status.udp_confirmed || n->status.temp_udp_confirmed) {
		return;
	}

	was = n->udp_tier;
	n->status.udp_confirmed = false;
	n->udp_tier = PATH_TIER_NONE;
	n->mtuprobes = 0;
	n->minmtu = 0;
	n->maxmtu = MTU;
	path_log_transition(mesh, n, was, PATH_TIER_NONE, "reliable retransmit");
}

bool path_promote_udp_if_better(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from) {
	if(!n || !from || !n->status.udp_confirmed) {
		return false;
	}

	if(n->address.sa.sa_family != AF_UNSPEC && !sockaddrcmp(from, &n->address)) {
		return false;
	}

	if(path_address_matches_canonical(n, from)) {
		return false;
	}

	path_tier_t next = path_udp_tier_for(from, ADDR_SRC_AUTH_DIRECT);

	if(!path_tier_better(next, n->udp_tier == PATH_TIER_NONE ? PATH_TIER_DIRECT_WAN_UDP : n->udp_tier)
	                && n->udp_tier != PATH_TIER_NONE) {
		return false;
	}

	path_tier_t was = n->udp_tier;
	update_node_udp(mesh, n, from);
	path_learn_address_cap(mesh, n, from, ADDR_SRC_AUTH_DIRECT, path_address_is_local(from) ? PATH_CAP_BOTH : PATH_CAP_UDP);
	n->udp_tier = next;
	path_log_transition(mesh, n, was, next, "local probe reply");
	return true;
}

void path_log_candidate(meshlink_handle_t *mesh, const node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap, const char *action) {
	if(!mesh || !n || mesh->log_level > MESHLINK_INFO) {
		return;
	}

	char *hostname = sa ? sockaddr2hostname(sa) : xstrdup("-");
	logger(mesh, MESHLINK_INFO, "Path candidate: %s %s %s source=%s cap=%s", n->name, action ? action : "", hostname, address_source_name(src), path_cap_name(cap));
	free(hostname);
}

void path_log_validation(meshlink_handle_t *mesh, const node_t *n, const sockaddr_t *sa, const char *action, const char *detail) {
	if(!mesh || !n || mesh->log_level > MESHLINK_INFO) {
		return;
	}

	char *hostname = sa ? sockaddr2hostname(sa) : xstrdup("-");
	logger(mesh, MESHLINK_INFO, "Path validation: %s %s %s%s%s", n->name, action ? action : "", hostname, detail && detail[0] ? " " : "", detail ? detail : "");
	free(hostname);
}

void path_log_meta(meshlink_handle_t *mesh, const node_t *n, const sockaddr_t *sa, const char *action) {
	if(!mesh || !n || mesh->log_level > MESHLINK_INFO) {
		return;
	}

	char *hostname = sa ? sockaddr2hostname(sa) : xstrdup("-");
	logger(mesh, MESHLINK_INFO, "Path META: %s %s %s", n->name, action ? action : "", hostname);
	free(hostname);
}

void path_log_transition(meshlink_handle_t *mesh, const node_t *n, path_tier_t from, path_tier_t to, const char *reason) {
	if(!mesh || !n) {
		return;
	}

	logger(mesh, MESHLINK_INFO, "Path route: %s %s -> %s (%s)", n->name, path_tier_name(from), path_tier_name(to), reason ? reason : "");
}
