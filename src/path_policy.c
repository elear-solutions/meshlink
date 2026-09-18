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
#include "crypto.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "event.h"
#include "net.h"
#include "net_upgrade.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "protocol.h"
#include "splay_tree.h"
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
static uint64_t path_fresh_nonce(void);
static void path_backbone_udp_timer(event_loop_t *loop, void *data);
static void path_backbone_udp_arm(meshlink_handle_t *mesh, int sec, long nsec);

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

	/* Graph-derived NLB-IP + another port is the hybrid hole. Peer-vouched
	   AUTH/EXTERNAL/DISCOVERY/HINT/UDP_REFLEXIVE on the same public IP is allowed. */
	if(path_is_untrusted_hybrid(n, sa, src)) {
		return false;
	}

	return true;
}

bool path_is_untrusted_hybrid(const node_t *n, const sockaddr_t *sa, address_source_t src) {
	if(!n || !sa) {
		return false;
	}

	if(src != ADDR_SRC_EDGE_DIRECT && src != ADDR_SRC_UNKNOWN) {
		return false;
	}

	if(path_address_matches_canonical(n, sa)) {
		return false;
	}

	return path_address_shares_canonical_ip(n, sa);
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

	if(path_is_untrusted_hybrid(n, sa, src)) {
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

	if(path_is_untrusted_hybrid(n, sa, src)) {
		path_log_candidate(mesh, n, sa, src, cap, "rejected hybrid");
		return false;
	}

	int i;
	bool upgraded;

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], sa)) {
			path_cap_t merged = (path_cap_t)(n->recent_cap[i] | cap);

			upgraded = source_trust(src) > source_trust(n->recent_source[i]) || merged != n->recent_cap[i];

			if(i == 0 && !upgraded) {
				return false;
			}

			recent_store_front(n, i, sa, src, cap);
			path_log_candidate(mesh, n, sa, n->recent_source[0], n->recent_cap[0], "updated");

			if((n->recent_cap[0] & PATH_CAP_UDP) && path_address_is_local(sa)) {
				path_consider_promotion(mesh, n, PATH_PROMOTION_DISCOVERY);
			}

			if(upgraded) {
				path_backbone_udp_note_direct(mesh, n, sa, n->recent_source[0], n->recent_cap[0]);
			}

			return true;
		}
	}

	recent_store_front(n, -1, sa, src, cap);
	path_log_candidate(mesh, n, sa, src, cap, "learned");

	if((cap & PATH_CAP_UDP) && path_address_is_local(sa)) {
		path_consider_promotion(mesh, n, PATH_PROMOTION_DISCOVERY);
	}

	path_backbone_udp_note_direct(mesh, n, sa, src, cap);
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

	if(path_is_untrusted_hybrid(n, sa, src)) {
		path_log_candidate(mesh, n, sa, src, cap, "rejected hybrid");
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
		if(path_address_matches_canonical(n, &n->recent[i]) || n->recent_source[i] == ADDR_SRC_CANONICAL
		                || path_is_untrusted_hybrid(n, &n->recent[i], n->recent_source[i])) {
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

static bool path_best_local_meta_from(const node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out, address_source_t want) {
	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		address_source_t src = n->recent_source[i];

		if(src != want) {
			continue;
		}

		if(!path_address_is_local(&n->recent[i])) {
			continue;
		}

		if(!path_is_meta_candidate(n, &n->recent[i], src, n->recent_cap[i])) {
			continue;
		}

		if(skip && !sockaddrcmp(&n->recent[i], skip)) {
			continue;
		}

		path_copy_sockaddr(out, &n->recent[i]);

		if(src_out) {
			*src_out = src;
		}

		return true;
	}

	return false;
}

bool path_best_local_meta(const node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out) {
	if(!n || !out) {
		return false;
	}

	/* Prefer DISCOVERY (listen port) over AUTH_DIRECT (often an inbound
	   ephemeral). Tick/setup must not redial a closed source port. */
	if(path_best_local_meta_from(n, skip, out, src_out, ADDR_SRC_DISCOVERY)) {
		return true;
	}

	return path_best_local_meta_from(n, skip, out, src_out, ADDR_SRC_AUTH_DIRECT);
}

bool path_best_startup_meta(const node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out) {
	if(path_best_direct_meta(n, skip, out, src_out)) {
		return true;
	}

	if(!n || !out || !n->edge_tree) {
		return false;
	}

	for splay_each(edge_t, e, n->edge_tree) {
		const sockaddr_t *sa;

		if(!e->reverse) {
			continue;
		}

		if(e->reverse->options & OPTION_INDIRECT) {
			continue;
		}

		sa = &e->reverse->address;

		if(skip && !sockaddrcmp(sa, skip)) {
			continue;
		}

		if(!path_is_meta_candidate(n, sa, ADDR_SRC_EDGE_DIRECT, PATH_CAP_BOTH)) {
			continue;
		}

		path_copy_sockaddr(out, sa);

		if(src_out) {
			*src_out = ADDR_SRC_EDGE_DIRECT;
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

	if(!meta_in && !dest->status.forced_relay && hop_udp_ready(dest)) {
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
		path_log_udp_tier(mesh, n, was, n->udp_tier, "confirmed");
	}

	path_consider_promotion(mesh, n, PATH_PROMOTION_UDP_CONFIRMED);
}

static void path_defer_demotion(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	if(n->demote_deferred) {
		return;
	}

	n->demote_deferred = true;
	snprintf(n->demote_reason, sizeof n->demote_reason, "%s", reason ? reason : "");

	if(mesh->route_guard_deferred_count < ROUTE_GUARD_DEFERRED_MAX) {
		mesh->route_guard_deferred[mesh->route_guard_deferred_count++] = n;
	} else {
		mesh->route_guard_overflow = true;
	}
}

static void path_apply_deferred_demotion(meshlink_handle_t *mesh, node_t *n) {
	if(!n->demote_deferred) {
		return;
	}

	n->demote_deferred = false;
	path_note_udp_demoted_reason(mesh, n, n->demote_reason);
}

void path_send_guard_enter(meshlink_handle_t *mesh) {
	if(mesh) {
		mesh->route_guard_depth++;
	}
}

void path_send_guard_leave(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->route_guard_depth || --mesh->route_guard_depth) {
		return;
	}

	bool overflow = mesh->route_guard_overflow;
	unsigned count = mesh->route_guard_deferred_count;

	mesh->route_guard_overflow = false;
	mesh->route_guard_deferred_count = 0;

	for(unsigned i = 0; i < count; i++) {
		path_apply_deferred_demotion(mesh, mesh->route_guard_deferred[i]);
	}

	if(overflow) {
		for splay_each(node_t, n, mesh->nodes) {
			path_apply_deferred_demotion(mesh, n);
		}
	}
}

void path_note_udp_demoted_reason(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	path_tier_t was;

	if(!n || !n->status.udp_confirmed || n->status.temp_udp_confirmed) {
		return;
	}

	if(mesh && mesh->route_guard_depth) {
		/* Mid-datagram. Switching carriers now would split this datagram
		   across two paths; the next one gets the new route. */
		path_defer_demotion(mesh, n, reason);
		return;
	}

	was = n->udp_tier;
	n->status.udp_confirmed = false;
	n->udp_tier = PATH_TIER_NONE;
	n->mtuprobes = 0;
	n->minmtu = 0;
	n->maxmtu = MTU;
	path_log_udp_tier(mesh, n, was, PATH_TIER_NONE, reason);
	path_note_selected_route(mesh, n, reason);

	if(mesh && n == mesh->backbone_udp.node) {
		mesh->backbone_udp.confirmed = false;
		mesh->backbone_udp.liveness_nonce = 0;
		mesh->backbone_udp.unanswered = 0;

		if(mesh->backbone_udp.endpoint.sa.sa_family) {
			path_copy_sockaddr(&mesh->backbone_udp.failed_endpoint, &mesh->backbone_udp.endpoint);
		}

		timeout_del(&mesh->loop, &n->mtutimeout);

		if(mesh->backbone_udp.timer.cb) {
			path_backbone_udp_arm(mesh, PATH_BACKBONE_UDP_ESTABLISH_SEC, 0);
		}
	}
}

void path_note_udp_demoted(meshlink_handle_t *mesh, node_t *n) {
	path_note_udp_demoted_reason(mesh, n, "reliable retransmit");
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
	update_node_udp_from(mesh, n, from, ADDR_SRC_AUTH_DIRECT);
	n->udp_tier = next;
	path_learn_address_cap(mesh, n, from, ADDR_SRC_AUTH_DIRECT, path_address_is_local(from) ? PATH_CAP_BOTH : PATH_CAP_UDP);
	path_log_udp_tier(mesh, n, was, next, "local probe reply");
	return true;
}

void path_note_selected_route(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	path_tier_t to;
	path_tier_t from;

	if(!n) {
		return;
	}

	to = path_select_destination_tier(n, false);
	from = n->last_path_tier;

	if(from == to) {
		return;
	}

	n->last_path_tier = to;

	if(!mesh || mesh->log_level > MESHLINK_INFO) {
		return;
	}

	logger(mesh, MESHLINK_INFO, "Path route: %s %s -> %s (%s)", n->name, path_tier_name(from), path_tier_name(to), reason ? reason : "");
}

/* --- one candidate under validation -------------------------------------- */

static int64_t timespec_ms_between(const struct timespec *from, const struct timespec *to) {
	return (int64_t)(to->tv_sec - from->tv_sec) * 1000 + (to->tv_nsec - from->tv_nsec) / 1000000;
}

static const int path_cooldown_ladder[] = {30, 60, 120, 300, 600};

static int path_cooldown_seconds(meshlink_handle_t *mesh, uint8_t failures) {
	size_t steps = sizeof path_cooldown_ladder / sizeof path_cooldown_ladder[0];
	int base = path_cooldown_ladder[failures >= steps ? steps - 1 : failures];
	int span = base / 5;

	/* +/-20% so a mesh-wide event does not make every node retry in lockstep. */
	return base - span + prng(mesh, (uint64_t)(2 * span + 1));
}

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

static void path_backbone_udp_arm(meshlink_handle_t *mesh, int sec, long nsec) {
	struct timespec when;

	when.tv_sec = sec < 0 ? 0 : sec;
	when.tv_nsec = nsec < 0 ? 0 : nsec;

	if(!mesh->backbone_udp.timer.cb) {
		timeout_add(&mesh->loop, &mesh->backbone_udp.timer, path_backbone_udp_timer, mesh, &when);
	} else {
		timeout_set(&mesh->loop, &mesh->backbone_udp.timer, &when);
	}

	if(mesh->datafromapp.cb) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

static void path_backbone_udp_arm_keepalive(meshlink_handle_t *mesh) {
	int base = mesh->backbone_udp_keepalive_sec > 0 ? mesh->backbone_udp_keepalive_sec : PATH_BACKBONE_UDP_KEEPALIVE_SEC;
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

static void path_backbone_udp_send(meshlink_handle_t *mesh) {
	backbone_udp_path_t *p = &mesh->backbone_udp;

	p->liveness_nonce = path_fresh_nonce();
	send_backbone_udp_probe(mesh);
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

	if(!n || !n->status.reachable || !n->status.validkey || n->devtool_force_meta) {
		p->liveness_nonce = 0;
		path_backbone_udp_arm(mesh, path_backbone_udp_next_establish(mesh), 0);
		return;
	}

	if(p->confirmed) {
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
		timeout_del(&mesh->loop, &node->mtutimeout);
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

void path_backbone_udp_observe_reply(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce) {
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
		p->establish_step = 0;
		n->status.udp_confirmed = true;

		if(n->address.sa.sa_family != AF_UNSPEC) {
			node_add_recent_address_cap(mesh, n, &n->address, p->source, PATH_CAP_UDP);
		}

		path_note_udp_confirmed(mesh, n);
		logger(mesh, MESHLINK_INFO, "Backbone UDP mapping to %s confirmed", n->name);

		if(!n->mtutimeout.cb && !n->devtool_force_meta) {
			send_mtu_probe(mesh, n);
		}
	}

	path_backbone_udp_arm_keepalive(mesh);
}

/* The active route has carried data long enough that replacing it is worth the
   disturbance. A route that was never recorded has no residency to serve. */
static bool path_residency_served(meshlink_handle_t *mesh, const node_t *n) {
	if(n->active_route.kind == DATA_ROUTE_NONE || !n->active_route.selected_at.tv_sec) {
		return true;
	}

	return mesh->loop.now.tv_sec - n->active_route.selected_at.tv_sec >= PATH_ROUTE_MIN_RESIDENCY_SEC;
}

static void promotion_timer_handler(event_loop_t *loop, void *data);

static void path_promotion_timer_stop(meshlink_handle_t *mesh, node_t *n) {
	if(mesh) {
		timeout_del(&mesh->loop, &n->promotion_timer);
	}
}

static void path_promotion_timer_arm(meshlink_handle_t *mesh, node_t *n, const struct timespec *tv) {
	struct timespec when = tv ? *tv : (struct timespec) {
		0, 0
	};

	if(!n->promotion_timer.cb) {
		timeout_add(&mesh->loop, &n->promotion_timer, promotion_timer_handler, n, &when);
	} else {
		timeout_set(&mesh->loop, &n->promotion_timer, &when);
	}

	if(mesh->datafromapp.cb) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

static const char *path_promotion_reason_name(path_promotion_reason_t reason) {
	switch(reason) {
	case PATH_PROMOTION_DISCOVERY:
		return "discovery";

	case PATH_PROMOTION_HINT:
		return "hint";

	case PATH_PROMOTION_COOLDOWN_CLEARED:
		return "cooldown-cleared";

	case PATH_PROMOTION_UDP_CONFIRMED:
		return "udp-confirmed";

	case PATH_PROMOTION_TICK:
		return "tick";

	default:
		return "unknown";
	}
}

static void path_candidate_discard(meshlink_handle_t *mesh, node_t *n) {
	path_promotion_timer_stop(mesh, n);
	memset(&n->promotion_candidate, 0, sizeof n->promotion_candidate);
}

/* End the in-flight attempt but keep what we learned about this endpoint: its
   identity, how often it has let us down, and how long it owes us. */
static void path_candidate_end_attempt(meshlink_handle_t *mesh, node_t *n) {
	route_candidate_t *c = &n->promotion_candidate;

	path_promotion_timer_stop(mesh, n);
	c->active = false;
	c->nonce = 0;
	c->successful_rounds = 0;
	memset(&c->first_success, 0, sizeof c->first_success);
	memset(&c->deadline, 0, sizeof c->deadline);
}

static void promotion_timer_handler(event_loop_t *loop, void *data) {
	meshlink_handle_t *mesh = loop->data;
	node_t *n = data;
	route_candidate_t *c = &n->promotion_candidate;

	if(!c->active || c->successful_rounds >= PATH_PROMOTION_ROUNDS) {
		path_promotion_timer_stop(mesh, n);
		return;
	}

	if(c->deadline.tv_sec && mesh->loop.now.tv_sec >= c->deadline.tv_sec) {
		path_candidate_timeout(mesh, n, "validation deadline");
		return;
	}

	send_candidate_probe(mesh, n);
	path_promotion_timer_arm(mesh, n, &(struct timespec) {
		PATH_CANDIDATE_PROBE_INTERVAL_SEC, 0
	});
}

/* A fresh discovery or network change is new information, so the endpoint may
   be tried again now. It is not evidence that the earlier failures were wrong,
   so the escalation ladder keeps its position. */
void path_candidate_clear_cooldown(meshlink_handle_t *mesh, node_t *n) {
	if(!n) {
		return;
	}

	memset(&n->promotion_candidate.cooldown_until, 0, sizeof n->promotion_candidate.cooldown_until);
	path_consider_promotion(mesh, n, PATH_PROMOTION_COOLDOWN_CLEARED);
}

/* A long healthy stretch does say the earlier failures are not representative. */
static void path_candidate_reset_escalation(node_t *n) {
	n->promotion_candidate.failures = 0;
	memset(&n->promotion_candidate.cooldown_until, 0, sizeof n->promotion_candidate.cooldown_until);
}

void path_candidate_timeout(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	if(!mesh || !n || !n->promotion_candidate.active) {
		return;
	}

	route_candidate_t *c = &n->promotion_candidate;
	int cooldown = path_cooldown_seconds(mesh, c->failures);

	if(c->failures < UINT8_MAX) {
		c->failures++;
	}

	path_candidate_end_attempt(mesh, n);
	c->cooldown_until = mesh->loop.now;
	c->cooldown_until.tv_sec += cooldown;

	if(mesh->log_level <= MESHLINK_INFO) {
		char detail[64];
		snprintf(detail, sizeof detail, "%s cooldown=%ds", reason ? reason : "no reply", cooldown);
		path_log_validation(mesh, n, &c->endpoint, "candidate-dropped", detail);
	}
}

void path_consider_promotion(meshlink_handle_t *mesh, node_t *n, path_promotion_reason_t reason) {
	if(!mesh || !n || n->mesh != mesh) {
		return;
	}

	route_candidate_t *c = &n->promotion_candidate;

	if(c->active) {
		return;
	}

	if(c->cooldown_until.tv_sec && mesh->loop.now.tv_sec < c->cooldown_until.tv_sec) {
		return;
	}

	if(!n->status.udp_confirmed || n->udp_tier != PATH_TIER_DIRECT_WAN_UDP) {
		return;
	}

	sockaddr_t better;

	if(!path_pick_local_udp_candidate(mesh, n, &better)) {
		return;
	}

	/* Retrying the endpoint that already failed keeps its place on the
	   escalation ladder. A different endpoint starts with a clean record. */
	uint8_t failures = c->endpoint.sa.sa_family && !sockaddrcmp(&c->endpoint, &better) ? c->failures : 0;

	memset(c, 0, sizeof *c);
	c->failures = failures;
	c->active = true;
	c->kind = DATA_ROUTE_DIRECT_UDP;
	c->endpoint = better;
	c->source = ADDR_SRC_DISCOVERY;
	c->nonce = path_fresh_nonce();
	c->deadline = mesh->loop.now;
	c->deadline.tv_sec += PATH_PROMOTION_DEADLINE_SEC;

	path_log_validation(mesh, n, &better, "candidate-start", path_promotion_reason_name(reason));
	path_promotion_timer_arm(mesh, n, &(struct timespec) {
		0, 0
	});
}

bool path_candidate_probe_target(meshlink_handle_t *mesh, node_t *n, sockaddr_t *out, uint64_t *nonce_out) {
	if(!mesh || !n || !out || !nonce_out) {
		return false;
	}

	route_candidate_t *c = &n->promotion_candidate;

	if(!c->active || !c->nonce) {
		return false;
	}

	*out = c->endpoint;
	*nonce_out = c->nonce;
	return true;
}

/* Commit is a pure endpoint swap for future records: the node session, its
   channels and its UDP proof all stay exactly as they are. */
static void path_candidate_commit(meshlink_handle_t *mesh, node_t *n) {
	route_candidate_t *c = &n->promotion_candidate;
	sockaddr_t endpoint = c->endpoint;

	path_candidate_discard(mesh, n);
	path_log_validation(mesh, n, &endpoint, "candidate-promoted", "validated");
	(void)path_promote_udp_if_better(mesh, n, &endpoint);
	n->active_route.selected_at = mesh->loop.now;
}

void path_observe_probe_reply(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce) {
	if(!mesh || !n || !from) {
		return;
	}

	if(n == mesh->backbone_udp.node && nonce && nonce == mesh->backbone_udp.liveness_nonce) {
		path_backbone_udp_observe_reply(mesh, n, from, nonce);
		return;
	}

	route_candidate_t *c = &n->promotion_candidate;

	/* A reply on the endpoint we are already using is liveness, not promotion.
	   It also clears any suspicion raised by a retransmission. */
	if(n->address.sa.sa_family != AF_UNSPEC && !sockaddrcmp(from, &n->address)) {
		if(n->active_route.suspect) {
			n->active_route.suspect = false;
			path_log_validation(mesh, n, from, "suspect-cleared", "probe answered");
		}

		return;
	}

	if(!c->active || !c->nonce || nonce != c->nonce || sockaddrcmp(from, &c->endpoint)) {
		return;
	}

	/* Two replies from one burst prove nothing about stability, so rounds have
	   to be separated in time and each one gets a fresh nonce. */
	if(c->successful_rounds && timespec_ms_between(&c->first_success, &mesh->loop.now) < PATH_PROMOTION_ROUND_GAP_MS) {
		return;
	}

	if(!c->successful_rounds) {
		c->first_success = mesh->loop.now;
	}

	c->successful_rounds++;
	c->nonce = path_fresh_nonce();

	if(c->successful_rounds < PATH_PROMOTION_ROUNDS) {
		path_log_validation(mesh, n, from, "candidate-round", "awaiting next round");
		path_promotion_timer_arm(mesh, n, &(struct timespec) {
			0, PATH_PROMOTION_ROUND_GAP_MS * 1000000
		});
		return;
	}

	/* Timer owns rounds and the deadline. Tick owns hold and residency. */
	path_promotion_timer_stop(mesh, n);

	if(timespec_ms_between(&c->first_success, &mesh->loop.now) < PATH_PROMOTION_HOLD_MS) {
		return;
	}

	if(!path_residency_served(mesh, n)) {
		return;
	}

	path_candidate_commit(mesh, n);
}

void path_note_route_suspect(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	if(!mesh || !n || n->active_route.suspect) {
		return;
	}

	n->active_route.suspect = true;
	n->active_route.suspect_at = mesh->loop.now;
	path_log_validation(mesh, n, &n->address, "route-suspect", reason ? reason : "");
}

bool path_has_live_fallback(meshlink_handle_t *mesh, const node_t *n) {
	if(!mesh || !n) {
		return false;
	}

	if(n->nexthop && n->nexthop != mesh->self && n->nexthop != n
	                && n->nexthop->connection && n->nexthop->connection->status.active) {
		return true;
	}

	return n->connection && n->connection->status.active;
}

bool path_liveness_probe_warranted(meshlink_handle_t *mesh, const node_t *n) {
	if(!mesh || !n) {
		return false;
	}

	/* Still discovering, validating, or recovering: keep probing. */
	if(!n->status.udp_confirmed || n->active_route.suspect || n->status.want_udp) {
		return true;
	}

	/* Never used by the application: nothing depends on this path being warm. */
	if(!n->last_application_traffic) {
		return false;
	}

	return mesh->loop.now.tv_sec - n->last_application_traffic < PATH_LIVENESS_INTERVAL_SEC;
}

static void path_commit_active_route(node_t *n, const path_target_t *target, const struct timespec *now) {
	data_route_t *route = &n->active_route;
	bool changed = route->kind != target->kind
	               || route->relay_carrier != target->relay_carrier
	               || route->first_hop != target->first_hop;

	if(!changed) {
		return;
	}

	route->kind = target->kind;
	route->relay_carrier = target->relay_carrier;
	route->first_hop = target->first_hop;
	route->local = target->local;
	route->suspect = false;
	route->selected_at = *now;
}

void path_route_tick(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	route_candidate_t *c = &n->promotion_candidate;
	bool validated = c->active && c->successful_rounds >= PATH_PROMOTION_ROUNDS;

	/* Hold and residency live here, not on promotion_timer. After round 2 the
	   timer is already stopped; a validated candidate is waiting on us, so the
	   validation deadline does not apply. */
	if(validated
	                && timespec_ms_between(&c->first_success, &mesh->loop.now) >= PATH_PROMOTION_HOLD_MS
	                && path_residency_served(mesh, n)) {
		path_candidate_commit(mesh, n);
	} else if(!validated && c->active && c->deadline.tv_sec && mesh->loop.now.tv_sec >= c->deadline.tv_sec) {
		path_candidate_timeout(mesh, n, "no validated reply");
	}

	/* Suspicion is resolved by probes, not by assumption. Demote only once the
	   probe window has closed unanswered, and only when something else is
	   already live to carry the traffic: a node with nowhere else to go stays
	   on its suspect path rather than being declared broken. */
	if(n->active_route.suspect
	                && timespec_ms_between(&n->active_route.suspect_at, &mesh->loop.now) >= PATH_SUSPECT_WINDOW_MS) {
		if(path_has_live_fallback(mesh, n)) {
			n->active_route.suspect = false;
			path_note_udp_demoted_reason(mesh, n, "suspect probes unanswered");

			path_target_t target;

			if(path_active_send_target(mesh, n, &target)) {
				path_commit_active_route(n, &target, &mesh->loop.now);
			}
		} else {
			n->active_route.suspect_at = mesh->loop.now;
			path_log_validation(mesh, n, &n->address, "route-degraded", "no live fallback, still probing");
		}
	}

	/* A long healthy stretch means the earlier failures are not representative. */
	if(!n->active_route.suspect && n->active_route.selected_at.tv_sec
	                && mesh->loop.now.tv_sec - n->active_route.selected_at.tv_sec >= PATH_HEALTHY_RESET_SEC) {
		path_candidate_reset_escalation(n);
	}

	/* After cooldown expires (or never started) this is the retry that used to
	   hitchhike on the path-MTU timer. */
	path_consider_promotion(mesh, n, PATH_PROMOTION_TICK);
}

const char *data_route_kind_name(data_route_kind_t kind) {
	switch(kind) {
	case DATA_ROUTE_DIRECT_UDP:
		return "direct-udp";

	case DATA_ROUTE_DIRECT_LOCAL_META:
		return "direct-local-meta";

	case DATA_ROUTE_RELAY:
		return "relay";

	case DATA_ROUTE_NONE:
	default:
		return "none";
	}
}

const char *relay_carrier_name(relay_carrier_t carrier) {
	switch(carrier) {
	case RELAY_CARRIER_UDP:
		return "udp";

	case RELAY_CARRIER_META_DIRECT:
		return "meta-direct";

	case RELAY_CARRIER_META_CANONICAL:
		return "meta-canonical";

	case RELAY_CARRIER_NONE:
	default:
		return "none";
	}
}

/* Which carrier a relay hop can take right now. META-in and devtool pinning are
   applied by the caller through force_meta. */
static relay_carrier_t relay_carrier_for(const node_t *hop, bool force_meta) {
	if(!force_meta && hop_udp_ready(hop)) {
		return RELAY_CARRIER_UDP;
	}

	if(!hop->connection || !hop->connection->status.active) {
		return RELAY_CARRIER_NONE;
	}

	return path_meta_is_canonical(hop, hop->connection) ? RELAY_CARRIER_META_CANONICAL : RELAY_CARRIER_META_DIRECT;
}

bool path_active_send_target(meshlink_handle_t *mesh, node_t *n, path_target_t *out) {
	if(!mesh || !n || !out) {
		return false;
	}

	memset(out, 0, sizeof *out);

	if(!n->status.reachable) {
		return false;
	}

	/* A validated direct UDP endpoint always wins: it is the top of the ladder
	   and needs no hop. Local versus WAN is an attribute of the same mechanism.
	   A suspect endpoint steps aside only while something else is already live;
	   with no fallback it keeps carrying data and is probed instead. */
	bool direct_udp_ready = !n->devtool_force_meta && !n->status.forced_relay && hop_udp_ready(n);
	bool stepping_aside = direct_udp_ready && n->active_route.suspect && path_has_live_fallback(mesh, n);

	if(direct_udp_ready && !stepping_aside) {
		out->kind = DATA_ROUTE_DIRECT_UDP;
		out->local = n->udp_tier == PATH_TIER_DIRECT_LOCAL_UDP;
		return true;
	}

	node_t *hop = n->nexthop;

	if(hop && hop != mesh->self && hop != n) {
		relay_carrier_t carrier = relay_carrier_for(hop, n->devtool_force_meta);

		if(carrier != RELAY_CARRIER_NONE) {
			out->kind = DATA_ROUTE_RELAY;
			out->relay_carrier = carrier;
			out->first_hop = hop;
			out->temporary_fallback = stepping_aside;
			return true;
		}
	}

	/* No hop, or the hop offers nothing: fall back to this node's own META. */
	if(n->connection && n->connection->status.active) {
		out->kind = DATA_ROUTE_DIRECT_LOCAL_META;
		out->local = path_address_is_local(&n->connection->address);
		out->temporary_fallback = stepping_aside;
		return true;
	}

	/* Nothing validated. The caller still tries META so a first record can
	   bootstrap a session rather than being dropped outright. */
	out->kind = DATA_ROUTE_DIRECT_LOCAL_META;
	out->temporary_fallback = stepping_aside;
	return true;
}

void path_record_active_route(meshlink_handle_t *mesh, node_t *n, const path_target_t *target) {
	if(!mesh || !n || !target) {
		return;
	}

	n->last_application_traffic = mesh->loop.now.tv_sec;

	if(target->temporary_fallback) {
		return;
	}

	path_commit_active_route(n, target, &mesh->loop.now);
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

void path_log_udp_tier(meshlink_handle_t *mesh, const node_t *n, path_tier_t from, path_tier_t to, const char *reason) {
	if(!mesh || !n || mesh->log_level > MESHLINK_INFO || from == to) {
		return;
	}

	logger(mesh, MESHLINK_INFO, "Path UDP: %s %s -> %s (%s)", n->name, path_tier_name(from), path_tier_name(to), reason ? reason : "");
}

void path_log_transition(meshlink_handle_t *mesh, const node_t *n, path_tier_t from, path_tier_t to, const char *reason) {
	/* Production Path route: logs go through path_note_selected_route() so last_path_tier stays authoritative. */
	(void)mesh;
	(void)n;
	(void)from;
	(void)to;
	(void)reason;
}
