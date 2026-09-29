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
#include "connection_policy.h"
#include "path_policy.h"
#include "protocol.h"
#include "relay.h"
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
static void path_commit_active_route(node_t *n, const path_target_t *target, const struct timespec *now);
static bool path_punch_endpoint_usable(const sockaddr_t *sa);
static void path_punch_note_demotion(meshlink_handle_t *mesh, node_t *n);
static void path_punch_rearm(meshlink_handle_t *mesh, node_t *n);
static void path_punch_fail(meshlink_handle_t *mesh, node_t *n);
static bool hop_udp_ready(const node_t *hop);
static bool path_fill_direct_udp(meshlink_handle_t *mesh, const node_t *n, path_target_t *out);
static bool path_fill_local_meta(meshlink_handle_t *mesh, const node_t *n, path_target_t *out);
static bool path_fill_relay_udp(meshlink_handle_t *mesh, const node_t *n, path_target_t *out);
static bool path_fill_relay_meta(meshlink_handle_t *mesh, const node_t *n, path_target_t *out);
static void path_consider_demanded_route_promotions(meshlink_handle_t *mesh, path_route_promotion_t which);
static path_promotion_reason_t path_promotion_reason_for_source(address_source_t src);

/* path_backbone_udp.c — re-arm establish after demotion. */
void path_backbone_udp_arm(meshlink_handle_t *mesh, int sec, long nsec);

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

	/* The UDP node cache hashes the whole sockaddr_t. Darwin's sin_len is
	   part of that, and a caller-built address leaves it 0 while recvfrom()
	   fills it in, so the same host:port misses. sin_zero is padding. */
	if(dst->sa.sa_family == AF_INET) {
		memset(dst->in.sin_zero, 0, sizeof dst->in.sin_zero);
#ifdef __APPLE__
		dst->in.sin_len = sizeof dst->in;
#endif
	}

#ifdef __APPLE__

	if(dst->sa.sa_family == AF_INET6) {
		dst->in6.sin6_len = sizeof dst->in6;
	}

#endif
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

	/* HINT/UNKNOWN/EDGE_DIRECT cannot stand in for a hostname canonical that
	   has not been tried yet (or is still in flight). EDGE must wait too: an
	   unresolved hostname means hybrid NLB-IP+other-port cannot be detected
	   yet and would burn the 250ms startup budget (ADR 0003). After a resolve
	   failure, backoff is set and a later application hint is allowed to fall
	   through. AUTH_DIRECT and DISCOVERY stay eligible so a real local peer is
	   not blocked. */
	if((src == ADDR_SRC_UNKNOWN || src == ADDR_SRC_HINT || src == ADDR_SRC_EDGE_DIRECT)
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

	/* SALEN() is sa_len on Darwin. A parsed address often has sa_len 0, and
	   memcpy of that length stores nothing, so a discovery result never
	   becomes dialable. */
	path_copy_sockaddr(&n->recent[0], sa);
	n->recent_source[0] = keep;
	n->recent_cap[0] = keep_cap;
	n->status.dirty = true;
}

static void learn_set_material(bool *material, bool value) {
	if(material) {
		*material = value;
	}
}

bool path_learn_address_cap(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	return path_learn_address_cap_ex(mesh, n, sa, src, cap, NULL);
}

bool path_learn_address_cap_ex(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap, bool *material) {
	learn_set_material(material, false);

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
				if((merged & PATH_CAP_UDP) && path_address_is_local(sa)) {
					path_consider_promotion(mesh, n, path_promotion_reason_for_source(src));
				}

				return false;
			}

			recent_store_front(n, i, sa, src, cap);
			path_log_candidate(mesh, n, sa, n->recent_source[0], n->recent_cap[0], "updated");

			if((n->recent_cap[0] & PATH_CAP_UDP) && path_address_is_local(sa)) {
				path_consider_promotion(mesh, n, path_promotion_reason_for_source(src));
			}

			if(upgraded) {
				path_backbone_udp_note_direct(mesh, n, sa, n->recent_source[0], n->recent_cap[0]);
			}

			/* An unchanged address moving forward is persistence/LRU, not a new fact. */
			learn_set_material(material, upgraded);
			return true;
		}
	}

	recent_store_front(n, -1, sa, src, cap);
	path_log_candidate(mesh, n, sa, src, cap, "learned");

	if((cap & PATH_CAP_UDP) && path_address_is_local(sa)) {
		path_consider_promotion(mesh, n, path_promotion_reason_for_source(src));
	}

	path_backbone_udp_note_direct(mesh, n, sa, src, cap);
	learn_set_material(material, true);
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

	path_copy_sockaddr(&n->recent[i], sa);
	n->recent_source[i] = src;
	n->recent_cap[i] = cap;
	n->status.dirty = true;
	path_log_candidate(mesh, n, sa, src, cap, "fallback");
	return true;
}

bool path_learn_address_fallback(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src) {
	return path_learn_address_fallback_cap(mesh, n, sa, src, path_default_cap(src));
}

void path_clear_catta_address(node_t *n) {
	if(!n) {
		return;
	}

	memset(&n->catta_address, 0, sizeof n->catta_address);
}

void path_clear_recent(node_t *n) {
	if(!n) {
		return;
	}

	memset(n->recent, 0, sizeof n->recent);
	memset(n->recent_source, 0, sizeof n->recent_source);
	memset(n->recent_cap, 0, sizeof n->recent_cap);
	n->status.dirty = true;
	/* Catta is not a recent[] slot. Callers that used to lose it here
	   still do, but the wipe lives next to the other address clears. */
	path_clear_catta_address(n);
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

	/* Standby auth clears upgrade_probe while the barrier is still live.
	   A second probe would drop that standby and abort the cutover. */
	if(n->meta_cutover) {
		return "cutover-active";
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

	/* ADR 0009: an older peer cannot run the ordered barrier. Stay canonical. */
	if(c->protocol_minor < PROT_MINOR_ORDERED_CUTOVER) {
		return "peer-protocol";
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
	path_endpoint_t ep;

	if(!mesh || !n || !n->status.udp_confirmed || n->udp_tier != PATH_TIER_DIRECT_WAN_UDP) {
		return false;
	}

	if(mesh->loop.now.tv_sec < n->udp_local_probe_next) {
		return false;
	}

	if(!path_pick_local_udp_candidate(mesh, n, &ep)) {
		return false;
	}

	if(out) {
		path_copy_sockaddr(out, &ep.address);
	}

	return true;
}

void path_schedule_local_udp_probe(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	n->udp_local_probe_next = mesh->loop.now.tv_sec + UDP_LOCAL_PROBE_SEC;
}

bool path_pick_local_udp_candidate(meshlink_handle_t *mesh, const node_t *n, path_endpoint_t *out) {
	(void)mesh;

	if(!n || !out) {
		return false;
	}

	memset(out, 0, sizeof *out);

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

		path_copy_sockaddr(&out->address, &n->recent[i]);
		out->source = n->recent_source[i];
		out->capability = n->recent_cap[i];
		return true;
	}

	if(n->catta_address.sa.sa_family != AF_UNSPEC && path_address_is_local(&n->catta_address)
	                && (n->address.sa.sa_family == AF_UNSPEC || sockaddrcmp(&n->catta_address, &n->address))) {
		path_copy_sockaddr(&out->address, &n->catta_address);
		out->source = ADDR_SRC_DISCOVERY;
		out->capability = PATH_CAP_BOTH;
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

	path_consider_route_promotion(mesh, n, PATH_PROMOTION_DIRECT_UDP);

	if(mesh && n == mesh->backbone_udp.node) {
		path_consider_demanded_route_promotions(mesh, PATH_PROMOTION_BACKBONE_UDP);
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

static bool path_route_uses_udp_sa(const data_route_t *r, const node_t *owner, const node_t *failed, const sockaddr_t *sa) {
	if(!r || !owner || !failed || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	if(r->kind == DATA_ROUTE_DIRECT_UDP && owner == failed) {
		return !sockaddrcmp(&r->udp_endpoint, sa);
	}

	if(r->kind == DATA_ROUTE_RELAY && r->relay_carrier == RELAY_CARRIER_UDP && r->first_hop == failed) {
		return !sockaddrcmp(&r->udp_endpoint, sa);
	}

	return false;
}

static void path_rerank_recorded(meshlink_handle_t *mesh, node_t *dest) {
	path_target_t target;

	if(!mesh || !dest) {
		return;
	}

	if(path_select_fallback(mesh, dest, &target)) {
		path_commit_active_route(dest, &target, &mesh->loop.now);
	}
}

static void path_rerank_if_route_uses_udp(meshlink_handle_t *mesh, node_t *failed, const sockaddr_t *sa) {
	if(!mesh || !failed || !sa) {
		return;
	}

	if(path_route_uses_udp_sa(&failed->active_route, failed, failed, sa)) {
		path_rerank_recorded(mesh, failed);
	}

	if(!mesh->nodes) {
		return;
	}

	for splay_each(node_t, dest, mesh->nodes) {
		if(dest == failed) {
			continue;
		}

		if(path_route_uses_udp_sa(&dest->active_route, dest, failed, sa)) {
			path_rerank_recorded(mesh, dest);
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

	if(mesh) {
		path_scheduler_end_type(mesh, n, PATH_TXN_PMTU_DISCOVERY);
	}

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

	if(mesh) {
		sockaddr_t live;
		bool have_live = n->address.sa.sa_family != AF_UNSPEC
		                 && n->address.sa.sa_family != AF_UNKNOWN;

		/* Rerank against the endpoint the route still names. Installing the
		   hint first would make that compare miss and leave the dead carrier. */
		if(have_live) {
			path_copy_sockaddr(&live, &n->address);
		}

		path_suspect_stop(mesh, n);
		path_rerank_if_route_uses_udp(mesh, n, have_live ? &live : &n->address);
		channel_refresh_carrier(mesh, n);
		/* The hint is a new candidate, not a restored confirmed address. */
		path_punch_note_demotion(mesh, n);
	}
}

void path_note_udp_demoted(meshlink_handle_t *mesh, node_t *n) {
	path_note_udp_demoted_reason(mesh, n, "reliable retransmit");
}

static bool path_promote_udp_endpoint(meshlink_handle_t *mesh, node_t *n, const path_endpoint_t *ep) {
	const sockaddr_t *from;
	path_cap_t cap;

	if(!n || !ep || !n->status.udp_confirmed) {
		return false;
	}

	from = &ep->address;

	if(n->address.sa.sa_family != AF_UNSPEC && !sockaddrcmp(from, &n->address)) {
		return false;
	}

	if(path_address_matches_canonical(n, from)) {
		return false;
	}

	path_tier_t next = path_udp_tier_for(from, ep->source);

	if(!path_tier_better(next, n->udp_tier == PATH_TIER_NONE ? PATH_TIER_DIRECT_WAN_UDP : n->udp_tier)
	                && n->udp_tier != PATH_TIER_NONE) {
		return false;
	}

	cap = ep->capability ? ep->capability : path_default_cap(ep->source);

	path_tier_t was = n->udp_tier;
	update_node_udp_from(mesh, n, from, ep->source);
	n->udp_tier = next;
	n->address_cap = cap;
	path_learn_address_cap(mesh, n, from, ep->source, cap);
	path_log_udp_tier(mesh, n, was, next, "local probe reply");
	return true;
}

/* Production commit install. Same sockaddr refreshes source and cap. Eligibility
   is the picker gate, re-checked before any write: UDP candidate, direct or
   reflexive, and a bound address. That rejects canonical, an EDGE_DIRECT or
   UNKNOWN NLB-IP hybrid, and a HINT/UNKNOWN blocked by an unresolved hostname
   canonical. Tier ranking stays on path_promote_udp_endpoint so the devtool
   wrapper can still refuse a non-improving dest. */
static bool path_install_committed_udp(meshlink_handle_t *mesh, node_t *n, const path_endpoint_t *ep) {
	const sockaddr_t *from;
	path_cap_t cap;
	path_tier_t next;
	path_tier_t was;

	if(!mesh || !n || !ep || !n->status.udp_confirmed) {
		return false;
	}

	from = &ep->address;
	cap = ep->capability ? ep->capability : path_default_cap(ep->source);

	if(!path_is_udp_candidate(n, from, ep->source, cap)
	                || (!path_is_direct_candidate(n, from, ep->source)
	                    && ep->source != ADDR_SRC_UDP_REFLEXIVE)
	                || !udp_address_bound(from)) {
		return false;
	}

	next = path_udp_tier_for(from, ep->source);
	was = n->udp_tier;
	update_node_udp_from(mesh, n, from, ep->source);
	n->address_source = ep->source;
	n->address_cap = cap;
	n->udp_tier = next;
	path_learn_address_cap(mesh, n, from, ep->source, cap);
	path_log_udp_tier(mesh, n, was, next, "candidate commit");
	return true;
}

bool path_promote_udp_if_better(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from) {
	path_endpoint_t ep;
	int i;

	if(!from) {
		return false;
	}

	memset(&ep, 0, sizeof ep);
	path_copy_sockaddr(&ep.address, from);
	ep.source = ADDR_SRC_AUTH_DIRECT;
	ep.capability = path_default_cap(ADDR_SRC_AUTH_DIRECT);

	if(n) {
		for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
			if(!sockaddrcmp(&n->recent[i], from)) {
				ep.source = n->recent_source[i];
				ep.capability = n->recent_cap[i];
				break;
			}
		}
	}

	return path_promote_udp_endpoint(mesh, n, &ep);
}

static path_tier_t path_route_to_tier(const data_route_t *r) {
	if(!r) {
		return PATH_TIER_NONE;
	}

	switch(r->kind) {
	case DATA_ROUTE_DIRECT_UDP:
		return r->local ? PATH_TIER_DIRECT_LOCAL_UDP : PATH_TIER_DIRECT_WAN_UDP;

	case DATA_ROUTE_DIRECT_LOCAL_META:
		return PATH_TIER_META_DIRECT;

	case DATA_ROUTE_RELAY:
		if(r->relay_carrier == RELAY_CARRIER_UDP) {
			return PATH_TIER_RELAY_UDP;
		}

		if(r->relay_carrier == RELAY_CARRIER_META_CANONICAL) {
			return PATH_TIER_META_CANONICAL;
		}

		return PATH_TIER_META_DIRECT;

	case DATA_ROUTE_NONE:
	default:
		return PATH_TIER_NONE;
	}
}

void path_note_selected_route(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	path_tier_t to;
	path_tier_t from;

	if(!n) {
		return;
	}

	to = path_route_to_tier(&n->active_route);
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

static bool timespec_after_or_equal(const struct timespec *a, const struct timespec *b) {
	return timespec_ms_between(b, a) >= 0;
}

static struct timespec path_ms_to_timespec(int64_t ms) {
	if(ms < 0) {
		ms = 0;
	}

	return (struct timespec) {
		ms / 1000, (long)(ms % 1000) * 1000000L
	};
}

static void timespec_add_ms(struct timespec *ts, int ms) {
	long nsec;

	if(!ts || ms < 0) {
		return;
	}

	ts->tv_sec += ms / 1000;
	nsec = ts->tv_nsec + (long)(ms % 1000) * 1000000L;

	if(nsec >= 1000000000L) {
		ts->tv_sec++;
		nsec -= 1000000000L;
	}

	ts->tv_nsec = nsec;
}

static void path_suspect_set_deadline(meshlink_handle_t *mesh, suspect_validation_t *s) {
	s->deadline = mesh->loop.now;
	timespec_add_ms(&s->deadline, PATH_SUSPECT_WINDOW_MS);
}

static struct timespec path_suspect_rearm_delay(meshlink_handle_t *mesh, const suspect_validation_t *s) {
	int64_t remain = timespec_ms_between(&mesh->loop.now, &s->deadline);
	int64_t gap;

	if(remain <= 0) {
		return (struct timespec) {
			0, 0
		};
	}

	if(s->probes_sent >= PATH_SUSPECT_PROBES) {
		return path_ms_to_timespec(remain);
	}

	gap = PATH_SUSPECT_WINDOW_MS / PATH_SUSPECT_PROBES;

	if(gap < 1) {
		gap = 1;
	}

	if(remain < gap) {
		gap = remain;
	}

	return path_ms_to_timespec(gap);
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

	if(mesh->threadstarted && mesh->loop.pipefd[1] != -1 && !pthread_equal(mesh->thread, pthread_self())) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

static const char *path_promotion_reason_name(path_promotion_reason_t reason) {
	switch(reason) {
	case PATH_PROMOTION_DISCOVERY:
		return "discovery";

	case PATH_PROMOTION_HINT:
		return "hint";

	case PATH_PROMOTION_AUTH_DIRECT:
		return "auth-direct";

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

static path_promotion_reason_t path_promotion_reason_for_source(address_source_t src) {
	switch(src) {
	case ADDR_SRC_DISCOVERY:
		return PATH_PROMOTION_DISCOVERY;

	case ADDR_SRC_HINT:
		return PATH_PROMOTION_HINT;

	case ADDR_SRC_AUTH_DIRECT:
		return PATH_PROMOTION_AUTH_DIRECT;

	default:
		return PATH_PROMOTION_TICK;
	}
}

static address_source_t path_promotion_observation_source(path_promotion_reason_t reason) {
	switch(reason) {
	case PATH_PROMOTION_DISCOVERY:
		return ADDR_SRC_DISCOVERY;

	case PATH_PROMOTION_HINT:
		return ADDR_SRC_HINT;

	case PATH_PROMOTION_AUTH_DIRECT:
		return ADDR_SRC_AUTH_DIRECT;

	default:
		return ADDR_SRC_UNKNOWN;
	}
}

static void path_candidate_discard(meshlink_handle_t *mesh, node_t *n) {
	path_promotion_timer_stop(mesh, n);
	path_scheduler_cancel(mesh, n, PATH_TX_CHANNEL_PROMOTION);
	memset(&n->promotion_candidate, 0, sizeof n->promotion_candidate);
}

void path_transaction_preempt(meshlink_handle_t *mesh, node_t *node, path_transaction_type_t type) {
	if(!mesh || !node) {
		return;
	}

	switch(type) {
	case PATH_TXN_PROMOTION:
		if(node->promotion_candidate.active
		                && node->promotion_candidate.successful_rounds >= PATH_PROMOTION_ROUNDS) {
			/* Already validated: stop emitting, keep the candidate so tick
			   can reacquire the slot and commit. Probing searches discard. */
			path_log_validation(mesh, node,
			                    node->promotion_candidate.endpoint.sa.sa_family ? &node->promotion_candidate.endpoint : NULL,
			                    "candidate-paused", "preempted");
			path_promotion_timer_stop(mesh, node);
			break;
		}

		if(node->promotion_candidate.active) {
			path_log_validation(mesh, node,
			                    node->promotion_candidate.endpoint.sa.sa_family ? &node->promotion_candidate.endpoint : NULL,
			                    "candidate-dropped", "preempted");
		}

		path_candidate_discard(mesh, node);
		break;

	case PATH_TXN_SUSPECT:
		path_suspect_stop(mesh, node);
		break;

	case PATH_TXN_PUNCH:
		/* The slot is already gone. Denial still ends at the deadline. */
		logger(mesh, MESHLINK_INFO, "Punch challenge for %s paused", node->name);

		if(!node->peer_udp.challenge.active) {
			break;
		}

		if(node->peer_udp.challenge.attempts >= PATH_PUNCH_CHALLENGE_ATTEMPTS
		                || timespec_after_or_equal(&mesh->loop.now, &node->peer_udp.challenge.deadline)) {
			path_punch_fail(mesh, node);
			break;
		}

		path_punch_rearm(mesh, node);
		break;

	default:
		break;
	}
}

/* End the in-flight attempt. Endpoint retry history lives on node_t. */
static void path_candidate_end_attempt(meshlink_handle_t *mesh, node_t *n) {
	route_candidate_t *c = &n->promotion_candidate;

	path_promotion_timer_stop(mesh, n);
	path_scheduler_cancel(mesh, n, PATH_TX_CHANNEL_PROMOTION);
	c->active = false;
	c->nonce = 0;
	c->successful_rounds = 0;
	memset(&c->first_success, 0, sizeof c->first_success);
	memset(&c->deadline, 0, sizeof c->deadline);
}

static void path_candidate_send_packet(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	send_candidate_probe(mesh, req->node);
}

void path_promotion_timer_tick(meshlink_handle_t *mesh, node_t *n) {
	route_candidate_t *c;
	path_probe_request_t req;
	path_sched_txn_t *txn;

	if(!mesh || !n) {
		return;
	}

	c = &n->promotion_candidate;

	if(!c->active || c->successful_rounds >= PATH_PROMOTION_ROUNDS) {
		path_promotion_timer_stop(mesh, n);
		return;
	}

	if(c->deadline.tv_sec && mesh->loop.now.tv_sec >= c->deadline.tv_sec) {
		path_candidate_timeout(mesh, n, "validation deadline");
		return;
	}

	txn = path_scheduler_begin_transaction(mesh, n, PATH_TXN_PROMOTION, PATH_TX_CHANNEL_PROMOTION, path_transaction_preempt);

	if(!txn) {
		path_promotion_timer_arm(mesh, n, &(struct timespec) {
			PATH_CANDIDATE_PROBE_INTERVAL_SEC, 0
		});
		return;
	}

	memset(&req, 0, sizeof req);
	req.node = n;
	req.length = PATH_PROMOTION_PROBE_LEN;
	req.priority = PATH_TX_CHANNEL_PROMOTION;
	req.send = path_candidate_send_packet;
	(void)path_scheduler_emit_packet(mesh, txn, &req);
	path_promotion_timer_arm(mesh, n, &(struct timespec) {
		PATH_CANDIDATE_PROBE_INTERVAL_SEC, 0
	});
}

static void promotion_timer_handler(event_loop_t *loop, void *data) {
	path_promotion_timer_tick(loop->data, data);
}

/* A justified observation may retry now. Failures stay: the ladder does not
   reset. Production callers go through the epoch gate in consider_promotion. */
static void path_candidate_clear_cooldown_from(meshlink_handle_t *mesh, node_t *n,
                address_source_t src) {
	if(!n) {
		return;
	}

	memset(&n->candidate_retry.cooldown_until, 0, sizeof n->candidate_retry.cooldown_until);

	if(mesh) {
		n->candidate_retry.network_generation = mesh->lan_network_epoch;
	}

	if(src == ADDR_SRC_AUTH_DIRECT) {
		n->candidate_retry.auth_seen = true;
	} else if(src == ADDR_SRC_DISCOVERY || src == ADDR_SRC_HINT) {
		n->candidate_retry.auth_seen = false;
	}

	path_consider_promotion(mesh, n, PATH_PROMOTION_COOLDOWN_CLEARED);
}

void path_candidate_clear_cooldown(meshlink_handle_t *mesh, node_t *n) {
	path_candidate_clear_cooldown_from(mesh, n, ADDR_SRC_UNKNOWN);
}

static void path_note_candidate_failure(meshlink_handle_t *mesh, node_t *n) {
	n->candidate_retry.last_failure_at = mesh->loop.now;
	memset(&n->active_route.healthy_since, 0, sizeof n->active_route.healthy_since);
}

void path_note_authenticated_route_success(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || n->active_route.kind == DATA_ROUTE_NONE || n->active_route.suspect) {
		return;
	}

	if(!n->active_route.healthy_since.tv_sec) {
		n->active_route.healthy_since = mesh->loop.now;
	}
}

static bool path_retry_is_endpoint(const node_t *n, const sockaddr_t *ep) {
	return n && ep && n->candidate_retry.endpoint.sa.sa_family && ep->sa.sa_family
	       && !sockaddrcmp(&n->candidate_retry.endpoint, ep);
}

static bool path_cooldown_outstanding(const meshlink_handle_t *mesh, const node_t *n) {
	return n->candidate_retry.cooldown_until.tv_sec
	       && mesh->loop.now.tv_sec < n->candidate_retry.cooldown_until.tv_sec;
}

static bool path_retry_epoch_is_new(const meshlink_handle_t *mesh, const node_t *n,
                                    const sockaddr_t *ep, address_source_t src) {
	const path_candidate_retry_t *r = &n->candidate_retry;

	if(!path_cooldown_outstanding(mesh, n) || !path_retry_is_endpoint(n, ep)) {
		return false;
	}

	if(mesh->lan_network_epoch != r->network_generation) {
		return true;
	}

	if(src == ADDR_SRC_AUTH_DIRECT && !r->auth_seen) {
		return true;
	}

	return false;
}

static bool path_failure_this_tick(const meshlink_handle_t *mesh, const node_t *n) {
	return n->candidate_retry.last_failure_at.tv_sec == mesh->loop.now.tv_sec
	       && n->candidate_retry.last_failure_at.tv_nsec == mesh->loop.now.tv_nsec;
}

/* A long healthy stretch does say the earlier failures are not representative.
   cooldown_until clears only via the observation epoch gate, time expiry, or
   the force helper. WAN health must not wipe an in-flight wait. */
static void path_candidate_reset_escalation(node_t *n) {
	n->candidate_retry.failures = 0;
}

static void path_retry_clear_if_endpoint(node_t *n, const sockaddr_t *ep) {
	if(path_retry_is_endpoint(n, ep)) {
		memset(&n->candidate_retry, 0, sizeof n->candidate_retry);
	}
}

void path_candidate_timeout(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	if(!mesh || !n || !n->promotion_candidate.active) {
		return;
	}

	route_candidate_t *c = &n->promotion_candidate;
	path_candidate_retry_t *r = &n->candidate_retry;
	sockaddr_t endpoint = c->endpoint;
	bool local_udp = c->kind == DATA_ROUTE_DIRECT_UDP;
	int cooldown = 0;

	if(local_udp) {
		if(!path_retry_is_endpoint(n, &c->endpoint)) {
			memset(r, 0, sizeof *r);
			path_copy_sockaddr(&r->endpoint, &c->endpoint);
		}

		path_note_candidate_failure(mesh, n);
		cooldown = path_cooldown_seconds(mesh, r->failures);

		if(r->failures < UINT8_MAX) {
			r->failures++;
		}
	}

	path_candidate_end_attempt(mesh, n);

	if(local_udp) {
		r->cooldown_until = mesh->loop.now;
		r->cooldown_until.tv_sec += cooldown;
		r->network_generation = mesh->lan_network_epoch;
	}

	if(mesh->log_level <= MESHLINK_INFO) {
		char detail[64];

		if(local_udp) {
			snprintf(detail, sizeof detail, "%s cooldown=%ds", reason ? reason : "no reply", cooldown);
		} else {
			snprintf(detail, sizeof detail, "%s", reason ? reason : "no reply");
		}

		path_log_validation(mesh, n, endpoint.sa.sa_family ? &endpoint : NULL, "candidate-dropped", detail);
	}
}

static bool path_is_ordinary_peer_pair(const meshlink_handle_t *mesh, const node_t *peer) {
	return mesh
	       && mesh->self
	       && peer
	       && peer != mesh->self
	       && connection_policy_lan_device_class(mesh->self->devclass)
	       && connection_policy_lan_device_class(peer->devclass)
	       && !connection_policy_is_backbone(mesh, peer);
}

bool path_peer_udp_demanded(const meshlink_handle_t *mesh, const node_t *peer) {
	if(!mesh || !peer) {
		return false;
	}

	if(peer->peer_udp.channel_count) {
		return true;
	}

	if(!peer->peer_udp.idle_until.tv_sec && !peer->peer_udp.idle_until.tv_nsec) {
		return false;
	}

	return timespec_ms_between(&mesh->loop.now, &peer->peer_udp.idle_until) > 0;
}

bool path_peer_udp_punching_allowed(const meshlink_handle_t *mesh, const node_t *n) {
	return path_is_ordinary_peer_pair(mesh, n) && path_peer_udp_demanded(mesh, n);
}

static bool path_punch_endpoint_usable(const sockaddr_t *sa) {
	uint16_t port = 0;

	if(!udp_address_usable(sa) || path_address_is_local(sa)) {
		return false;
	}

	/* udp_address_usable still accepts broadcast. ADR 0008 does not record it. */
	if(sa->sa.sa_family == AF_INET && ntohl(sa->in.sin_addr.s_addr) == 0xffffffffu) {
		return false;
	}

	if(sa->sa.sa_family == AF_INET) {
		port = sa->in.sin_port;
	} else if(sa->sa.sa_family == AF_INET6) {
		port = sa->in6.sin6_port;
	}

	return port != 0;
}

static const int path_punch_ladder[] = {1, 2, 5, 10, 30};

static void path_punch_reset_schedule(node_t *n) {
	n->peer_udp.request_step = 0;
	n->peer_udp.ladder_stopped = false;
	memset(&n->peer_udp.next_request, 0, sizeof n->peer_udp.next_request);
	n->peer_udp.request_session = 0;
}

/* Session change stops the ladder. A demand epoch or a network epoch restarts it. */
static void path_punch_stop_ladder(node_t *n) {
	n->peer_udp.ladder_stopped = true;
}

static void path_punch_schedule(node_t *n, const struct timespec *now) {
	unsigned step = n->peer_udp.request_step;

	if(step >= sizeof path_punch_ladder / sizeof path_punch_ladder[0]) {
		step = sizeof path_punch_ladder / sizeof path_punch_ladder[0] - 1;
	}

	n->peer_udp.next_request = *now;
	n->peer_udp.next_request.tv_sec += path_punch_ladder[step];

	if((size_t)n->peer_udp.request_step + 1 < sizeof path_punch_ladder / sizeof path_punch_ladder[0]) {
		n->peer_udp.request_step++;
	}
}

static bool path_punch_direct_confirmed(const node_t *n) {
	return n->status.udp_confirmed
	       && (n->udp_tier == PATH_TIER_DIRECT_LOCAL_UDP || n->udp_tier == PATH_TIER_DIRECT_WAN_UDP);
}

static void path_punch_endpoint_tick(meshlink_handle_t *mesh, node_t *peer) {
	if(!mesh || !peer) {
		return;
	}

	if(!path_peer_udp_punching_allowed(mesh, peer) || path_punch_direct_confirmed(peer)) {
		path_punch_reset_schedule(peer);
		return;
	}

	if(peer->peer_udp.network_epoch != mesh->lan_network_epoch) {
		path_punch_cancel(mesh, peer);
		memset(&peer->peer_udp.ingress, 0, sizeof peer->peer_udp.ingress);
		peer->peer_udp.ingress_session = 0;
		peer->peer_udp.ingress_demand_epoch = 0;
		peer->peer_udp.ingress_network_epoch = 0;
		path_punch_reset_schedule(peer);
		path_clear_pending_punch_hint(peer);
		peer->peer_udp.network_epoch = mesh->lan_network_epoch;
	}

	if(peer->session_id && peer->peer_udp.request_session
	                && peer->peer_udp.request_session != peer->session_id) {
		path_punch_cancel(mesh, peer);
		memset(&peer->peer_udp.ingress, 0, sizeof peer->peer_udp.ingress);
		peer->peer_udp.ingress_session = 0;
		peer->peer_udp.ingress_demand_epoch = 0;
		peer->peer_udp.ingress_network_epoch = 0;
		path_punch_stop_ladder(peer);
		path_clear_pending_punch_hint(peer);
		peer->peer_udp.request_session = peer->session_id;
		return;
	}

	if(peer->peer_udp.pending_hint.sa.sa_family) {
		int64_t age = timespec_ms_between(&peer->peer_udp.pending_hint_at, &mesh->loop.now);

		if(age > (int64_t)PATH_UDP_OBSERVATION_FRESH_SEC * 1000
		                || (peer->session_id && peer->peer_udp.pending_hint_session
		                    && peer->peer_udp.pending_hint_session != peer->session_id)
		                || peer->peer_udp.pending_hint_demand_epoch != peer->peer_udp.demand_epoch) {
			logger(mesh, MESHLINK_INFO, "Punch hint for %s expired", peer->name);
			path_clear_pending_punch_hint(peer);
		}
	}

	if(peer->peer_udp.ladder_stopped) {
		return;
	}

	if((peer->peer_udp.next_request.tv_sec || peer->peer_udp.next_request.tv_nsec)
	                && timespec_ms_between(&mesh->loop.now, &peer->peer_udp.next_request) > 0) {
		return;
	}

	if(!send_punch_endpoint_request(mesh, peer)) {
		return;
	}

	/* No challenge destination: walk REQ_EXTERNAL/LAN. This is not PMTU. */
	send_punch_bootstrap(mesh, peer);
	path_punch_schedule(peer, &mesh->loop.now);
	peer->peer_udp.request_session = peer->session_id;
}

static void path_punch_on_new_demand(meshlink_handle_t *mesh, node_t *peer) {
	path_punch_cancel(mesh, peer);
	path_punch_reset_schedule(peer);
	memset(&peer->peer_udp.last_hint, 0, sizeof peer->peer_udp.last_hint);
	path_clear_pending_punch_hint(peer);
	peer->peer_udp.network_epoch = mesh->lan_network_epoch;
	peer->peer_udp.demand_epoch++;
	path_punch_endpoint_tick(mesh, peer);
}

static void path_punch_note_hint(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa) {
	if(n->peer_udp.last_hint.sa.sa_family && !sockaddrcmp(&n->peer_udp.last_hint, sa)) {
		return;
	}

	path_copy_sockaddr(&n->peer_udp.last_hint, sa);
	/* Same restart as a demand epoch or a network epoch: send on this tick. */
	path_punch_reset_schedule(n);
	path_punch_endpoint_tick(mesh, n);
}

void path_note_authenticated_udp_observation(meshlink_handle_t *mesh, node_t *node, const sockaddr_t *endpoint) {
	if(!mesh || !node || !endpoint || node == mesh->self || !node->session_id) {
		return;
	}

	if(!path_punch_endpoint_usable(endpoint)) {
		return;
	}

	path_copy_sockaddr(&node->udp_observation.endpoint, endpoint);
	node->udp_observation.observed_at = mesh->loop.now;
	node->udp_observation.session_id = node->session_id;
}

bool path_get_fresh_udp_observation(const meshlink_handle_t *mesh, const node_t *node, sockaddr_t *out) {
	int64_t age_ms;

	if(!mesh || !node || !out) {
		return false;
	}

	if(!node->udp_observation.session_id || node->udp_observation.session_id != node->session_id) {
		return false;
	}

	if(!node->udp_observation.observed_at.tv_sec && !node->udp_observation.observed_at.tv_nsec) {
		return false;
	}

	if(!path_punch_endpoint_usable(&node->udp_observation.endpoint)) {
		return false;
	}

	age_ms = timespec_ms_between(&node->udp_observation.observed_at, &mesh->loop.now);

	if(age_ms < 0 || age_ms > (int64_t)PATH_UDP_OBSERVATION_FRESH_SEC * 1000) {
		return false;
	}

	path_copy_sockaddr(out, &node->udp_observation.endpoint);
	return true;
}

void path_clear_pending_punch_hint(node_t *n) {
	if(!n) {
		return;
	}

	memset(&n->peer_udp.pending_hint, 0, sizeof n->peer_udp.pending_hint);
	memset(&n->peer_udp.pending_hint_at, 0, sizeof n->peer_udp.pending_hint_at);
	n->peer_udp.pending_hint_session = 0;
	n->peer_udp.pending_hint_demand_epoch = 0;
}

void path_clear_udp_observation(node_t *n) {
	if(!n) {
		return;
	}

	if(n->mesh) {
		path_punch_cancel(n->mesh, n);
	}

	memset(&n->udp_observation, 0, sizeof n->udp_observation);
	memset(&n->peer_udp.ingress, 0, sizeof n->peer_udp.ingress);
	n->peer_udp.ingress_session = 0;
	n->peer_udp.ingress_demand_epoch = 0;
	n->peer_udp.ingress_network_epoch = 0;
	memset(&n->peer_udp.failed_ingress, 0, sizeof n->peer_udp.failed_ingress);
	path_punch_stop_ladder(n);
	memset(&n->peer_udp.last_hint, 0, sizeof n->peer_udp.last_hint);
	path_clear_pending_punch_hint(n);
}

bool path_select_punch_hint(const meshlink_handle_t *mesh, const node_t *node, sockaddr_t *out, bool *from_observation) {
	if(from_observation) {
		*from_observation = false;
	}

	if(!mesh || !node || !out) {
		return false;
	}

	if(path_get_fresh_udp_observation(mesh, node, out)) {
		if(from_observation) {
			*from_observation = true;
		}

		return true;
	}

	if(node->status.udp_confirmed && path_punch_endpoint_usable(&node->address)) {
		path_copy_sockaddr(out, &node->address);
		return true;
	}

	return false;
}

static sockaddr_t path_punch_last_probe;
static bool path_punch_last_probe_valid;
static unsigned path_punch_ans_exports;

unsigned path_punch_test_ans_exports(void) {
	return path_punch_ans_exports;
}

bool path_punch_last_probe_dest(sockaddr_t *out) {
	if(!out || !path_punch_last_probe_valid) {
		return false;
	}

	path_copy_sockaddr(out, &path_punch_last_probe);
	return true;
}

static bool path_punch_ingress_usable(const sockaddr_t *sa) {
	uint16_t port = 0;

	if(!address_connectable(sa)) {
		return false;
	}

	if(sa->sa.sa_family == AF_INET) {
		if(ntohl(sa->in.sin_addr.s_addr) == INADDR_BROADCAST) {
			return false;
		}

		port = sa->in.sin_port;
	} else if(sa->sa.sa_family == AF_INET6) {
		port = sa->in6.sin6_port;
	}

	return port != 0;
}

static bool path_punch_challenge_current(const meshlink_handle_t *mesh, const node_t *n) {
	const punch_challenge_t *c;

	if(!mesh || !n || !n->peer_udp.challenge.active || !n->peer_udp.challenge.nonce) {
		return false;
	}

	if(!n->status.validkey || !path_peer_udp_punching_allowed(mesh, n)) {
		return false;
	}

	c = &n->peer_udp.challenge;

	if(n->session_id && c->session_id && n->session_id != c->session_id) {
		return false;
	}

	if(c->network_epoch != mesh->lan_network_epoch) {
		return false;
	}

	return c->demand_epoch == n->peer_udp.demand_epoch;
}

static const char *path_punch_source_name(punch_provenance_t prov) {
	return prov == PUNCH_PROV_AUTH_INGRESS ? "peer-reflexive" : "rendezvous";
}

static void path_punch_log_at(meshlink_handle_t *mesh, const node_t *n, const char *fmt, const sockaddr_t *sa, punch_provenance_t prov) {
	char *host = NULL;
	char *port = NULL;
	sockaddr_t logged;

	if(!mesh || !n || !sa || mesh->log_level > MESHLINK_INFO) {
		return;
	}

	path_copy_sockaddr(&logged, sa);
	sockaddr2str(&logged, &host, &port);
	logger(mesh, MESHLINK_INFO, fmt, n->name, host ? host : "?", port ? port : "?", path_punch_source_name(prov));
	free(host);
	free(port);
}

static void path_punch_timer_cb(event_loop_t *loop, void *data) {
	path_punch_challenge_timeout(loop->data, data);
}

static void path_punch_rearm(meshlink_handle_t *mesh, node_t *n) {
	struct timespec when;
	int64_t remain_ms;

	if(!mesh || !n || n->devtool_force_meta || !n->peer_udp.challenge.active) {
		return;
	}

	remain_ms = timespec_ms_between(&mesh->loop.now, &n->peer_udp.challenge.deadline);

	if(remain_ms > PATH_PROMOTION_ROUND_GAP_MS) {
		remain_ms = PATH_PROMOTION_ROUND_GAP_MS;
	}

	when = path_ms_to_timespec(remain_ms);

	if(!n->punch_timer.cb) {
		timeout_add(&mesh->loop, &n->punch_timer, path_punch_timer_cb, n, &when);
	} else {
		timeout_set(&mesh->loop, &n->punch_timer, &when);
	}

	if(mesh->threadstarted && mesh->loop.pipefd[1] != -1 && !pthread_equal(mesh->thread, pthread_self())) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

static void path_punch_disarm(meshlink_handle_t *mesh, node_t *n) {
	if(mesh) {
		timeout_del(&mesh->loop, &n->punch_timer);
		path_scheduler_cancel(mesh, n, PATH_TX_PUNCH);
	}

	memset(&n->peer_udp.challenge, 0, sizeof n->peer_udp.challenge);
}

void path_punch_cancel(meshlink_handle_t *mesh, node_t *n) {
	if(!n) {
		return;
	}

	path_punch_disarm(mesh, n);
	memset(&n->peer_udp.failed_ingress, 0, sizeof n->peer_udp.failed_ingress);
	n->peer_udp.hint_failed = false;
}

static void path_punch_send_cb(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	node_t *n = req ? req->node : NULL;

	if(!n || !n->peer_udp.challenge.active || !n->peer_udp.challenge.nonce) {
		return;
	}

	if(!send_punch_probe(mesh, n)) {
		return;
	}

	if(n->peer_udp.challenge.attempts < 255) {
		n->peer_udp.challenge.attempts++;
	}
}

static bool path_punch_emit(meshlink_handle_t *mesh, node_t *n) {
	path_probe_request_t req;
	path_sched_txn_t *txn;

	txn = path_scheduler_begin_transaction(mesh, n, PATH_TXN_PUNCH, PATH_TX_PUNCH, path_transaction_preempt);

	if(!txn) {
		return false;
	}

	memset(&req, 0, sizeof req);
	req.node = n;
	req.length = PATH_PROMOTION_PROBE_LEN;
	req.priority = PATH_TX_PUNCH;
	req.send = path_punch_send_cb;
	return path_scheduler_emit_packet(mesh, txn, &req) != PATH_SCHED_DENIED;
}

void path_punch_release(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || n->devtool_force_meta || !path_punch_challenge_current(mesh, n)) {
		return;
	}

	if(n->peer_udp.challenge.attempts >= PATH_PUNCH_CHALLENGE_ATTEMPTS
	                || timespec_after_or_equal(&mesh->loop.now, &n->peer_udp.challenge.deadline)) {
		path_punch_fail(mesh, n);
		return;
	}

	path_punch_emit(mesh, n);
	path_punch_rearm(mesh, n);
}

static void path_punch_begin(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, punch_provenance_t prov) {
	bool usable = prov == PUNCH_PROV_AUTH_INGRESS ? path_punch_ingress_usable(sa) : path_punch_endpoint_usable(sa);
	uint64_t nonce;

	if(!mesh || !n || !sa || !usable) {
		return;
	}

	if(!n->status.validkey || !path_peer_udp_punching_allowed(mesh, n)) {
		return;
	}

	path_punch_disarm(mesh, n);
	nonce = path_fresh_nonce();

	if(!nonce) {
		nonce = path_fresh_nonce();
	}

	if(!nonce) {
		return;
	}

	n->peer_udp.challenge.active = true;
	n->peer_udp.challenge.provenance = prov;
	path_copy_sockaddr(&n->peer_udp.challenge.endpoint, sa);
	n->peer_udp.challenge.nonce = nonce;
	n->peer_udp.challenge.session_id = n->session_id;
	n->peer_udp.challenge.network_epoch = mesh->lan_network_epoch;
	n->peer_udp.challenge.demand_epoch = n->peer_udp.demand_epoch;
	n->peer_udp.challenge.deadline = mesh->loop.now;
	n->peer_udp.challenge.deadline.tv_sec += PATH_PROMOTION_DEADLINE_SEC;
	path_punch_last_probe_valid = true;
	path_copy_sockaddr(&path_punch_last_probe, sa);
	path_punch_log_at(mesh, n, "Punch challenge for %s: %s port %s source=%s", sa, prov);

	if(n->devtool_force_meta) {
		return;
	}

	path_punch_emit(mesh, n);
	path_punch_rearm(mesh, n);
}

static void path_punch_fail(meshlink_handle_t *mesh, node_t *n) {
	punch_provenance_t prov = n->peer_udp.challenge.provenance;
	sockaddr_t ep;

	path_copy_sockaddr(&ep, &n->peer_udp.challenge.endpoint);
	path_punch_log_at(mesh, n, "Punch challenge failed for %s at %s port %s source=%s", &ep, prov);
	path_punch_disarm(mesh, n);

	if(prov == PUNCH_PROV_AUTH_INGRESS) {
		path_copy_sockaddr(&n->peer_udp.failed_ingress, &ep);

		if(!n->peer_udp.hint_failed && path_punch_endpoint_usable(&n->peer_udp.last_hint)) {
			path_punch_begin(mesh, n, &n->peer_udp.last_hint, PUNCH_PROV_NMN_HINT);
			return;
		}
	} else if(prov == PUNCH_PROV_NMN_HINT) {
		n->peer_udp.hint_failed = true;
	}

	send_punch_bootstrap(mesh, n);
}

void path_punch_challenge_timeout(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	if(!path_punch_challenge_current(mesh, n)) {
		path_punch_cancel(mesh, n);
		return;
	}

	if(n->peer_udp.challenge.attempts >= PATH_PUNCH_CHALLENGE_ATTEMPTS
	                || timespec_after_or_equal(&mesh->loop.now, &n->peer_udp.challenge.deadline)) {
		path_punch_fail(mesh, n);
		return;
	}

	if(n->devtool_force_meta) {
		return;
	}

	path_punch_emit(mesh, n);
	path_punch_rearm(mesh, n);
}

static bool path_punch_ingress_remembered(const meshlink_handle_t *mesh, const node_t *n) {
	if(!path_punch_ingress_usable(&n->peer_udp.ingress)) {
		return false;
	}

	if(n->session_id && n->peer_udp.ingress_session && n->peer_udp.ingress_session != n->session_id) {
		return false;
	}

	if(n->peer_udp.ingress_network_epoch != mesh->lan_network_epoch) {
		return false;
	}

	if(n->peer_udp.ingress_demand_epoch != n->peer_udp.demand_epoch) {
		return false;
	}

	if(n->peer_udp.failed_ingress.sa.sa_family && !sockaddrcmp(&n->peer_udp.failed_ingress, &n->peer_udp.ingress)) {
		return false;
	}

	return true;
}

static void path_punch_note_demotion(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || n->status.udp_confirmed || !path_peer_udp_punching_allowed(mesh, n)) {
		return;
	}

	/* Remembered ingress outranks a hint. Neither is written to n->address. */
	if(path_punch_ingress_remembered(mesh, n)) {
		path_punch_begin(mesh, n, &n->peer_udp.ingress, PUNCH_PROV_AUTH_INGRESS);
		return;
	}

	if(path_punch_endpoint_usable(&n->peer_udp.last_hint)) {
		n->peer_udp.hint_failed = false;
		path_punch_begin(mesh, n, &n->peer_udp.last_hint, PUNCH_PROV_NMN_HINT);
		return;
	}

	send_punch_bootstrap(mesh, n);
}

void path_observe_punch_ingress(meshlink_handle_t *mesh, node_t *node, const sockaddr_t *endpoint) {
	sockaddr_t ep;

	if(!mesh || !node || !endpoint || !path_is_ordinary_peer_pair(mesh, node)) {
		return;
	}

	/* path_copy_sockaddr() clears dst before reading src. Snapshot first so a
	   caller can pass peer_udp.ingress itself. */
	memcpy(&ep, endpoint, sizeof ep);

	if(!path_punch_ingress_usable(&ep) || node->status.udp_confirmed) {
		return;
	}

	path_copy_sockaddr(&node->peer_udp.ingress, &ep);
	node->peer_udp.ingress_session = node->session_id;
	node->peer_udp.ingress_demand_epoch = node->peer_udp.demand_epoch;
	node->peer_udp.ingress_network_epoch = mesh->lan_network_epoch;
	node_udp_cache_alias(mesh, node, &ep);

	if(!node->status.validkey || !path_peer_udp_punching_allowed(mesh, node)) {
		return;
	}

	if(path_punch_challenge_current(mesh, node)
	                && node->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS
	                && !sockaddrcmp(&node->peer_udp.challenge.endpoint, &ep)) {
		return;
	}

	if(node->peer_udp.failed_ingress.sa.sa_family && !sockaddrcmp(&node->peer_udp.failed_ingress, &ep)) {
		return;
	}

	path_punch_begin(mesh, node, &ep, PUNCH_PROV_AUTH_INGRESS);
}

void path_punch_arm_ingress(meshlink_handle_t *mesh, node_t *node) {
	if(!mesh || !node || !node->peer_udp.ingress.sa.sa_family) {
		return;
	}

	if(node->peer_udp.ingress_session && node->session_id
	                && node->peer_udp.ingress_session != node->session_id) {
		return;
	}

	path_observe_punch_ingress(mesh, node, &node->peer_udp.ingress);
}

bool path_punch_accept_reply(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce) {
	sockaddr_t ep;
	char *address = NULL;
	char *port = NULL;

	if(!path_punch_challenge_current(mesh, n) || !from || !nonce) {
		return false;
	}

	if(nonce != n->peer_udp.challenge.nonce || sockaddrcmp(from, &n->peer_udp.challenge.endpoint)) {
		return false;
	}

	punch_provenance_t prov = n->peer_udp.challenge.provenance;

	path_copy_sockaddr(&ep, &n->peer_udp.challenge.endpoint);
	path_punch_disarm(mesh, n);
	memset(&n->peer_udp.failed_ingress, 0, sizeof n->peer_udp.failed_ingress);
	update_node_udp_from(mesh, n, &ep, ADDR_SRC_UDP_REFLEXIVE);
	n->status.udp_confirmed = true;
	path_punch_log_at(mesh, n, "Punch confirmed %s at %s port %s source=%s", &ep, prov);

	/* Authenticated ingress is local. Only a public rendezvous confirmation
	   is still advertised, and only when that endpoint is eligible to export. */
	if(prov != PUNCH_PROV_AUTH_INGRESS && path_punch_endpoint_usable(&ep)) {
		path_punch_ans_exports++;

		if(n->status.reachable && n->nexthop && n->nexthop->connection && n->nexthop->connection->socket >= 0) {
			sockaddr2str(&n->address, &address, &port);

			if(address && port) {
				send_request(mesh, n->nexthop->connection, NULL, "%d %s %s . -1 -1 -1 0 %s %s", ANS_KEY, n->name, n->name, address, port);
			}

			free(address);
			free(port);
		}
	}

	path_note_udp_confirmed(mesh, n);
	send_mtu_probe(mesh, n);
	return true;
}

static void path_confirm_remembered_udp(meshlink_handle_t *mesh, node_t *n) {
	if(n->address.sa.sa_family && !path_address_is_local(&n->address)) {
		char *address = NULL;
		char *port = NULL;

		sockaddr2str(&n->address, &address, &port);

		if(address && port && n->nexthop && n->nexthop->connection) {
			send_request(mesh, n->nexthop->connection, NULL, "%d %s %s . -1 -1 -1 0 %s %s", ANS_KEY, n->name, n->name, address, port);
		} else {
			logger(mesh, MESHLINK_WARNING, "Cannot send reflexive address to %s via %s", n->name, n->nexthop ? n->nexthop->name : n->name);
		}

		free(address);
		free(port);
	}

	n->status.udp_confirmed = true;

	if(n->address.sa.sa_family != AF_UNSPEC && node_add_recent_address_cap(mesh, n, &n->address, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP)) {
		n->upgrade_recent_idx = 0;
	}

	path_note_udp_confirmed(mesh, n);
	try_upgrade_probe(mesh, n);
}

bool path_try_confirm_udp_probe_reply(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce) {
	if(!mesh || !n || !from || n->status.udp_confirmed) {
		return false;
	}

	/* A public source is recorded before any accept. That arms or continues
	   AUTH_INGRESS, including over a rendezvous hint for the same address,
	   so the hint cannot confirm ahead of the source we actually received.
	   A repeat of that ingress challenge is what commits. */
	if(path_peer_udp_punching_allowed(mesh, n) && !path_address_is_local(from)) {
		path_observe_punch_ingress(mesh, n, from);
		path_punch_accept_reply(mesh, n, from, nonce);
		return true;
	}

	/* A live private or link-local challenge is the only way this reply can
	   confirm. A nonce-zero echo or a different source must not fall through
	   to the legacy path, and it must not retarget the challenge. */
	if(path_punch_challenge_current(mesh, n)) {
		path_punch_accept_reply(mesh, n, from, nonce);
		return true;
	}

	if(path_peer_udp_punching_allowed(mesh, n)) {
		if(path_address_is_local(from) && nonce == 0) {
			/* from may alias n->last_udp_from, which update forgets before it copies. */
			sockaddr_t ep;

			path_copy_sockaddr(&ep, from);
			update_node_udp_from(mesh, n, &ep, ADDR_SRC_UDP_REFLEXIVE);
			n->status.udp_confirmed = true;

			if(n->address.sa.sa_family != AF_UNSPEC && node_add_recent_address_cap(mesh, n, &n->address, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP)) {
				n->upgrade_recent_idx = 0;
			}

			path_note_udp_confirmed(mesh, n);
			try_upgrade_probe(mesh, n);
			return false;
		}

		return true;
	}

	path_confirm_remembered_udp(mesh, n);
	return false;
}

bool path_unconfirmed_punch_dest(const meshlink_handle_t *mesh, const node_t *n, sockaddr_t *out) {
	const sockaddr_t *ep;

	if(!n || !out || n->status.udp_confirmed) {
		return false;
	}

	if(mesh && path_punch_challenge_current(mesh, n)) {
		ep = &n->peer_udp.challenge.endpoint;

		if(n->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS ? path_punch_ingress_usable(ep) : path_punch_endpoint_usable(ep)) {
			path_copy_sockaddr(out, ep);
			return true;
		}
	}

	if(n->peer_udp.hint_failed || !n->peer_udp.last_hint.sa.sa_family || !path_punch_endpoint_usable(&n->peer_udp.last_hint)) {
		return false;
	}

	path_copy_sockaddr(out, &n->peer_udp.last_hint);
	return true;
}

static bool pending_hint_same(const node_t *node, const sockaddr_t *sa) {
	return node->peer_udp.pending_hint.sa.sa_family && !sockaddrcmp(&node->peer_udp.pending_hint, sa);
}

static void stage_pending_punch_hint(meshlink_handle_t *mesh, node_t *node, const sockaddr_t *sa) {
	char *host = NULL;
	char *port = NULL;

	path_copy_sockaddr(&node->peer_udp.pending_hint, sa);
	node->peer_udp.pending_hint_at = mesh->loop.now;
	node->peer_udp.pending_hint_session = node->session_id;
	node->peer_udp.pending_hint_demand_epoch = node->peer_udp.demand_epoch;

	if(mesh->log_level <= MESHLINK_INFO) {
		sockaddr_t logged;

		path_copy_sockaddr(&logged, sa);
		sockaddr2str(&logged, &host, &port);
		logger(mesh, MESHLINK_INFO, "Staged punch hint from %s: %s port %s validkey=%s",
		       node->name, host, port, node->status.validkey ? "yes" : "no");
		free(host);
		free(port);
	}
}

void path_apply_pending_punch_hint(meshlink_handle_t *mesh, node_t *node) {
	sockaddr_t sa;
	int64_t age;

	if(!mesh || !node || !node->peer_udp.pending_hint.sa.sa_family) {
		return;
	}

	age = timespec_ms_between(&node->peer_udp.pending_hint_at, &mesh->loop.now);

	if(age > (int64_t)PATH_UDP_OBSERVATION_FRESH_SEC * 1000
	                || (node->session_id && node->peer_udp.pending_hint_session
	                    && node->peer_udp.pending_hint_session != node->session_id)
	                || node->peer_udp.pending_hint_demand_epoch != node->peer_udp.demand_epoch
	                || !path_peer_udp_punching_allowed(mesh, node)) {
		logger(mesh, MESHLINK_INFO, "Dropping staged punch hint for %s", node->name);
		path_clear_pending_punch_hint(node);
		return;
	}

	if(!node->status.validkey) {
		return;
	}

	path_copy_sockaddr(&sa, &node->peer_udp.pending_hint);
	logger(mesh, MESHLINK_INFO, "Applying staged punch hint for %s", node->name);
	path_clear_pending_punch_hint(node);
	path_note_punch_endpoint(mesh, node, &sa);
}

void path_note_punch_endpoint(meshlink_handle_t *mesh, node_t *node, const sockaddr_t *sa) {
	bool confirmed;
	bool same;
	bool already;
	char *host;
	char *port;

	if(!mesh || !node || !sa) {
		return;
	}

	if(!path_peer_udp_punching_allowed(mesh, node) || !path_punch_endpoint_usable(sa)) {
		return;
	}

	already = pending_hint_same(node, sa);

	if(!already) {
		stage_pending_punch_hint(mesh, node, sa);
	} else if(!node->status.validkey) {
		/* Same destination, still no key. Keep the ladder parked and slide the
		   freshness window forward so a repeated hint does not expire early. */
		node->peer_udp.pending_hint_at = mesh->loop.now;
		node->peer_udp.pending_hint_session = node->session_id;
		node->peer_udp.pending_hint_demand_epoch = node->peer_udp.demand_epoch;
		return;
	}

	if(!node->status.validkey) {
		return;
	}

	path_clear_pending_punch_hint(node);

	if(mesh->log_level <= MESHLINK_INFO) {
		sockaddr_t logged;

		path_copy_sockaddr(&logged, sa);
		sockaddr2str(&logged, &host, &port);
		logger(mesh, MESHLINK_INFO, "Using punch hint from %s: %s port %s", node->name, host, port);
		free(host);
		free(port);
	}

	confirmed = node->status.udp_confirmed && node->address.sa.sa_family != AF_UNSPEC;
	same = confirmed && !sockaddrcmp(&node->address, sa);
	path_learn_address_cap(mesh, node, sa, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP);

	if(confirmed && !same) {
		logger(mesh, MESHLINK_INFO, "Keeping confirmed UDP endpoint of %s; punch hint stored", node->name);
		path_punch_note_hint(mesh, node, sa);
		return;
	}

	if(!confirmed) {
		bool same_hint = node->peer_udp.last_hint.sa.sa_family && !sockaddrcmp(&node->peer_udp.last_hint, sa);

		/* A moving hint may be tried later. It does not replace an in-flight
		   peer-reflexive challenge, and it is not written into n->address. */
		if(!same_hint) {
			node->peer_udp.hint_failed = false;
		}

		path_punch_note_hint(mesh, node, sa);

		if(path_punch_challenge_current(mesh, node)
		                && node->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS) {
			logger(mesh, MESHLINK_INFO, "Keeping peer-reflexive challenge of %s; punch hint stored", node->name);
			return;
		}

		if(path_punch_challenge_current(mesh, node)
		                && node->peer_udp.challenge.provenance == PUNCH_PROV_NMN_HINT
		                && !sockaddrcmp(&node->peer_udp.challenge.endpoint, sa)) {
			return;
		}

		if(node->peer_udp.hint_failed && same_hint) {
			return;
		}

		path_punch_begin(mesh, node, sa, PUNCH_PROV_NMN_HINT);
		return;
	}

	path_punch_note_hint(mesh, node, sa);
}

void path_peer_ensure_udp_key(meshlink_handle_t *mesh, node_t *peer) {
	if(!mesh || !peer) {
		return;
	}

	if(!peer->status.reachable || peer->status.validkey) {
		return;
	}

	if(peer->status.waitingforkey) {
		node_kex_consider(mesh, peer);
		return;
	}

	if(!connection_policy_backbone_udp_required(mesh, peer)
	                && !path_peer_udp_punching_allowed(mesh, peer)) {
		return;
	}

	send_req_key(mesh, peer);
}

static void path_peer_udp_stop(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	path_punch_cancel(mesh, n);
	memset(&n->peer_udp.ingress, 0, sizeof n->peer_udp.ingress);
	n->peer_udp.ingress_session = 0;
	n->peer_udp.ingress_demand_epoch = 0;
	n->peer_udp.ingress_network_epoch = 0;
	timeout_del(&mesh->loop, &n->mtutimeout);
	timeout_del(&mesh->loop, &n->promotion_timer);
	memset(&n->promotion_candidate, 0, sizeof n->promotion_candidate);
	path_suspect_stop(mesh, n);
	n->status.want_udp = false;
	memset(&n->peer_udp.idle_until, 0, sizeof n->peer_udp.idle_until);
	path_punch_reset_schedule(n);
	memset(&n->peer_udp.last_hint, 0, sizeof n->peer_udp.last_hint);
	path_clear_pending_punch_hint(n);
	path_scheduler_cancel(mesh, n, PATH_TX_CHANNEL_PROMOTION);
	path_scheduler_cancel(mesh, n, PATH_TX_LIVENESS);
	path_scheduler_cancel(mesh, n, PATH_TX_PMTU_INCREASE);
	path_note_udp_demoted_reason(mesh, n, "peer demand idle");
}

bool path_channel_acquire(meshlink_handle_t *mesh, node_t *peer) {
	bool first;

	if(!path_is_ordinary_peer_pair(mesh, peer)) {
		return false;
	}

	first = !peer->peer_udp.channel_count;
	peer->peer_udp.channel_count++;

	if(!first) {
		return true;
	}

	memset(&peer->peer_udp.idle_until, 0, sizeof peer->peer_udp.idle_until);
	path_peer_ensure_udp_key(mesh, peer);
	path_punch_on_new_demand(mesh, peer);

	if(!path_peer_udp_punching_allowed(mesh, peer)) {
		return true;
	}

	path_punch_arm_ingress(mesh, peer);
	path_consider_promotion(mesh, peer, PATH_PROMOTION_TICK);

	/* WAN punch stays on the challenge. A local address has nothing to punch
	   and still discovers PMTU from the channel. */
	if(path_address_is_local(&peer->address)) {
		send_mtu_probe(mesh, peer);
	}

	return true;
}

void path_channel_release(meshlink_handle_t *mesh, node_t *peer) {
	if(!mesh || !peer || !peer->peer_udp.channel_count) {
		return;
	}

	peer->peer_udp.channel_count--;

	if(peer->peer_udp.channel_count) {
		return;
	}

	if(path_is_ordinary_peer_pair(mesh, peer)) {
		peer->peer_udp.idle_until = mesh->loop.now;
		peer->peer_udp.idle_until.tv_sec += PATH_PEER_UDP_GRACE_SEC;
	} else {
		path_peer_udp_stop(mesh, peer);
	}
}

static void path_log_validation_source(meshlink_handle_t *mesh, const node_t *n, const sockaddr_t *sa,
                                       const char *action, const char *detail, address_source_t src) {
	char buf[160];

	if(detail && detail[0]) {
		snprintf(buf, sizeof buf, "%s source=%s", detail, address_source_name(src));
	} else {
		snprintf(buf, sizeof buf, "source=%s", address_source_name(src));
	}

	path_log_validation(mesh, n, sa, action, buf);
}

void path_consider_promotion(meshlink_handle_t *mesh, node_t *n, path_promotion_reason_t reason) {
	if(!mesh || !n || n->mesh != mesh) {
		return;
	}

	if(!path_peer_udp_punching_allowed(mesh, n)) {
		return;
	}

	route_candidate_t *c = &n->promotion_candidate;
	bool replace_carrier = false;

	if(c->active) {
		if((reason != PATH_PROMOTION_HINT && reason != PATH_PROMOTION_DISCOVERY
		                && reason != PATH_PROMOTION_AUTH_DIRECT)
		                || c->nonce
		                || c->kind != DATA_ROUTE_DIRECT_UDP) {
			return;
		}

		replace_carrier = true;
	}

	if(!n->status.udp_confirmed || n->udp_tier != PATH_TIER_DIRECT_WAN_UDP) {
		return;
	}

	path_endpoint_t better;

	if(!path_pick_local_udp_candidate(mesh, n, &better)) {
		return;
	}

	if(path_retry_is_endpoint(n, &better.address)
	                && path_cooldown_outstanding(mesh, n)) {
		address_source_t src = path_promotion_observation_source(reason);

		if(src != ADDR_SRC_UNKNOWN && path_retry_epoch_is_new(mesh, n, &better.address, src)) {
			path_candidate_clear_cooldown_from(mesh, n, src);
		}

		return;
	}

	if(replace_carrier) {
		path_candidate_discard(mesh, n);
	}

	/* Retrying the endpoint that already failed keeps its place on the
	   escalation ladder. A different endpoint starts with a clean record. */
	if(n->candidate_retry.endpoint.sa.sa_family && sockaddrcmp(&n->candidate_retry.endpoint, &better.address)) {
		memset(&n->candidate_retry, 0, sizeof n->candidate_retry);
	}

	if(!path_scheduler_begin_transaction(mesh, n, PATH_TXN_PROMOTION, PATH_TX_CHANNEL_PROMOTION, path_transaction_preempt)) {
		return;
	}

	memset(c, 0, sizeof *c);
	c->active = true;
	c->kind = DATA_ROUTE_DIRECT_UDP;
	path_copy_sockaddr(&c->endpoint, &better.address);
	c->source = better.source;
	c->capability = better.capability;
	c->local = path_address_is_local(&better.address);
	c->nonce = path_fresh_nonce();
	c->deadline = mesh->loop.now;
	c->deadline.tv_sec += PATH_PROMOTION_DEADLINE_SEC;

	path_log_validation_source(mesh, n, &better.address, "candidate-start",
	                           path_promotion_reason_name(reason), better.source);
	path_promotion_timer_arm(mesh, n, &(struct timespec) {
		0, 0
	});
}

static int path_carrier_rank(data_route_kind_t kind, relay_carrier_t carrier, bool local) {
	switch(kind) {
	case DATA_ROUTE_DIRECT_UDP:
		return local ? 0 : 1;

	case DATA_ROUTE_DIRECT_LOCAL_META:
		return local ? 2 : 6;

	case DATA_ROUTE_RELAY:
		if(carrier == RELAY_CARRIER_UDP) {
			return 3;
		}

		if(carrier == RELAY_CARRIER_META_DIRECT) {
			return 4;
		}

		return 5;

	case DATA_ROUTE_NONE:
	default:
		return 7;
	}
}

/* True when a live direct UDP or local META carrier strictly outranks the candidate. */
static bool path_carrier_outranked(meshlink_handle_t *mesh, node_t *n, const route_candidate_t *c) {
	path_target_t live;
	int cand;
	int live_rank;

	if(!mesh || !n || !c || !c->active) {
		return false;
	}

	cand = path_carrier_rank(c->kind, c->relay_carrier, c->local);
	memset(&live, 0, sizeof live);

	if(path_fill_direct_udp(mesh, n, &live)) {
		live_rank = path_carrier_rank(live.kind, live.relay_carrier, live.local);

		if(live_rank < cand) {
			return true;
		}
	}

	memset(&live, 0, sizeof live);

	if(path_fill_local_meta(mesh, n, &live)) {
		live_rank = path_carrier_rank(live.kind, live.relay_carrier, live.local);

		if(live_rank < cand) {
			return true;
		}
	}

	return false;
}

static const char *path_route_promotion_name(path_route_promotion_t which) {
	switch(which) {
	case PATH_PROMOTION_DIRECT_UDP:
		return "direct-udp";

	case PATH_PROMOTION_BACKBONE_UDP:
		return "backbone-udp";

	case PATH_PROMOTION_LOCAL_META:
		return "local-meta";

	case PATH_PROMOTION_META_DIRECT:
		return "meta-direct";

	default:
		return "unknown";
	}
}

void path_consider_route_promotion(meshlink_handle_t *mesh, node_t *n, path_route_promotion_t which) {
	path_target_t proposed;
	route_candidate_t *c;
	int have;
	int want;

	if(!mesh) {
		return;
	}

	if(!n) {
		path_consider_demanded_route_promotions(mesh, which);
		return;
	}

	if(n->mesh && n->mesh != mesh) {
		return;
	}

	if(n->active_route.kind == DATA_ROUTE_NONE) {
		return;
	}

	if(!path_peer_udp_demanded(mesh, n)) {
		return;
	}

	c = &n->promotion_candidate;
	memset(&proposed, 0, sizeof proposed);

	switch(which) {
	case PATH_PROMOTION_DIRECT_UDP:
		if(!path_fill_direct_udp(mesh, n, &proposed)) {
			return;
		}

		break;

	case PATH_PROMOTION_BACKBONE_UDP:
		if(!path_fill_relay_udp(mesh, n, &proposed)) {
			return;
		}

		break;

	case PATH_PROMOTION_LOCAL_META:
		if(!path_fill_local_meta(mesh, n, &proposed)) {
			return;
		}

		break;

	case PATH_PROMOTION_META_DIRECT:
		if(!path_fill_relay_meta(mesh, n, &proposed)
		                || proposed.relay_carrier != RELAY_CARRIER_META_DIRECT) {
			return;
		}

		break;

	default:
		return;
	}

	have = path_carrier_rank(n->active_route.kind, n->active_route.relay_carrier, n->active_route.local);
	want = path_carrier_rank(proposed.kind, proposed.relay_carrier, proposed.local);

	if(want >= have) {
		return;
	}

	/* Strictly better carrier replaces a lower candidate immediately.
	   Equal or worse keeps it. Local UDP is rank 0, so WAN and relay cannot
	   supersede a local-UDP candidate. */
	if(c->active) {
		int cand = path_carrier_rank(c->kind, c->relay_carrier, c->local);

		if(want >= cand) {
			return;
		}

		path_candidate_discard(mesh, n);
	}

	if(!path_scheduler_begin_transaction(mesh, n, PATH_TXN_PROMOTION, PATH_TX_CHANNEL_PROMOTION, path_transaction_preempt)) {
		return;
	}

	memset(c, 0, sizeof *c);
	c->active = true;
	c->kind = proposed.kind;
	c->relay_carrier = proposed.relay_carrier;
	c->first_hop = proposed.first_hop;
	c->local = proposed.local;
	c->source = proposed.endpoint_source;
	path_copy_sockaddr(&c->endpoint, &proposed.udp_endpoint);
	c->successful_rounds = PATH_PROMOTION_ROUNDS;
	c->first_success = mesh->loop.now;
	path_log_validation_source(mesh, n, proposed.udp_endpoint.sa.sa_family ? &proposed.udp_endpoint : NULL,
	                           "candidate-start", path_route_promotion_name(which), c->source);
}

static void path_consider_demanded_route_promotions(meshlink_handle_t *mesh, path_route_promotion_t which) {
	if(!mesh || !mesh->nodes) {
		return;
	}

	for splay_each(node_t, dest, mesh->nodes) {
		if(dest == mesh->self
		                || dest->active_route.kind == DATA_ROUTE_NONE
		                || !path_peer_udp_demanded(mesh, dest)) {
			continue;
		}

		path_consider_route_promotion(mesh, dest, which);
	}
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

static bool path_target_matches_candidate(const route_candidate_t *c, const path_target_t *t) {
	if(!c || !t) {
		return false;
	}

	if(c->kind != t->kind
	                || c->relay_carrier != t->relay_carrier
	                || c->first_hop != t->first_hop
	                || c->local != t->local
	                || c->source != t->endpoint_source) {
		return false;
	}

	return !sockaddrcmp(&c->endpoint, &t->udp_endpoint);
}

/* Commit is a pure endpoint swap for future records: the node session, its
   channels and its UDP proof all stay exactly as they are. */
void path_commit_candidate(meshlink_handle_t *mesh, node_t *n) {
	route_candidate_t *c;
	path_target_t target;
	sockaddr_t endpoint;
	int have;
	int want;

	if(!mesh || !n) {
		return;
	}

	c = &n->promotion_candidate;

	if(path_carrier_outranked(mesh, n, c)) {
		path_log_validation(mesh, n, c->endpoint.sa.sa_family ? &c->endpoint : NULL,
		                    "candidate-dropped", "better carrier");
		path_candidate_discard(mesh, n);
		path_consider_route_promotion(mesh, n, PATH_PROMOTION_DIRECT_UDP);
		path_consider_route_promotion(mesh, n, PATH_PROMOTION_LOCAL_META);
		return;
	}

	endpoint = c->endpoint;
	memset(&target, 0, sizeof target);

	/* nonce == 0 is an already-live carrier; a nonzero nonce is probe-proven. */
	if(c->kind == DATA_ROUTE_DIRECT_UDP && !c->nonce) {
		if(!path_fill_direct_udp(mesh, n, &target) || !path_target_matches_candidate(c, &target)) {
			path_candidate_discard(mesh, n);
			return;
		}
	} else if(c->kind == DATA_ROUTE_DIRECT_UDP) {
		target.kind = DATA_ROUTE_DIRECT_UDP;
		path_copy_sockaddr(&target.udp_endpoint, &endpoint);
		target.endpoint_source = c->source;
		target.local = path_udp_tier_for(&endpoint, c->source) == PATH_TIER_DIRECT_LOCAL_UDP;
	} else if(c->kind == DATA_ROUTE_DIRECT_LOCAL_META) {
		if(!path_fill_local_meta(mesh, n, &target) || !path_target_matches_candidate(c, &target)) {
			path_candidate_discard(mesh, n);
			return;
		}
	} else if(c->kind == DATA_ROUTE_RELAY && c->relay_carrier == RELAY_CARRIER_UDP) {
		if(!path_fill_relay_udp(mesh, n, &target) || !path_target_matches_candidate(c, &target)) {
			path_candidate_discard(mesh, n);
			return;
		}
	} else if(c->kind == DATA_ROUTE_RELAY && c->relay_carrier == RELAY_CARRIER_META_DIRECT) {
		if(!path_fill_relay_meta(mesh, n, &target) || !path_target_matches_candidate(c, &target)) {
			path_candidate_discard(mesh, n);
			return;
		}
	} else {
		path_candidate_discard(mesh, n);
		return;
	}

	have = path_carrier_rank(n->active_route.kind, n->active_route.relay_carrier, n->active_route.local);
	want = path_carrier_rank(target.kind, target.relay_carrier, target.local);

	if(want >= have) {
		path_candidate_discard(mesh, n);
		return;
	}

	if(target.kind == DATA_ROUTE_DIRECT_UDP) {
		path_endpoint_t ep;
		address_source_t src = c->source;
		path_cap_t cap = c->capability;

		memset(&ep, 0, sizeof ep);
		path_copy_sockaddr(&ep.address, &endpoint);
		ep.source = src;
		ep.capability = cap;

		if(!path_install_committed_udp(mesh, n, &ep)) {
			path_log_validation_source(mesh, n, &endpoint, "candidate-dropped", "endpoint install rejected", src);
			path_candidate_discard(mesh, n);
			return;
		}

		path_retry_clear_if_endpoint(n, &target.udp_endpoint);
		path_candidate_discard(mesh, n);
		path_log_validation_source(mesh, n, &endpoint, "candidate-promoted", "validated", src);
		path_commit_active_route(n, &target, &mesh->loop.now);
		return;
	}

	{
		address_source_t src = c->source;

		path_candidate_discard(mesh, n);
		path_log_validation_source(mesh, n, endpoint.sa.sa_family ? &endpoint : NULL, "candidate-promoted", "validated", src);
		path_commit_active_route(n, &target, &mesh->loop.now);
	}
}

static bool path_suspect_begin_epoch(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *endpoint);
static void suspect_timer_handler(event_loop_t *loop, void *data);
static void path_suspect_expire(meshlink_handle_t *mesh, node_t *n);

static void path_suspect_timer_arm(meshlink_handle_t *mesh, node_t *n, const struct timespec *tv) {
	struct timespec when = tv ? *tv : (struct timespec) {
		0, 0
	};

	if(!n->suspect_validation.timer.cb) {
		timeout_add(&mesh->loop, &n->suspect_validation.timer, suspect_timer_handler, n, &when);
	} else {
		timeout_set(&mesh->loop, &n->suspect_validation.timer, &when);
	}

	if(mesh->threadstarted && mesh->loop.pipefd[1] != -1 && !pthread_equal(mesh->thread, pthread_self())) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

void path_suspect_stop(meshlink_handle_t *mesh, node_t *n) {
	if(!n) {
		return;
	}

	if(mesh) {
		timeout_del(&mesh->loop, &n->suspect_validation.timer);
		path_scheduler_cancel(mesh, n, PATH_TX_ACTIVE_ROUTE_RECOVERY);
	}

	memset(&n->suspect_validation, 0, sizeof n->suspect_validation);
}

static void path_suspect_send_packet(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	send_suspect_probe(mesh, req->node);
}

static void path_suspect_send(meshlink_handle_t *mesh, node_t *n) {
	path_probe_request_t req;

	memset(&req, 0, sizeof req);
	req.node = n;
	req.length = PATH_PROMOTION_PROBE_LEN;
	req.priority = PATH_TX_ACTIVE_ROUTE_RECOVERY;
	req.send = path_suspect_send_packet;
	(void)path_scheduler_emit_packet(mesh, path_scheduler_begin_transaction(mesh, n, PATH_TXN_SUSPECT, PATH_TX_ACTIVE_ROUTE_RECOVERY, path_transaction_preempt), &req);
}

static bool path_suspect_begin_epoch(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *endpoint) {
	path_suspect_stop(mesh, n);

	if(!path_scheduler_begin_transaction(mesh, n, PATH_TXN_SUSPECT, PATH_TX_ACTIVE_ROUTE_RECOVERY, path_transaction_preempt)) {
		return false;
	}

	n->suspect_validation.active = true;
	path_copy_sockaddr(&n->suspect_validation.endpoint, endpoint);
	n->suspect_validation.nonce = path_fresh_nonce();
	path_suspect_set_deadline(mesh, &n->suspect_validation);
	path_suspect_timer_arm(mesh, n, &(struct timespec) {
		0, 0
	});
	return true;
}

static void path_suspect_reopen_epoch(meshlink_handle_t *mesh, node_t *n) {
	suspect_validation_t *s = &n->suspect_validation;

	s->nonce = path_fresh_nonce();
	s->probes_sent = 0;
	s->replies_received = 0;
	path_suspect_set_deadline(mesh, s);
	n->active_route.suspect_at = mesh->loop.now;
	path_log_validation(mesh, n, &s->endpoint, "route-degraded", "no live fallback, still probing");
	path_suspect_timer_arm(mesh, n, &(struct timespec) {
		0, 0
	});
}

static void path_suspect_mark_route(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	n->active_route.suspect = true;
	n->active_route.suspect_at = mesh->loop.now;
	memset(&n->active_route.healthy_since, 0, sizeof n->active_route.healthy_since);
	path_log_validation(mesh, n, &n->active_route.udp_endpoint, "route-suspect", reason ? reason : "");
}

static bool path_route_depends_on_hop_udp(const node_t *dest, const node_t *hop) {
	if(!dest || !hop || dest == hop || !dest->active_route.suspect) {
		return false;
	}

	if(dest->active_route.kind != DATA_ROUTE_RELAY
	                || dest->active_route.relay_carrier != RELAY_CARRIER_UDP
	                || dest->active_route.first_hop != hop) {
		return false;
	}

	if(hop->suspect_validation.active) {
		return !sockaddrcmp(&dest->active_route.udp_endpoint, &hop->suspect_validation.endpoint);
	}

	return true;
}

static bool path_suspect_any_dependent_fallback(meshlink_handle_t *mesh, node_t *hop) {
	if(!mesh || !hop || !mesh->nodes) {
		return false;
	}

	for splay_each(node_t, dest, mesh->nodes) {
		if(path_route_depends_on_hop_udp(dest, hop) && path_has_live_fallback(mesh, dest)) {
			return true;
		}
	}

	return false;
}

static void path_suspect_commit_fallback(meshlink_handle_t *mesh, node_t *n) {
	path_target_t target;

	if(!n) {
		return;
	}

	if(n->promotion_candidate.active) {
		path_candidate_discard(mesh, n);
	}

	n->active_route.suspect = false;

	if(n->active_route.kind == DATA_ROUTE_DIRECT_UDP) {
		path_note_udp_demoted_reason(mesh, n, "suspect probes unanswered");
	}

	if(path_select_fallback(mesh, n, &target)) {
		path_commit_active_route(n, &target, &mesh->loop.now);
	}
}

static void path_suspect_expire_dependents(meshlink_handle_t *mesh, node_t *hop) {
	if(!mesh || !hop || !mesh->nodes) {
		return;
	}

	for splay_each(node_t, dest, mesh->nodes) {
		if(!path_route_depends_on_hop_udp(dest, hop)) {
			continue;
		}

		if(path_has_live_fallback(mesh, dest)) {
			if(dest->promotion_candidate.active) {
				path_candidate_discard(mesh, dest);
			}

			path_suspect_commit_fallback(mesh, dest);
		}
	}
}

static void path_suspect_expire(meshlink_handle_t *mesh, node_t *n) {
	suspect_validation_t *s;

	if(!mesh || !n) {
		return;
	}

	s = &n->suspect_validation;

	if(!s->active) {
		if(n->active_route.kind == DATA_ROUTE_RELAY
		                && n->active_route.relay_carrier == RELAY_CARRIER_UDP
		                && n->active_route.first_hop) {
			if(n->active_route.first_hop->suspect_validation.active) {
				path_suspect_expire(mesh, n->active_route.first_hop);
			} else if(n->active_route.suspect) {
				path_suspect_begin_epoch(mesh, n->active_route.first_hop, &n->active_route.udp_endpoint);
			}

			return;
		}

		/* No epoch means we never acquired a recovery slot. Retry; never
		   demote without a transaction and probes. */
		if(n->active_route.suspect && !n->promotion_candidate.active
		                && n->active_route.udp_endpoint.sa.sa_family
		                && n->active_route.udp_endpoint.sa.sa_family != AF_UNKNOWN) {
			path_suspect_begin_epoch(mesh, n, &n->active_route.udp_endpoint);
		}

		return;
	}

	/* Suspect failure wins only when a fallback can take over. Discarding
	   the candidate first would destroy the only rescue path on a route
	   that has to reopen the epoch. */
	if(path_has_live_fallback(mesh, n) || path_suspect_any_dependent_fallback(mesh, n)) {
		/* Dependents first. Demoting this hop reranks them and would hide
		   the relay route before their promotions are discarded. */
		path_suspect_expire_dependents(mesh, n);

		if(n->active_route.suspect) {
			path_suspect_commit_fallback(mesh, n);
		} else if(n->status.udp_confirmed) {
			path_note_udp_demoted_reason(mesh, n, "suspect probes unanswered");
		}

		if(s->active) {
			path_suspect_stop(mesh, n);
		}

		return;
	}

	path_suspect_reopen_epoch(mesh, n);
}

static void suspect_timer_handler(event_loop_t *loop, void *data) {
	meshlink_handle_t *mesh = loop->data;
	node_t *n = data;
	suspect_validation_t *s = &n->suspect_validation;
	struct timespec delay;

	if(!s->active) {
		path_suspect_stop(mesh, n);
		return;
	}

	if(timespec_after_or_equal(&mesh->loop.now, &s->deadline)) {
		path_suspect_expire(mesh, n);
		return;
	}

	if(s->probes_sent < PATH_SUSPECT_PROBES) {
		path_suspect_send(mesh, n);
	}

	if(!s->active) {
		return;
	}

	delay = path_suspect_rearm_delay(mesh, s);
	path_suspect_timer_arm(mesh, n, &delay);
}

void path_clear_route_suspicion(meshlink_handle_t *mesh, node_t *n) {
	sockaddr_t ep;

	if(!mesh || !n) {
		return;
	}

	path_copy_sockaddr(&ep, &n->suspect_validation.endpoint);

	if(n->active_route.suspect) {
		n->active_route.suspect = false;
		path_log_validation(mesh, n, ep.sa.sa_family ? &ep : NULL, "suspect-cleared", "probe answered");
		path_note_authenticated_route_success(mesh, n);
	}

	if(mesh->nodes) {
		for splay_each(node_t, dest, mesh->nodes) {
			if(!path_route_depends_on_hop_udp(dest, n)) {
				continue;
			}

			dest->active_route.suspect = false;
			path_log_validation(mesh, dest, ep.sa.sa_family ? &ep : NULL, "suspect-cleared", "hop probe answered");
			path_note_authenticated_route_success(mesh, dest);
		}
	}

	path_suspect_stop(mesh, n);
}

bool path_suspect_probe_target(meshlink_handle_t *mesh, node_t *n, sockaddr_t *out, uint64_t *nonce_out) {
	const suspect_validation_t *s;

	if(!mesh || !n || !out || !nonce_out) {
		return false;
	}

	s = &n->suspect_validation;

	if((!s->active || !s->nonce)
	                && n->active_route.kind == DATA_ROUTE_RELAY
	                && n->active_route.relay_carrier == RELAY_CARRIER_UDP
	                && n->active_route.first_hop) {
		s = &n->active_route.first_hop->suspect_validation;
	}

	if(!s->active || !s->nonce) {
		return false;
	}

	path_copy_sockaddr(out, &s->endpoint);
	*nonce_out = s->nonce;
	return true;
}

void path_observe_probe_reply(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *from, uint64_t nonce) {
	if(!mesh || !n || !from) {
		return;
	}

	if(n == mesh->backbone_udp.node && nonce && nonce == mesh->backbone_udp.liveness_nonce) {
		path_backbone_udp_observe_reply(mesh, n, from, nonce);
		return;
	}

	suspect_validation_t *s = &n->suspect_validation;

	if(s->active && s->nonce && nonce == s->nonce && !sockaddrcmp(from, &s->endpoint)) {
		if(timespec_after_or_equal(&mesh->loop.now, &s->deadline)) {
			return;
		}

		s->replies_received++;
		path_clear_route_suspicion(mesh, n);
		return;
	}

	route_candidate_t *c = &n->promotion_candidate;

	/* A reply on the endpoint we are already using is liveness, not promotion.
	   It must not clear a suspect epoch that this nonce does not belong to. */
	if(n->address.sa.sa_family != AF_UNSPEC && !sockaddrcmp(from, &n->address)) {
		path_note_authenticated_route_success(mesh, n);
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

	path_scheduler_cancel_packets(mesh, n, PATH_TX_CHANNEL_PROMOTION);

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

	if(!path_scheduler_has_transaction(mesh, n, PATH_TXN_PROMOTION)
	                && !path_scheduler_begin_transaction(mesh, n, PATH_TXN_PROMOTION, PATH_TX_CHANNEL_PROMOTION, path_transaction_preempt)) {
		return;
	}

	path_commit_candidate(mesh, n);
}

void path_note_route_suspect(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	node_t *hop;
	const sockaddr_t *ep;

	if(!mesh || !n || n->active_route.suspect) {
		return;
	}

	ep = &n->active_route.udp_endpoint;

	if(ep->sa.sa_family == AF_UNSPEC || ep->sa.sa_family == AF_UNKNOWN) {
		return;
	}

	if(n->active_route.kind == DATA_ROUTE_DIRECT_UDP) {
		if(!path_suspect_begin_epoch(mesh, n, ep)) {
			return;
		}

		path_suspect_mark_route(mesh, n, reason);
		return;
	}

	if(n->active_route.kind != DATA_ROUTE_RELAY
	                || n->active_route.relay_carrier != RELAY_CARRIER_UDP
	                || !n->active_route.first_hop) {
		return;
	}

	hop = n->active_route.first_hop;

	if(hop->suspect_validation.active && !sockaddrcmp(&hop->suspect_validation.endpoint, ep)) {
		path_suspect_mark_route(mesh, n, reason);

		if(hop->active_route.kind == DATA_ROUTE_DIRECT_UDP
		                && !hop->active_route.suspect
		                && !sockaddrcmp(&hop->active_route.udp_endpoint, ep)) {
			path_suspect_mark_route(mesh, hop, reason);
		}

		return;
	}

	if(!path_suspect_begin_epoch(mesh, hop, ep)) {
		return;
	}

	path_suspect_mark_route(mesh, n, reason);

	if(hop->active_route.kind == DATA_ROUTE_DIRECT_UDP
	                && !hop->active_route.suspect
	                && !sockaddrcmp(&hop->active_route.udp_endpoint, ep)) {
		path_suspect_mark_route(mesh, hop, reason);
	}
}

static node_t *path_app_relay_hop(meshlink_handle_t *mesh, const node_t *n) {
	node_t *hop;

	if(!mesh || !n) {
		return NULL;
	}

	if(n->status.forced_relay) {
		hop = n->nexthop;
	} else {
		hop = connection_policy_backbone(mesh);
	}

	if(!hop || hop == mesh->self || hop == n) {
		return NULL;
	}

	if(!n->status.forced_relay && hop->status.conflict_backbone) {
		return NULL;
	}

	return hop;
}

static bool path_target_matches_skip(const data_route_t *skip, const path_target_t *t) {
	if(!skip || skip->kind == DATA_ROUTE_NONE) {
		return false;
	}

	if(skip->kind != t->kind
	                || skip->relay_carrier != t->relay_carrier
	                || skip->first_hop != t->first_hop
	                || skip->local != t->local
	                || skip->endpoint_source != t->endpoint_source) {
		return false;
	}

	return !sockaddrcmp(&skip->udp_endpoint, &t->udp_endpoint);
}

static bool path_fill_direct_udp(meshlink_handle_t *mesh, const node_t *n, path_target_t *out) {
	if(n->devtool_force_meta || n->status.forced_relay) {
		return false;
	}

	if(connection_policy_is_backbone(mesh, n)
	                && mesh->backbone_udp.confirmed
	                && mesh->backbone_udp.endpoint.sa.sa_family
	                && mesh->backbone_udp.endpoint.sa.sa_family != AF_UNKNOWN) {
		out->kind = DATA_ROUTE_DIRECT_UDP;
		path_copy_sockaddr(&out->udp_endpoint, &mesh->backbone_udp.endpoint);
		out->endpoint_source = mesh->backbone_udp.source;
		out->local = path_address_is_local(&mesh->backbone_udp.endpoint);
		return true;
	}

	if(!hop_udp_ready(n) || n->address.sa.sa_family == AF_UNSPEC || n->address.sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	out->kind = DATA_ROUTE_DIRECT_UDP;
	path_copy_sockaddr(&out->udp_endpoint, &n->address);
	out->endpoint_source = n->address_source;
	out->local = n->udp_tier == PATH_TIER_DIRECT_LOCAL_UDP;
	return true;
}

static bool path_fill_local_meta(meshlink_handle_t *mesh, const node_t *n, path_target_t *out) {
	if(!connection_policy_is_local_adjacency(mesh, n)) {
		return false;
	}

	out->kind = DATA_ROUTE_DIRECT_LOCAL_META;
	out->local = true;
	return true;
}

static bool path_fill_relay_udp(meshlink_handle_t *mesh, const node_t *n, path_target_t *out) {
	node_t *hop = path_app_relay_hop(mesh, n);

	if(!hop || n->devtool_force_meta) {
		return false;
	}

	if(mesh->self && n->name && relay_names_unusable(mesh->self->name, n->name)) {
		return false;
	}

	if(!hop_udp_ready(hop)) {
		return false;
	}

	if(!n->status.forced_relay && hop == mesh->backbone_udp.node) {
		if(!mesh->backbone_udp.confirmed
		                || mesh->backbone_udp.endpoint.sa.sa_family == AF_UNSPEC
		                || mesh->backbone_udp.endpoint.sa.sa_family == AF_UNKNOWN) {
			return false;
		}

		out->kind = DATA_ROUTE_RELAY;
		out->relay_carrier = RELAY_CARRIER_UDP;
		out->first_hop = hop;
		path_copy_sockaddr(&out->udp_endpoint, &mesh->backbone_udp.endpoint);
		out->endpoint_source = mesh->backbone_udp.source;
		return true;
	}

	if(hop->address.sa.sa_family == AF_UNSPEC || hop->address.sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	out->kind = DATA_ROUTE_RELAY;
	out->relay_carrier = RELAY_CARRIER_UDP;
	out->first_hop = hop;
	path_copy_sockaddr(&out->udp_endpoint, &hop->address);
	out->endpoint_source = hop->address_source;
	return true;
}

static bool path_fill_relay_meta(meshlink_handle_t *mesh, const node_t *n, path_target_t *out) {
	node_t *hop = path_app_relay_hop(mesh, n);

	if(!hop || !hop->connection || !hop->connection->status.active) {
		return false;
	}

	out->kind = DATA_ROUTE_RELAY;
	out->relay_carrier = path_meta_is_canonical(hop, hop->connection) ? RELAY_CARRIER_META_CANONICAL : RELAY_CARRIER_META_DIRECT;
	out->first_hop = hop;
	return true;
}

static bool path_fill_dest_meta(meshlink_handle_t *mesh, const node_t *n, path_target_t *out) {
	if(connection_policy_is_local_adjacency(mesh, n)) {
		return false;
	}

	if(!n->connection || !n->connection->status.active) {
		return false;
	}

	out->kind = DATA_ROUTE_DIRECT_LOCAL_META;
	out->local = path_address_is_local(&n->connection->address);
	return true;
}

static bool path_rank_carriers(meshlink_handle_t *mesh, node_t *n, const data_route_t *skip, path_target_t *out) {
	memset(out, 0, sizeof *out);

	if(path_fill_direct_udp(mesh, n, out) && !path_target_matches_skip(skip, out)) {
		return true;
	}

	memset(out, 0, sizeof *out);

	if(path_fill_local_meta(mesh, n, out) && !path_target_matches_skip(skip, out)) {
		return true;
	}

	memset(out, 0, sizeof *out);

	if(path_fill_relay_udp(mesh, n, out) && !path_target_matches_skip(skip, out)) {
		return true;
	}

	memset(out, 0, sizeof *out);

	if(path_fill_relay_meta(mesh, n, out) && !path_target_matches_skip(skip, out)) {
		return true;
	}

	memset(out, 0, sizeof *out);

	if(path_fill_dest_meta(mesh, n, out) && !path_target_matches_skip(skip, out)) {
		return true;
	}

	memset(out, 0, sizeof *out);
	return false;
}

static bool path_recorded_usable(const meshlink_handle_t *mesh, const node_t *n) {
	const data_route_t *r = &n->active_route;
	node_t *hop;
	const connection_t *c;

	if(!mesh) {
		return false;
	}

	switch(r->kind) {
	case DATA_ROUTE_DIRECT_UDP:
		if(r->udp_endpoint.sa.sa_family == AF_UNSPEC || r->udp_endpoint.sa.sa_family == AF_UNKNOWN) {
			return false;
		}

		if(n == mesh->backbone_udp.node) {
			return mesh->backbone_udp.confirmed
			       && !sockaddrcmp(&r->udp_endpoint, &mesh->backbone_udp.endpoint);
		}

		return hop_udp_ready(n) && !sockaddrcmp(&r->udp_endpoint, &n->address);

	case DATA_ROUTE_DIRECT_LOCAL_META:
		if(!n->connection || !n->connection->status.active) {
			return false;
		}

		if(r->local) {
			if(!connection_policy_is_local_adjacency(mesh, n)) {
				return false;
			}

			return path_address_is_local(&n->connection->address);
		}

		return true;

	case DATA_ROUTE_RELAY:
		hop = n->status.forced_relay ? n->nexthop : connection_policy_backbone((meshlink_handle_t *)mesh);

		if(!hop || r->first_hop != hop || hop == mesh->self || hop == n) {
			return false;
		}

		if(!n->status.forced_relay && hop->status.conflict_backbone) {
			return false;
		}

		if(r->relay_carrier == RELAY_CARRIER_UDP) {
			if(n->status.forced_relay) {
				return hop_udp_ready(hop)
				       && r->udp_endpoint.sa.sa_family != AF_UNSPEC
				       && r->udp_endpoint.sa.sa_family != AF_UNKNOWN
				       && !sockaddrcmp(&r->udp_endpoint, &hop->address);
			}

			return hop == mesh->backbone_udp.node
			       && mesh->backbone_udp.confirmed
			       && !sockaddrcmp(&r->udp_endpoint, &mesh->backbone_udp.endpoint);
		}

		c = hop->connection;

		if(!c || !c->status.active) {
			return false;
		}

		if(r->relay_carrier == RELAY_CARRIER_META_CANONICAL) {
			return path_meta_is_canonical(hop, c);
		}

		if(r->relay_carrier == RELAY_CARRIER_META_DIRECT) {
			return !path_meta_is_canonical(hop, c);
		}

		return false;

	case DATA_ROUTE_NONE:
	default:
		return false;
	}
}

static void path_route_to_target(const data_route_t *r, path_target_t *out, bool temporary) {
	memset(out, 0, sizeof *out);
	out->kind = r->kind;
	out->relay_carrier = r->relay_carrier;
	out->first_hop = r->first_hop;
	out->local = r->local;
	out->endpoint_source = r->endpoint_source;
	path_copy_sockaddr(&out->udp_endpoint, &r->udp_endpoint);
	out->temporary_fallback = temporary;
}

bool path_has_live_fallback(meshlink_handle_t *mesh, const node_t *n) {
	path_target_t target;

	if(!mesh || !n) {
		return false;
	}

	return path_rank_carriers(mesh, (node_t *)n, &n->active_route, &target);
}

bool path_liveness_probe_warranted(meshlink_handle_t *mesh, const node_t *n) {
	return path_peer_udp_punching_allowed(mesh, n);
}

static void path_commit_active_route(node_t *n, const path_target_t *target, const struct timespec *now) {
	data_route_t *route = &n->active_route;
	bool changed = route->kind != target->kind
	               || route->relay_carrier != target->relay_carrier
	               || route->first_hop != target->first_hop
	               || route->local != target->local
	               || route->endpoint_source != target->endpoint_source
	               || sockaddrcmp(&route->udp_endpoint, &target->udp_endpoint);

	if(!changed) {
		return;
	}

	path_suspect_stop(n->mesh, n);

	route->kind = target->kind;
	route->relay_carrier = target->relay_carrier;
	route->first_hop = target->first_hop;
	route->local = target->local;
	route->endpoint_source = target->endpoint_source;
	path_copy_sockaddr(&route->udp_endpoint, &target->udp_endpoint);
	route->suspect = false;
	route->selected_at = *now;
	memset(&route->healthy_since, 0, sizeof route->healthy_since);

	if(n->promotion_candidate.active
	                && n->promotion_candidate.kind == DATA_ROUTE_DIRECT_UDP
	                && !n->promotion_candidate.nonce) {
		path_target_t live;

		memset(&live, 0, sizeof live);

		if(!path_fill_direct_udp(n->mesh, n, &live)
		                || !path_target_matches_candidate(&n->promotion_candidate, &live)) {
			path_candidate_discard(n->mesh, n);
		}
	}

	if(n->promotion_candidate.active
	                && n->promotion_candidate.kind == target->kind
	                && n->promotion_candidate.relay_carrier == target->relay_carrier
	                && n->promotion_candidate.first_hop == target->first_hop
	                && n->promotion_candidate.local == target->local
	                && !sockaddrcmp(&n->promotion_candidate.endpoint, &target->udp_endpoint)) {
		path_candidate_discard(n->mesh, n);
	}

	path_note_selected_route(n->mesh, n, "commit");
	channel_refresh_mtu(n->mesh, n);
}

void path_route_tick(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	if(!n->peer_udp.channel_count
	                && (n->peer_udp.idle_until.tv_sec || n->peer_udp.idle_until.tv_nsec)
	                && timespec_ms_between(&n->peer_udp.idle_until, &mesh->loop.now) >= 0) {
		path_peer_udp_stop(mesh, n);
	}

	route_candidate_t *c = &n->promotion_candidate;
	bool validated = c->active && c->successful_rounds >= PATH_PROMOTION_ROUNDS;
	bool committed = false;

	/* Hold and residency live here, not on promotion_timer. After round 2 the
	   timer is already stopped; a validated candidate is waiting on us, so the
	   validation deadline does not apply. */
	if(validated
	                && timespec_ms_between(&c->first_success, &mesh->loop.now) >= PATH_PROMOTION_HOLD_MS
	                && path_residency_served(mesh, n)) {
		if(path_scheduler_has_transaction(mesh, n, PATH_TXN_PROMOTION)
		                || path_scheduler_begin_transaction(mesh, n, PATH_TXN_PROMOTION, PATH_TX_CHANNEL_PROMOTION, path_transaction_preempt)) {
			path_commit_candidate(mesh, n);
			committed = true;
		}
	} else if(!validated && c->active && c->deadline.tv_sec && mesh->loop.now.tv_sec >= c->deadline.tv_sec) {
		path_candidate_timeout(mesh, n, "no validated reply");
		committed = true;
	}

	/* The suspect timer owns the epoch. Tick only reconciles a missed
	   deadline so a stalled loop cannot leave suspicion stuck. */
	if(n->suspect_validation.active) {
		if(timespec_after_or_equal(&mesh->loop.now, &n->suspect_validation.deadline)) {
			path_suspect_expire(mesh, n);
		}
	} else if(n->active_route.suspect) {
		if(n->active_route.kind == DATA_ROUTE_RELAY
		                && n->active_route.relay_carrier == RELAY_CARRIER_UDP
		                && n->active_route.first_hop) {
			if(n->active_route.first_hop->suspect_validation.active) {
				if(timespec_after_or_equal(&mesh->loop.now, &n->active_route.first_hop->suspect_validation.deadline)) {
					path_suspect_expire(mesh, n->active_route.first_hop);
				}
			} else {
				path_suspect_begin_epoch(mesh, n->active_route.first_hop, &n->active_route.udp_endpoint);
			}
		} else {
			path_suspect_begin_epoch(mesh, n, &n->active_route.udp_endpoint);
		}
	}

	/* Failures reset from authenticated service after the latest failure, never
	   from selected_at, and never while a cooldown is still owed.
	   cooldown_until itself clears only via the observation epoch gate, time
	   expiry, or the force helper. */
	if(!n->active_route.suspect
	                && n->active_route.healthy_since.tv_sec
	                && mesh->loop.now.tv_sec - n->active_route.healthy_since.tv_sec >= PATH_HEALTHY_RESET_SEC
	                && !path_cooldown_outstanding(mesh, n)
	                && !path_failure_this_tick(mesh, n)) {
		path_candidate_reset_escalation(n);
	}

	/* After cooldown expires (or never started) this is the retry that used to
	   hitchhike on the path-MTU timer. Skip consider_* in the same tick that
	   committed or retired the current candidate so the cooldown and same-tick
	   failure just written are observed before the next start. */
	path_peer_ensure_udp_key(mesh, n);
	path_punch_endpoint_tick(mesh, n);

	if(!committed) {
		path_consider_route_promotion(mesh, n, PATH_PROMOTION_DIRECT_UDP);
		path_consider_route_promotion(mesh, n, PATH_PROMOTION_LOCAL_META);
		path_consider_route_promotion(mesh, n, PATH_PROMOTION_BACKBONE_UDP);
		path_consider_route_promotion(mesh, n, PATH_PROMOTION_META_DIRECT);
		path_consider_promotion(mesh, n, PATH_PROMOTION_TICK);
	}
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

bool path_select_fallback(meshlink_handle_t *mesh, node_t *n, path_target_t *out) {
	if(!mesh || !n || !out) {
		return false;
	}

	memset(out, 0, sizeof *out);

	if(!n->status.reachable) {
		return false;
	}

	if(path_rank_carriers(mesh, n, NULL, out)) {
		return true;
	}

	out->kind = DATA_ROUTE_DIRECT_LOCAL_META;
	return true;
}

bool path_resolve_active_route(meshlink_handle_t *mesh, node_t *n, path_target_t *out) {
	if(!mesh || !n || !out) {
		return false;
	}

	memset(out, 0, sizeof *out);

	if(!n->status.reachable) {
		return false;
	}

	if(n->active_route.kind == DATA_ROUTE_NONE) {
		return false;
	}

	if(n->active_route.suspect && path_has_live_fallback(mesh, n)) {
		if(path_rank_carriers(mesh, n, &n->active_route, out)) {
			out->temporary_fallback = true;
			return true;
		}
	}

	if(path_recorded_usable(mesh, n)) {
		path_route_to_target(&n->active_route, out, false);
		return true;
	}

	if(path_select_fallback(mesh, n, out)) {
		path_commit_active_route(n, out, &mesh->loop.now);
		return true;
	}

	return false;
}

bool path_active_send_target(meshlink_handle_t *mesh, node_t *n, path_target_t *out) {
	if(!mesh || !n || !out) {
		return false;
	}

	memset(out, 0, sizeof *out);

	if(!n->status.reachable) {
		return false;
	}

	if(n->active_route.kind == DATA_ROUTE_NONE || n->status.forced_relay || n->devtool_force_meta) {
		return path_select_fallback(mesh, n, out);
	}

	return path_resolve_active_route(mesh, n, out);
}

void path_record_active_route(meshlink_handle_t *mesh, node_t *n, const path_target_t *target) {
	if(!mesh || !n || !target) {
		return;
	}

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
