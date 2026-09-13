/*
    path_policy.c -- validated-path ranking and address provenance
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "connection.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "xalloc.h"

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

bool path_canonical_unresolved(const node_t *n) {
	if(!n || !n->canonical_address || !n->canonical_address[0]) {
		return false;
	}

	return n->canonical_sa.sa.sa_family == AF_UNSPEC || n->canonical_sa.sa.sa_family == AF_UNKNOWN;
}

bool path_is_direct_candidate(const node_t *n, const sockaddr_t *sa, address_source_t src) {
	if(!n || !sa || !path_source_is_direct(src)) {
		return false;
	}

	if(path_address_matches_canonical(n, sa)) {
		return false;
	}

	/* UNKNOWN-as-direct is for legacy numeric configs. Skip it while a hostname
	   canonical has not resolved — leftover NLB must not win the first META walk. */
	if(src == ADDR_SRC_UNKNOWN && path_canonical_unresolved(n)) {
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

static bool canonical_to_sockaddr(const char *canonical, sockaddr_t *out) {
	if(!canonical || !out) {
		return false;
	}

	char *copy = xstrdup(canonical);
	char *port = strchr(copy, ' ');

	if(!port || !port[1]) {
		free(copy);
		return false;
	}

	*port++ = 0;
	bool ok = host_port_to_sockaddr(copy, port, out);
	free(copy);
	return ok;
}

void path_refresh_canonical_endpoint(node_t *n) {
	if(!n) {
		return;
	}

	memset(&n->canonical_sa, 0, sizeof n->canonical_sa);
	canonical_to_sockaddr(n->canonical_address, &n->canonical_sa);
}

void path_set_canonical_sockaddr(node_t *n, const sockaddr_t *sa) {
	if(!n || !sa) {
		return;
	}

	path_copy_sockaddr(&n->canonical_sa, sa);
}

bool path_address_matches_canonical(const node_t *n, const sockaddr_t *sa) {
	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	if(n->canonical_sa.sa.sa_family != AF_UNSPEC && !sockaddrcmp(sa, &n->canonical_sa)) {
		return true;
	}

	sockaddr_t parsed;

	if(n->canonical_address && canonical_to_sockaddr(n->canonical_address, &parsed) && !sockaddrcmp(sa, &parsed)) {
		return true;
	}

	return false;
}

static int source_trust(address_source_t src) {
	switch(src) {
	case ADDR_SRC_AUTH_DIRECT:
		return SOURCE_TRUST_AUTH_DIRECT;

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

	if(mesh && mesh->log_level <= MESHLINK_DEBUG) {
		char *hostname = sockaddr2hostname(sa);
		logger(mesh, MESHLINK_DEBUG, "Path policy: not storing %s for %s as a direct candidate (source %s)", hostname, n->name, address_source_name(src));
		free(hostname);
	}

	return true;
}

/* Rotate sa to recent[0]. If this slot already had a higher-trust source, keep that source. */
static void recent_store_front(node_t *n, int i, const sockaddr_t *sa, address_source_t src) {
	address_source_t keep = src;

	if(i >= 0 && source_trust(n->recent_source[i]) > source_trust(src)) {
		keep = n->recent_source[i];
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
	}

	memcpy(n->recent, sa, SALEN(sa->sa));
	n->recent_source[0] = keep;
	n->status.dirty = true;
}

bool path_learn_address(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src) {
	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	if(src == ADDR_SRC_INDIRECT || reject_canonical(mesh, n, sa, src)) {
		return false;
	}

	int i;

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], sa)) {
			if(i == 0 && source_trust(src) <= source_trust(n->recent_source[0])) {
				return false;
			}

			recent_store_front(n, i, sa, src);
			return true;
		}
	}

	recent_store_front(n, -1, sa, src);

	if(mesh && mesh->log_level <= MESHLINK_DEBUG) {
		char *hostname = sockaddr2hostname(sa);
		logger(mesh, MESHLINK_DEBUG, "Path policy: learned %s for %s from %s", hostname, n->name, address_source_name(src));
		free(hostname);
	}

	return true;
}

bool path_learn_address_fallback(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src) {
	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return false;
	}

	if(reject_canonical(mesh, n, sa, src)) {
		return false;
	}

	int i;

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], sa)) {
			if(source_trust(src) > source_trust(n->recent_source[i])) {
				n->recent_source[i] = src;
				n->status.dirty = true;
				return true;
			}

			return false;
		}
	}

	if(i == 0 || i >= MAX_RECENT) {
		return false;
	}

	memcpy(&n->recent[i], sa, SALEN(sa->sa));
	n->recent_source[i] = src;
	n->status.dirty = true;

	if(mesh && mesh->log_level <= MESHLINK_DEBUG) {
		char *hostname = sockaddr2hostname(sa);
		logger(mesh, MESHLINK_DEBUG, "Path policy: remembering fallback %s for %s from %s", hostname, n->name, address_source_name(src));
		free(hostname);
	}

	return true;
}

void path_clear_recent(node_t *n) {
	if(!n) {
		return;
	}

	memset(n->recent, 0, sizeof n->recent);
	memset(n->recent_source, 0, sizeof n->recent_source);
	n->status.dirty = true;
}

void path_plant_recent(node_t *n, const sockaddr_t *sa) {
	int i;

	if(!n || !sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		return;
	}

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], sa)) {
			recent_store_front(n, i, sa, ADDR_SRC_UNKNOWN);
			n->recent_source[0] = ADDR_SRC_UNKNOWN;
			return;
		}
	}

	recent_store_front(n, -1, sa, ADDR_SRC_UNKNOWN);
	n->recent_source[0] = ADDR_SRC_UNKNOWN;
}

bool path_sanitize_recent(meshlink_handle_t *mesh, node_t *n) {
	if(!n) {
		return false;
	}

	path_refresh_canonical_endpoint(n);

	bool changed = false;
	sockaddr_t kept[MAX_RECENT];
	address_source_t kept_src[MAX_RECENT];
	int out = 0;

	memset(kept, 0, sizeof kept);
	memset(kept_src, 0, sizeof kept_src);

	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(path_address_matches_canonical(n, &n->recent[i]) || n->recent_source[i] == ADDR_SRC_CANONICAL) {
			if(mesh && mesh->log_level <= MESHLINK_INFO) {
				char *hostname = sockaddr2hostname(&n->recent[i]);
				logger(mesh, MESHLINK_INFO, "Path policy: sanitized %s from recent[] of %s (source %s)", hostname, n->name, address_source_name(n->recent_source[i]));
				free(hostname);
			}

			changed = true;
			continue;
		}

		kept[out] = n->recent[i];
		kept_src[out] = n->recent_source[i];
		out++;
	}

	if(changed) {
		memcpy(n->recent, kept, sizeof kept);
		memcpy(n->recent_source, kept_src, sizeof kept_src);
		n->status.dirty = true;
	}

	return changed;
}

bool path_best_direct_meta(const node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out) {
	if(!n || !out) {
		return false;
	}

	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!path_is_direct_candidate(n, &n->recent[i], n->recent_source[i])) {
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
		if(!path_is_direct_candidate(n, &n->recent[i], n->recent_source[i])) {
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
	path_log_transition(mesh, n, was, next, "local probe reply");
	return true;
}

void path_log_transition(meshlink_handle_t *mesh, const node_t *n, path_tier_t from, path_tier_t to, const char *reason) {
	if(!mesh || !n) {
		return;
	}

	logger(mesh, MESHLINK_INFO, "Path policy: %s %s -> %s (%s)", n->name, path_tier_name(from), path_tier_name(to), reason ? reason : "");
}
