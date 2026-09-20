/*
    path_policy_devtool.c -- branch coverage for path_policy.c
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
#include "event.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "net_upgrade.h"
#include "path_policy.h"
#include "path_policy_devtool.h"
#include "sptps.h"
#include "xalloc.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define CHECK(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "path_policy_cover_unit failed: %s", #cond); \
		return false; \
	} \
} while(0)

static void set_v4(sockaddr_t *sa, const char *ip, uint16_t port) {
	memset(sa, 0, sizeof * sa);
	sa->in.sin_family = AF_INET;
	sa->in.sin_port = htons(port);
	inet_pton(AF_INET, ip, &sa->in.sin_addr);
}

static void set_v6(sockaddr_t *sa, const char *ip, uint16_t port) {
	memset(sa, 0, sizeof * sa);
	sa->in6.sin6_family = AF_INET6;
	sa->in6.sin6_port = htons(port);
	inet_pton(AF_INET6, ip, &sa->in6.sin6_addr);
}

/* Coverage nodes are stack-local and never free these pointers. */
static char *scratch(const char *s) {
	return (char *)(uintptr_t)s;
}

static bool timespec_neq(const struct timespec *a, const struct timespec *b) {
	return a->tv_sec != b->tv_sec || a->tv_nsec != b->tv_nsec;
}

static bool cover_names(meshlink_handle_t *mesh) {
	CHECK(!strcmp(address_source_name(ADDR_SRC_AUTH_DIRECT), "auth-direct"));
	CHECK(!strcmp(address_source_name(ADDR_SRC_DISCOVERY), "discovery"));
	CHECK(!strcmp(address_source_name(ADDR_SRC_HINT), "hint"));
	CHECK(!strcmp(address_source_name(ADDR_SRC_EXTERNAL), "external"));
	CHECK(!strcmp(address_source_name(ADDR_SRC_EDGE_DIRECT), "edge-direct"));
	CHECK(!strcmp(address_source_name(ADDR_SRC_CANONICAL), "canonical"));
	CHECK(!strcmp(address_source_name(ADDR_SRC_INDIRECT), "indirect"));
	CHECK(!strcmp(address_source_name(ADDR_SRC_UDP_REFLEXIVE), "udp-reflexive"));
	CHECK(!strcmp(address_source_name(ADDR_SRC_UNKNOWN), "unknown"));
	CHECK(!strcmp(address_source_name((address_source_t)99), "unknown"));
	CHECK(!strcmp(path_cap_name(PATH_CAP_BOTH), "meta+udp"));
	CHECK(!strcmp(path_cap_name(PATH_CAP_META), "meta"));
	CHECK(!strcmp(path_cap_name(PATH_CAP_UDP), "udp"));
	CHECK(!strcmp(path_cap_name(PATH_CAP_NONE), "none"));
	CHECK(path_default_cap(ADDR_SRC_HINT) == PATH_CAP_BOTH);
	CHECK(path_default_cap(ADDR_SRC_UDP_REFLEXIVE) == PATH_CAP_UDP);
	CHECK(path_default_cap(ADDR_SRC_UNKNOWN) == PATH_CAP_UDP);

	CHECK(!strcmp(path_tier_name(PATH_TIER_DIRECT_LOCAL_UDP), "direct-local-udp"));
	CHECK(!strcmp(path_tier_name(PATH_TIER_DIRECT_WAN_UDP), "direct-wan-udp"));
	CHECK(!strcmp(path_tier_name(PATH_TIER_RELAY_UDP), "relay-udp"));
	CHECK(!strcmp(path_tier_name(PATH_TIER_META_DIRECT), "meta-direct"));
	CHECK(!strcmp(path_tier_name(PATH_TIER_META_CANONICAL), "meta-canonical"));
	CHECK(!strcmp(path_tier_name(PATH_TIER_NONE), "none"));
	CHECK(!strcmp(path_tier_name((path_tier_t)99), "none"));

	CHECK(!strcmp(meta_dial_tier_name(META_DIAL_CANONICAL), "canonical"));
	CHECK(!strcmp(meta_dial_tier_name(META_DIAL_DIRECT), "direct"));
	CHECK(!strcmp(meta_dial_tier_name((meta_dial_tier_t)7), "direct"));

	CHECK(path_source_is_direct(ADDR_SRC_AUTH_DIRECT));
	CHECK(path_source_is_direct(ADDR_SRC_DISCOVERY));
	CHECK(path_source_is_direct(ADDR_SRC_HINT));
	CHECK(path_source_is_direct(ADDR_SRC_EXTERNAL));
	CHECK(path_source_is_direct(ADDR_SRC_EDGE_DIRECT));
	CHECK(path_source_is_direct(ADDR_SRC_UNKNOWN));
	CHECK(!path_source_is_direct(ADDR_SRC_CANONICAL));
	CHECK(!path_source_is_direct(ADDR_SRC_INDIRECT));
	CHECK(!path_source_is_direct(ADDR_SRC_UDP_REFLEXIVE));
	CHECK(!path_source_is_direct((address_source_t)99));

	CHECK(path_tier_better(PATH_TIER_DIRECT_LOCAL_UDP, PATH_TIER_DIRECT_WAN_UDP));
	CHECK(!path_tier_better(PATH_TIER_DIRECT_WAN_UDP, PATH_TIER_DIRECT_LOCAL_UDP));
	CHECK(!path_tier_better(PATH_TIER_META_DIRECT, PATH_TIER_META_DIRECT));
	return true;
}

static bool cover_local_classify(meshlink_handle_t *mesh) {
	CHECK(!path_address_is_local(NULL));

	sockaddr_t sa;
	memset(&sa, 0, sizeof sa);
	CHECK(!path_address_is_local(&sa));

	set_v4(&sa, "127.0.0.1", 1);
	CHECK(path_address_is_local(&sa));
	set_v4(&sa, "10.9.8.7", 1);
	CHECK(path_address_is_local(&sa));
	set_v4(&sa, "172.16.0.1", 1);
	CHECK(path_address_is_local(&sa));
	set_v4(&sa, "172.31.255.255", 1);
	CHECK(path_address_is_local(&sa));
	set_v4(&sa, "172.15.255.255", 1);
	CHECK(!path_address_is_local(&sa));
	set_v4(&sa, "172.32.0.1", 1);
	CHECK(!path_address_is_local(&sa));
	set_v4(&sa, "192.168.1.1", 1);
	CHECK(path_address_is_local(&sa));
	set_v4(&sa, "169.254.1.1", 1);
	CHECK(path_address_is_local(&sa));
	set_v4(&sa, "203.0.113.10", 1);
	CHECK(!path_address_is_local(&sa));
	set_v4(&sa, "8.8.8.8", 1);
	CHECK(!path_address_is_local(&sa));

	set_v6(&sa, "::1", 1);
	CHECK(path_address_is_local(&sa));
	set_v6(&sa, "fe80::1", 1);
	CHECK(path_address_is_local(&sa));
	set_v6(&sa, "fec0::1", 1);
	CHECK(path_address_is_local(&sa));
	set_v6(&sa, "fd00::1", 1);
	CHECK(path_address_is_local(&sa));
	set_v6(&sa, "fc00::1", 1);
	CHECK(path_address_is_local(&sa));
	set_v6(&sa, "2001:db8::1", 1);
	CHECK(!path_address_is_local(&sa));

	set_v4(&sa, "203.0.113.10", 9);
	CHECK(path_udp_tier_for(&sa, ADDR_SRC_AUTH_DIRECT) == PATH_TIER_DIRECT_WAN_UDP);
	CHECK(path_udp_tier_for(&sa, ADDR_SRC_DISCOVERY) == PATH_TIER_DIRECT_LOCAL_UDP);
	set_v4(&sa, "192.168.1.9", 9);
	CHECK(path_udp_tier_for(&sa, ADDR_SRC_HINT) == PATH_TIER_DIRECT_LOCAL_UDP);
	CHECK(path_udp_tier_for(NULL, ADDR_SRC_AUTH_DIRECT) == PATH_TIER_DIRECT_WAN_UDP);
	return true;
}

static bool cover_canonical(meshlink_handle_t *mesh) {
	path_refresh_canonical_endpoint(NULL);
	path_set_canonical_sockaddr(NULL, NULL);

	node_t n;
	memset(&n, 0, sizeof n);
	n.name = scratch("cover");
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_UNSPEC);

	n.canonical_address = scratch("noport");
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_UNSPEC);

	n.canonical_address = scratch("203.0.113.9 ");
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_UNSPEC);

	n.canonical_address = scratch("nlb.example 443");
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_UNSPEC);

	n.canonical_address = scratch("203.0.113.9 9");
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_INET);

	sockaddr_t sa;
	set_v4(&sa, "198.51.100.7", 9);
	path_set_canonical_sockaddr(NULL, &sa);
	path_set_canonical_sockaddr(&n, NULL);
	path_set_canonical_sockaddr(&n, &sa);
	CHECK(!sockaddrcmp(&n.canonical_sa, &sa));

	n.canonical_address = scratch("198.51.100.7 9");
	CHECK(!path_address_matches_canonical(NULL, &sa));
	CHECK(!path_address_matches_canonical(&n, NULL));
	sockaddr_t bad;
	memset(&bad, 0, sizeof bad);
	CHECK(!path_address_matches_canonical(&n, &bad));
	bad.sa.sa_family = AF_UNKNOWN;
	CHECK(!path_address_matches_canonical(&n, &bad));
	CHECK(path_address_matches_canonical(&n, &sa));

	set_v4(&sa, "203.0.113.9", 9);
	CHECK(!path_address_matches_canonical(&n, &sa));

	memset(&n.canonical_sa, 0, sizeof n.canonical_sa);
	n.canonical_address = scratch("198.51.100.7 9");
	set_v4(&sa, "198.51.100.7", 9);
	CHECK(path_address_matches_canonical(&n, &sa));

	n.canonical_address = scratch("198.51.100.8 9");
	CHECK(!path_address_matches_canonical(&n, &sa));

	n.canonical_address = scratch("198.51.100.7 9");
	path_refresh_canonical_endpoint(&n);
	sockaddr_t hybrid;
	set_v4(&hybrid, "198.51.100.7", 23349);
	CHECK(path_address_shares_canonical_ip(&n, &hybrid));
	CHECK(!path_address_matches_canonical(&n, &hybrid));
	CHECK(path_is_untrusted_hybrid(&n, &hybrid, ADDR_SRC_EDGE_DIRECT));
	CHECK(path_is_untrusted_hybrid(&n, &hybrid, ADDR_SRC_UNKNOWN));
	CHECK(!path_is_untrusted_hybrid(&n, &hybrid, ADDR_SRC_EXTERNAL));
	CHECK(!path_is_untrusted_hybrid(&n, &hybrid, ADDR_SRC_AUTH_DIRECT));
	CHECK(!path_is_untrusted_hybrid(&n, &hybrid, ADDR_SRC_UDP_REFLEXIVE));
	CHECK(!path_is_untrusted_hybrid(&n, &hybrid, ADDR_SRC_DISCOVERY));
	CHECK(!path_is_untrusted_hybrid(&n, &hybrid, ADDR_SRC_HINT));
	CHECK(!path_is_direct_candidate(&n, &hybrid, ADDR_SRC_EDGE_DIRECT));
	CHECK(!path_is_direct_candidate(&n, &hybrid, ADDR_SRC_UNKNOWN));
	CHECK(path_is_direct_candidate(&n, &hybrid, ADDR_SRC_EXTERNAL));
	CHECK(path_is_direct_candidate(&n, &hybrid, ADDR_SRC_AUTH_DIRECT));
	CHECK(path_is_direct_candidate(&n, &hybrid, ADDR_SRC_DISCOVERY));
	CHECK(path_is_direct_candidate(&n, &hybrid, ADDR_SRC_HINT));
	CHECK(!path_is_udp_candidate(&n, &hybrid, ADDR_SRC_EDGE_DIRECT, PATH_CAP_BOTH));
	CHECK(!path_is_udp_candidate(&n, &hybrid, ADDR_SRC_UNKNOWN, PATH_CAP_UDP));
	CHECK(path_is_udp_candidate(&n, &hybrid, ADDR_SRC_EXTERNAL, PATH_CAP_BOTH));
	CHECK(path_is_udp_candidate(&n, &hybrid, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH));
	CHECK(path_is_udp_candidate(&n, &hybrid, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP));
	CHECK(path_is_udp_candidate(&n, &hybrid, ADDR_SRC_DISCOVERY, PATH_CAP_BOTH));
	CHECK(path_is_udp_candidate(&n, &hybrid, ADDR_SRC_HINT, PATH_CAP_BOTH));

	sockaddr_t extra, extra_hybrid, other_direct;
	set_v4(&extra, "198.51.100.8", 443);
	CHECK(path_add_canonical_endpoint(&n, &extra));
	set_v4(&extra_hybrid, "198.51.100.8", 23349);
	CHECK(path_address_shares_canonical_ip(&n, &extra_hybrid));
	CHECK(path_is_untrusted_hybrid(&n, &extra_hybrid, ADDR_SRC_EDGE_DIRECT));
	CHECK(path_is_untrusted_hybrid(&n, &extra_hybrid, ADDR_SRC_UNKNOWN));
	CHECK(!path_is_untrusted_hybrid(&n, &extra_hybrid, ADDR_SRC_EXTERNAL));
	CHECK(!path_is_udp_candidate(&n, &extra_hybrid, ADDR_SRC_EDGE_DIRECT, PATH_CAP_BOTH));
	CHECK(path_is_udp_candidate(&n, &extra_hybrid, ADDR_SRC_EXTERNAL, PATH_CAP_BOTH));
	set_v4(&other_direct, "203.0.113.50", 23349);
	CHECK(!path_is_untrusted_hybrid(&n, &other_direct, ADDR_SRC_EDGE_DIRECT));
	CHECK(path_is_direct_candidate(&n, &other_direct, ADDR_SRC_EDGE_DIRECT));
	CHECK(path_is_udp_candidate(&n, &other_direct, ADDR_SRC_EDGE_DIRECT, PATH_CAP_BOTH));

	path_clear_canonical_endpoints(&n);
	sockaddr_t weird;
	memset(&weird, 0, sizeof weird);
	weird.sa.sa_family = AF_UNIX;
	CHECK(!path_add_canonical_endpoint(&n, &weird));
	CHECK(n.canonical_sa_count == 0);

	n.canonical_resolve_pending = true;
	n.canonical_resolve_gen = 7;
	n.canonical_resolve_backoff = 5;
	n.canonical_resolve_next = 99;
	path_reset_canonical_resolve(&n);
	CHECK(!n.canonical_resolve_pending);
	CHECK(n.canonical_resolve_gen == 0);
	CHECK(n.canonical_resolve_backoff == 0);
	CHECK(n.canonical_resolve_next == 0);
	path_reset_canonical_resolve(&n);
	CHECK(n.canonical_resolve_gen == 0);

	CHECK(!path_assign_canonical_address(NULL, xstrdup("nlb.example 443")));

	node_t assign;
	memset(&assign, 0, sizeof assign);
	assign.name = scratch("cover-assign");
	assign.canonical_address = xstrdup("nlb.example 443");
	set_v4(&sa, "198.51.100.9", 443);
	path_set_canonical_sockaddr(&assign, &sa);
	CHECK(assign.canonical_sa_count == 1);
	assign.canonical_resolve_gen = 7;
	CHECK(!path_assign_canonical_address(&assign, xstrdup("nlb.example 443")));
	CHECK(assign.canonical_resolve_gen == 7);
	CHECK(assign.canonical_sa_count == 1);
	CHECK(path_assign_canonical_address(&assign, xstrdup("nlb.example 444")));
	CHECK(assign.canonical_resolve_gen == 0);
	CHECK(assign.canonical_sa_count == 0);
	CHECK(assign.canonical_address && !strcmp(assign.canonical_address, "nlb.example 444"));
	free(assign.canonical_address);
	return true;
}

static bool cover_learn_sanitize(meshlink_handle_t *mesh) {
	node_t n;
	memset(&n, 0, sizeof n);
	n.name = scratch("cover");
	n.canonical_address = scratch("198.51.100.1 9");
	path_refresh_canonical_endpoint(&n);

	sockaddr_t local, wan, wan2, nlb, extra[MAX_RECENT];
	set_v4(&local, "192.168.1.10", 1000);
	set_v4(&wan, "203.0.113.10", 2000);
	set_v4(&wan2, "203.0.113.11", 2001);
	set_v4(&nlb, "198.51.100.1", 9);

	CHECK(!path_learn_address(mesh, NULL, &local, ADDR_SRC_HINT));
	CHECK(!path_learn_address(mesh, &n, NULL, ADDR_SRC_HINT));
	sockaddr_t unspec;
	memset(&unspec, 0, sizeof unspec);
	CHECK(!path_learn_address(mesh, &n, &unspec, ADDR_SRC_HINT));
	unspec.sa.sa_family = AF_UNKNOWN;
	CHECK(!path_learn_address(mesh, &n, &unspec, ADDR_SRC_HINT));

	CHECK(!path_learn_address(mesh, &n, &nlb, ADDR_SRC_AUTH_DIRECT));
	CHECK(!path_learn_address(NULL, &n, &wan, ADDR_SRC_CANONICAL));
	CHECK(!path_learn_address(mesh, &n, &wan, ADDR_SRC_INDIRECT));
	CHECK(!n.recent[0].sa.sa_family);

	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_HINT));
	CHECK(n.recent_source[0] == ADDR_SRC_HINT);
	n.recent_source[0] = ADDR_SRC_CANONICAL;
	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_HINT));
	CHECK(n.recent_source[0] == ADDR_SRC_HINT);
	n.recent_source[0] = ADDR_SRC_INDIRECT;
	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_EDGE_DIRECT));
	CHECK(n.recent_source[0] == ADDR_SRC_EDGE_DIRECT);
	CHECK(!path_learn_address(mesh, &n, &wan, ADDR_SRC_UNKNOWN));
	CHECK(!path_learn_address(mesh, &n, &wan, ADDR_SRC_UNKNOWN));
	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_AUTH_DIRECT));
	CHECK(n.recent_source[0] == ADDR_SRC_AUTH_DIRECT);

	CHECK(path_learn_address(mesh, &n, &local, ADDR_SRC_DISCOVERY));
	CHECK(!sockaddrcmp(&n.recent[0], &local));
	CHECK(n.recent_source[0] == ADDR_SRC_DISCOVERY);
	CHECK(!sockaddrcmp(&n.recent[1], &wan));

	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_EXTERNAL));
	CHECK(!sockaddrcmp(&n.recent[0], &wan));
	CHECK(n.recent_source[0] == ADDR_SRC_AUTH_DIRECT);

	CHECK(path_learn_address(mesh, &n, &wan2, ADDR_SRC_EDGE_DIRECT));

	for(int i = 0; i < MAX_RECENT; i++) {
		char ip[16];
		snprintf(ip, sizeof ip, "203.0.113.%d", 20 + i);
		set_v4(&extra[i], ip, (uint16_t)(3000 + i));
		CHECK(path_learn_address(mesh, &n, &extra[i], ADDR_SRC_HINT));
	}

	CHECK(!sockaddrcmp(&n.recent[0], &extra[MAX_RECENT - 1]));
	CHECK(n.recent[MAX_RECENT - 1].sa.sa_family);

	path_clear_recent(NULL);
	path_clear_recent(&n);
	CHECK(!n.recent[0].sa.sa_family);
	CHECK(n.status.dirty);
	return true;
}

static bool cover_sanitize(meshlink_handle_t *mesh) {
	node_t n;
	sockaddr_t local, wan, wan2, nlb, unspec;

	memset(&n, 0, sizeof n);
	n.name = scratch("cover");
	n.canonical_address = scratch("198.51.100.1 9");
	path_refresh_canonical_endpoint(&n);
	set_v4(&local, "192.168.1.10", 1000);
	set_v4(&wan, "203.0.113.10", 2000);
	set_v4(&wan2, "203.0.113.11", 2001);
	set_v4(&nlb, "198.51.100.1", 9);

	CHECK(!path_learn_address_fallback(mesh, NULL, &local, ADDR_SRC_HINT));
	CHECK(!path_learn_address_fallback(mesh, &n, NULL, ADDR_SRC_HINT));
	memset(&unspec, 0, sizeof unspec);
	CHECK(!path_learn_address_fallback(mesh, &n, &unspec, ADDR_SRC_HINT));
	unspec.sa.sa_family = AF_UNKNOWN;
	CHECK(!path_learn_address_fallback(mesh, &n, &unspec, ADDR_SRC_HINT));
	CHECK(!path_learn_address_fallback(mesh, &n, &nlb, ADDR_SRC_HINT));
	CHECK(!path_learn_address_fallback(NULL, &n, &wan, ADDR_SRC_CANONICAL));
	CHECK(!path_learn_address_fallback(mesh, &n, &local, ADDR_SRC_HINT));

	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_HINT));
	CHECK(path_learn_address_fallback(mesh, &n, &local, ADDR_SRC_DISCOVERY));
	CHECK(!sockaddrcmp(&n.recent[1], &local));
	CHECK(n.recent_source[1] == ADDR_SRC_DISCOVERY);
	CHECK(!path_learn_address_fallback(mesh, &n, &local, ADDR_SRC_UNKNOWN));
	CHECK(path_learn_address_fallback(mesh, &n, &local, ADDR_SRC_AUTH_DIRECT));
	CHECK(n.recent_source[1] == ADDR_SRC_AUTH_DIRECT);

	CHECK(path_learn_address_fallback(mesh, &n, &wan2, ADDR_SRC_HINT));
	sockaddr_t more;
	set_v4(&more, "203.0.113.40", 40);
	CHECK(path_learn_address_fallback(mesh, &n, &more, ADDR_SRC_HINT));
	sockaddr_t more2;
	set_v4(&more2, "203.0.113.41", 41);
	CHECK(path_learn_address_fallback(mesh, &n, &more2, ADDR_SRC_HINT));
	sockaddr_t more3;
	set_v4(&more3, "203.0.113.42", 42);
	CHECK(!path_learn_address_fallback(mesh, &n, &more3, ADDR_SRC_HINT));

	path_clear_recent(&n);
	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_UNKNOWN));
	n.recent_source[0] = ADDR_SRC_CANONICAL;
	CHECK(path_sanitize_recent(mesh, &n));
	CHECK(!n.recent[0].sa.sa_family);

	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_HINT));
	n.recent_source[0] = ADDR_SRC_INDIRECT;
	CHECK(!path_sanitize_recent(NULL, &n));
	CHECK(n.recent_source[0] == ADDR_SRC_INDIRECT);
	CHECK(path_learn_address_fallback(mesh, &n, &wan2, ADDR_SRC_INDIRECT));
	CHECK(n.recent_source[1] == ADDR_SRC_INDIRECT);

	CHECK(path_learn_address(mesh, &n, &nlb, ADDR_SRC_UNKNOWN) == false);
	n.recent[0] = nlb;
	n.recent_source[0] = ADDR_SRC_UNKNOWN;
	n.recent_cap[0] = PATH_CAP_UDP;
	n.recent[1] = wan;
	n.recent_source[1] = ADDR_SRC_HINT;
	n.recent_cap[1] = PATH_CAP_BOTH;
	CHECK(path_sanitize_recent(mesh, &n));
	CHECK(!sockaddrcmp(&n.recent[0], &wan));
	CHECK(!n.recent[1].sa.sa_family);

	sockaddr_t hybrid;
	set_v4(&hybrid, "198.51.100.1", 23349);
	CHECK(!path_learn_address(mesh, &n, &hybrid, ADDR_SRC_EDGE_DIRECT));
	CHECK(!path_learn_address(mesh, &n, &hybrid, ADDR_SRC_UNKNOWN));
	CHECK(path_learn_address(mesh, &n, &hybrid, ADDR_SRC_EXTERNAL));
	path_clear_recent(&n);
	n.recent[0] = hybrid;
	n.recent_source[0] = ADDR_SRC_EDGE_DIRECT;
	n.recent_cap[0] = PATH_CAP_BOTH;
	CHECK(path_sanitize_recent(mesh, &n));
	CHECK(!n.recent[0].sa.sa_family);

	CHECK(!path_sanitize_recent(NULL, NULL));
	CHECK(!path_sanitize_recent(mesh, &n));

	n.canonical_address = scratch("nlb.example 443");
	path_refresh_canonical_endpoint(&n);
	CHECK(!path_sanitize_recent(mesh, &n));

	path_clear_recent(&n);
	n.recent[0] = nlb;
	n.recent_source[0] = ADDR_SRC_UNKNOWN;
	n.recent_cap[0] = PATH_CAP_UDP;
	CHECK(!path_is_direct_candidate(&n, &nlb, ADDR_SRC_UNKNOWN));
	CHECK(!path_best_direct_meta(&n, NULL, &wan2, NULL));
	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_HINT));
	CHECK(!path_is_direct_candidate(&n, &wan, ADDR_SRC_HINT));
	CHECK(!path_best_direct_meta(&n, NULL, &wan2, NULL));
	CHECK(path_learn_address(mesh, &n, &wan, ADDR_SRC_AUTH_DIRECT));
	CHECK(path_best_direct_meta(&n, NULL, &wan2, NULL));
	CHECK(!sockaddrcmp(&wan2, &wan));
	return true;
}

static bool cover_select(meshlink_handle_t *mesh) {
	node_t hop;
	node_t dest;
	connection_t conn;
	memset(&hop, 0, sizeof hop);
	memset(&dest, 0, sizeof dest);
	memset(&conn, 0, sizeof conn);
	hop.name = scratch("hop");
	dest.name = scratch("dest");

	CHECK(path_select_hop_tier(NULL, false) == PATH_TIER_NONE);
	CHECK(path_select_destination_tier(NULL, false) == PATH_TIER_NONE);
	CHECK(path_select_hop_tier(&hop, false) == PATH_TIER_NONE);

	hop.status.udp_confirmed = true;
	hop.status.validkey = true;
	CHECK(path_select_hop_tier(&hop, false) == PATH_TIER_RELAY_UDP);
	hop.status.temp_udp_confirmed = true;
	CHECK(path_select_hop_tier(&hop, false) == PATH_TIER_NONE);
	hop.status.temp_udp_confirmed = false;

	conn.status.active = true;
	hop.connection = &conn;
	CHECK(path_select_hop_tier(&hop, true) == PATH_TIER_META_DIRECT);
	path_mark_meta_dial(NULL, true);
	path_mark_meta_dial(&conn, true);
	CHECK(path_meta_is_canonical(&hop, &conn));
	CHECK(path_select_hop_tier(&hop, true) == PATH_TIER_META_CANONICAL);
	path_mark_meta_dial(&conn, false);
	conn.status.via_canonical = true;
	CHECK(path_meta_is_canonical(&hop, &conn));
	conn.status.via_canonical = false;
	conn.status.meta_dial_tier = META_DIAL_DIRECT;
	set_v4(&conn.address, "198.51.100.1", 9);
	hop.canonical_address = scratch("198.51.100.1 9");
	path_refresh_canonical_endpoint(&hop);
	CHECK(path_meta_is_canonical(&hop, &conn));
	CHECK(!path_meta_is_canonical(NULL, NULL));
	CHECK(!path_meta_is_canonical(&hop, NULL));
	set_v4(&conn.address, "192.168.1.2", 1);
	CHECK(!path_meta_is_canonical(&hop, &conn));
	conn.status.active = false;
	CHECK(path_select_hop_tier(&hop, true) == PATH_TIER_NONE);
	hop.connection = NULL;
	CHECK(path_select_hop_tier(&hop, true) == PATH_TIER_NONE);

	conn.status.active = true;
	path_mark_meta_dial(&conn, false);
	hop.connection = &conn;
	hop.status.udp_confirmed = false;

	dest.status.udp_confirmed = true;
	dest.status.validkey = true;
	dest.udp_tier = PATH_TIER_DIRECT_LOCAL_UDP;
	CHECK(path_select_destination_tier(&dest, false) == PATH_TIER_DIRECT_LOCAL_UDP);
	CHECK(path_select_destination_tier(&dest, true) == PATH_TIER_NONE);
	dest.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	CHECK(path_select_destination_tier(&dest, false) == PATH_TIER_DIRECT_WAN_UDP);
	dest.udp_tier = PATH_TIER_NONE;
	CHECK(path_select_destination_tier(&dest, false) == PATH_TIER_DIRECT_WAN_UDP);

	dest.status.udp_confirmed = false;
	dest.nexthop = &hop;
	hop.status.udp_confirmed = true;
	hop.status.validkey = true;
	CHECK(path_select_destination_tier(&dest, false) == PATH_TIER_RELAY_UDP);
	CHECK(path_select_destination_tier(&dest, true) == PATH_TIER_META_DIRECT);
	dest.nexthop = &dest;
	dest.connection = &conn;
	CHECK(path_select_destination_tier(&dest, false) == PATH_TIER_META_DIRECT);

	sockaddr_t skip, out, local, wan, nlb;
	set_v4(&local, "10.0.0.2", 1);
	set_v4(&wan, "203.0.113.2", 2);
	set_v4(&nlb, "198.51.100.1", 9);
	dest.canonical_address = scratch("198.51.100.1 9");
	path_refresh_canonical_endpoint(&dest);
	path_clear_recent(&dest);
	dest.recent[0] = nlb;
	dest.recent_source[0] = ADDR_SRC_UNKNOWN;
	dest.recent_cap[0] = PATH_CAP_UDP;
	dest.recent[1] = wan;
	dest.recent_source[1] = ADDR_SRC_INDIRECT;
	dest.recent_cap[1] = PATH_CAP_META;
	CHECK(!path_best_direct_meta(NULL, NULL, &out, NULL));
	CHECK(!path_best_direct_meta(&dest, NULL, NULL, NULL));
	address_source_t src = ADDR_SRC_UNKNOWN;
	CHECK(!path_best_direct_meta(&dest, NULL, &out, &src));
	CHECK(path_sanitize_recent(mesh, &dest));
	CHECK(!path_has_direct_meta_candidate(&dest, NULL));
	CHECK(path_learn_address(mesh, &dest, &local, ADDR_SRC_HINT));
	CHECK(path_best_direct_meta(&dest, NULL, &out, &src));
	CHECK(!sockaddrcmp(&out, &local));
	CHECK(src == ADDR_SRC_HINT);
	CHECK(path_has_direct_meta_candidate(&dest, NULL));
	CHECK(!path_best_local_meta(&dest, NULL, &out, &src));
	skip = local;
	CHECK(!path_has_direct_meta_candidate(&dest, &skip));
	CHECK(!path_best_local_meta(NULL, NULL, &out, NULL));
	CHECK(!path_best_local_meta(&dest, NULL, NULL, NULL));
	path_clear_recent(&dest);
	CHECK(path_learn_address(mesh, &dest, &local, ADDR_SRC_DISCOVERY));
	CHECK(path_best_local_meta(&dest, NULL, &out, &src));
	CHECK(!sockaddrcmp(&out, &local));
	CHECK(src == ADDR_SRC_DISCOVERY);
	CHECK(!path_best_local_meta(&dest, &skip, &out, &src));
	path_clear_recent(&dest);
	CHECK(path_learn_address(mesh, &dest, &local, ADDR_SRC_AUTH_DIRECT));
	CHECK(path_best_local_meta(&dest, NULL, &out, &src));
	CHECK(src == ADDR_SRC_AUTH_DIRECT);
	path_clear_recent(&dest);
	CHECK(path_learn_address(mesh, &dest, &wan, ADDR_SRC_AUTH_DIRECT));
	CHECK(!path_best_local_meta(&dest, NULL, &out, &src));
	CHECK(path_best_direct_meta(&dest, NULL, &out, &src));
	path_clear_recent(&dest);
	CHECK(path_learn_address(mesh, &dest, &local, ADDR_SRC_DISCOVERY));
	{
		sockaddr_t ephemeral;
		set_v4(&ephemeral, "10.0.0.2", 99);
		CHECK(path_learn_address(mesh, &dest, &ephemeral, ADDR_SRC_AUTH_DIRECT));
		CHECK(path_best_local_meta(&dest, NULL, &out, &src));
		CHECK(src == ADDR_SRC_DISCOVERY);
		CHECK(!sockaddrcmp(&out, &local));
	}
	return true;
}

static bool cover_probe(meshlink_handle_t *mesh) {
	node_t dummy;
	sockaddr_t out, local, wan, nlb, unixish, relayed;

	memset(&dummy, 0, sizeof dummy);
	dummy.name = scratch("probe");
	path_note_udp_confirmed(mesh, NULL);
	path_log_transition(NULL, &dummy, PATH_TIER_NONE, PATH_TIER_META_DIRECT, "x");
	path_log_transition(mesh, NULL, PATH_TIER_NONE, PATH_TIER_META_DIRECT, "x");
	path_log_transition(mesh, &dummy, PATH_TIER_NONE, PATH_TIER_META_DIRECT, NULL);
	CHECK(!path_udp_should_probe_local(NULL, &dummy, NULL));
	CHECK(!path_udp_should_probe_local(mesh, NULL, NULL));
	CHECK(!path_pick_local_udp_candidate(mesh, NULL, NULL));

	set_v4(&local, "10.1.2.3", 1234);
	set_v4(&wan, "203.0.113.50", 9);
	set_v4(&nlb, "198.51.100.1", 9);
	set_v4(&relayed, "203.0.113.90", 90);
	memset(&unixish, 0, sizeof unixish);
	unixish.sa.sa_family = AF_UNIX;

	dummy.status.udp_confirmed = true;
	dummy.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	dummy.canonical_address = scratch("198.51.100.1 9");
	path_refresh_canonical_endpoint(&dummy);
	dummy.recent[0] = nlb;
	dummy.recent_source[0] = ADDR_SRC_UNKNOWN;
	dummy.recent_cap[0] = PATH_CAP_UDP;
	dummy.recent[1] = wan;
	dummy.recent_source[1] = ADDR_SRC_HINT;
	dummy.recent_cap[1] = PATH_CAP_BOTH;
	dummy.recent[2] = unixish;
	dummy.recent_source[2] = ADDR_SRC_DISCOVERY;
	dummy.recent_cap[2] = PATH_CAP_BOTH;
	dummy.address = wan;
	CHECK(!path_pick_local_udp_candidate(mesh, &dummy, &out));
	CHECK(!path_udp_should_probe_local(mesh, &dummy, NULL));

	dummy.address = local;
	dummy.recent[3] = local;
	dummy.recent_source[3] = ADDR_SRC_HINT;
	dummy.recent_cap[3] = PATH_CAP_BOTH;
	dummy.recent[4] = relayed;
	dummy.recent_source[4] = ADDR_SRC_INDIRECT;
	dummy.recent_cap[4] = PATH_CAP_META;
	CHECK(!path_pick_local_udp_candidate(mesh, &dummy, &out));
	dummy.address = wan;
	CHECK(path_pick_local_udp_candidate(mesh, &dummy, &out));
	CHECK(!sockaddrcmp(&out, &local));
	dummy.udp_local_probe_next = mesh->loop.now.tv_sec + 60;
	CHECK(!path_udp_should_probe_local(mesh, &dummy, NULL));
	dummy.udp_local_probe_next = 0;
	CHECK(path_udp_should_probe_local(mesh, &dummy, NULL));
	dummy.udp_tier = PATH_TIER_DIRECT_LOCAL_UDP;
	CHECK(!path_udp_should_probe_local(mesh, &dummy, NULL));
	dummy.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	dummy.status.udp_confirmed = false;
	CHECK(!path_udp_should_probe_local(mesh, &dummy, NULL));

	path_clear_recent(&dummy);
	dummy.address = wan;
	set_v4(&dummy.catta_address, "192.168.9.9", 9);
	CHECK(path_pick_local_udp_candidate(mesh, &dummy, &out));
	CHECK(!sockaddrcmp(&out, &dummy.catta_address));
	dummy.address = dummy.catta_address;
	CHECK(!path_pick_local_udp_candidate(mesh, &dummy, &out));
	memset(&dummy.catta_address, 0, sizeof dummy.catta_address);
	set_v4(&dummy.catta_address, "203.0.113.60", 9);
	CHECK(!path_pick_local_udp_candidate(mesh, &dummy, &out));
	return true;
}

typedef struct live_snapshot_t {
	sockaddr_t addr;
	sockaddr_t recent[MAX_RECENT];
	address_source_t src[MAX_RECENT];
	path_cap_t cap[MAX_RECENT];
	sockaddr_t catta;
	sockaddr_t csa;
	sockaddr_t extra;
	sockaddr_t last_from;
	char *canon;
	path_tier_t tier;
	time_t probe;
	bool uc;
	int sock;
} live_snapshot_t;

static void snapshot_live(node_t *live, live_snapshot_t *s) {
	s->addr = live->address;
	s->catta = live->catta_address;
	s->csa = live->canonical_sa;
	s->extra = live->udp_cache_extra;
	s->last_from = live->last_udp_from;
	s->canon = live->canonical_address;
	s->tier = live->udp_tier;
	s->probe = live->udp_local_probe_next;
	s->uc = live->status.udp_confirmed;
	s->sock = live->sock;
	memcpy(s->recent, live->recent, sizeof s->recent);
	memcpy(s->src, live->recent_source, sizeof s->src);
	memcpy(s->cap, live->recent_cap, sizeof s->cap);
}

static void restore_live(meshlink_handle_t *mesh, node_t *live, const live_snapshot_t *s) {
	if(s->addr.sa.sa_family) {
		update_node_udp(mesh, live, &s->addr);
	}

	memcpy(live->recent, s->recent, sizeof s->recent);
	memcpy(live->recent_source, s->src, sizeof s->src);
	memcpy(live->recent_cap, s->cap, sizeof s->cap);
	live->address = s->addr;
	live->catta_address = s->catta;
	live->canonical_sa = s->csa;
	live->udp_cache_extra = s->extra;
	live->last_udp_from = s->last_from;
	live->canonical_address = s->canon;
	live->udp_tier = s->tier;
	live->udp_local_probe_next = s->probe;
	live->status.udp_confirmed = s->uc;
	live->sock = s->sock;
}

static bool cover_promote(meshlink_handle_t *mesh, node_t *live) {
	live_snapshot_t saved;
	bool ok = true;
	sockaddr_t local, wan, nlb;

	snapshot_live(live, &saved);

	set_v4(&local, "10.1.2.3", 1234);
	set_v4(&wan, "203.0.113.50", 9);
	set_v4(&nlb, "198.51.100.1", 9);

#define CHECK_LIVE(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "path_policy_cover_unit failed: %s", #cond); \
		ok = false; \
		goto done; \
	} \
} while(0)

	live->address = wan;
	live->status.udp_confirmed = true;
	path_clear_recent(live);
	path_learn_address(mesh, live, &wan, ADDR_SRC_AUTH_DIRECT);
	live->udp_tier = PATH_TIER_NONE;
	path_note_udp_confirmed(mesh, live);
	CHECK_LIVE(live->udp_tier == PATH_TIER_DIRECT_WAN_UDP);
	path_note_udp_confirmed(mesh, live);

	path_learn_address(mesh, live, &local, ADDR_SRC_DISCOVERY);
	timeout_del(&mesh->loop, &live->promotion_timer);
	memset(&live->promotion_candidate, 0, sizeof live->promotion_candidate);
	live->address = local;
	live->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	path_note_udp_confirmed(mesh, live);
	CHECK_LIVE(live->udp_tier == PATH_TIER_DIRECT_LOCAL_UDP);

	live->status.udp_confirmed = false;
	CHECK_LIVE(!path_promote_udp_if_better(mesh, live, &wan));
	live->status.udp_confirmed = true;
	CHECK_LIVE(!path_promote_udp_if_better(mesh, NULL, &wan));
	CHECK_LIVE(!path_promote_udp_if_better(mesh, live, NULL));
	CHECK_LIVE(!path_promote_udp_if_better(mesh, live, &live->address));

	live->canonical_address = scratch("198.51.100.1 9");
	path_refresh_canonical_endpoint(live);
	CHECK_LIVE(!path_promote_udp_if_better(mesh, live, &nlb));

	live->udp_tier = PATH_TIER_DIRECT_LOCAL_UDP;
	CHECK_LIVE(!path_promote_udp_if_better(mesh, live, &wan));

	live->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	set_v4(&wan, "203.0.113.77", 77);
	CHECK_LIVE(!path_promote_udp_if_better(mesh, live, &wan));

	live->udp_tier = PATH_TIER_NONE;
	set_v4(&wan, "203.0.113.78", 78);
	CHECK_LIVE(path_promote_udp_if_better(mesh, live, &wan));
	CHECK_LIVE(live->udp_tier == PATH_TIER_DIRECT_WAN_UDP);

	CHECK_LIVE(path_promote_udp_if_better(mesh, live, &local));
	CHECK_LIVE(live->udp_tier == PATH_TIER_DIRECT_LOCAL_UDP);
	CHECK_LIVE(!path_promote_udp_if_better(mesh, live, &wan));

done:
	timeout_del(&mesh->loop, &live->promotion_timer);
	memset(&live->promotion_candidate, 0, sizeof live->promotion_candidate);
	restore_live(mesh, live, &saved);
	return ok;
#undef CHECK_LIVE
}

static bool cover_udp_cache(meshlink_handle_t *mesh, node_t *live) {
	live_snapshot_t saved;
	node_t *other = NULL;
	sockaddr_t old_addr, new_addr, third;
	bool ok = true;

	snapshot_live(live, &saved);

	set_v4(&old_addr, "203.0.113.80", 80);
	set_v4(&new_addr, "203.0.113.81", 81);
	set_v4(&third, "203.0.113.82", 82);

#define CHECK_LIVE(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "path_policy_cover_unit failed: %s", #cond); \
		ok = false; \
		goto done; \
	} \
} while(0)

	update_node_udp(mesh, live, &old_addr);
	path_copy_sockaddr(&live->last_udp_from, &old_addr);
	CHECK_LIVE(lookup_node_udp(mesh, &old_addr) == live);

	update_node_udp(mesh, live, &new_addr);
	CHECK_LIVE(!live->last_udp_from.sa.sa_family);
	CHECK_LIVE(lookup_node_udp(mesh, &new_addr) == live);
	CHECK_LIVE(!lookup_node_udp(mesh, &old_addr));

	other = new_node();
	other->name = xstrdup("cover-udp-other");
	node_add(mesh, other);
	update_node_udp(mesh, other, &old_addr);
	CHECK_LIVE(lookup_node_udp(mesh, &old_addr) == other);

	/* Stale last_udp_from on live must not evict other's cache key. */
	path_copy_sockaddr(&live->last_udp_from, &old_addr);
	update_node_udp(mesh, live, &third);
	CHECK_LIVE(lookup_node_udp(mesh, &old_addr) == other);
	CHECK_LIVE(lookup_node_udp(mesh, &third) == live);
	CHECK_LIVE(!live->last_udp_from.sa.sa_family);

	node_del(mesh, other);
	other = NULL;

done:
	other = lookup_node(mesh, "cover-udp-other");

	if(other) {
		node_del(mesh, other);
	}

	restore_live(mesh, live, &saved);
	return ok;
#undef CHECK_LIVE
}

static bool cover_transport(meshlink_handle_t *mesh) {
	node_t n;
	sockaddr_t r1, r2, r3, tcp, nlb;

	memset(&n, 0, sizeof n);
	n.name = scratch("transport");
	set_v4(&r1, "203.0.113.10", 60300);
	set_v4(&r2, "203.0.113.10", 51803);
	set_v4(&r3, "203.0.113.10", 31182);
	set_v4(&tcp, "203.0.113.10", 23349);
	set_v4(&nlb, "198.51.100.1", 443);

	CHECK(path_learn_address_cap(mesh, &n, &r1, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP));
	CHECK(n.recent_cap[0] == PATH_CAP_UDP);
	CHECK(!path_is_meta_candidate(&n, &r1, ADDR_SRC_UDP_REFLEXIVE, n.recent_cap[0]));
	CHECK(path_is_udp_candidate(&n, &r1, ADDR_SRC_UDP_REFLEXIVE, n.recent_cap[0]));
	CHECK(path_learn_address_cap(mesh, &n, &r2, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP));
	CHECK(path_learn_address_cap(mesh, &n, &r3, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP));
	CHECK(!path_best_direct_meta(&n, NULL, &tcp, NULL));

	CHECK(path_learn_address_cap(mesh, &n, &tcp, ADDR_SRC_AUTH_DIRECT, PATH_CAP_META));
	CHECK(path_is_meta_candidate(&n, &tcp, ADDR_SRC_AUTH_DIRECT, n.recent_cap[0]));

	CHECK(path_learn_address_cap(mesh, &n, &tcp, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP));
	CHECK(n.recent_source[0] == ADDR_SRC_AUTH_DIRECT);
	CHECK(n.recent_cap[0] == PATH_CAP_BOTH);

	path_clear_recent(&n);
	n.canonical_address = scratch("nlb.example 443");
	n.canonical_sa_count = 0;
	n.canonical_resolve_backoff = 0;
	CHECK(path_learn_address_cap(mesh, &n, &r1, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_BOTH));
	CHECK(path_is_meta_candidate(&n, &r1, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_BOTH));

	path_clear_recent(&n);
	n.canonical_address = scratch("nlb.example 443");
	path_refresh_canonical_endpoint(&n);
	CHECK(path_learn_address(mesh, &n, &r1, ADDR_SRC_HINT));
	CHECK(!path_is_direct_candidate(&n, &r1, ADDR_SRC_HINT));

	path_clear_recent(&n);
	n.recent[0] = r1;
	n.recent_source[0] = ADDR_SRC_UNKNOWN;
	n.recent_cap[0] = PATH_CAP_NONE;
	path_migrate_legacy_caps(&n);
	CHECK(n.recent_cap[0] == PATH_CAP_UDP);
	CHECK(!path_is_meta_candidate(&n, &r1, ADDR_SRC_UNKNOWN, n.recent_cap[0]));
	return true;
}

static bool cover_active_route(meshlink_handle_t *mesh) {
	node_t dest;
	connection_t conn;
	path_target_t target;
	node_t hop;
	connection_t hopconn;
	node_t *saved_bb;
	backbone_udp_path_t saved_udp;
	struct timespec selected_at;
	sockaddr_t local_ep;
	bool ok;

	memset(&dest, 0, sizeof dest);
	memset(&conn, 0, sizeof conn);
	dest.name = scratch("dest");
	dest.mesh = mesh;
	dest.devclass = DEV_CLASS_STATIONARY;
	dest.lan_admitted_epoch = mesh->lan_network_epoch;
	dest.status.reachable = true;
	dest.status.udp_confirmed = true;
	dest.status.validkey = true;
	dest.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	set_v4(&dest.address, "203.0.113.12", 9);
	dest.address_source = ADDR_SRC_UDP_REFLEXIVE;
	conn.status.active = true;
	conn.node = &dest;
	set_v4(&conn.address, "10.0.0.1", 1);
	dest.connection = &conn;

	CHECK(!strcmp(data_route_kind_name(DATA_ROUTE_DIRECT_UDP), "direct-udp"));
	CHECK(!strcmp(data_route_kind_name(DATA_ROUTE_DIRECT_LOCAL_META), "direct-local-meta"));
	CHECK(!strcmp(data_route_kind_name(DATA_ROUTE_RELAY), "relay"));
	CHECK(!strcmp(data_route_kind_name(DATA_ROUTE_NONE), "none"));
	CHECK(!strcmp(relay_carrier_name(RELAY_CARRIER_UDP), "udp"));
	CHECK(!strcmp(relay_carrier_name(RELAY_CARRIER_META_DIRECT), "meta-direct"));
	CHECK(!strcmp(relay_carrier_name(RELAY_CARRIER_META_CANONICAL), "meta-canonical"));
	CHECK(!strcmp(relay_carrier_name(RELAY_CARRIER_NONE), "none"));

	CHECK(!path_active_send_target(NULL, &dest, &target));
	CHECK(!path_active_send_target(mesh, NULL, &target));
	CHECK(!path_active_send_target(mesh, &dest, NULL));
	path_record_active_route(NULL, &dest, &target);
	path_record_active_route(mesh, NULL, &target);
	path_record_active_route(mesh, &dest, NULL);

	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_DIRECT_UDP);
	CHECK(!target.temporary_fallback);
	CHECK(!sockaddrcmp(&target.udp_endpoint, &dest.address));
	path_record_active_route(mesh, &dest, &target);
	CHECK(dest.active_route.kind == DATA_ROUTE_DIRECT_UDP);
	CHECK(!dest.active_route.suspect);

	memset(&hop, 0, sizeof hop);
	memset(&hopconn, 0, sizeof hopconn);
	hop.name = scratch("camera-hop");
	hop.status.udp_confirmed = true;
	hop.status.validkey = true;
	hop.status.reachable = true;
	set_v4(&hop.address, "10.1.2.3", 9);
	hopconn.status.active = true;
	hopconn.node = &hop;
	hop.connection = &hopconn;
	dest.nexthop = &hop;

	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_DIRECT_UDP);
	CHECK(!target.temporary_fallback);

	hop.status.udp_confirmed = false;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_DIRECT_UDP);
	hop.status.udp_confirmed = true;

	path_note_route_suspect(mesh, &dest, "reliable retransmit");
	CHECK(dest.active_route.suspect);
	CHECK(path_has_live_fallback(mesh, &dest));

	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_DIRECT_LOCAL_META);
	CHECK(target.local);
	CHECK(target.temporary_fallback);
	path_record_active_route(mesh, &dest, &target);
	CHECK(dest.active_route.kind == DATA_ROUTE_DIRECT_UDP);
	CHECK(dest.active_route.suspect);
	CHECK(dest.last_application_traffic == mesh->loop.now.tv_sec);

	dest.active_route.suspect_at.tv_sec = mesh->loop.now.tv_sec - 2;
	path_route_tick(mesh, &dest);
	CHECK(!dest.active_route.suspect);
	CHECK(!dest.status.udp_confirmed);
	CHECK(dest.active_route.kind == DATA_ROUTE_DIRECT_LOCAL_META);

	memset(&dest.active_route, 0, sizeof dest.active_route);
	dest.status.udp_confirmed = false;
	dest.udp_tier = PATH_TIER_NONE;
	dest.connection = NULL;
	dest.lan_admitted_epoch = 0;
	dest.nexthop = &hop;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.first_hop != &hop);

	saved_bb = mesh->backbone.node;
	saved_udp = mesh->backbone_udp;
	ok = true;
	mesh->backbone.node = &hop;
	hop.status.conflict_backbone = false;
	hop.status.udp_confirmed = true;
	hop.status.validkey = true;
	set_v4(&hop.address, "203.0.113.80", 9);
	memset(&mesh->backbone_udp, 0, sizeof mesh->backbone_udp);
	mesh->backbone_udp.node = &hop;
	mesh->backbone_udp.confirmed = true;
	path_copy_sockaddr(&mesh->backbone_udp.endpoint, &hop.address);
	mesh->backbone_udp.source = ADDR_SRC_AUTH_DIRECT;

	memset(&dest.active_route, 0, sizeof dest.active_route);

	if(!path_active_send_target(mesh, &dest, &target)
	                || target.kind != DATA_ROUTE_RELAY
	                || target.relay_carrier != RELAY_CARRIER_UDP
	                || target.first_hop != &hop) {
		ok = false;
	}

	if(ok) {
		path_record_active_route(mesh, &dest, &target);
		hop.status.udp_confirmed = false;

		if(!path_active_send_target(mesh, &dest, &target)
		                || target.kind != DATA_ROUTE_RELAY
		                || target.relay_carrier != RELAY_CARRIER_UDP) {
			ok = false;
		}

		hop.status.udp_confirmed = true;
		mesh->backbone_udp.confirmed = false;

		if(!path_active_send_target(mesh, &dest, &target)
		                || (target.kind == DATA_ROUTE_RELAY && target.relay_carrier == RELAY_CARRIER_UDP)) {
			ok = false;
		}

		mesh->backbone_udp.confirmed = true;
	}

	if(ok) {
		hop.status.conflict_backbone = true;
		memset(&dest.active_route, 0, sizeof dest.active_route);

		if(!path_active_send_target(mesh, &dest, &target) || target.first_hop == &hop) {
			ok = false;
		}

		hop.status.conflict_backbone = false;
	}

	mesh->backbone.node = saved_bb;
	mesh->backbone_udp = saved_udp;

	if(!ok) {
		logger(mesh, MESHLINK_ERROR, "path_policy_cover_unit failed: backbone relay identity");
		return false;
	}

	memset(&dest.active_route, 0, sizeof dest.active_route);
	dest.status.udp_confirmed = true;
	dest.status.validkey = true;
	dest.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	set_v4(&dest.address, "203.0.113.12", 9);
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_DIRECT_UDP);
	path_record_active_route(mesh, &dest, &target);
	dest.active_route.selected_at.tv_sec -= PATH_ROUTE_MIN_RESIDENCY_SEC + 1;
	selected_at = dest.active_route.selected_at;

	memset(&dest.promotion_candidate, 0, sizeof dest.promotion_candidate);
	dest.promotion_candidate.active = true;
	dest.promotion_candidate.kind = DATA_ROUTE_DIRECT_UDP;
	set_v4(&local_ep, "10.9.8.7", 9);
	dest.promotion_candidate.endpoint = local_ep;
	dest.promotion_candidate.source = ADDR_SRC_DISCOVERY;
	dest.promotion_candidate.nonce = 1;
	path_commit_candidate(mesh, &dest);
	CHECK(dest.active_route.kind == DATA_ROUTE_DIRECT_UDP);
	CHECK(dest.active_route.local);
	CHECK(!sockaddrcmp(&dest.active_route.udp_endpoint, &local_ep));
	CHECK(dest.active_route.selected_at.tv_sec != selected_at.tv_sec);

	dest.status.reachable = false;
	CHECK(!path_active_send_target(mesh, &dest, &target));
	path_route_tick(mesh, NULL);
	path_route_tick(NULL, &dest);
	return true;
}

static bool cover_route_usability_and_promotion(meshlink_handle_t *mesh) {
	node_t dest;
	connection_t conn;
	node_t hop;
	connection_t hopconn;
	path_target_t target;
	node_t *saved_bb;
	backbone_udp_path_t saved_udp;
	struct timespec selected_at;
	bool validkey;

	memset(&dest, 0, sizeof dest);
	memset(&conn, 0, sizeof conn);
	memset(&hop, 0, sizeof hop);
	memset(&hopconn, 0, sizeof hopconn);
	dest.name = scratch("dest");
	dest.mesh = mesh;
	dest.devclass = DEV_CLASS_STATIONARY;
	dest.lan_admitted_epoch = mesh->lan_network_epoch;
	dest.status.reachable = true;
	dest.status.udp_confirmed = true;
	dest.status.validkey = true;
	dest.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	set_v4(&dest.address, "203.0.113.12", 9);
	conn.status.active = true;
	conn.node = &dest;
	set_v4(&conn.address, "10.0.0.1", 1);
	dest.connection = &conn;

	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_DIRECT_UDP);
	path_record_active_route(mesh, &dest, &target);
	selected_at = dest.active_route.selected_at;
	mesh->loop.now.tv_sec += 1;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_DIRECT_UDP);
	CHECK(dest.active_route.selected_at.tv_sec == selected_at.tv_sec);
	CHECK(dest.active_route.selected_at.tv_nsec == selected_at.tv_nsec);

	dest.status.udp_confirmed = false;
	mesh->loop.now.tv_sec += 1;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind != DATA_ROUTE_DIRECT_UDP);
	CHECK(dest.active_route.kind != DATA_ROUTE_DIRECT_UDP);
	CHECK(timespec_neq(&dest.active_route.selected_at, &selected_at));

	hop.name = scratch("bb");
	hop.status.reachable = true;
	hop.status.validkey = true;
	hop.status.udp_confirmed = true;
	set_v4(&hop.address, "203.0.113.80", 9);
	hopconn.status.active = true;
	hopconn.node = &hop;
	set_v4(&hopconn.address, "203.0.113.80", 9);
	hop.connection = &hopconn;
	path_mark_meta_dial(&hopconn, true);

	saved_bb = mesh->backbone.node;
	saved_udp = mesh->backbone_udp;
	mesh->backbone.node = &hop;
	memset(&mesh->backbone_udp, 0, sizeof mesh->backbone_udp);
	mesh->backbone_udp.node = &hop;

	memset(&dest.active_route, 0, sizeof dest.active_route);
	dest.status.udp_confirmed = false;
	dest.udp_tier = PATH_TIER_NONE;
	dest.connection = NULL;
	dest.lan_admitted_epoch = 0;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_RELAY);
	CHECK(target.relay_carrier == RELAY_CARRIER_META_CANONICAL);
	path_record_active_route(mesh, &dest, &target);
	selected_at = dest.active_route.selected_at;
	path_mark_meta_dial(&hopconn, false);
	mesh->loop.now.tv_sec += 1;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_RELAY);
	CHECK(target.relay_carrier == RELAY_CARRIER_META_DIRECT);
	CHECK(dest.active_route.relay_carrier == RELAY_CARRIER_META_DIRECT);
	CHECK(timespec_neq(&dest.active_route.selected_at, &selected_at));
	selected_at = dest.active_route.selected_at;
	path_mark_meta_dial(&hopconn, true);
	mesh->loop.now.tv_sec += 1;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.relay_carrier == RELAY_CARRIER_META_CANONICAL);
	CHECK(dest.active_route.relay_carrier == RELAY_CARRIER_META_CANONICAL);
	CHECK(timespec_neq(&dest.active_route.selected_at, &selected_at));

	memset(&dest.promotion_candidate, 0, sizeof dest.promotion_candidate);
	selected_at = dest.active_route.selected_at;
	dest.peer_udp.channel_count = 1;
	memset(&dest.peer_udp.idle_until, 0, sizeof dest.peer_udp.idle_until);
	mesh->backbone_udp.confirmed = true;
	path_copy_sockaddr(&mesh->backbone_udp.endpoint, &hop.address);
	mesh->backbone_udp.source = ADDR_SRC_AUTH_DIRECT;
	path_consider_route_promotion(mesh, &dest, PATH_PROMOTION_BACKBONE_UDP);
	CHECK(dest.promotion_candidate.active);
	CHECK(dest.promotion_candidate.kind == DATA_ROUTE_RELAY);
	CHECK(dest.promotion_candidate.relay_carrier == RELAY_CARRIER_UDP);
	mesh->loop.now.tv_sec += 1;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_RELAY);
	CHECK(target.relay_carrier == RELAY_CARRIER_META_CANONICAL);
	CHECK(dest.active_route.selected_at.tv_sec == selected_at.tv_sec);
	CHECK(dest.active_route.selected_at.tv_nsec == selected_at.tv_nsec);
	dest.active_route.selected_at.tv_sec -= PATH_ROUTE_MIN_RESIDENCY_SEC + 1;
	selected_at = dest.active_route.selected_at;
	dest.promotion_candidate.first_success.tv_sec -= 1;
	path_route_tick(mesh, &dest);
	CHECK(!dest.promotion_candidate.active);
	CHECK(dest.active_route.kind == DATA_ROUTE_RELAY);
	CHECK(dest.active_route.relay_carrier == RELAY_CARRIER_UDP);
	CHECK(timespec_neq(&dest.active_route.selected_at, &selected_at));

	memset(&dest.promotion_candidate, 0, sizeof dest.promotion_candidate);
	dest.connection = &conn;
	dest.lan_admitted_epoch = mesh->lan_network_epoch;
	validkey = dest.status.validkey;
	selected_at = dest.active_route.selected_at;
	path_consider_route_promotion(mesh, &dest, PATH_PROMOTION_LOCAL_META);
	CHECK(dest.promotion_candidate.active);
	CHECK(dest.promotion_candidate.kind == DATA_ROUTE_DIRECT_LOCAL_META);
	mesh->loop.now.tv_sec += 1;
	CHECK(path_active_send_target(mesh, &dest, &target));
	CHECK(target.kind == DATA_ROUTE_RELAY);
	CHECK(target.relay_carrier == RELAY_CARRIER_UDP);
	CHECK(dest.status.validkey == validkey);
	CHECK(dest.active_route.selected_at.tv_sec == selected_at.tv_sec);
	CHECK(dest.active_route.selected_at.tv_nsec == selected_at.tv_nsec);
	dest.active_route.selected_at.tv_sec -= PATH_ROUTE_MIN_RESIDENCY_SEC + 1;
	selected_at = dest.active_route.selected_at;
	dest.promotion_candidate.first_success.tv_sec -= 1;
	path_route_tick(mesh, &dest);
	CHECK(!dest.promotion_candidate.active);
	CHECK(dest.active_route.kind == DATA_ROUTE_DIRECT_LOCAL_META);
	CHECK(dest.active_route.local);
	CHECK(dest.status.validkey == validkey);
	CHECK(timespec_neq(&dest.active_route.selected_at, &selected_at));

	/* A worse candidate must not overwrite a better route that landed during hold. */
	memset(&dest.promotion_candidate, 0, sizeof dest.promotion_candidate);
	timeout_del(&mesh->loop, &dest.promotion_timer);
	dest.status.udp_confirmed = false;
	dest.udp_tier = PATH_TIER_NONE;
	dest.connection = &conn;
	dest.lan_admitted_epoch = mesh->lan_network_epoch;
	path_mark_meta_dial(&hopconn, true);
	memset(&target, 0, sizeof target);
	target.kind = DATA_ROUTE_RELAY;
	target.relay_carrier = RELAY_CARRIER_META_CANONICAL;
	target.first_hop = &hop;
	path_record_active_route(mesh, &dest, &target);
	CHECK(dest.active_route.kind == DATA_ROUTE_RELAY);
	CHECK(dest.active_route.relay_carrier == RELAY_CARRIER_META_CANONICAL);
	path_consider_route_promotion(mesh, &dest, PATH_PROMOTION_LOCAL_META);
	CHECK(dest.promotion_candidate.active);
	CHECK(dest.promotion_candidate.kind == DATA_ROUTE_DIRECT_LOCAL_META);
	dest.status.udp_confirmed = true;
	dest.status.validkey = true;
	dest.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	set_v4(&dest.address, "203.0.113.12", 9);
	memset(&target, 0, sizeof target);
	target.kind = DATA_ROUTE_DIRECT_UDP;
	path_copy_sockaddr(&target.udp_endpoint, &dest.address);
	target.endpoint_source = dest.address_source;
	path_record_active_route(mesh, &dest, &target);
	CHECK(dest.active_route.kind == DATA_ROUTE_DIRECT_UDP);
	dest.active_route.selected_at.tv_sec -= PATH_ROUTE_MIN_RESIDENCY_SEC + 1;
	dest.promotion_candidate.first_success.tv_sec -= 1;
	path_route_tick(mesh, &dest);
	CHECK(!dest.promotion_candidate.active);
	CHECK(dest.active_route.kind == DATA_ROUTE_DIRECT_UDP);

	/* Backbone UDP endpoint change during hold must not commit the new endpoint. */
	memset(&dest.promotion_candidate, 0, sizeof dest.promotion_candidate);
	timeout_del(&mesh->loop, &dest.promotion_timer);
	dest.status.udp_confirmed = false;
	dest.udp_tier = PATH_TIER_NONE;
	dest.connection = NULL;
	dest.lan_admitted_epoch = 0;
	path_mark_meta_dial(&hopconn, true);
	memset(&target, 0, sizeof target);
	target.kind = DATA_ROUTE_RELAY;
	target.relay_carrier = RELAY_CARRIER_META_CANONICAL;
	target.first_hop = &hop;
	path_record_active_route(mesh, &dest, &target);
	path_copy_sockaddr(&mesh->backbone_udp.endpoint, &hop.address);
	mesh->backbone_udp.source = ADDR_SRC_AUTH_DIRECT;
	mesh->backbone_udp.confirmed = true;
	path_consider_route_promotion(mesh, &dest, PATH_PROMOTION_BACKBONE_UDP);
	CHECK(dest.promotion_candidate.active);
	CHECK(dest.promotion_candidate.relay_carrier == RELAY_CARRIER_UDP);
	CHECK(!sockaddrcmp(&dest.promotion_candidate.endpoint, &hop.address));
	set_v4(&mesh->backbone_udp.endpoint, "203.0.113.81", 9);
	mesh->backbone_udp.source = ADDR_SRC_UDP_REFLEXIVE;
	dest.active_route.selected_at.tv_sec -= PATH_ROUTE_MIN_RESIDENCY_SEC + 1;
	dest.promotion_candidate.first_success.tv_sec -= 1;
	path_route_tick(mesh, &dest);
	CHECK(!dest.promotion_candidate.active);
	CHECK(dest.active_route.kind == DATA_ROUTE_RELAY);
	CHECK(dest.active_route.relay_carrier == RELAY_CARRIER_META_CANONICAL);
	CHECK(sockaddrcmp(&dest.active_route.udp_endpoint, &mesh->backbone_udp.endpoint));

	/* Already-live direct-UDP carrier: demote during hold must not commit the stale endpoint. */
	memset(&dest.promotion_candidate, 0, sizeof dest.promotion_candidate);
	timeout_del(&mesh->loop, &dest.promotion_timer);
	dest.connection = NULL;
	dest.lan_admitted_epoch = 0;
	dest.status.udp_confirmed = true;
	dest.status.validkey = true;
	dest.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	set_v4(&dest.address, "203.0.113.12", 9);
	memset(&target, 0, sizeof target);
	target.kind = DATA_ROUTE_RELAY;
	target.relay_carrier = RELAY_CARRIER_META_CANONICAL;
	target.first_hop = &hop;
	path_record_active_route(mesh, &dest, &target);
	path_consider_route_promotion(mesh, &dest, PATH_PROMOTION_DIRECT_UDP);
	CHECK(dest.promotion_candidate.active);
	CHECK(dest.promotion_candidate.kind == DATA_ROUTE_DIRECT_UDP);
	CHECK(!dest.promotion_candidate.nonce);
	path_note_udp_demoted_reason(mesh, &dest, "cover");
	CHECK(!dest.status.udp_confirmed);
	dest.active_route.selected_at.tv_sec -= PATH_ROUTE_MIN_RESIDENCY_SEC + 1;
	selected_at = dest.active_route.selected_at;
	dest.promotion_candidate.first_success.tv_sec -= 1;
	path_route_tick(mesh, &dest);
	CHECK(!dest.promotion_candidate.active);
	CHECK(dest.active_route.kind == DATA_ROUTE_RELAY);
	CHECK(dest.active_route.relay_carrier == RELAY_CARRIER_META_CANONICAL);
	CHECK(dest.active_route.selected_at.tv_sec == selected_at.tv_sec);
	CHECK(dest.active_route.selected_at.tv_nsec == selected_at.tv_nsec);

	mesh->backbone.node = saved_bb;
	mesh->backbone_udp = saved_udp;

	/* Candidate first_hop deleted during hold: relay-UDP and META-direct. */
	{
		node_t *waiter = new_node();
		node_t *dying = new_node();

		waiter->name = xstrdup("cover-cand-waiter");
		waiter->devclass = DEV_CLASS_STATIONARY;
		waiter->status.reachable = true;
		waiter->status.validkey = true;
		node_add(mesh, waiter);

		dying->name = xstrdup("cover-dying-hop");
		dying->devclass = DEV_CLASS_STATIONARY;
		dying->status.reachable = true;
		dying->status.validkey = true;
		node_add(mesh, dying);

		waiter->promotion_candidate.active = true;
		waiter->promotion_candidate.kind = DATA_ROUTE_RELAY;
		waiter->promotion_candidate.relay_carrier = RELAY_CARRIER_UDP;
		waiter->promotion_candidate.first_hop = dying;
		waiter->active_route.kind = DATA_ROUTE_RELAY;
		waiter->active_route.relay_carrier = RELAY_CARRIER_META_CANONICAL;
		waiter->active_route.first_hop = dying;
		node_del(mesh, dying);
		dying = NULL;
		CHECK(!waiter->promotion_candidate.active);
		CHECK(!waiter->promotion_candidate.first_hop);
		CHECK(!waiter->promotion_candidate.kind);
		CHECK(!waiter->active_route.first_hop);

		dying = new_node();
		dying->name = xstrdup("cover-dying-hop-meta");
		dying->devclass = DEV_CLASS_STATIONARY;
		dying->status.reachable = true;
		dying->status.validkey = true;
		node_add(mesh, dying);

		timeout_del(&mesh->loop, &waiter->promotion_timer);
		memset(&waiter->promotion_candidate, 0, sizeof waiter->promotion_candidate);
		waiter->promotion_candidate.active = true;
		waiter->promotion_candidate.kind = DATA_ROUTE_RELAY;
		waiter->promotion_candidate.relay_carrier = RELAY_CARRIER_META_DIRECT;
		waiter->promotion_candidate.first_hop = dying;
		waiter->active_route.kind = DATA_ROUTE_RELAY;
		waiter->active_route.relay_carrier = RELAY_CARRIER_META_CANONICAL;
		waiter->active_route.first_hop = dying;
		node_del(mesh, dying);
		dying = NULL;
		CHECK(!waiter->promotion_candidate.active);
		CHECK(!waiter->promotion_candidate.first_hop);
		CHECK(waiter->promotion_candidate.relay_carrier == RELAY_CARRIER_NONE);

		node_del(mesh, waiter);
	}

	/* Idle dest with a stale recorded route must not get an elective candidate. */
	{
		node_t *idle = new_node();

		idle->name = xstrdup("cover-idle-dest");
		idle->devclass = DEV_CLASS_STATIONARY;
		idle->status.reachable = true;
		idle->status.validkey = true;
		node_add(mesh, idle);

		memset(&idle->active_route, 0, sizeof idle->active_route);
		idle->active_route.kind = DATA_ROUTE_RELAY;
		idle->active_route.relay_carrier = RELAY_CARRIER_META_CANONICAL;
		idle->active_route.first_hop = saved_bb;
		idle->active_route.selected_at = mesh->loop.now;
		memset(&idle->peer_udp, 0, sizeof idle->peer_udp);

		path_consider_route_promotion(mesh, idle, PATH_PROMOTION_BACKBONE_UDP);
		CHECK(!idle->promotion_candidate.active);

		dest.peer_udp.channel_count = 0;
		memset(&dest.peer_udp.idle_until, 0, sizeof dest.peer_udp.idle_until);
		memset(&dest.promotion_candidate, 0, sizeof dest.promotion_candidate);
		path_consider_route_promotion(mesh, &dest, PATH_PROMOTION_BACKBONE_UDP);
		CHECK(!dest.promotion_candidate.active);

		node_del(mesh, idle);
	}

	{
		node_t *n;
		const char *leftover[] = {
			"cover-cand-waiter",
			"cover-dying-hop",
			"cover-dying-hop-meta",
			"cover-idle-dest",
		};

		for(size_t i = 0; i < sizeof leftover / sizeof leftover[0]; i++) {
			n = lookup_node(mesh, leftover[i]);

			if(n) {
				node_del(mesh, n);
			}
		}
	}

	timeout_del(&mesh->loop, &dest.promotion_timer);
	memset(&dest.promotion_candidate, 0, sizeof dest.promotion_candidate);
	return true;
}

static bool cover_preserve(meshlink_handle_t *mesh) {
	return upgrade_preserve_cover_unit(mesh);
}

static bool cover_demand(meshlink_handle_t *mesh) {
	node_t dummy;

	memset(&dummy, 0, sizeof dummy);
	dummy.name = scratch("demand");
	dummy.mesh = mesh;

	CHECK(!path_peer_udp_demanded(NULL, &dummy));
	CHECK(!path_peer_udp_demanded(mesh, NULL));
	CHECK(!path_peer_udp_demanded(mesh, &dummy));
	CHECK(!path_liveness_probe_warranted(mesh, &dummy));
	path_peer_ensure_udp_key(NULL, &dummy);
	path_peer_ensure_udp_key(mesh, NULL);
	path_peer_ensure_udp_key(mesh, &dummy);

	CHECK(!path_channel_acquire(NULL, &dummy));
	CHECK(!path_channel_acquire(mesh, NULL));
	CHECK(!dummy.peer_udp.channel_count);

	/* Backbone, UNKNOWN, and self are not ordinary peer pairs. */
	dummy.devclass = DEV_CLASS_BACKBONE;
	CHECK(!path_channel_acquire(mesh, &dummy));
	CHECK(!dummy.peer_udp.channel_count);
	CHECK(!path_liveness_probe_warranted(mesh, &dummy));
	dummy.peer_udp.channel_count = 1;
	path_channel_release(mesh, &dummy);
	CHECK(!dummy.peer_udp.channel_count);
	CHECK(!dummy.peer_udp.idle_until.tv_sec);

	dummy.devclass = DEV_CLASS_UNKNOWN;
	CHECK(!path_channel_acquire(mesh, &dummy));
	CHECK(!dummy.peer_udp.channel_count);

	if(mesh->self) {
		unsigned self_count = mesh->self->peer_udp.channel_count;
		CHECK(!path_channel_acquire(mesh, mesh->self));
		CHECK(mesh->self->peer_udp.channel_count == self_count);
	}

	dummy.devclass = DEV_CLASS_STATIONARY;
	CHECK(path_channel_acquire(mesh, &dummy));
	CHECK(dummy.peer_udp.channel_count == 1);
	CHECK(path_peer_udp_demanded(mesh, &dummy));
	CHECK(path_liveness_probe_warranted(mesh, &dummy));

	CHECK(path_channel_acquire(mesh, &dummy));
	CHECK(dummy.peer_udp.channel_count == 2);

	path_channel_release(mesh, &dummy);
	CHECK(dummy.peer_udp.channel_count == 1);
	CHECK(!dummy.peer_udp.idle_until.tv_sec);
	CHECK(path_peer_udp_demanded(mesh, &dummy));

	path_channel_release(NULL, &dummy);
	path_channel_release(mesh, NULL);
	CHECK(dummy.peer_udp.channel_count == 1);

	path_channel_release(mesh, &dummy);
	CHECK(!dummy.peer_udp.channel_count);
	CHECK(dummy.peer_udp.idle_until.tv_sec == mesh->loop.now.tv_sec + PATH_PEER_UDP_GRACE_SEC);
	CHECK(path_peer_udp_demanded(mesh, &dummy));
	CHECK(path_liveness_probe_warranted(mesh, &dummy));

	path_channel_release(mesh, &dummy);
	CHECK(!dummy.peer_udp.channel_count);

	/* Reclassify after acquire: release still decrements, and does not leave
	   grace that could reactivate if the class becomes eligible again. */
	memset(&dummy.peer_udp, 0, sizeof dummy.peer_udp);
	dummy.devclass = DEV_CLASS_STATIONARY;
	CHECK(path_channel_acquire(mesh, &dummy));
	CHECK(dummy.peer_udp.channel_count == 1);
	dummy.devclass = DEV_CLASS_UNKNOWN;
	path_channel_release(mesh, &dummy);
	CHECK(!dummy.peer_udp.channel_count);
	CHECK(!dummy.peer_udp.idle_until.tv_sec);
	dummy.devclass = DEV_CLASS_STATIONARY;
	CHECK(!path_peer_udp_demanded(mesh, &dummy));
	CHECK(!path_liveness_probe_warranted(mesh, &dummy));

	dummy.devclass = DEV_CLASS_STATIONARY;
	CHECK(path_channel_acquire(mesh, &dummy));
	CHECK(dummy.peer_udp.channel_count == 1);
	dummy.devclass = DEV_CLASS_BACKBONE;
	path_channel_release(mesh, &dummy);
	CHECK(!dummy.peer_udp.channel_count);
	dummy.devclass = DEV_CLASS_STATIONARY;
	CHECK(!path_peer_udp_demanded(mesh, &dummy));
	CHECK(!path_liveness_probe_warranted(mesh, &dummy));
	path_channel_release(mesh, &dummy);
	CHECK(!dummy.peer_udp.channel_count);

	dummy.peer_udp.idle_until = mesh->loop.now;
	dummy.peer_udp.idle_until.tv_sec -= 1;

	if(dummy.peer_udp.idle_until.tv_sec < 0) {
		dummy.peer_udp.idle_until.tv_sec = 0;
		dummy.peer_udp.idle_until.tv_nsec = 0;
		CHECK(!path_peer_udp_demanded(mesh, &dummy));
	} else {
		CHECK(!path_peer_udp_demanded(mesh, &dummy));
		path_route_tick(mesh, &dummy);
		CHECK(!dummy.peer_udp.idle_until.tv_sec);
		CHECK(!dummy.peer_udp.idle_until.tv_nsec);
		CHECK(!path_liveness_probe_warranted(mesh, &dummy));
	}

	timeout_del(&mesh->loop, &dummy.mtutimeout);
	timeout_del(&mesh->loop, &dummy.promotion_timer);
	return true;
}

static bool cover_promotion(meshlink_handle_t *mesh, node_t *live) {
	live_snapshot_t saved;
	peer_path_demand_t saved_demand;
	bool ok = true;
	sockaddr_t local, wan;
	uint64_t nonce, spent;

	snapshot_live(live, &saved);
	timeout_del(&mesh->loop, &live->promotion_timer);
	memset(&live->promotion_candidate, 0, sizeof live->promotion_candidate);
	memset(&live->candidate_retry, 0, sizeof live->candidate_retry);
	saved_demand = live->peer_udp;
	live->peer_udp.channel_count = 1;
	memset(&live->peer_udp.idle_until, 0, sizeof live->peer_udp.idle_until);

	set_v4(&local, "10.9.8.7", 4242);
	set_v4(&wan, "203.0.113.40", 9);

#define CHECK_LIVE(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "path_policy_cover_unit failed: %s", #cond); \
		ok = false; \
		goto done; \
	} \
} while(0)

	live->address = wan;
	live->status.udp_confirmed = true;
	path_clear_recent(live);
	path_learn_address(mesh, live, &wan, ADDR_SRC_AUTH_DIRECT);
	live->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	path_consider_promotion(mesh, live, PATH_PROMOTION_TICK);
	CHECK_LIVE(!live->promotion_candidate.active);

	path_learn_address(mesh, live, &local, ADDR_SRC_DISCOVERY);
	CHECK_LIVE(live->promotion_candidate.active);
	CHECK_LIVE(live->promotion_timer.cb);
	send_candidate_probe(mesh, live);
	CHECK_LIVE(!live->probe_dest_override_active);

	path_candidate_timeout(mesh, live, "cover");
	CHECK_LIVE(!live->promotion_candidate.active);
	CHECK_LIVE(!live->promotion_timer.cb);
	CHECK_LIVE(live->candidate_retry.cooldown_until.tv_sec > mesh->loop.now.tv_sec);

	path_consider_promotion(mesh, live, PATH_PROMOTION_TICK);
	CHECK_LIVE(!live->promotion_candidate.active);

	path_candidate_clear_cooldown(mesh, live);
	CHECK_LIVE(live->promotion_candidate.active);
	CHECK_LIVE(live->promotion_timer.cb);

	nonce = live->promotion_candidate.nonce;
	CHECK_LIVE(nonce);
	path_observe_probe_reply(mesh, live, &local, nonce ^ 1);
	CHECK_LIVE(live->promotion_candidate.successful_rounds == 0);

	path_observe_probe_reply(mesh, live, &local, nonce);
	CHECK_LIVE(live->promotion_candidate.successful_rounds == 1);
	CHECK_LIVE(live->promotion_timer.cb);
	spent = nonce;
	nonce = live->promotion_candidate.nonce;
	CHECK_LIVE(nonce != spent);
	path_observe_probe_reply(mesh, live, &local, spent);
	CHECK_LIVE(live->promotion_candidate.successful_rounds == 1);

	memset(&live->active_route, 0, sizeof live->active_route);
	live->active_route.kind = DATA_ROUTE_DIRECT_UDP;
	path_copy_sockaddr(&live->active_route.udp_endpoint, &wan);
	live->active_route.selected_at = mesh->loop.now;
	live->promotion_candidate.first_success.tv_sec -= 1;
	path_observe_probe_reply(mesh, live, &local, nonce);
	CHECK_LIVE(live->promotion_candidate.successful_rounds == 2);
	CHECK_LIVE(!live->promotion_timer.cb);
	CHECK_LIVE(live->promotion_candidate.active);

	live->active_route.selected_at.tv_sec -= PATH_ROUTE_MIN_RESIDENCY_SEC + 1;
	path_route_tick(mesh, live);
	CHECK_LIVE(!live->promotion_candidate.active);
	CHECK_LIVE(!sockaddrcmp(&live->address, &local));
	CHECK_LIVE(!live->candidate_retry.failures);
	CHECK_LIVE(!live->candidate_retry.cooldown_until.tv_sec);

done:
	timeout_del(&mesh->loop, &live->promotion_timer);
	memset(&live->promotion_candidate, 0, sizeof live->promotion_candidate);
	memset(&live->candidate_retry, 0, sizeof live->candidate_retry);
	live->peer_udp = saved_demand;
	restore_live(mesh, live, &saved);
	return ok;
#undef CHECK_LIVE
}

static bool cover_escalation(meshlink_handle_t *mesh, node_t *live) {
	live_snapshot_t saved;
	peer_path_demand_t saved_demand;
	data_route_t saved_route;
	bool ok = true;
	sockaddr_t local, wan;

	snapshot_live(live, &saved);
	saved_route = live->active_route;
	timeout_del(&mesh->loop, &live->promotion_timer);
	memset(&live->promotion_candidate, 0, sizeof live->promotion_candidate);
	memset(&live->candidate_retry, 0, sizeof live->candidate_retry);
	saved_demand = live->peer_udp;
	live->peer_udp.channel_count = 1;
	memset(&live->peer_udp.idle_until, 0, sizeof live->peer_udp.idle_until);

	set_v4(&local, "10.9.8.7", 4242);
	set_v4(&wan, "203.0.113.40", 9);

#define CHECK_LIVE(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "path_policy_cover_unit failed: %s", #cond); \
		ok = false; \
		goto done; \
	} \
} while(0)

	live->address = wan;
	live->status.udp_confirmed = true;
	memset(&live->catta_address, 0, sizeof live->catta_address);
	path_clear_recent(live);
	path_learn_address(mesh, live, &wan, ADDR_SRC_AUTH_DIRECT);
	live->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	memset(&live->active_route, 0, sizeof live->active_route);
	live->active_route.kind = DATA_ROUTE_DIRECT_UDP;
	path_copy_sockaddr(&live->active_route.udp_endpoint, &wan);
	live->active_route.selected_at = mesh->loop.now;
	live->active_route.selected_at.tv_sec -= PATH_HEALTHY_RESET_SEC + 1;

	path_learn_address(mesh, live, &local, ADDR_SRC_DISCOVERY);
	CHECK_LIVE(live->promotion_candidate.active);

	path_candidate_timeout(mesh, live, "cover-aged-route");
	path_route_tick(mesh, live);
	CHECK_LIVE(live->candidate_retry.failures == 1);
	CHECK_LIVE(live->candidate_retry.cooldown_until.tv_sec > mesh->loop.now.tv_sec);
	CHECK_LIVE(!live->promotion_candidate.active);
	CHECK_LIVE(!live->active_route.healthy_since.tv_sec);

	path_observe_probe_reply(mesh, live, &wan, 0);
	CHECK_LIVE(live->active_route.healthy_since.tv_sec != 0);

	live->active_route.healthy_since.tv_sec -= PATH_HEALTHY_RESET_SEC;
	path_route_tick(mesh, live);
	CHECK_LIVE(live->candidate_retry.failures == 1);
	CHECK_LIVE(live->candidate_retry.cooldown_until.tv_sec > mesh->loop.now.tv_sec);

	memset(&live->candidate_retry.cooldown_until, 0, sizeof live->candidate_retry.cooldown_until);
	path_clear_recent(live);
	path_learn_address(mesh, live, &wan, ADDR_SRC_AUTH_DIRECT);
	live->candidate_retry.last_failure_at.tv_sec -= PATH_HEALTHY_RESET_SEC + 1;
	live->active_route.healthy_since.tv_sec -= PATH_HEALTHY_RESET_SEC;
	path_route_tick(mesh, live);
	CHECK_LIVE(live->candidate_retry.failures == 0);
	CHECK_LIVE(!live->promotion_candidate.active);

	path_observe_probe_reply(mesh, live, &wan, 0);
	CHECK_LIVE(live->active_route.healthy_since.tv_sec != 0);
	path_note_route_suspect(mesh, live, "cover-escalation");
	CHECK_LIVE(live->active_route.suspect);
	CHECK_LIVE(!live->active_route.healthy_since.tv_sec);

done:
	timeout_del(&mesh->loop, &live->promotion_timer);
	memset(&live->promotion_candidate, 0, sizeof live->promotion_candidate);
	memset(&live->candidate_retry, 0, sizeof live->candidate_retry);
	live->peer_udp = saved_demand;
	live->active_route = saved_route;
	restore_live(mesh, live, &saved);
	return ok;
#undef CHECK_LIVE
}

static bool cover_retry_survives_carrier(meshlink_handle_t *mesh) {
	node_t dest;
	connection_t conn;
	node_t hop;
	connection_t hopconn;
	node_t *saved_bb;
	backbone_udp_path_t saved_udp;
	sockaddr_t local, wan;
	path_candidate_retry_t saved_retry;
	bool ok = true;

	memset(&dest, 0, sizeof dest);
	memset(&conn, 0, sizeof conn);
	memset(&hop, 0, sizeof hop);
	memset(&hopconn, 0, sizeof hopconn);
	dest.name = scratch("retry-dest");
	dest.mesh = mesh;
	dest.devclass = DEV_CLASS_STATIONARY;
	dest.status.reachable = true;
	dest.status.udp_confirmed = true;
	dest.status.validkey = true;
	dest.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	dest.peer_udp.channel_count = 1;
	set_v4(&wan, "203.0.113.40", 9);
	set_v4(&local, "10.9.8.7", 4242);
	dest.address = wan;
	conn.status.active = true;
	conn.node = &dest;
	set_v4(&conn.address, "10.0.0.1", 1);
	dest.connection = &conn;
	path_mark_meta_dial(&conn, true);

	hop.name = scratch("retry-bb");
	hop.status.reachable = true;
	hop.status.validkey = true;
	hop.status.udp_confirmed = true;
	set_v4(&hop.address, "203.0.113.80", 9);
	hopconn.status.active = true;
	hopconn.node = &hop;
	hopconn.address = hop.address;
	hop.connection = &hopconn;
	path_mark_meta_dial(&hopconn, true);

	saved_bb = mesh->backbone.node;
	saved_udp = mesh->backbone_udp;

#define CHECK_RETRY(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "path_policy_cover_unit failed: %s", #cond); \
		ok = false; \
		goto done; \
	} \
} while(0)

	path_clear_recent(&dest);
	path_learn_address(mesh, &dest, &wan, ADDR_SRC_AUTH_DIRECT);
	memset(&dest.active_route, 0, sizeof dest.active_route);
	dest.active_route.kind = DATA_ROUTE_RELAY;
	dest.active_route.relay_carrier = RELAY_CARRIER_META_CANONICAL;
	dest.active_route.first_hop = &hop;
	dest.active_route.selected_at = mesh->loop.now;

	path_learn_address(mesh, &dest, &local, ADDR_SRC_DISCOVERY);
	CHECK_RETRY(dest.promotion_candidate.active);
	CHECK_RETRY(dest.promotion_candidate.kind == DATA_ROUTE_DIRECT_UDP);

	path_candidate_timeout(mesh, &dest, "retry-1");
	CHECK_RETRY(dest.candidate_retry.failures == 1);
	CHECK_RETRY(dest.candidate_retry.cooldown_until.tv_sec > mesh->loop.now.tv_sec);
	path_candidate_clear_cooldown(mesh, &dest);
	CHECK_RETRY(dest.promotion_candidate.active);
	path_candidate_timeout(mesh, &dest, "retry-2");
	CHECK_RETRY(dest.candidate_retry.failures == 2);
	CHECK_RETRY(dest.candidate_retry.cooldown_until.tv_sec > mesh->loop.now.tv_sec);
	CHECK_RETRY(!dest.promotion_candidate.active);
	saved_retry = dest.candidate_retry;

	mesh->backbone.node = &hop;
	memset(&mesh->backbone_udp, 0, sizeof mesh->backbone_udp);
	mesh->backbone_udp.node = &hop;
	mesh->backbone_udp.confirmed = true;
	path_copy_sockaddr(&mesh->backbone_udp.endpoint, &hop.address);
	mesh->backbone_udp.source = ADDR_SRC_AUTH_DIRECT;
	path_consider_route_promotion(mesh, &dest, PATH_PROMOTION_BACKBONE_UDP);
	CHECK_RETRY(dest.promotion_candidate.active);
	CHECK_RETRY(dest.promotion_candidate.kind == DATA_ROUTE_RELAY);
	CHECK_RETRY(dest.promotion_candidate.relay_carrier == RELAY_CARRIER_UDP);
	CHECK_RETRY(dest.candidate_retry.failures == saved_retry.failures);
	CHECK_RETRY(dest.candidate_retry.last_failure_at.tv_sec == saved_retry.last_failure_at.tv_sec);
	CHECK_RETRY(dest.candidate_retry.last_failure_at.tv_nsec == saved_retry.last_failure_at.tv_nsec);
	CHECK_RETRY(dest.candidate_retry.cooldown_until.tv_sec == saved_retry.cooldown_until.tv_sec);
	CHECK_RETRY(dest.candidate_retry.cooldown_until.tv_nsec == saved_retry.cooldown_until.tv_nsec);
	CHECK_RETRY(!sockaddrcmp(&dest.candidate_retry.endpoint, &saved_retry.endpoint));

	dest.active_route.selected_at.tv_sec -= PATH_ROUTE_MIN_RESIDENCY_SEC + 1;
	dest.promotion_candidate.first_success.tv_sec -= 1;
	path_route_tick(mesh, &dest);
	CHECK_RETRY(!dest.promotion_candidate.active);
	CHECK_RETRY(dest.active_route.kind == DATA_ROUTE_RELAY);
	CHECK_RETRY(dest.active_route.relay_carrier == RELAY_CARRIER_UDP);
	CHECK_RETRY(dest.candidate_retry.failures == saved_retry.failures);
	CHECK_RETRY(dest.candidate_retry.cooldown_until.tv_sec == saved_retry.cooldown_until.tv_sec);
	CHECK_RETRY(!sockaddrcmp(&dest.candidate_retry.endpoint, &saved_retry.endpoint));

	path_consider_promotion(mesh, &dest, PATH_PROMOTION_TICK);
	CHECK_RETRY(!dest.promotion_candidate.active);
	path_consider_promotion(mesh, &dest, PATH_PROMOTION_DISCOVERY);
	CHECK_RETRY(!dest.promotion_candidate.active);
	path_consider_promotion(mesh, &dest, PATH_PROMOTION_HINT);
	CHECK_RETRY(!dest.promotion_candidate.active);
	path_learn_address(mesh, &dest, &local, ADDR_SRC_DISCOVERY);
	CHECK_RETRY(!dest.promotion_candidate.active);
	CHECK_RETRY(dest.candidate_retry.failures == saved_retry.failures);
	CHECK_RETRY(dest.candidate_retry.cooldown_until.tv_sec == saved_retry.cooldown_until.tv_sec);

done:
	timeout_del(&mesh->loop, &dest.promotion_timer);
	mesh->backbone.node = saved_bb;
	mesh->backbone_udp = saved_udp;
	return ok;
#undef CHECK_RETRY
}

bool path_policy_cover_unit(meshlink_handle_t *mesh, node_t *live) {
	if(!mesh || !live) {
		return false;
	}

	if(!cover_names(mesh)
	                || !cover_local_classify(mesh)
	                || !cover_canonical(mesh)
	                || !cover_learn_sanitize(mesh)
	                || !cover_sanitize(mesh)
	                || !cover_select(mesh)
	                || !cover_probe(mesh)
	                || !cover_demand(mesh)
	                || !cover_promote(mesh, live)
	                || !cover_promotion(mesh, live)
	                || !cover_escalation(mesh, live)
	                || !cover_retry_survives_carrier(mesh)
	                || !cover_udp_cache(mesh, live)
	                || !cover_transport(mesh)
	                || !cover_active_route(mesh)
	                || !cover_route_usability_and_promotion(mesh)
	                || !cover_preserve(mesh)) {
		return false;
	}

	return true;
}
