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
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "path_policy_devtool.h"
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
	n.name = "cover";
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_UNSPEC);

	n.canonical_address = "noport";
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_UNSPEC);

	n.canonical_address = "203.0.113.9 ";
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_UNSPEC);

	n.canonical_address = "nlb.example 443";
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_UNSPEC);

	n.canonical_address = "203.0.113.9 9";
	path_refresh_canonical_endpoint(&n);
	CHECK(n.canonical_sa.sa.sa_family == AF_INET);

	sockaddr_t sa;
	set_v4(&sa, "198.51.100.7", 9);
	path_set_canonical_sockaddr(NULL, &sa);
	path_set_canonical_sockaddr(&n, NULL);
	path_set_canonical_sockaddr(&n, &sa);
	CHECK(!sockaddrcmp(&n.canonical_sa, &sa));

	n.canonical_address = "198.51.100.7 9";
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
	n.canonical_address = "198.51.100.7 9";
	set_v4(&sa, "198.51.100.7", 9);
	CHECK(path_address_matches_canonical(&n, &sa));

	n.canonical_address = "198.51.100.8 9";
	CHECK(!path_address_matches_canonical(&n, &sa));

	n.canonical_address = "198.51.100.7 9";
	path_refresh_canonical_endpoint(&n);
	sockaddr_t hybrid;
	set_v4(&hybrid, "198.51.100.7", 23349);
	CHECK(path_address_shares_canonical_ip(&n, &hybrid));
	CHECK(!path_address_matches_canonical(&n, &hybrid));
	CHECK(!path_is_direct_candidate(&n, &hybrid, ADDR_SRC_EDGE_DIRECT));
	CHECK(path_is_direct_candidate(&n, &hybrid, ADDR_SRC_EXTERNAL));
	CHECK(path_is_direct_candidate(&n, &hybrid, ADDR_SRC_AUTH_DIRECT));

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
	return true;
}

static bool cover_learn_sanitize(meshlink_handle_t *mesh) {
	node_t n;
	memset(&n, 0, sizeof n);
	n.name = "cover";
	n.canonical_address = "198.51.100.1 9";
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
	n.name = "cover";
	n.canonical_address = "198.51.100.1 9";
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

	CHECK(!path_sanitize_recent(NULL, NULL));
	CHECK(!path_sanitize_recent(mesh, &n));

	n.canonical_address = "nlb.example 443";
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
	hop.name = "hop";
	dest.name = "dest";

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
	hop.canonical_address = "198.51.100.1 9";
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
	dest.canonical_address = "198.51.100.1 9";
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
	skip = local;
	CHECK(!path_has_direct_meta_candidate(&dest, &skip));
	return true;
}

static bool cover_probe(meshlink_handle_t *mesh) {
	node_t dummy;
	sockaddr_t out, local, wan, nlb, unixish, relayed;

	memset(&dummy, 0, sizeof dummy);
	dummy.name = "probe";
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
	dummy.canonical_address = "198.51.100.1 9";
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

	live->canonical_address = "198.51.100.1 9";
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
	n.name = "transport";
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
	n.canonical_address = "nlb.example 443";
	n.canonical_sa_count = 0;
	n.canonical_resolve_backoff = 0;
	CHECK(path_learn_address_cap(mesh, &n, &r1, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_BOTH));
	CHECK(path_is_meta_candidate(&n, &r1, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_BOTH));

	path_clear_recent(&n);
	n.canonical_address = "nlb.example 443";
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
	                || !cover_promote(mesh, live)
	                || !cover_udp_cache(mesh, live)
	                || !cover_transport(mesh)) {
		return false;
	}

	return true;
}
