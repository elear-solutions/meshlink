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
	CHECK(!strcmp(address_source_name(ADDR_SRC_UNKNOWN), "unknown"));
	CHECK(!strcmp(address_source_name((address_source_t)99), "unknown"));

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
	CHECK(path_sanitize_recent(NULL, &n));
	CHECK(!n.recent[0].sa.sa_family);

	CHECK(path_learn_address(mesh, &n, &nlb, ADDR_SRC_UNKNOWN) == false);
	n.recent[0] = nlb;
	n.recent_source[0] = ADDR_SRC_UNKNOWN;
	n.recent[1] = wan;
	n.recent_source[1] = ADDR_SRC_HINT;
	CHECK(path_sanitize_recent(mesh, &n));
	CHECK(!sockaddrcmp(&n.recent[0], &wan));
	CHECK(!n.recent[1].sa.sa_family);

	CHECK(!path_sanitize_recent(NULL, NULL));
	CHECK(!path_sanitize_recent(mesh, &n));

	n.canonical_address = "nlb.example 443";
	path_refresh_canonical_endpoint(&n);
	CHECK(!path_sanitize_recent(mesh, &n));
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
	dest.recent[1] = wan;
	dest.recent_source[1] = ADDR_SRC_INDIRECT;
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

static bool cover_probe_promote(meshlink_handle_t *mesh, node_t *live) {
	sockaddr_t saved_addr = live->address;
	sockaddr_t saved_recent[MAX_RECENT];
	address_source_t saved_src[MAX_RECENT];
	sockaddr_t saved_catta = live->catta_address;
	sockaddr_t saved_csa = live->canonical_sa;
	char *saved_canon = live->canonical_address;
	path_tier_t saved_tier = live->udp_tier;
	time_t saved_probe = live->udp_local_probe_next;
	bool saved_uc = live->status.udp_confirmed;
	int saved_sock = live->sock;
	memcpy(saved_recent, live->recent, sizeof saved_recent);
	memcpy(saved_src, live->recent_source, sizeof saved_src);

	path_note_udp_confirmed(mesh, NULL);
	path_log_transition(NULL, live, PATH_TIER_NONE, PATH_TIER_META_DIRECT, "x");
	path_log_transition(mesh, NULL, PATH_TIER_NONE, PATH_TIER_META_DIRECT, "x");
	path_log_transition(mesh, live, PATH_TIER_NONE, PATH_TIER_META_DIRECT, NULL);

	node_t dummy;
	memset(&dummy, 0, sizeof dummy);
	dummy.name = "probe";
	CHECK(!path_udp_should_probe_local(NULL, &dummy));
	CHECK(!path_udp_should_probe_local(mesh, NULL));
	CHECK(!path_pick_local_udp_candidate(mesh, NULL, NULL));

	sockaddr_t out, local, wan, nlb, unixish, relayed;
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
	dummy.recent[1] = wan;
	dummy.recent_source[1] = ADDR_SRC_HINT;
	dummy.recent[2] = unixish;
	dummy.recent_source[2] = ADDR_SRC_DISCOVERY;
	dummy.address = wan;
	CHECK(!path_pick_local_udp_candidate(mesh, &dummy, &out));
	CHECK(!path_udp_should_probe_local(mesh, &dummy));

	dummy.address = local;
	dummy.recent[3] = local;
	dummy.recent_source[3] = ADDR_SRC_HINT;
	dummy.recent[4] = relayed;
	dummy.recent_source[4] = ADDR_SRC_INDIRECT;
	CHECK(!path_pick_local_udp_candidate(mesh, &dummy, &out));
	dummy.address = wan;
	CHECK(path_pick_local_udp_candidate(mesh, &dummy, &out));
	CHECK(!sockaddrcmp(&out, &local));
	dummy.udp_local_probe_next = mesh->loop.now.tv_sec + 60;
	CHECK(!path_udp_should_probe_local(mesh, &dummy));
	dummy.udp_local_probe_next = 0;
	CHECK(path_udp_should_probe_local(mesh, &dummy));
	dummy.udp_tier = PATH_TIER_DIRECT_LOCAL_UDP;
	CHECK(!path_udp_should_probe_local(mesh, &dummy));
	dummy.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	dummy.status.udp_confirmed = false;
	CHECK(!path_udp_should_probe_local(mesh, &dummy));

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

	live->address = wan;
	live->status.udp_confirmed = true;
	path_clear_recent(live);
	path_learn_address(mesh, live, &wan, ADDR_SRC_AUTH_DIRECT);
	live->udp_tier = PATH_TIER_NONE;
	path_note_udp_confirmed(mesh, live);
	CHECK(live->udp_tier == PATH_TIER_DIRECT_WAN_UDP);
	path_note_udp_confirmed(mesh, live);

	path_learn_address(mesh, live, &local, ADDR_SRC_DISCOVERY);
	live->address = local;
	live->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	path_note_udp_confirmed(mesh, live);
	CHECK(live->udp_tier == PATH_TIER_DIRECT_LOCAL_UDP);

	live->status.udp_confirmed = false;
	CHECK(!path_promote_udp_if_better(mesh, live, &wan));
	live->status.udp_confirmed = true;
	CHECK(!path_promote_udp_if_better(mesh, NULL, &wan));
	CHECK(!path_promote_udp_if_better(mesh, live, NULL));
	CHECK(!path_promote_udp_if_better(mesh, live, &live->address));

	live->canonical_address = "198.51.100.1 9";
	path_refresh_canonical_endpoint(live);
	CHECK(!path_promote_udp_if_better(mesh, live, &nlb));

	live->udp_tier = PATH_TIER_DIRECT_LOCAL_UDP;
	CHECK(!path_promote_udp_if_better(mesh, live, &wan));

	live->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	set_v4(&wan, "203.0.113.77", 77);
	CHECK(!path_promote_udp_if_better(mesh, live, &wan));

	live->udp_tier = PATH_TIER_NONE;
	set_v4(&wan, "203.0.113.78", 78);
	CHECK(path_promote_udp_if_better(mesh, live, &wan));
	CHECK(live->udp_tier == PATH_TIER_DIRECT_WAN_UDP);

	CHECK(path_promote_udp_if_better(mesh, live, &local));
	CHECK(live->udp_tier == PATH_TIER_DIRECT_LOCAL_UDP);
	CHECK(!path_promote_udp_if_better(mesh, live, &wan));

	if(saved_addr.sa.sa_family) {
		update_node_udp_from(mesh, live, &saved_addr, ADDR_SRC_AUTH_DIRECT);
	}

	memcpy(live->recent, saved_recent, sizeof saved_recent);
	memcpy(live->recent_source, saved_src, sizeof saved_src);
	live->address = saved_addr;
	live->catta_address = saved_catta;
	live->canonical_sa = saved_csa;
	live->canonical_address = saved_canon;
	live->udp_tier = saved_tier;
	live->udp_local_probe_next = saved_probe;
	live->status.udp_confirmed = saved_uc;
	live->sock = saved_sock;
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
	                || !cover_select(mesh)
	                || !cover_probe_promote(mesh, live)) {
		return false;
	}

	return true;
}
