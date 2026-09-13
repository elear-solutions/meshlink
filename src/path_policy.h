#ifndef MESHLINK_PATH_POLICY_H
#define MESHLINK_PATH_POLICY_H

/*
    path_policy.h -- validated-path ranking and address provenance
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "sockaddr.h"

#include <stdbool.h>
#include <stdint.h>

struct meshlink_handle;
struct node_t;
struct connection_t;

/* How an address was learned. Persisted next to recent[]. */
typedef enum address_source_t {
	ADDR_SRC_UNKNOWN = 0,       /* legacy load or unclassified */
	ADDR_SRC_AUTH_DIRECT,       /* authenticated TCP/UDP from the peer itself */
	ADDR_SRC_DISCOVERY,         /* local mDNS / Catta */
	ADDR_SRC_HINT,              /* application or invitation hint */
	ADDR_SRC_EXTERNAL,          /* peer-vouched REQ_EXTERNAL */
	ADDR_SRC_EDGE_DIRECT,       /* graph edge that is not OPTION_INDIRECT */
	ADDR_SRC_CANONICAL,         /* canonical / NLB endpoint (never stored in recent[]) */
	ADDR_SRC_INDIRECT           /* forwarded or OPTION_INDIRECT */
} address_source_t;

/* Ranked validated-path tiers. Lower is better. */
typedef enum path_tier_t {
	PATH_TIER_DIRECT_LOCAL_UDP = 0,
	PATH_TIER_DIRECT_WAN_UDP,
	PATH_TIER_RELAY_UDP,
	PATH_TIER_META_DIRECT,
	PATH_TIER_META_CANONICAL,
	PATH_TIER_NONE
} path_tier_t;

/* META dial classification for a candidate or live connection. */
typedef enum meta_dial_tier_t {
	META_DIAL_DIRECT = 0,
	META_DIAL_CANONICAL
} meta_dial_tier_t;

#define UDP_LOCAL_PROBE_SEC 15

const char *address_source_name(address_source_t src);
const char *path_tier_name(path_tier_t tier);
const char *meta_dial_tier_name(meta_dial_tier_t tier);

bool path_source_is_direct(address_source_t src);
bool path_tier_better(path_tier_t a, path_tier_t b);
bool path_address_is_local(const sockaddr_t *sa);
path_tier_t path_udp_tier_for(const sockaddr_t *sa, address_source_t src);

/* Numeric "host port" -> cached canonical_sa. Hostname stays AF_UNSPEC until resolve. */
void path_refresh_canonical_endpoint(struct node_t *n);
void path_set_canonical_sockaddr(struct node_t *n, const sockaddr_t *sa);
bool path_address_matches_canonical(const struct node_t *n, const sockaddr_t *sa);

/* Remember sa with provenance. Canonical-equivalent addresses are dropped. */
bool path_learn_address(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src);
bool path_learn_address_fallback(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src);
void path_clear_recent(struct node_t *n);

/* Drop or reclassify persisted NLB entries. Returns true if recent[] changed. */
bool path_sanitize_recent(struct meshlink_handle *mesh, struct node_t *n);

bool path_best_direct_meta(const struct node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out);
bool path_has_direct_meta_candidate(const struct node_t *n, const sockaddr_t *skip);
bool path_meta_is_canonical(const struct node_t *n, const struct connection_t *c);
void path_mark_meta_dial(struct connection_t *c, bool canonical);

path_tier_t path_select_hop_tier(const struct node_t *hop, bool meta_in);
path_tier_t path_select_destination_tier(const struct node_t *dest, bool meta_in);

bool path_udp_should_probe_local(struct meshlink_handle *mesh, const struct node_t *n);
bool path_pick_local_udp_candidate(struct meshlink_handle *mesh, const struct node_t *n, sockaddr_t *out);
void path_note_udp_confirmed(struct meshlink_handle *mesh, struct node_t *n);
bool path_promote_udp_if_better(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from);

void path_log_transition(struct meshlink_handle *mesh, const struct node_t *n, path_tier_t from, path_tier_t to, const char *reason);

#endif
