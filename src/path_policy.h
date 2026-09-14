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
struct addrinfo;

/* How an address was learned. Persisted next to recent[]. */
typedef enum address_source_t {
	ADDR_SRC_UNKNOWN = 0,       /* legacy load or unclassified */
	ADDR_SRC_AUTH_DIRECT,       /* authenticated TCP from the peer itself */
	ADDR_SRC_DISCOVERY,         /* local mDNS / Catta */
	ADDR_SRC_HINT,              /* application or invitation hint */
	ADDR_SRC_EXTERNAL,          /* peer-vouched REQ_EXTERNAL */
	ADDR_SRC_EDGE_DIRECT,       /* graph edge that is not OPTION_INDIRECT */
	ADDR_SRC_CANONICAL,         /* canonical / NLB endpoint (never stored in recent[]) */
	ADDR_SRC_INDIRECT,          /* forwarded or OPTION_INDIRECT */
	ADDR_SRC_UDP_REFLEXIVE      /* ANS_KEY / inbound remap / NAT-mapped UDP confirm */
} address_source_t;

/* Which transports may consume a recent[] slot. Independent of provenance. */
typedef uint8_t path_cap_t;
#define PATH_CAP_NONE 0x00
#define PATH_CAP_META 0x01
#define PATH_CAP_UDP  0x02
#define PATH_CAP_BOTH (PATH_CAP_META | PATH_CAP_UDP)

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
#define MAX_CANONICAL_SA 8
#define CANONICAL_RESOLVE_TIMEOUT 2
#define CANONICAL_RESOLVE_BACKOFF_MIN 5
#define CANONICAL_RESOLVE_BACKOFF_MAX 600

const char *address_source_name(address_source_t src);
const char *path_tier_name(path_tier_t tier);
const char *meta_dial_tier_name(meta_dial_tier_t tier);
const char *path_cap_name(path_cap_t cap);
path_cap_t path_default_cap(address_source_t src);

/* Bounded copy: AF_INET/AF_INET6 only. Never full-union-assigns a short sockaddr. */
void path_copy_sockaddr(sockaddr_t *dst, const sockaddr_t *src);

/* True for AUTH/DISCOVERY/HINT/EXTERNAL/EDGE and UNKNOWN (legacy load). Not CANONICAL/INDIRECT/UDP_REFLEXIVE. */
bool path_source_is_direct(address_source_t src);
/* Direct META candidate: source_is_direct, not canonical-equivalent, HINT/UNKNOWN blocked while a hostname canonical has not been resolved or failed, EDGE_DIRECT hybrid-IP rejected. */
bool path_is_direct_candidate(const struct node_t *n, const sockaddr_t *sa, address_source_t src);
/* META walk: PATH_CAP_META + direct candidate. UDP_REFLEXIVE that later gained META stays eligible. */
bool path_is_meta_candidate(const struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap);
/* UDP dest: PATH_CAP_UDP, not CANONICAL/INDIRECT, not canonical-equivalent. */
bool path_is_udp_candidate(const struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap);
bool path_canonical_unresolved(const struct node_t *n);
bool path_canonical_is_hostname(const struct node_t *n);
bool path_tier_better(path_tier_t a, path_tier_t b);
bool path_address_is_local(const sockaddr_t *sa);
path_tier_t path_udp_tier_for(const sockaddr_t *sa, address_source_t src);

/* Numeric "host port" -> cached canonical_sa. Hostname stays in canonical_address until resolve. */
void path_refresh_canonical_endpoint(struct node_t *n);
/* Takes ownership of canonical_address. Same string is a no-op (cache and ADNS cookie stay). */
bool path_assign_canonical_address(struct node_t *n, char *canonical_address);
void path_clear_canonical_endpoints(struct node_t *n);
void path_set_canonical_sockaddr(struct node_t *n, const sockaddr_t *sa);
bool path_add_canonical_endpoint(struct node_t *n, const sockaddr_t *sa);
bool path_address_matches_canonical(const struct node_t *n, const sockaddr_t *sa);
/* Same IP as any cached canonical endpoint, port ignored. */
bool path_address_shares_canonical_ip(const struct node_t *n, const sockaddr_t *sa);
bool path_canonical_host_matches(const struct node_t *n, const char *host, const char *serv);
/* Built like get_recent_addresses: caller frees each node with free(). */
struct addrinfo *path_canonical_addrinfo(const struct node_t *n);
/* Drop pending/backoff and invalidate the ADNS cookie (gen = 0). */
void path_reset_canonical_resolve(struct node_t *n);
void path_request_canonical_resolve(struct meshlink_handle *mesh, struct node_t *n);
void path_reclassify_active_meta(struct meshlink_handle *mesh, struct node_t *n);
void path_migrate_legacy_caps(struct node_t *n);
void path_persist_node(struct meshlink_handle *mesh, struct node_t *n);

/* Remember sa with provenance and transport cap. Canonical-equivalent addresses are dropped. INDIRECT is never stored at the front. */
bool path_learn_address(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src);
bool path_learn_address_cap(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap);
/* Append behind proven slots. Empty or full recent[] drops the address (does not evict). INDIRECT is allowed. */
bool path_learn_address_fallback(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src);
bool path_learn_address_fallback_cap(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap);
void path_clear_recent(struct node_t *n);
/* Force ADDR_SRC_UNKNOWN / UDP-only at the front (test/devtools plant of a leftover NLB). */
void path_plant_recent(struct node_t *n, const sockaddr_t *sa);

/* Drop canonical-equivalent and ADDR_SRC_CANONICAL slots. Returns true if recent[] changed. */
bool path_sanitize_recent(struct meshlink_handle *mesh, struct node_t *n);

bool path_best_direct_meta(const struct node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out);
bool path_has_direct_meta_candidate(const struct node_t *n, const sockaddr_t *skip);
/* Sole reader for "this META is canonical": via_canonical (kept in sync with meta_dial_tier) or address match. */
bool path_meta_is_canonical(const struct node_t *n, const struct connection_t *c);
/* Sole writer for via_canonical + meta_dial_tier. */
void path_mark_meta_dial(struct connection_t *c, bool canonical);
const char *path_upgrade_ineligible_reason(struct meshlink_handle *mesh, const struct node_t *n);

/* Hop/dest select: validated UDP first, then META. META-in pins META-out. */
path_tier_t path_select_hop_tier(const struct node_t *hop, bool meta_in);
path_tier_t path_select_destination_tier(const struct node_t *dest, bool meta_in);

/* When out is non-NULL, fills the local candidate (one pick). out may be NULL for a boolean check. */
bool path_udp_should_probe_local(struct meshlink_handle *mesh, const struct node_t *n, sockaddr_t *out);
bool path_pick_local_udp_candidate(struct meshlink_handle *mesh, const struct node_t *n, sockaddr_t *out);
void path_schedule_local_udp_probe(struct meshlink_handle *mesh, struct node_t *n);
void path_note_udp_confirmed(struct meshlink_handle *mesh, struct node_t *n);
void path_note_udp_demoted(struct meshlink_handle *mesh, struct node_t *n);
bool path_promote_udp_if_better(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from);

void path_log_candidate(struct meshlink_handle *mesh, const struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap, const char *action);
void path_log_validation(struct meshlink_handle *mesh, const struct node_t *n, const sockaddr_t *sa, const char *action, const char *detail);
void path_log_meta(struct meshlink_handle *mesh, const struct node_t *n, const sockaddr_t *sa, const char *action);
void path_log_transition(struct meshlink_handle *mesh, const struct node_t *n, path_tier_t from, path_tier_t to, const char *reason);

#endif
