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
#include <time.h>

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

/* The six preference labels of ADR 0004 are attributes of three mechanisms. */
typedef enum data_route_kind_t {
	DATA_ROUTE_NONE = 0,
	DATA_ROUTE_DIRECT_UDP,
	DATA_ROUTE_DIRECT_LOCAL_META,
	DATA_ROUTE_RELAY
} data_route_kind_t;

typedef enum relay_carrier_t {
	RELAY_CARRIER_NONE = 0,
	RELAY_CARRIER_UDP,
	RELAY_CARRIER_META_DIRECT,
	RELAY_CARRIER_META_CANONICAL
} relay_carrier_t;

/* Where this destination's application records go right now. Never holds a
   connection_t *: META targets are resolved from the node under mesh->mutex at
   send time, so tearing a connection down cannot leave a dangling route. */
typedef struct data_route_t {
	data_route_kind_t kind;
	relay_carrier_t relay_carrier;
	struct node_t *first_hop;               /* NULL unless kind is RELAY */
	bool local;
	bool suspect;                           /* probing after a retransmit, still carrying */
	struct timespec selected_at;            /* start of the minimum residency */
	struct timespec suspect_at;             /* when the retransmission raised suspicion */
} data_route_t;

/* The one higher-ranked endpoint being validated, if any. */
typedef struct route_candidate_t {
	bool active;
	data_route_kind_t kind;
	sockaddr_t endpoint;
	address_source_t source;
	uint64_t nonce;
	uint8_t successful_rounds;
	uint8_t failures;                       /* drives the cooldown ladder */
	struct timespec first_success;
	struct timespec deadline;
	struct timespec cooldown_until;
} route_candidate_t;

/* What the send path was told to use for one record. */
typedef struct path_target_t {
	data_route_kind_t kind;
	relay_carrier_t relay_carrier;
	struct node_t *first_hop;
	bool local;
	bool temporary_fallback;                /* live fallback while the preferred route is still suspect */
} path_target_t;

#define UDP_LOCAL_PROBE_SEC 15
#define MAX_CANONICAL_SA 8

/* ADR 0004 stability budget. Promotion is deliberately slow: a better path has
   to prove itself twice, then wait, and the path it would replace has to have
   served long enough that swapping is worth the disturbance. */
#define PATH_LIVENESS_INTERVAL_SEC       60
#define PATH_PROMOTION_ROUNDS             2
#define PATH_PROMOTION_ROUND_GAP_MS     500
#define PATH_PROMOTION_HOLD_MS         1000
#define PATH_PROMOTION_DEADLINE_SEC      10
#define PATH_CANDIDATE_PROBE_INTERVAL_SEC 1
#define PATH_PROMOTION_PROBE_LEN        64
#define PATH_ROUTE_MIN_RESIDENCY_SEC     30
#define PATH_PMTU_INCREASE_INTERVAL_SEC 600
#define PATH_SUSPECT_PROBES               2
#define PATH_SUSPECT_WINDOW_MS         1000
#define PATH_HEALTHY_RESET_SEC           60
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
/* Direct META candidate: source_is_direct, not canonical-equivalent, HINT/UNKNOWN blocked while a hostname canonical has not been resolved or failed, EDGE_DIRECT/UNKNOWN hybrid-IP rejected. */
bool path_is_direct_candidate(const struct node_t *n, const sockaddr_t *sa, address_source_t src);
/* META walk: PATH_CAP_META + direct candidate. UDP_REFLEXIVE that later gained META stays eligible. */
bool path_is_meta_candidate(const struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap);
/* UDP dest: PATH_CAP_UDP, not CANONICAL/INDIRECT, not canonical-equivalent, not an untrusted hybrid. */
bool path_is_udp_candidate(const struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap);
/* Same IP as a cached canonical endpoint, different port, and the source is EDGE_DIRECT or UNKNOWN. */
bool path_is_untrusted_hybrid(const struct node_t *n, const sockaddr_t *sa, address_source_t src);
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

/* Drop canonical-equivalent, ADDR_SRC_CANONICAL, and untrusted hybrid slots. Returns true if recent[] changed. */
bool path_sanitize_recent(struct meshlink_handle *mesh, struct node_t *n);

bool path_best_direct_meta(const struct node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out);
/* One startup META pick: best recent[] candidate, else a direct known edge. */
bool path_best_startup_meta(const struct node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out);
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
void path_note_udp_demoted_reason(struct meshlink_handle *mesh, struct node_t *n, const char *reason);

/* --- promotion of one candidate endpoint, and honest demotion ------------- */

/* Why a candidate start was considered. Log-only; does not change policy. */
typedef enum path_promotion_reason_t {
	PATH_PROMOTION_DISCOVERY,
	PATH_PROMOTION_HINT,
	PATH_PROMOTION_COOLDOWN_CLEARED,
	PATH_PROMOTION_UDP_CONFIRMED,
	PATH_PROMOTION_TICK
} path_promotion_reason_t;

/* Start a local-UDP candidate on promotion_timer when WAN is confirmed, no
   candidate is in flight, cooldown is idle, and a better local endpoint
   exists. Does not send; the timer sends 64-byte nonce probes. */
void path_consider_promotion(struct meshlink_handle *mesh, struct node_t *n, path_promotion_reason_t reason);

/* Query the in-flight candidate endpoint and nonce. Does not start or send.
   False means nothing is under validation. */
bool path_candidate_probe_target(struct meshlink_handle *mesh, struct node_t *n, sockaddr_t *out, uint64_t *nonce_out);

/* An authenticated probe reply arrived from `from` carrying `nonce`. Counts a
   validation round. The timer owns the rounds and the 10s deadline; once
   PATH_PROMOTION_ROUNDS have passed it is stopped and path_route_tick commits
   after hold and residency. */
void path_observe_probe_reply(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from, uint64_t nonce);

/* Give up on the candidate and put its endpoint into escalating cooldown. */
void path_candidate_timeout(struct meshlink_handle *mesh, struct node_t *n, const char *reason);

/* A fresh discovery or network change may clear cooldown once. */
void path_candidate_clear_cooldown(struct meshlink_handle *mesh, struct node_t *n);

/* Periodic: expire a stale candidate, resolve suspect state, reset escalation
   after a long healthy stretch. Requires mesh->mutex. */
void path_route_tick(struct meshlink_handle *mesh, struct node_t *n);

/* Mark the active route suspect after a reliable retransmission. Does not
   demote: the route keeps carrying data until its probes go unanswered. */
void path_note_route_suspect(struct meshlink_handle *mesh, struct node_t *n, const char *reason);

/* True when a lower-ranked route is already live and could take over now. */
bool path_has_live_fallback(struct meshlink_handle *mesh, const struct node_t *n);

/* True when this peer is worth spending a liveness probe on: either it is
   carrying application traffic, or something about its path is unresolved. */
bool path_liveness_probe_warranted(struct meshlink_handle *mesh, const struct node_t *n);

/* Bracket one synchronous utcp_send(). Demotions seen in between are recorded
   and applied on leave, so every fragment of one datagram uses one carrier.
   Both require mesh->mutex and nest. */
void path_send_guard_enter(struct meshlink_handle *mesh);
void path_send_guard_leave(struct meshlink_handle *mesh);
bool path_promote_udp_if_better(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from);

/* Compute the selected destination route, log only on change, update last_path_tier. */
void path_note_selected_route(struct meshlink_handle *mesh, struct node_t *n, const char *reason);

/* --- ADR 0004: one active route, one validation candidate ----------------- */

/* Resolve where this destination's next application record goes. False means
   there is nothing usable and the caller should drop. Requires mesh->mutex. */
bool path_active_send_target(struct meshlink_handle *mesh, struct node_t *n, path_target_t *out);

/* Record the route the send path just used, so residency and logs agree with
   what actually happened. Requires mesh->mutex. */
void path_record_active_route(struct meshlink_handle *mesh, struct node_t *n, const path_target_t *target);

const char *data_route_kind_name(data_route_kind_t kind);
const char *relay_carrier_name(relay_carrier_t carrier);

void path_log_candidate(struct meshlink_handle *mesh, const struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap, const char *action);
void path_log_validation(struct meshlink_handle *mesh, const struct node_t *n, const sockaddr_t *sa, const char *action, const char *detail);
void path_log_meta(struct meshlink_handle *mesh, const struct node_t *n, const sockaddr_t *sa, const char *action);
void path_log_udp_tier(struct meshlink_handle *mesh, const struct node_t *n, path_tier_t from, path_tier_t to, const char *reason);
void path_log_transition(struct meshlink_handle *mesh, const struct node_t *n, path_tier_t from, path_tier_t to, const char *reason);

#endif
