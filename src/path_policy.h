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

#include "event.h"
#include "path_types.h"
#include "sockaddr.h"

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct meshlink_handle;
struct node_t;
struct connection_t;
struct addrinfo;

/* One learned UDP/META dest: address plus the recent[] slot it came from. */
typedef struct path_endpoint_t {
	sockaddr_t address;
	address_source_t source;
	path_cap_t capability;
} path_endpoint_t;

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
	sockaddr_t udp_endpoint;                /* exact UDP dest; unset for META */
	address_source_t endpoint_source;
	bool local;
	bool suspect;                           /* probing after a retransmit, still carrying */
	struct timespec selected_at;            /* start of the minimum residency */
	struct timespec suspect_at;             /* when the retransmission raised suspicion */
	struct timespec healthy_since;          /* start of authenticated service after the latest candidate failure or commit; zero until then */
} data_route_t;

/* Local-UDP endpoint retry history. Lives on node_t, not on the in-flight
   candidate: carrier promotions may replace promotion_candidate without
   forgiving a stale local endpoint. */
typedef struct path_candidate_retry_t {
	sockaddr_t endpoint;
	uint8_t failures;                       /* drives the cooldown ladder */
	struct timespec cooldown_until;
	struct timespec last_failure_at;        /* same-tick guard */
	uint64_t network_generation;            /* mesh->lan_network_epoch at timeout or last clear */
	bool auth_seen;                         /* AUTH_DIRECT already spent its reset on this stamp */
} path_candidate_retry_t;

/* The one higher-ranked route being validated, if any. Identity and
   validation only; endpoint retry state is path_candidate_retry_t. */
typedef struct route_candidate_t {
	bool active;
	data_route_kind_t kind;
	relay_carrier_t relay_carrier;
	struct node_t *first_hop;
	sockaddr_t endpoint;
	address_source_t source;
	path_cap_t capability;                  /* PATH_CAP_NONE => path_default_cap(source) at install */
	bool local;
	uint64_t nonce;
	uint8_t successful_rounds;
	uint8_t requests_sent;                  /* scheduler-owned; PATH_PROMOTION_MAX_REQUESTS */
	struct timespec first_success;
	struct timespec deadline;
} route_candidate_t;

/* One in-flight suspect recovery for the recorded UDP endpoint. PMTU, promotion,
   and previous-epoch replies must not satisfy this nonce. The epoch holds a
   scheduler transaction slot until stop/expire; packets admit through
   path_scheduler_emit_packet(). */
typedef struct suspect_validation_t {
	bool active;
	sockaddr_t endpoint;
	uint64_t nonce;                         /* epoch id; never 0 */
	uint8_t probes_sent;
	uint8_t replies_received;
	struct timespec deadline;               /* now + PATH_SUSPECT_WINDOW_MS */
	timeout_t timer;
} suspect_validation_t;

/* What the send path was told to use for one record. */
typedef struct path_target_t {
	data_route_kind_t kind;
	relay_carrier_t relay_carrier;
	struct node_t *first_hop;
	sockaddr_t udp_endpoint;
	address_source_t endpoint_source;
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
#define PATH_ROUTE_MIN_RESIDENCY_SEC     10

/* ADR 0011 knobs live with their machines. Included here so existing
   path_policy.h users keep seeing them. */
#include "path_plpmtu.h"
#include "path_liveness.h"

#define PATH_SUSPECT_PROBES               2
#define PATH_SUSPECT_WINDOW_MS         1000
#define PATH_HEALTHY_RESET_SEC           60
#define PATH_BACKBONE_UDP_ESTABLISH_SEC   1
#define PATH_BACKBONE_UDP_ESTABLISH_MISS  3
#define PATH_BACKBONE_UDP_KEEPALIVE_MISS  2
#define PATH_BACKBONE_UDP_ESTABLISH_BACKOFF_MAX 30
#define PATH_PEER_UDP_GRACE_SEC           5
/* Three backbone keepalives. Older than this, an observation is not a punch hint. */
#define PATH_UDP_OBSERVATION_FRESH_SEC    (PATH_BACKBONE_UDP_KEEPALIVE_SEC * 3)

/* Where the endpoint under challenge came from. A rendezvous hint only
   bootstraps; a peer-reflexive source is the address we actually received. */
typedef enum punch_provenance_t {
	PUNCH_PROV_NONE = 0,
	PUNCH_PROV_NMN_HINT,
	PUNCH_PROV_AUTH_INGRESS,
} punch_provenance_t;

/* Two sends, one promotion-round apart, then the challenge fails closed. */
#define PATH_PUNCH_CHALLENGE_ATTEMPTS 2

/* Confirmed-endpoint migration. The quiet window refuses a second live path.
   The nonce proof is the same bar as the original confirm. Same-IP keeps PMTU. */
#define PATH_REBIND_QUIET_MS            500
#define PATH_REBIND_PROBE_GAP_MS        250
#define PATH_REBIND_ATTEMPTS              3
#define PATH_REBIND_DEADLINE_MS        1500
#define PATH_REBIND_HOLDDOWN_SEC          5
#define PATH_REBIND_FLAP_WINDOW_SEC      60
#define PATH_REBIND_FLAP_WARN             6
#define PATH_REBIND_MIGRATION_RING        8

/* One candidate and one nonce challenge. Counters survive cancel. */
typedef struct udp_rebind_t {
	struct timespec current_rx_at;          /* last authenticated datagram from n->address */
	sockaddr_t candidate;
	struct timespec candidate_first_at;
	struct timespec candidate_last_at;
	uint32_t candidate_packets;
	bool challenge_active;
	sockaddr_t challenge_endpoint;
	uint64_t challenge_nonce;
	uint8_t challenge_attempts;
	struct timespec challenge_deadline;
	uint32_t challenge_session;
	uint64_t challenge_network_epoch;
	sockaddr_t held_endpoint;               /* failed candidate; not retried until held_until */
	struct timespec held_until;
	struct timespec migrations[PATH_REBIND_MIGRATION_RING];
	uint8_t migration_pos;
	uint8_t migration_fill;
	struct timespec flap_warned_until;      /* suppress repeated warnings for one flap window */
	uint32_t seen;
	uint32_t migrated;
	uint32_t failed;
	bool rescue;                            /* demotion is waiting on this challenge */
} udp_rebind_t;

/* One in-flight proof. The nonce is never zero while active. Confirmation
   requires the reply source to be this endpoint, not merely some packet. */
typedef struct punch_challenge_t {
	bool active;
	punch_provenance_t provenance;
	sockaddr_t endpoint;
	uint64_t nonce;
	uint8_t attempts;                       /* packets actually sent, not queued */
	uint32_t session_id;
	uint64_t network_epoch;
	uint32_t demand_epoch;
	struct timespec deadline;               /* absolute; denial cannot extend past this */
} punch_challenge_t;

/* Ordinary-peer UDP punching is refcounted from channels. Backbone UDP is not.
   Endpoint requests share one ladder per peer, not per channel. */
typedef struct peer_path_demand_t {
	unsigned channel_count;
	struct timespec idle_until;             /* {0,0} = no grace */
	struct timespec next_request;           /* {0,0} = send on the next tick */
	uint8_t request_step;                   /* index into 1,2,5,10,30s */
	bool ladder_stopped;                    /* session change; demand or network epoch clears it */
	uint32_t requests_sent;                 /* successful REQ_PUNCH_ENDPOINT sends */
	uint32_t request_session;               /* session_id last requested */
	uint64_t network_epoch;                 /* lan_network_epoch when the ladder was armed */
	uint32_t demand_epoch;                  /* increments on each 0→1 demand */
	sockaddr_t last_hint;                   /* latest NMN rendezvous hint; not a confirmed address */
	sockaddr_t pending_hint;                /* staged before validkey; AF_UNSPEC if none */
	struct timespec pending_hint_at;        /* when pending_hint was staged */
	uint32_t pending_hint_session;          /* session_id at staging */
	uint64_t pending_hint_demand_epoch;     /* demand_epoch at staging */
	punch_challenge_t challenge;            /* the one endpoint we are proving right now */
	sockaddr_t ingress;                     /* latest authenticated direct source; AF_UNSPEC if none */
	uint32_t ingress_session;               /* session_id when ingress was observed */
	uint32_t ingress_demand_epoch;          /* demand_epoch when ingress was observed */
	uint64_t ingress_network_epoch;         /* lan_network_epoch when ingress was observed */
	sockaddr_t failed_ingress;              /* auth source that already failed this demand; not retried */
	bool hint_failed;                       /* the current last_hint already failed its challenge */
} peer_path_demand_t;

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

/* Remember sa with provenance and transport cap. Canonical-equivalent addresses are dropped. INDIRECT is never stored at the front.
   The return value is true when the address was stored or moved to the front, including an unchanged LRU move.
   *material is set only when the address was new or its source or capability was upgraded. material may be NULL. */
bool path_learn_address(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src);
bool path_learn_address_cap(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap);
bool path_learn_address_cap_ex(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap, bool *material);
/* Append behind proven slots. Empty or full recent[] drops the address (does not evict). INDIRECT is allowed. */
bool path_learn_address_fallback(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src);
bool path_learn_address_fallback_cap(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap);
void path_clear_catta_address(struct node_t *n);
void path_clear_recent(struct node_t *n);
/* Force ADDR_SRC_UNKNOWN / UDP-only at the front (test/devtools plant of a leftover NLB). */
void path_plant_recent(struct node_t *n, const sockaddr_t *sa);

/* Drop canonical-equivalent, ADDR_SRC_CANONICAL, and untrusted hybrid slots. Returns true if recent[] changed. */
bool path_sanitize_recent(struct meshlink_handle *mesh, struct node_t *n);

bool path_best_direct_meta(const struct node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out);
/* Local META pick: DISCOVERY or AUTH_DIRECT, path_address_is_local, META-capable. No EDGE_DIRECT. */
bool path_best_local_meta(const struct node_t *n, const sockaddr_t *skip, sockaddr_t *out, address_source_t *src_out);
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

/* When out is non-NULL, fills the local candidate address (one pick). out may be NULL for a boolean check. */
bool path_udp_should_probe_local(struct meshlink_handle *mesh, const struct node_t *n, sockaddr_t *out);
bool path_pick_local_udp_candidate(struct meshlink_handle *mesh, const struct node_t *n, path_endpoint_t *out);
void path_schedule_local_udp_probe(struct meshlink_handle *mesh, struct node_t *n);
void path_note_udp_confirmed(struct meshlink_handle *mesh, struct node_t *n);
void path_note_udp_demoted(struct meshlink_handle *mesh, struct node_t *n);
void path_note_udp_demoted_reason(struct meshlink_handle *mesh, struct node_t *n, const char *reason);

/* Required backbone UDP relay mapping. connection_policy starts/stops it. */
int path_backbone_udp_keepalive_base_sec(struct meshlink_handle *mesh);
void path_backbone_udp_start(struct meshlink_handle *mesh, struct node_t *bb);
void path_backbone_udp_stop(struct meshlink_handle *mesh);
void path_backbone_udp_reset(struct meshlink_handle *mesh, struct node_t *n);
void path_backbone_udp_observe_reply(struct meshlink_handle *mesh, struct node_t *n,
	                const sockaddr_t *from, uint64_t nonce, const sockaddr_t *observed);
/* Reset establishment backoff and wake when a viable new direct UDP dest is learned.
   Call only from learn paths that stored or upgraded the address; duplicate discovery
   of the same endpoint must not collapse establish_step. */
void path_backbone_udp_note_direct(struct meshlink_handle *mesh, struct node_t *n,
                                   const sockaddr_t *sa, address_source_t src, path_cap_t cap);

/* --- promotion of one candidate endpoint, and honest demotion ------------- */

/* Why a candidate start was considered. DISCOVERY, HINT and AUTH_DIRECT are
   observations that may clear a same-endpoint cooldown once per
   (lan_network_epoch, endpoint); TICK and UDP_CONFIRMED never do. */
typedef enum path_promotion_reason_t {
	PATH_PROMOTION_DISCOVERY,
	PATH_PROMOTION_HINT,
	PATH_PROMOTION_AUTH_DIRECT,
	PATH_PROMOTION_COOLDOWN_CLEARED,
	PATH_PROMOTION_UDP_CONFIRMED,
	PATH_PROMOTION_TICK
} path_promotion_reason_t;

/* Elective better-carrier promotion. Already-validated classes wait hold +
   residency; they do not probe. n NULL walks demanded destinations. */
typedef enum path_route_promotion_t {
	PATH_PROMOTION_DIRECT_UDP = 0,
	PATH_PROMOTION_BACKBONE_UDP,
	PATH_PROMOTION_LOCAL_META,
	PATH_PROMOTION_META_DIRECT
} path_route_promotion_t;

/* Start a local-UDP candidate on promotion_timer when WAN is confirmed, no
   candidate is in flight, cooldown is idle, and a better local endpoint
   exists. Does not send; the timer sends 64-byte nonce probes. */
void path_consider_promotion(struct meshlink_handle *mesh, struct node_t *n, path_promotion_reason_t reason);

/* Start at most one better-carrier candidate. Already-validated (backbone UDP,
   local META, backbone META-direct, dest UDP) wait hold and residency. */
void path_consider_route_promotion(struct meshlink_handle *mesh, struct node_t *n, path_route_promotion_t which);

/* Query the in-flight candidate endpoint and nonce. Does not start or send.
   False means nothing is under validation. */
bool path_candidate_probe_target(struct meshlink_handle *mesh, struct node_t *n, sockaddr_t *out, uint64_t *nonce_out);

/* An authenticated probe reply arrived from `from` carrying `nonce`. Suspect
   recovery matches endpoint and current epoch first. Promotion counts a
   validation round. The promotion timer owns the rounds and the 10s deadline;
   once PATH_PROMOTION_ROUNDS have passed it is stopped and path_route_tick
   commits after hold and residency. */
void path_observe_probe_reply(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from, uint64_t nonce);

/* Give up on the candidate and put its endpoint into escalating cooldown. */
void path_candidate_timeout(struct meshlink_handle *mesh, struct node_t *n, const char *reason);

/* The clearer. Production eligibility is the observation epoch gate in
   path_consider_promotion; this helper (and the devtool) force a retry
   without forgiving failures. */
void path_candidate_clear_cooldown(struct meshlink_handle *mesh, struct node_t *n);

/* Periodic: expire a stale candidate, resolve suspect state, reset failures
   from healthy_since (never selected_at, never while cooldown is live).
   Requires mesh->mutex. */
void path_route_tick(struct meshlink_handle *mesh, struct node_t *n);

/* Mark the active DIRECT_UDP or RELAY_UDP route suspect after a reliable
   retransmission and start a two-probe nonce epoch. Acquires the recovery
   transaction first; if the slot is unavailable the route is not marked and
   the next retransmit retries. Never starts a suspect deadline without a
   transaction. Relay UDP probes the hop with that hop's authenticated packets,
   not the destination. Does not demote: the route keeps carrying data until
   those probes go unanswered. Already-suspect is a no-op. */
void path_note_route_suspect(struct meshlink_handle *mesh, struct node_t *n, const char *reason);

/* Drop the suspect transaction without logging a heal. Idempotent. */
void path_suspect_stop(struct meshlink_handle *mesh, struct node_t *n);

/* Matching suspect-epoch reply: clear the flag, stop the transaction, then
   record authenticated success. */
void path_clear_route_suspicion(struct meshlink_handle *mesh, struct node_t *n);

/* Query the in-flight suspect endpoint and nonce. False if none. */
bool path_suspect_probe_target(struct meshlink_handle *mesh, struct node_t *n, sockaddr_t *out, uint64_t *nonce_out);

/* First authenticated proof of the active route after a failure or commit.
   Liveness replies and application records; not send-side or fallback. */
void path_note_authenticated_route_success(struct meshlink_handle *mesh, struct node_t *n);

/* True when a lower-ranked route is already live and could take over now. */
bool path_has_live_fallback(struct meshlink_handle *mesh, const struct node_t *n);

/* True when this peer has channel demand (live channels or grace). Does not
   imply punching: backbone/UNKNOWN/self pairs can hold a count of zero. */
bool path_peer_udp_demanded(const struct meshlink_handle *mesh, const struct node_t *peer);

/* Direct peer UDP only: both sides LAN-class, neither is the backbone, demand is live. */
bool path_peer_udp_punching_allowed(const struct meshlink_handle *mesh, const struct node_t *n);

/* REQ_KEY when reachable, no node SPTPS yet, and UDP is required (backbone mapping
   or ordinary-peer demand). No-op if already waitingforkey. */
void path_peer_ensure_udp_key(struct meshlink_handle *mesh, struct node_t *peer);

/* Runtime punch hint from an authenticated direct UDP datagram. Does not set
   udp_confirmed, does not change the active route, and is not persisted. */
void path_note_authenticated_udp_observation(struct meshlink_handle *mesh, struct node_t *node, const sockaddr_t *endpoint);
/* Fresh, session-matched observation. False leaves *out untouched. */
bool path_get_fresh_udp_observation(const struct meshlink_handle *mesh, const struct node_t *node, sockaddr_t *out);
/* NMN output proof may use authenticated local observations; never export them. */
bool path_get_fresh_relay_udp_observation(const struct meshlink_handle *mesh, const struct node_t *node, sockaddr_t *out);
/* Drop the observation and the request ladder. Channel demand is kept. */
void path_clear_udp_observation(struct node_t *node);
/* Observation, else a confirmed active UDP endpoint. Never recent[0]. */
bool path_select_punch_hint(const struct meshlink_handle *mesh, const struct node_t *node, sockaddr_t *out, bool *from_observation);
/* Install a hinted peer endpoint. A hint bootstraps; it does not become n->address. */
void path_note_punch_endpoint(struct meshlink_handle *mesh, struct node_t *node, const sockaddr_t *sa);
/* Install a hint that arrived before validkey. No-op when nothing is staged. */
void path_apply_pending_punch_hint(struct meshlink_handle *mesh, struct node_t *node);
void path_clear_pending_punch_hint(struct node_t *node);
/* Authenticated direct source. Remembered even before a key; challenged only
   while punching is allowed. A repeated source does not restart the challenge. */
void path_observe_punch_ingress(struct meshlink_handle *mesh, struct node_t *node, const sockaddr_t *endpoint);
/* Start a challenge for an ingress observed before the key or the demand existed. */
void path_punch_arm_ingress(struct meshlink_handle *mesh, struct node_t *node);
/* Commit only when nonce and UDP source match the current challenge and the
   session, network, and demand epochs still match. False leaves state alone. */
bool path_punch_accept_reply(struct meshlink_handle *mesh, struct node_t *node, const sockaddr_t *from, uint64_t nonce);
/* Unconfirmed ordinary-peer probe reply. True means the caller must stop:
   an active challenge was accepted or rejected, or a public source stayed
   on AUTH_INGRESS. False means a nonce-zero local reply (or a non-peer)
   was confirmed and the current reply should finish PMTU. A local confirm
   installs from, emits no ANS_KEY, and does not start another probe. */
bool path_try_confirm_udp_probe_reply(struct meshlink_handle *mesh, struct node_t *node, const sockaddr_t *from, uint64_t nonce);
/* Drop the in-flight challenge and its queued probes. Keeps the remembered ingress. */
void path_punch_cancel(struct meshlink_handle *mesh, struct node_t *node);
/* A challenge recorded while probes were held (devtool_force_meta) has no
   timer. Call this once the hold is cleared so it sends. */
void path_punch_release(struct meshlink_handle *mesh, struct node_t *node);
/* Mesh-loop callback and the devtool hook for a challenge deadline. */
void path_punch_challenge_timeout(struct meshlink_handle *mesh, struct node_t *node);

/* Authenticated direct UDP from a confirmed ordinary peer. Same source refreshes
   liveness. A new source is a rebind candidate; a nonce reply is what moves
   n->address. Relay and backbone peers are ignored. */
void path_rebind_observe_rx(struct meshlink_handle *mesh, struct node_t *node, const sockaddr_t *endpoint);
/* Commit only on nonce and source match, with session and network epoch unchanged.
   False leaves the challenge alone so another probe reply can still match. */
bool path_rebind_accept_reply(struct meshlink_handle *mesh, struct node_t *node, const sockaddr_t *from, uint64_t nonce);
/* True when a fresh candidate should postpone demotion. Starts or awaits its challenge. */
bool path_rebind_try_rescue(struct meshlink_handle *mesh, struct node_t *node);
/* Drop the challenge, timer, and candidate. Counters and hold-down stay. */
void path_rebind_cancel(struct meshlink_handle *mesh, struct node_t *node);
/* Mesh-loop callback and the devtool hook for a rebind deadline. */
void path_rebind_challenge_timeout(struct meshlink_handle *mesh, struct node_t *node);
/* Scheduler dropped the slot. Fail a challenge that no longer has a timer. */
void path_rebind_fail_orphaned(struct meshlink_handle *mesh, struct node_t *node);
/* Unconfirmed probe dest: the in-flight challenge, else a hint that has not failed. */
bool path_unconfirmed_punch_dest(const struct meshlink_handle *mesh, const struct node_t *n, sockaddr_t *out);
/* Dest sampled immediately before the probe path_note_punch_endpoint just armed. */
bool path_punch_last_probe_dest(struct meshlink_handle *mesh, sockaddr_t *out);
unsigned path_punch_test_ans_exports(struct meshlink_handle *mesh);
/* Scheduler dropped the slot. Fail a challenge that no longer has a timer. */
void path_punch_fail_orphaned(struct meshlink_handle *mesh, struct node_t *node);

/* First/last channel to an ordinary peer. acquire() is false (no count change)
   for backbone/UNKNOWN/self. Release always decrements a non-zero count so a
   later class change cannot leak demand. 0→1 starts key exchange and punching;
   1→0 keeps the route for PATH_PEER_UDP_GRACE_SEC if the pair is still ordinary,
   otherwise stops UDP immediately. */
bool path_channel_acquire(struct meshlink_handle *mesh, struct node_t *peer);
void path_channel_release(struct meshlink_handle *mesh, struct node_t *peer);

/* True when a demanded ordinary peer is worth a liveness probe: still
   punching, recovering, or keeping the NAT mapping warm. */
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

/* True when an SPTPS datagram of sptps_len bytes fits on this carrier.
   Shorter than the SPTPS overhead always fits. Requires mesh->mutex. */
bool path_target_fits_record(const struct meshlink_handle *mesh, const struct node_t *n, const path_target_t *target, size_t sptps_len);

/* path_active_send_target, except a temporary suspect fallback that cannot
   carry this record is replaced by the suspected primary, then by META.
   The original fallback is kept only when nothing else can take it. */
bool path_send_target_for_record(struct meshlink_handle *mesh, struct node_t *n, size_t sptps_len, path_target_t *out);

/* Copy the recorded route if it is still instantiable. Suspect plus a live
   fallback fills temporary_fallback without committing. Unusable recorded
   identity selects and commits a fallback. Requires mesh->mutex. */
bool path_resolve_active_route(struct meshlink_handle *mesh, struct node_t *n, path_target_t *out);

/* Rank currently live carriers in product order. First route, exact hard
   failure, and suspect demotion. Requires mesh->mutex. */
bool path_select_fallback(struct meshlink_handle *mesh, struct node_t *n, path_target_t *out);

/* Commit a validated promotion candidate as the active DIRECT_UDP route. */
void path_commit_candidate(struct meshlink_handle *mesh, struct node_t *n);

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

/* One promotion-timer turn. Cover fires this after preemption; production uses the timeout. */
void path_promotion_timer_tick(struct meshlink_handle *mesh, struct node_t *n);

/* Scheduler APIs remain visible through path_policy.h for existing callers. */
#include "path_scheduler.h"

#endif
