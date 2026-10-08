#ifndef MESHLINK_NODE_H
#define MESHLINK_NODE_H

/*
    node.h -- header for node.c
    Copyright (C) 2014, 2017 Guus Sliepen <guus@meshlink.io>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "event.h"
#include "path_policy.h"
#include "sockaddr.h"
#include "sptps.h"
#include "utcp.h"
#include "submesh.h"

typedef struct node_status_t {
	uint16_t validkey: 1;               /* 1 if we currently have a valid key for him */
	uint16_t waitingforkey: 1;          /* 1 if we already sent out a request */
	uint16_t visited: 1;                /* 1 if this node has been visited by one of the graph algorithms */
	uint16_t reachable: 1;              /* 1 if this node is reachable in the graph */
	uint16_t udp_confirmed: 1;          /* 1 if a probe reply proved bidirectional UDP */
	uint16_t broadcast: 1;              /* 1 if the next UDP packet should be broadcast to the local network */
	uint16_t blacklisted: 1;            /* 1 if the node is blacklist so we never want to speak with him anymore */
	uint16_t destroyed: 1;              /* 1 if the node is being destroyed, deallocate channels when any callback is triggered */
	uint16_t duplicate: 1;              /* 1 if the node is duplicate, ie. multiple nodes using the same Name are online */
	uint16_t dirty: 1;                  /* 1 if the configuration of the node is dirty and needs to be written out */
	uint16_t want_udp: 1;               /* 1 if we want working UDP because we have data to send */
	uint16_t tiny: 1;                   /* 1 if this is a tiny node */
	uint16_t in_req_sptps: 1;           /* 1 while processing dest META REQ_SPTPS */
	uint16_t temp_udp_confirmed: 1;     /* 1 while sending a probe reply */
	uint16_t forced_relay: 1;           /* 1 if devtool pinned nexthop */
	uint16_t conflict_backbone: 1;      /* 1 if this node conflicts with stored backbone identity. Finding 5 skips it in META pools; finding 10 skips it as relay. */
} node_status_t;

/* Size of node_t.recent[]. devtool_node_status_t.recent[] mirrors it as DEVTOOL_MAX_RECENT
   in the public header; devtools.c static-asserts the two agree. */
#define MAX_RECENT 5

typedef struct lan_presence_t {
	uint64_t network_epoch;
	time_t last_discovered_at;
} lan_presence_t;

/* Runtime-only. Not a route, not persisted, not udp_confirmed. */
typedef struct udp_observation_t {
	sockaddr_t endpoint;
	struct timespec observed_at;
	uint32_t session_id;
	uint64_t network_epoch;
} udp_observation_t;


/* One runtime owner per demanded NMN output peer. No application session. */
typedef struct relay_hop_t {
	timeout_t timer;
	struct timespec demand_until, deadline, retry_at, last_sent_at;
	sockaddr_t candidate, confirmed_endpoint;
	uint64_t nonce, network_epoch;
	uint32_t session_id;
	unsigned attempts;
	bool confirmed;
	uint32_t challenges_sent, confirmations, failures, admission_delays;
	uint32_t udp_sent, meta_fallbacks, fallback_reason[7];
} relay_hop_t;

typedef enum {
	PLPMTU_DISABLED = 0,
	PLPMTU_BASE,
	PLPMTU_VERIFY,
	PLPMTU_SEARCHING,
	PLPMTU_COMPLETE,
	PLPMTU_ERROR
} path_plpmtu_state_t;

typedef struct path_plpmtu_t {
	path_plpmtu_state_t state;
	uint16_t size;
	uint16_t largest_failed;
	uint16_t probe_size;
	uint16_t pending_size; /* Timer-owned target awaiting admission. */
	uint64_t probe_nonce;
	uint64_t recovery_nonce; /* Small, timer-owned echo between size attempts. */
	uint8_t probe_tries;
	uint8_t raise_backoff;
	bool hostile;
	bool bh_verifying;
	bool raising;
	bool relay_verifying;
	struct timespec relay_verify_at, relay_verified_at;
	uint32_t relay_verifications, relay_verify_failures, relay_verify_admission_delays;
	struct timespec probe_sent_at, raise_at, last_oversize_sent_at, bh_first_at;
	uint8_t bh_evidence;
	sockaddr_t path_ip;
	uint32_t path_net_fp; /* Network identity when this directional path was proved. */
	timeout_t timer;
	uint32_t probes_sent, probes_lost, probes_oversize, black_holes, emsgsize, cache_hits, hostile_marks;
} path_plpmtu_t;

typedef enum {
	LIVENESS_IDLE = 0,
	LIVENESS_PARKED,
	LIVENESS_PROBING
} path_liveness_state_t;

typedef struct path_liveness_t {
	path_liveness_state_t state;
	uint64_t nonce;
	uint8_t tries;
	struct timespec first_try_at;
	timeout_t timer;
	uint32_t probes_sent, retries, giveups;
	bool gave_up;
} path_liveness_t;

typedef struct path_keepalive_t {
	uint32_t interval_ms;
	struct timespec last_tx_at, last_rx_at, last_grow_at, last_probe_at;
	uint32_t pending_gap_ms;
	sockaddr_t pending_ip;
	struct timespec pending_since;
	sockaddr_t local_endpoint, local_endpoint_peer;
	uint64_t local_endpoint_epoch;
	timeout_t timer;
	uint32_t sent, expiries;
} path_keepalive_t;

typedef struct path_local_discovery_t {
	uint64_t nonce;
	uint8_t tries;
	bool active, exhausted;
	timeout_t timer;
} path_local_discovery_t;

typedef struct path_mtu_cache_entry_t {
	uint8_t family;
	uint8_t addr[16];
	uint16_t size, largest_failed;
	uint8_t flags, raise_backoff;
	uint32_t keepalive_ms;
	int64_t updated_at;
	uint32_t net_fp;
} path_mtu_cache_entry_t;

typedef struct node_t {
	// Public member variables
	char *name;                             /* name of this node */
	void *priv;

	// Private member variables
	node_status_t status;
	struct connection_t *relay_budget_connection; /* Runtime reporting connection identity. */
	uint16_t relay_budget;                  /* Accepted type-8 vpn budget; raises channel MSS on UDP relay */
	dev_class_t devclass;

	// Used for packet I/O
	int sock;                               /* Socket to use for outgoing UDP packets */
	uint32_t session_id;                    /* Unique ID for this node's currently running process */
	sptps_t sptps;
	sockaddr_t address;                     /* his real (internet) ip to send UDP packets to */
	address_source_t address_source;        /* provenance of the active UDP dest */
	path_cap_t address_cap;                 /* transport eligibility of the active UDP dest */
	uint32_t sptps_restart_count;           /* send_req_key() restarts of node SPTPS */

	struct utcp *utcp;

	// Traffic counters
	uint64_t in_data;                       /* Bytes received from channels */
	uint64_t out_data;                      /* Bytes sent via channels */
	uint64_t in_forward;                    /* Bytes received for channels that need to be forwarded to other nodes */
	uint64_t out_forward;                   /* Bytes forwarded from channel from other nodes */
	uint64_t in_meta;                       /* Bytes received from meta-connections, heartbeat packets etc. */
	uint64_t out_meta;                      /* Bytes sent on meta-connections, heartbeat packets etc. */

	uint16_t mtu_probe_request_len;         /* Outbound probe-request payload length; set only around sptps_send_record for dest-IP DEBUG log */
	path_plpmtu_t plpmtu;
	relay_hop_t relay_hop;
	unsigned udp_send_result;
	path_liveness_t liveness;
	path_keepalive_t keepalive;
	path_local_discovery_t local_discovery;
	path_mtu_cache_entry_t mtu_cache[PATH_MTU_CACHE_ENTRIES];

	// Type-8 DEBUG log scratch (borrowed; set only around sptps_send_record)
	const char *relay_send_origin;          /* Origin name for type-8 DEBUG log */
	const char *relay_send_dest;            /* Dest name for type-8 DEBUG log */

	// Used for meta-connection I/O, timeouts
	struct meshlink_handle *mesh;           /* The mesh this node belongs to */
	struct submesh_t *submesh;              /* Nodes Sub-Mesh Handle*/

	time_t last_req_key;

	/* Node-owned SPTPS recovery. Not tied to one META socket. */
	struct timespec key_retry_at;           /* {0,0} = watchdog not armed */
	uint8_t key_retry_step;                 /* index into 2,5,10,30,60s */
	uint32_t key_retry_epoch;               /* increments in node_kex_arm(), including send_req_key() and the responder handshake */
	bool key_delivery_uncertain;            /* cutover lost the old primary before the barrier */
	bool key_retry_wanted;                  /* inbound REQ_SPTPS asked for a retry; not channel demand */

	struct ecdsa *ecdsa;                    /* His public ECDSA key */

	struct connection_t *connection;        /* Connection associated with this node (if a direct connection exists) */
	struct meta_cutover *meta_cutover;      /* Ordered canonical->direct barrier; owned by net_upgrade.c */
	time_t last_connect_try;
	time_t last_successfull_connection;

	// Canonical -> direct upgrade probe state
	struct connection_t *upgrade_probe;     /* In-flight probe connection, NULL if none */
	time_t upgrade_next_try;                /* Earliest time for the next probe (0 = now) */
	int upgrade_backoff;                    /* Current backoff in seconds; 0 until a probe fails */
	uint8_t upgrade_recent_idx;             /* recent[] slot the next probe tries */
	sockaddr_t startup_skip_sa;             /* dest the startup budget canceled; upgrade probes skip it until a META activates */

	char *canonical_address;                /* The canonical address of this node, if known */
	char *external_ip_address;              /* The external IP address of this node, if known */
	int udp_choice;                         /* Per-node dest rotation when UDP is unconfirmed */
	sockaddr_t recent[MAX_RECENT];          /* Recently seen addresses */
	address_source_t recent_source[MAX_RECENT]; /* Provenance aligned with recent[] */
	path_cap_t recent_cap[MAX_RECENT];      /* Transport eligibility aligned with recent[] */

	lan_presence_t lan_presence;            /* Runtime only; not persisted */
	time_t lan_auth_direct_until;           /* AUTH_DIRECT reconnect grace; 0 if none */
	uint64_t lan_admitted_epoch;            /* lan_network_epoch when this LAN META was admitted */
	sockaddr_t catta_address;               /* Latest address seen by Catta */
	sockaddr_t canonical_sa;                /* First resolved canonical endpoint, AF_UNSPEC if unknown */
	sockaddr_t canonical_extra[MAX_CANONICAL_SA - 1]; /* Additional resolved canonical endpoints */
	uint8_t canonical_sa_count;             /* Number of cached canonical endpoints */
	bool canonical_resolve_pending;         /* DNS request in flight */
	uint32_t canonical_resolve_gen;         /* 0 = none in flight; else mesh->canonical_resolve_seq cookie */
	int canonical_resolve_backoff;          /* Seconds until the next resolve retry */
	time_t canonical_resolve_next;          /* Earliest time to retry hostname resolve */
	sockaddr_t last_udp_from;               /* Source of the last inbound UDP packet */
	udp_observation_t udp_observation;      /* Authenticated direct UDP source; runtime only */
	uint32_t punch_hints_sent;              /* Address-only ANS_KEY hints this node sent */
	sockaddr_t udp_cache_extra;             /* Extra node_udp_cache key (local probe / alternate from) */
	path_tier_t udp_tier;                   /* Validated UDP dest tier */
	path_tier_t last_path_tier;             /* Last logged destination-wide tier */
	time_t udp_local_probe_next;            /* Earliest local-UDP validation while WAN is active */
	bool demote_deferred;                   /* UDP demotion seen inside a send, applied when it unwinds */
	char demote_reason[32];                 /* Reason to log once the deferred demotion is applied */

	// One active data route, at most one candidate being validated (ADR 0004)
	data_route_t active_route;
	route_candidate_t promotion_candidate;
	path_candidate_retry_t candidate_retry; /* local-UDP endpoint cooldown; not wiped by carrier promotions */
	timeout_t promotion_timer;
	timeout_t punch_timer;                  /* reciprocal hole-punch challenge; not inside peer_udp */
	timeout_t rebind_timer;                 /* confirmed-endpoint migration; not inside udp_rebind */
	suspect_validation_t suspect_validation; /* nonce-epoch recovery; not PMTU */
	udp_rebind_t udp_rebind;                /* live NAT rebind of a confirmed ordinary peer */
	peer_path_demand_t peer_udp;            /* Channel refcount + grace for ordinary-peer UDP */
	sockaddr_t probe_dest_override;          /* Dest for a PKT_PROBE while override is active */
	bool probe_dest_override_active;        /* Armed around one send_udppacket, then cleared */
	sockaddr_t app_udp_override;            /* Committed application UDP dest for one send */
	bool app_udp_override_active;           /* Armed around one application/type-8 UDP send */
	bool devtool_force_meta;                /* Test-only persistent application-route override */
	uint32_t fallback_oversize_redirects;   /* Suspect fallback could not carry the record */
	uint32_t relay_oversize_drops;          /* Legacy name: UDP sends skipped for hop MTU. */
	time_t fallback_oversize_logged_at;     /* Last redirect INFO; at most once per 10s */
	time_t relay_oversize_logged_at;        /* Last oversize INFO; at most once per 10s. */
	uint16_t devtool_drop_size_probes_above; /* Test: receiver drops SIZE_REQUEST longer than this; 0 = off */
	uint8_t devtool_drop_liveness_replies;  /* Test: drop this many LIVENESS echoes */
	unsigned devtool_drop_direct_udp_records; /* Test: next N direct-UDP application sends are discarded */

	// Graph-related member variables
	time_t last_reachable;
	time_t last_unreachable;

	int distance;
	struct node_t *nexthop;                 /* nearest node from us to him */
	struct node_t *prev_nexthop;            /* nexthop at last graph apply */
	struct edge_t *prevedge;                /* nearest node from him to us */

	struct splay_tree_t *edge_tree;         /* Edges with this node as one of the endpoints */
} node_t;

void init_nodes(struct meshlink_handle *mesh);
void exit_nodes(struct meshlink_handle *mesh);
node_t *new_node(void) __attribute__((__malloc__));
void free_node(node_t *n);
void node_add(struct meshlink_handle *mesh, node_t *n);
void node_del(struct meshlink_handle *mesh, node_t *n);
void node_set_validkey(struct meshlink_handle *mesh, node_t *n, bool valid);
node_t *lookup_node(struct meshlink_handle *mesh, const char *name) __attribute__((__warn_unused_result__));
node_t *lookup_node_udp(struct meshlink_handle *mesh, const sockaddr_t *sa) __attribute__((__warn_unused_result__));
void update_node_udp(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *sa);
void update_node_udp_from(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *sa, address_source_t src);
void node_udp_cache_alias(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *sa);
bool node_add_recent_address(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *addr, address_source_t src);
bool node_add_recent_address_cap(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *addr, address_source_t src, path_cap_t cap);
bool node_add_recent_address_cap_ex(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *addr, address_source_t src, path_cap_t cap, bool *material);
bool node_append_recent_address(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *addr, address_source_t src);
bool node_append_recent_address_cap(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *addr, address_source_t src, path_cap_t cap);
bool graph_may_seed_udp(const node_t *n, const sockaddr_t *edge_addr);
/* True when n->address or recent[] already carries listen port (pre-graph snapshot). */
bool node_has_known_listen_port(const node_t *n, uint16_t port) __attribute__((__warn_unused_result__));

#endif
