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
	uint16_t udp_confirmed: 1;          /* 1 if the address is one that we received UDP traffic on */
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
} node_status_t;

/* Size of node_t.recent[]. devtool_node_status_t.recent[] mirrors it as DEVTOOL_MAX_RECENT
   in the public header; devtools.c static-asserts the two agree. */
#define MAX_RECENT 5

typedef struct node_t {
	// Public member variables
	char *name;                             /* name of this node */
	void *priv;

	// Private member variables
	node_status_t status;
	uint16_t minmtu;                        /* Probed minimum MTU */
	uint16_t relay_budget;                  /* Last accepted final-hop encrypted-record budget */
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

	// MTU probes
	timeout_t mtutimeout;                   /* Probe event */
	int mtuprobes;                          /* Number of probes */
	uint16_t mtu;                           /* Maximum size of packets to send to this node */
	uint16_t maxmtu;                        /* Probed maximum MTU */
	uint16_t mtu_probe_request_len;         /* Outbound probe-request payload length; set only around sptps_send_record for dest-IP DEBUG log */

	// Type-8 DEBUG log scratch (borrowed; set only around sptps_send_record)
	const char *relay_send_origin;          /* Origin name for type-8 DEBUG log */
	const char *relay_send_dest;            /* Dest name for type-8 DEBUG log */

	// Used for meta-connection I/O, timeouts
	struct meshlink_handle *mesh;           /* The mesh this node belongs to */
	struct submesh_t *submesh;              /* Nodes Sub-Mesh Handle*/

	time_t last_req_key;

	struct ecdsa *ecdsa;                    /* His public ECDSA key */

	struct connection_t *connection;        /* Connection associated with this node (if a direct connection exists) */
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
	sockaddr_t catta_address;               /* Latest address seen by Catta */
	sockaddr_t canonical_sa;                /* First resolved canonical endpoint, AF_UNSPEC if unknown */
	sockaddr_t canonical_extra[MAX_CANONICAL_SA - 1]; /* Additional resolved canonical endpoints */
	uint8_t canonical_sa_count;             /* Number of cached canonical endpoints */
	bool canonical_resolve_pending;         /* DNS request in flight */
	uint32_t canonical_resolve_gen;         /* 0 = none in flight; else mesh->canonical_resolve_seq cookie */
	int canonical_resolve_backoff;          /* Seconds until the next resolve retry */
	time_t canonical_resolve_next;          /* Earliest time to retry hostname resolve */
	sockaddr_t last_udp_from;               /* Source of the last inbound UDP packet */
	sockaddr_t udp_cache_extra;             /* Extra node_udp_cache key (local probe / alternate from) */
	path_tier_t udp_tier;                   /* Validated UDP dest tier */
	path_tier_t last_path_tier;             /* Last logged destination-wide tier */
	time_t udp_local_probe_next;            /* Earliest local-UDP validation while WAN is active */

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
bool node_append_recent_address(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *addr, address_source_t src);
bool node_append_recent_address_cap(struct meshlink_handle *mesh, node_t *n, const sockaddr_t *addr, address_source_t src, path_cap_t cap);
bool graph_may_seed_udp(const node_t *n, const sockaddr_t *edge_addr);

#endif
