#ifndef MESHLINK_DEVTOOLS_H
#define MESHLINK_DEVTOOLS_H

/*
    devtools.h -- header for devtools.h
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>


/// \file devtools.h
/** This header files declares functions that are only intended for debugging and quality control.
 *  They are not necessary for the normal operation of MeshLink.
 *  Applications should not depend on any of these functions for their normal operation.
 */

/// An edge in the MeshLink network.
typedef struct devtool_edge devtool_edge_t;

/// An edge in the MeshLink network.
struct devtool_edge {
	struct meshlink_node *from;     ///< Pointer to a node. Node memory is
	//   owned by meshlink and should not be
	//   deallocated. Node contents may be
	//   changed by meshlink.
	struct meshlink_node *to;       ///< Pointer to a node. Node memory is
	//   owned by meshlink and should not be
	//   deallocated. Node contents may be
	//   changed by meshlink.
	struct sockaddr_storage address;///< The address information associated
	//   with this edge.
	int weight;                     ///< Weight assigned to this edge.
};

/// Get a list of edges.
/** This function returns an array with copies of all known bidirectional edges.
 *  The edges are copied to capture the mesh state at call time, since edges
 *  mutate frequently. The nodes pointed to within the devtool_edge_t type
 *  are not copies; these are the same pointers that one would get from a call
 *  to meshlink_get_all_nodes().
 *
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param edges        A pointer to a previously allocated array of
 *                      devtool_edge_t, or NULL in which case MeshLink will
 *                      allocate a new array.
 *                      The application is allowed to call free() on the array whenever it wishes.
 *                      The pointers in the devtool_edge_t elements are valid until
 *                      meshlink_close() is called.
 *  @param nmemb        A pointer to a variable holding the number of elements that
 *                      are stored in the array. In case the @a edges @a
 *                      argument is not NULL, MeshLink might call realloc()
 *                      on the array to change its size.
 *                      The contents of this variable will be changed to reflect
 *                      the new size of the array.
 *  @return             A pointer to an array containing devtool_edge_t elements,
 *                      or NULL in case of an error.
 *                      If the @a edges @a argument was not NULL, then the
 *                      return value can be either the same value or a different
 *                      value. If the new values is NULL, then the old array
 *                      will have been freed by Meshlink.
 */
devtool_edge_t *devtool_get_all_edges(meshlink_handle_t *mesh, devtool_edge_t *edges, size_t *nmemb);

/// Export a list of edges to a file in JSON format.
/*  @param mesh         A handle which represents an instance of MeshLink.
 *  @param FILE         An open file descriptor to which a JSON representation of the edges will be written.
 *
 *  @return             True in case of success, false otherwise.
 */
bool devtool_export_json_all_edges_state(meshlink_handle_t *mesh, FILE *stream);

/// The status of a node.
typedef struct devtool_node_status devtool_node_status_t;

/// Number of recently seen addresses MeshLink remembers per node (node_t.recent[]).
#define DEVTOOL_MAX_RECENT 5

/// Number of cached canonical endpoints (node_t.canonical_sa + canonical_extra).
#define DEVTOOL_MAX_CANONICAL 8

/** Append-only snapshot. Bump when fields are added. New fields go at the end.
 *  devtool_get_node_status() writes devtool_status_version. */
#define DEVTOOL_NODE_STATUS_VERSION 6

typedef enum {
	DEVTOOL_PLPMTU_DISABLED = 0,
	DEVTOOL_PLPMTU_BASE,
	DEVTOOL_PLPMTU_VERIFY,
	DEVTOOL_PLPMTU_SEARCHING,
	DEVTOOL_PLPMTU_COMPLETE,
	DEVTOOL_PLPMTU_ERROR
} devtool_plpmtu_state_t;

typedef struct devtool_plpmtu_cache_entry {
	uint8_t family;
	uint8_t addr[16];
	uint16_t size;
	uint16_t largest_failed;
	uint8_t flags;
	uint8_t raise_backoff;
	uint32_t keepalive_ms;
	int64_t updated_at;
	uint32_t net_fp;
} devtool_plpmtu_cache_entry_t;

/// The status of a node.
struct devtool_node_status {
	uint32_t status;
	struct sockaddr_storage address;

	enum {
		DEVTOOL_UDP_FAILED = -2,     /// UDP tried but failed
		DEVTOOL_UDP_IMPOSSIBLE = -1, /// UDP not possible (node unreachable)
		DEVTOOL_UDP_UNKNOWN = 0,     /// UDP status not known (never tried to communicate with the node)
		DEVTOOL_UDP_TRYING,          /// UDP detection in progress
		DEVTOOL_UDP_WORKING,         /// UDP communication established
	} udp_status;

	uint64_t in_data;                    /// Bytes received from channels
	uint64_t out_data;                   /// Bytes sent via channels
	uint64_t in_forward;                 /// Bytes received for channels that need to be forwarded to other nodes
	uint64_t out_forward;                /// Bytes forwarded from channel from other nodes
	uint64_t in_meta;                    /// Bytes received from meta-connections, heartbeat packets etc.
	uint64_t out_meta;                   /// Bytes sent on meta-connections, heartbeat packets etc.

	// External address information (from REQ_EXTERNAL messages)
	char *external_ip_address;            /// External IP address and port in "IP PORT" format
	                                      /// Set by REQ_EXTERNAL messages from backbone nodes
	                                      /// NULL if not known or for portable nodes
	char *canonical_address;             /// Canonical address if known
	                                      /// Set by REQ_CANONICAL messages
	                                      /// NULL if not known

	// Meta connection information (from node_t.connection)
	bool meta_connected;                  /// True if there is an active meta connection with this node
	struct sockaddr_storage meta_address; /// Remote address of the meta connection (AF_UNSPEC if none)
	bool meta_via_canonical;              /// True if the meta connection went via a relay (we dialled canonical/indirect-edge, or the peer reached us that way)
	bool meta_is_outgoing;                /// True if we initiated the meta connection and own its outgoing_t
	time_t meta_activated_at;             /// connection_t.activated_at (0 if no META)
	time_t meta_last_key_renewal;         /// connection_t.last_key_renewal (0 if no META)
	bool upgrade_probe_active;            /// True if a direct-upgrade probe is in flight
	int upgrade_backoff;                  /// Current probe backoff in seconds (0 = none)

	// Recently seen direct addresses (node_t.recent[]), front first
	size_t recent_count;                  /// Number of valid entries in recent
	struct sockaddr_storage recent[DEVTOOL_MAX_RECENT]; /// Copies of node_t.recent[]
	uint8_t recent_source[DEVTOOL_MAX_RECENT]; /// address_source_t aligned with recent[]
	uint8_t recent_cap[DEVTOOL_MAX_RECENT]; /// path_cap_t aligned with recent[]
	struct sockaddr_storage canonical_resolved[DEVTOOL_MAX_CANONICAL]; /// cached canonical endpoints
	size_t canonical_resolved_count;      /// number of resolved canonical endpoints
	int udp_tier;                         /// path_tier_t of the confirmed UDP dest
	int dest_path_tier;                   /// path_select_destination_tier()
	int meta_dial_tier;                   /// meta_dial_tier_t of the active META connection
	bool would_probe_local_udp;           /// WAN UDP is active and a local candidate is waiting
	int active_meta_tier;                 /// path_select_hop_tier of the node itself
	struct sockaddr_storage upgrade_target; /// next META-capable direct candidate
	struct sockaddr_storage startup_skip; /// dest the bounded startup cancelled; upgrade probes skip it (AF_UNSPEC once a META activates)
	const char *upgrade_ineligible_reason; /// NULL if an upgrade probe may start
	bool validkey;                        /// node SPTPS has a valid key
	bool waitingforkey;                   /// node is waiting for a key exchange
	int sptps_state;                      /// node_t.sptps.state
	uint32_t sptps_outseqno;              /// node SPTPS outbound sequence
	uint32_t sptps_restart_count;         /// send_req_key() restarts
	uint32_t punch_requests_sent;         /// REQ_PUNCH_ENDPOINT sends for this peer
	uint32_t punch_hints_sent;            /// address-only punch hints this node sent
	uint8_t punch_request_step;           /// endpoint-request ladder step
	bool udp_observation_fresh;           /// a session-matched observation is inside the freshness window
	struct sockaddr_storage udp_observation; /// that observation, or AF_UNSPEC
	bool meta_drain_active;               /// a retired META socket is still flushing
	uint32_t connection_generation;       /// outgoing generation of the active META

	// One active route and at most one candidate (ADR 0004)
	int active_route_kind;                /// data_route_kind_t currently carrying application records
	int active_route_carrier;             /// relay_carrier_t when the route is a relay
	bool active_route_suspect;            /// a retransmission raised suspicion, probes pending
	bool active_route_local;              /// the route's endpoint is on the local network
	const char *active_route_first_hop;   /// first_hop->name when kind is RELAY; NULL otherwise (not owned)
	bool candidate_active;                /// an endpoint is being validated for promotion
	uint8_t candidate_rounds;             /// validation rounds this candidate has passed
	uint8_t candidate_failures;           /// consecutive failures, drives the cooldown ladder
	uint64_t candidate_nonce;             /// nonce the current round must echo (0 if none)
	struct sockaddr_storage candidate_endpoint; /// endpoint under validation (AF_UNSPEC if none)
	int candidate_cooldown_remaining;     /// seconds until this endpoint may be tried again
	uint16_t channel_mtu;                 /// current UTCP MTU (header + MSS), not chosen once
	uint16_t relay_budget;                /// accepted type-8 vpn budget; 0 if none

	/* DEVTOOL_NODE_STATUS_VERSION 2. Append only. */
	uint32_t devtool_status_version;      /// DEVTOOL_NODE_STATUS_VERSION
	int cutover_state;                    /// meta cutover state, 0 if idle
	uint64_t cutover_id;                  /// barrier id, 0 if idle
	bool cutover_timer_armed;             /// barrier timer is scheduled
	unsigned cutover_pending_records;     /// plaintext records held for the barrier
	size_t cutover_pending_bytes;         /// bytes in that FIFO
	bool cutover_has_standby;             /// a direct socket is held beside the canonical one
	uint8_t key_retry_step;               /// index into the 2/5/10/30/60s ladder
	uint32_t key_retry_epoch;             /// increments on each node_kex_arm()
	bool key_retry_armed;                 /// watchdog deadline is set
	bool key_delivery_uncertain;          /// old primary died before the barrier was proven
	bool pending_punch_hint;              /// a hint is staged ahead of validkey

	/* DEVTOOL_NODE_STATUS_VERSION 3. Append only. */
	uint8_t punch_challenge_provenance;   /// 0 none, 1 NMN hint, 2 authenticated ingress
	uint8_t punch_challenge_attempts;     /// probes actually sent for the current challenge
	bool punch_challenge_active;          /// a punch nonce is outstanding
	struct sockaddr_storage punch_challenge_endpoint; /// AF_UNSPEC if none

	/* DEVTOOL_NODE_STATUS_VERSION 4. Append only. */
	bool rebind_challenge_active;         /// a rebind nonce is outstanding
	struct sockaddr_storage rebind_candidate_endpoint; /// AF_UNSPEC if none
	uint32_t rebind_seen;                 /// distinct authenticated sources after confirm
	uint32_t rebind_migrated;             /// nonce-proved endpoint swaps
	uint32_t rebind_failed;               /// challenges that missed their deadline

	/* DEVTOOL_NODE_STATUS_VERSION 5. Append only. */
	uint32_t fallback_oversize_redirects; /// suspect fallback could not carry a record
	uint32_t relay_oversize_drops;        /// type-8 records dropped for hop MTU

	/* DEVTOOL_NODE_STATUS_VERSION 6. Append only. */
	devtool_plpmtu_state_t plpmtu_state;
	uint16_t plpmtu_size;
	uint16_t plpmtu_largest_failed;
	uint16_t plpmtu_probe_size;
	bool plpmtu_hostile;
	int plpmtu_raise_in_sec;
	uint32_t plpmtu_probes_sent;
	uint32_t plpmtu_probes_lost;
	uint32_t plpmtu_probes_oversize;
	uint32_t plpmtu_black_holes;
	uint32_t plpmtu_emsgsize;
	uint32_t plpmtu_cache_hits;
	int liveness_state;
	uint32_t liveness_probes_sent;
	uint32_t liveness_retries;
	uint32_t liveness_giveups;
	uint32_t keepalive_interval_ms;
	uint32_t keepalives_sent;
	uint32_t keepalive_expiries;
};

/// Get the status of a node.
/** This function returns a struct containing extra information about a node.
 *  The information is a snapshot taken at call time.
 *
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param node         A pointer to a meshlink_node_t.
 *  @param status       A pointer to a devtools_node_status_t variable that has
 *                      to be provided by the caller.
 *                      The contents of this variable will be changed to reflect
 *                      the current status of the node.
 */
void devtool_get_node_status(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_node_status_t *status);

const char *devtool_get_backbone_name(meshlink_handle_t *mesh);
meshlink_node_t *devtool_get_backbone(meshlink_handle_t *mesh);
bool devtool_node_has_conflict_backbone(meshlink_handle_t *mesh, meshlink_node_t *node);

/// Number of entries in mesh->outgoings (logical META intents).
unsigned devtool_outgoing_count(meshlink_handle_t *mesh);

/// Purpose of the BACKBONE_REQUIRED outgoing, or -1 if none.
/** Values match meta_connection_purpose_t: NONE=0, BACKBONE_REQUIRED=1,
 *  LAN_RESILIENCE=2. Handover spare was removed — ADR 0007 keeps handover in net_upgrade.
 */
int devtool_backbone_intent_purpose(meshlink_handle_t *mesh);

/// Name of the BACKBONE_REQUIRED target, or NULL if none.
const char *devtool_backbone_intent_name(meshlink_handle_t *mesh);

/// Ladder index of the BACKBONE_REQUIRED outgoing, or -1 if none.
int devtool_backbone_intent_retry_step(meshlink_handle_t *mesh);

/// Absolute deadline of the armed BACKBONE_REQUIRED retry, or false if none is armed.
bool devtool_backbone_intent_retry_deadline(meshlink_handle_t *mesh, struct timespec *deadline);

/// True when this instance is allowed to initiate META (not a BACKBONE-class node).
bool devtool_self_initiates_meta(meshlink_handle_t *mesh);

/// Overwrite a node's device class and re-run topology + META-pool policy.
/** Tests only. Does not persist. Used to reclassify a live stored backbone as
 *  wrong-class/conflicted and assert the reserved intent and its sockets die.
 */
void devtool_set_node_devclass(meshlink_handle_t *mesh, meshlink_node_t *node, int devclass);

/// Allow this instance to create and serve invitations even when it is not the unique backbone.
/** Production invite/join stay gated. Tests use this only to plant a non-production invitation blob.
 *  It does not weaken meshlink_join().
 */
void devtool_set_allow_peer_bootstrap(meshlink_handle_t *mesh, bool allow);

/// Plant a local DISCOVERY address and run connection-policy discovery (LAN overlay tests).
bool devtool_learn_discovery_address(meshlink_handle_t *mesh, meshlink_node_t *node,
                                     const struct sockaddr *addr);

/// Clear runtime DISCOVERY presence for a peer without touching recent[] or AUTH_DIRECT grace.
/** Setup only: isolates LAN_AUTH_DIRECT_GRACE_SEC after a live local META drop.
 *  Does not advance the network epoch and does not clear lan_auth_direct_until.
 */
void devtool_clear_lan_discovery_presence(meshlink_handle_t *mesh, meshlink_node_t *node);

/// True while the coalesced LAN mDNS query timer is armed.
bool devtool_lan_discovery_query_pending(meshlink_handle_t *mesh);

/// Times discovery_refresh ran from that timer. A no-op fire does not increment.
unsigned devtool_lan_discovery_query_fires(meshlink_handle_t *mesh);

/// Remaining delay in ms, or -1 when the timer is not armed.
int devtool_lan_discovery_query_delay_ms(meshlink_handle_t *mesh);

/// Run the armed timer callback now. Does not send multicast by itself.
bool devtool_fire_lan_discovery_query(meshlink_handle_t *mesh);

/// Same hook the inbound mesh mDNS query branch uses after it answers.
void devtool_note_inbound_mdns_query(meshlink_handle_t *mesh);

/// Deliver one ADD_EDGE. A new from or to node arms the LAN query when it should.
bool devtool_inject_add_edge(meshlink_handle_t *mesh, const char *from_name, int from_devclass, const char *to_name, int to_devclass);

/// Run discovery_stop, which drops the LAN query timer.
void devtool_discovery_stop(meshlink_handle_t *mesh);

/// Number of LAN_RESILIENCE outgoings.
unsigned devtool_lan_intent_count(meshlink_handle_t *mesh);

/// Number of authenticated local META adjacencies (in+out, unique peers, excluding backbone).
unsigned devtool_local_adjacency_count(meshlink_handle_t *mesh);

/// Run ack_h's admit-then-replace sequence for a synthetic socket to node.
/** Does not mutate node state when the candidate is refused. Used to prove a
 *  rejected WAN duplicate cannot disturb an existing local adjacency.
 */
bool devtool_try_ack_replace(meshlink_handle_t *mesh, meshlink_node_t *node,
                             const struct sockaddr *from, int announced_devclass);

/// Free the memory allocated by devtool_get_node_status.
/** This function frees the dynamically allocated strings in a devtool_node_status_t struct.
 *  Call this function when you're done with the status data to prevent memory leaks.
 *
 *  @param status A pointer to the devtool_node_status_t struct to clean up.
 */
void devtool_free_node_status(devtool_node_status_t *status);

/// Reset the traffic counters of a node.
/** This function resets the byte counters for the given node to zero.
 *  It also returns the status containing the counters right before they are zeroed.
 *
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param node         A pointer to a meshlink_node_t.
 *  @param status       A pointer to a devtools_node_status_t variable that has
 *                      to be provided by the caller.
 *                      The contents of this variable will be changed to reflect
 *                      the current status of the node before the counters are zeroed.
 *                      If a NULL pointers is passed, no status will be written.
 */
void devtool_reset_node_counters(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_node_status_t *status);

/// Get the list of all submeshes of a meshlink instance.
/** This function returns an array of submesh handles.
 *  These pointers are the same pointers that are present in the submeshes list
 *  in mesh handle.
 *
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param submeshes    A pointer to an array of submesh handles if any allocated previously.
 *  @param nmemb        A pointer to a size_t variable that has
 *                      to be provided by the caller.
 *                      The contents of this variable will be changed to indicate
 *                      the number if array elements.
 */
meshlink_submesh_t **devtool_get_all_submeshes(meshlink_handle_t *mesh, meshlink_submesh_t **submeshes, size_t *nmemb);

/// Open a MeshLink instance in a given network namespace.
/** This function opens MeshLink in the given network namespace.
 *
 *  @param confbase The directory in which MeshLink will store its configuration files.
 *                  After the function returns, the application is free to overwrite or free @a confbase @a.
 *  @param name     The name which this instance of the application will use in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name @a.
 *  @param appname  The application name which will be used in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name @a.
 *  @param devclass The device class which will be used in the mesh.
 *  @param netns    A filedescriptor that represents the network namespace.
 *
 *  @return         A pointer to a meshlink_handle_t which represents this instance of MeshLink, or NULL in case of an error.
 *                  The pointer is valid until meshlink_close() is called.
 */
meshlink_handle_t *devtool_open_in_netns(const char *confbase, const char *name, const char *appname, dev_class_t devclass, int netns);

/// Debug function pointer variable for set port API
/** This function pointer variable is a userspace tracepoint or debugger callback for
 *  set port function @a meshlink_set_port @a.
 *  On assigning a debug function variable invokes callback when try_bind() succeeds in meshlink_set_port API.
 *
 */
extern void (*devtool_trybind_probe)(void);

/// Debug function pointer variable for encrypted key rotate API
/** This function pointer variable is a userspace tracepoint or debugger callback for
 *  encrypted key rotation function @a meshlink_encrypted_key_rotate @a.
 *  On assigning a debug function variable invokes callback for each stage from the key rotate API.
 *
 *  @param stage Debug stage number.
 */
extern void (*devtool_keyrotate_probe)(int stage);

/// Debug function pointer variable for asynchronous DNS resolving
extern void (*devtool_adns_resolve_probe)(void);

/// Debug function pointer variable for SPTPS key renewal
/** This function pointer variable is a userspace tracepoint or debugger callback for
 *  SPTPS key renewal.
 *
 *  @param node The node whose SPTPS key(s) are being renewed
 */
extern void (*devtool_sptps_renewal_probe)(meshlink_node_t *node);

/// Stages reported by devtool_upgrade_probe.
typedef enum {
	DEVTOOL_UPGRADE_PROBE_STARTED = 0,   /// A direct probe connection was opened next to the canonical one
	DEVTOOL_UPGRADE_PROBE_SUCCEEDED = 1, /// The probe authenticated and the node migrated to it
	DEVTOOL_UPGRADE_PROBE_FAILED = 2,    /// The probe died before authenticating; backoff applied
} devtool_upgrade_probe_stage_t;

/// Debug function pointer variable for canonical -> direct upgrade probes
/** Called with the mesh mutex held, once per probe start, success or failure, so
 *  tests can wait on the migration. Usually this happens on MeshLink's own thread,
 *  but a probe started from meshlink_hint_address() reports STARTED (or FAILED) on
 *  the thread that called that API, so the hook must not assume either thread.
 *
 *  @param mesh  The mesh the probe belongs to.
 *  @param node  The node being probed.
 *  @param stage One of devtool_upgrade_probe_stage_t.
 */
extern void (*devtool_upgrade_probe)(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_upgrade_probe_stage_t stage);

/// Test knob: send the next ACK twice, like a peer that repeats its ACK would.
/** A repeated ACK is a protocol violation which the receiving side must reject instead
 *  of activating (or holding as a spare) the same connection a second time. The knob is
 *  process-wide: set it right before the ACK to double; send_ack() clears it after use.
 */
extern bool devtool_repeat_next_ack;

/// When set, the responder records PREPARE but does not send READY.
extern bool devtool_hold_cutover_ready;

/// Set on the mesh thread once a READY was withheld. Tests poll this instead of logs.
extern volatile bool devtool_cutover_ready_held;

/// Send the withheld READY for node. Mesh mutex is taken internally.
bool devtool_release_cutover_ready(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Shut the node's current META socket down. The I/O path frees it; this does not.
bool devtool_shutdown_meta_primary(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Queue REQ_KEY on the node's current META connection.
bool devtool_queue_req_key(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Feed one request into the spare, or the primary if there is no spare.
bool devtool_inject_meta_request(struct meshlink_handle *mesh, struct meshlink_node *node, const char *request);

/// Abort the live cutover and replay onto the old primary when it is still canonical.
void devtool_abort_meta_cutover(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Force renewal of SPTPS sessions with the given node.
/** This causes the SPTPS sessions for both the UDP and TCP connections to renew their keys.
 *
 *  @param mesh A handle which represents an instance of MeshLink.
 *  @param node The node whose SPTPS key(s) should be renewed
 */
void devtool_force_sptps_renewal(meshlink_handle_t *mesh, meshlink_node_t *node);

/// Debug function pointer variable for asserting inviter/invitee committing sequence
/** This function pointer variable is a userspace tracepoint or debugger callback which
 *  invokes either after inviter writing invitees host file into the disk
 *  or after invitee writing it's main config file and host config files that inviter sent into
 *  the disk.
 *
 *  @param inviter_commited_first       true if inviter committed first else false if invitee committed first the other host file into the disk.
 */
extern void (*devtool_set_inviter_commits_first)(bool inviter_commited_first);

/// Set the meta-connection status callback.
/** This functions sets the callback that is called whenever a meta-connection is made or closed.
 *  The callback is run in MeshLink's own thread.
 *  It is therefore important that the callback uses apprioriate methods (queues, pipes, locking, etc.)
 *  to hand the data over to the application's thread.
 *  The callback should also not block itself and return as quickly as possible.
 *
 *  \memberof meshlink_handle
 *  @param mesh      A handle which represents an instance of MeshLink.
 *  @param cb        A pointer to the function which will be called when a node's meta-connection status changes.
 *                   If a NULL pointer is given, the callback will be disabled.
 */
void devtool_set_meta_status_cb(struct meshlink_handle *mesh, meshlink_node_status_cb_t cb);

/// Set a node's learned REQ_EXTERNAL address (host and port, space-separated).
/** @param mesh                   Mesh handle.
 *  @param node                   Node whose REQ_EXTERNAL string to replace.
 *  @param external_ip_address    "host port", or NULL to clear.
 */
void devtool_set_external_ip_address(struct meshlink_handle *mesh, struct meshlink_node *node, const char *external_ip_address);

/// Apply update_node_udp() as if this address was learned from the graph or a peer.
/** @param mesh  Mesh handle.
 *  @param node  Node whose UDP dest to set.
 *  @param addr  New dest; NULL only drops the UDP cache entry; an AF_UNSPEC
 *               sockaddr forgets everything learned (cache entry, node_t.address
 *               and node_t.recent[]).
 */
void devtool_update_node_udp(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr);

/// Peek at the UDP destination choose_udp_address() would use, without advancing rotation.
/** @param mesh  Mesh handle.
 *  @param node  Peer to pick a dest for.
 *  @param addr  Filled with the chosen dest on success.
 *  @param sock  Filled with the listen-socket index on success.
 *  @return      true if a usable dest with a matching listen fd exists.
 */
bool devtool_choose_udp_address(struct meshlink_handle *mesh, struct meshlink_node *node, struct sockaddr_storage *addr, int *sock);

/// Same as devtool_choose_udp_address(), but consumes a rotation slot like a real send would.
/** The rotation state is shared with the event-loop send path, so call this on
 *  a stopped mesh when the sequence of picks must be deterministic.
 *
 *  @param mesh  Mesh handle.
 *  @param node  Peer to pick a dest for.
 *  @param addr  Filled with the chosen dest on success.
 *  @param sock  Filled with the listen-socket index on success.
 *  @return      true if a usable dest with a matching listen fd exists.
 */
bool devtool_choose_udp_address_advance(struct meshlink_handle *mesh, struct meshlink_node *node, struct sockaddr_storage *addr, int *sock);

/// Pin or clear node_t.status.udp_confirmed for dest-pick tests.
/** Relay-aware: a change recomputes dependents. Clearing confirmation restarts dest
 *  probes unless `devtool_force_meta` is set on the node.
 *
 *  @param mesh       Mesh handle.
 *  @param node       Node to update.
 *  @param confirmed  New udp_confirmed flag.
 */
void devtool_set_udp_confirmed(struct meshlink_handle *mesh, struct meshlink_node *node, bool confirmed);

/// Age the confirmed-endpoint receive timestamp so a rebind challenge can start.
/** age_ms is how long ago the current endpoint last spoke. Requires mesh->mutex not held. */
void devtool_rebind_age_current_rx(struct meshlink_handle *mesh, struct meshlink_node *node, int age_ms);

/// Feed one authenticated source into the rebind observer. Requires mesh->mutex not held.
void devtool_rebind_observe(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *sa);

/// Persistently force a node's application records onto META.
/** Used by tests that are not about UDP. Enabling stops UDP probes and ignores
 *  delayed probe replies without clearing recent[]; disabling resumes probing.
 */
void devtool_force_meta(struct meshlink_handle *mesh, struct meshlink_node *node, bool enabled);

/// Plant an address in recent[] as ADDR_SRC_UNKNOWN, bypassing canonical rejection.
/** Used to reconstruct a persisted NLB-in-recent[] entry from an old install.
 *  Marks the node dirty and writes its host config.
 */
bool devtool_plant_recent_address(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr);

/// Plant UNKNOWN hybrid with META+UDP caps without sanitizing (live META-walk tests).
/** Unlike plant_recent_address (UDP-only), this leaves a META-capable hybrid in
 *  recent[] so the outgoing walk can prove it skips the address.
 */
bool devtool_plant_meta_hybrid_address(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr);

/// Force a confirmed UDP dest and tier without waiting for a probe reply.
bool devtool_confirm_udp_from(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr, int tier);

/// Drive path_promote_udp_if_better (production WAN→local promotion).
bool devtool_promote_udp_if_better(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr);

/// True when sssp_bfs would seed n->address from this edge dest.
/** @param mesh  Mesh handle.
 *  @param node  Node the edge points to.
 *  @param addr  Candidate edge address.
 *  @return      true if graph_may_seed_udp() accepts the candidate.
 */
bool devtool_graph_may_seed_udp(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr);

/// Pretend dest is only reachable via nexthop UDP (for relay tests).
/** Pins dest's nexthop, clears dest's direct UDP confirmation, marks nexthop
 *  UDP-confirmed, stops dest probes, resets dest probe count, and clears dest's
 *  stored relay budget. Does not write minmtu. nexthop must already have a
 *  valid key.
 *
 *  @param mesh     Mesh handle.
 *  @param dest     Node that should be reached only via nexthop.
 *  @param nexthop  Relay with a confirmed UDP session. Must not be dest.
 *  @return         true on success.
 */
bool devtool_force_relay_path(struct meshlink_handle *mesh, struct meshlink_node *dest, struct meshlink_node *nexthop);

/// Inject a raw SPTPS record, or a constructed inner record when data is NULL.
/** When data is non-NULL, encrypts and sends `type` with that payload to `to`.
 *  When data is NULL, encrypts a dummy record of `type` using `to`'s session
 *  and wraps it as type 8 or sends META REQ_SPTPS.
 *
 *  @param mesh  Mesh handle.
 *  @param to    Neighbor or destination node.
 *  @param type  SPTPS record type.
 *  @param data  Payload, or NULL to construct an inner record.
 *  @param len   Payload length.
 *  @return      true on success.
 */
bool devtool_send_raw_record(struct meshlink_handle *mesh, struct meshlink_node *to, uint8_t type, const void *data, size_t len);

/// Plant a settled PLPMTU. 0 disables it. Otherwise size must be in [MINMTU, MTU].
bool devtool_set_plpmtu(struct meshlink_handle *mesh, struct meshlink_node *node, uint16_t size);

/// Drop every origin-and-destination report-table entry.
/** @param mesh  Mesh handle.
 */
void devtool_clear_relay_reports(struct meshlink_handle *mesh);

/// Create or update a report-table entry.
/** `age_sec` is subtracted from the instance's current loop time so the entry
 *  stays inside the thirty-second idle window. Unknown names are allowed so
 *  tests can fill the 4,096-entry cap without opening extra instances.
 *
 *  @param mesh           Mesh handle.
 *  @param origin         Origin name stored on the entry.
 *  @param destination    Destination name stored on the entry.
 *  @param age_sec        Seconds to subtract from the current loop time.
 *  @param have_reported  Whether the entry has already queued a report.
 *  @return               true on success.
 */
bool devtool_seed_relay_report(struct meshlink_handle *mesh, const char *origin, const char *destination, unsigned age_sec, bool have_reported);

/// True when the report table has an entry for this pair.
bool devtool_has_relay_report(struct meshlink_handle *mesh, const char *origin, const char *destination);

/// True when that pair has stamped a successful report.
bool devtool_relay_report_have_reported(struct meshlink_handle *mesh, const char *origin, const char *destination);

/// Number of live report-table entries.
size_t devtool_relay_report_count(struct meshlink_handle *mesh);

/// Insert `count` dummy pairs named f0000/x, f0001/x, ...
bool devtool_fill_relay_reports(struct meshlink_handle *mesh, size_t count, unsigned age_sec, bool have_reported);

/// Force every `REQ_RELAY_MTU` `send_request` to fail until cleared.
/** Failed queues do not stamp the one-second oversize clock.
 *
 *  @param mesh  Mesh handle.
 *  @param fail  true to fail, false to resume normal sends.
 */
void devtool_fail_relay_reports(struct meshlink_handle *mesh, bool fail);


/// Deliver a type-8 payload using `from`'s SPTPS decrypt buffer as the source (alias test).
bool devtool_handle_relay_aliased(struct meshlink_handle *mesh, struct meshlink_node *from, const void *data, size_t len);

/// Encrypt type/data with dest's session and deliver it as dest META REQ_SPTPS.
bool devtool_send_meta_sptps(struct meshlink_handle *mesh, struct meshlink_node *dest, uint8_t type, const void *data, size_t len);

/// Force the dest-unwrap realloc path to fail until cleared.
void devtool_fail_relay_realloc(struct meshlink_handle *mesh, bool fail);

/// Inject a `REQ_RELAY_MTU` request string through `from`'s current META connection.
bool devtool_handle_req_relay_mtu(struct meshlink_handle *mesh, struct meshlink_node *from, const char *request);

/// Drive remaining relay.c branches on a live trio (from / dest / hop).
bool devtool_relay_cover_unit(struct meshlink_handle *mesh, struct meshlink_node *from, struct meshlink_node *dest, struct meshlink_node *hop);

/// Drive every path_policy.c branch. `node` is restored before return.
bool devtool_path_policy_cover_unit(struct meshlink_handle *mesh, struct meshlink_node *node);

/// path_select_destination_tier() / path_select_hop_tier() with an explicit META-in pin.
int devtool_select_destination_tier(struct meshlink_handle *mesh, struct meshlink_node *node, bool meta_in);
int devtool_select_hop_tier(struct meshlink_handle *mesh, struct meshlink_node *node, bool meta_in);

/// Pin dest via hop, set both UDP flags, and return dest tier under one lock.
/** Stops dest/hop MTU timers when that side is unconfirmed so inbound probes
 *  cannot change the snapshot before the caller reads it.
 */
int devtool_select_dest_with_udp(struct meshlink_handle *mesh, struct meshlink_node *dest, bool dest_udp, struct meshlink_node *hop, bool hop_udp, bool meta_in);

/// Run one periodic route tick for this node without waiting for the timer.
/** Expires a stale candidate, resolves a suspect route and resets failures
 *  from healthy_since (never selected_at, never while cooldown is live),
 *  so tests do not depend on wall-clock timing.
 */
void devtool_path_route_tick(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Resolve and record the send target as send_application_record() does.
/** @param chosen_kind  Filled with the data_route_kind_t that would carry this record.
 *  @return             false if there is no usable target.
 */
bool devtool_apply_send_target(struct meshlink_handle *mesh, struct meshlink_node *node, int *chosen_kind);

/// Start or fetch the endpoint under validation, and the nonce its probe carries.
/** @return false when there is nothing to validate right now.
 */
bool devtool_candidate_probe_target(struct meshlink_handle *mesh, struct meshlink_node *node, struct sockaddr_storage *addr, uint64_t *nonce);

/// Feed an authenticated probe reply into the promotion/suspect state machines.
void devtool_observe_probe_reply(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr, uint64_t nonce);

/// Mark the active route suspect, as a reliable retransmission would.
void devtool_note_route_suspect(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Query the in-flight suspect endpoint and nonce. False if none.
bool devtool_suspect_probe_target(struct meshlink_handle *mesh, struct meshlink_node *node, struct sockaddr_storage *addr, uint64_t *nonce);

/// True when a lower-ranked route is already live for this node.
bool devtool_has_live_fallback(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Age the active route's residency, suspicion, suspect deadline and healthy_since by `seconds`.
/** Lets a test reach the residency, suspect-window and healthy-reset
 *  boundaries immediately. A negative value moves them away, so a test can
 *  hold a route inside its residency for as long as it needs.
 */
void devtool_age_route(struct meshlink_handle *mesh, struct meshlink_node *node, int seconds);

/// Drop the suspect timer without aging the route. The epoch stays active.
/** Tests that are not about suspect expiry use this so a one-second window
 *  cannot discard an in-flight promotion while they wait on something else.
 */
void devtool_disarm_suspect_timer(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Age the promotion candidate's round gap, deadline and cooldown by `seconds`.
void devtool_age_candidate(struct meshlink_handle *mesh, struct meshlink_node *node, int seconds);

/// True when this peer currently warrants a liveness probe.
bool devtool_liveness_probe_warranted(struct meshlink_handle *mesh, struct meshlink_node *node);

/// How many times send_ping() has run on the META socket to this node. 0 if none.
unsigned devtool_meta_pings_sent(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Parked 64-byte liveness probes this node has emitted toward `node`.
unsigned devtool_liveness_probes_sent(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Discard the next `count` direct-UDP application records to `node`. 0 clears it.
bool devtool_drop_next_direct_udp_records(struct meshlink_handle *mesh, struct meshlink_node *node, unsigned count);

/// Drop SIZE_REQUEST probes longer than `limit`. 0 disables the limit.
bool devtool_drop_size_probes_above(struct meshlink_handle *mesh, struct meshlink_node *node, uint16_t limit);

/// Drop the next `count` LIVENESS echo replies. 0 clears it.
bool devtool_drop_liveness_replies(struct meshlink_handle *mesh, struct meshlink_node *node, uint8_t count);

/// Make the next PLPMTU tick treat the raise timer as due.
bool devtool_plpmtu_raise_due(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Plant the idle keepalive interval, in milliseconds.
bool devtool_set_keepalive_interval(struct meshlink_handle *mesh, struct meshlink_node *node, uint32_t ms);

/// Copy one per-IP MTU cache entry. False when index is out of range.
bool devtool_plpmtu_cache_entry(struct meshlink_handle *mesh, struct meshlink_node *node, int index, devtool_plpmtu_cache_entry_t *out);

unsigned devtool_probe_second_tokens(struct meshlink_handle *mesh);
unsigned devtool_probe_minute_tokens(struct meshlink_handle *mesh);
unsigned devtool_probe_active_transactions(struct meshlink_handle *mesh);

/// Optional (non-backbone) packets the scheduler has emitted. Does not include the backbone bucket.
uint64_t devtool_probe_optional_packets_sent(struct meshlink_handle *mesh);
void devtool_set_probe_budget(struct meshlink_handle *mesh, unsigned second, unsigned minute, unsigned txns);
unsigned devtool_candidate_requests_sent(struct meshlink_handle *mesh, struct meshlink_node *node);
void devtool_scheduler_drain(struct meshlink_handle *mesh);

/// Shorten the backbone UDP keepalive interval for tests. Seconds must be >= 1.
void devtool_set_backbone_udp_keepalive(struct meshlink_handle *mesh, int seconds);

/// True when this mesh has a confirmed backbone UDP mapping.
bool devtool_backbone_udp_confirmed(struct meshlink_handle *mesh);

/// True when the backbone UDP keepalive/establish timer is armed.
bool devtool_backbone_udp_timer_armed(struct meshlink_handle *mesh);

/// Copy the in-flight backbone UDP endpoint. False if none.
bool devtool_backbone_udp_endpoint(struct meshlink_handle *mesh, struct sockaddr_storage *addr);

/// Copy the last failed backbone UDP endpoint. False if none.
bool devtool_backbone_udp_failed_endpoint(struct meshlink_handle *mesh, struct sockaddr_storage *addr);

/// Current telescopic establishment backoff step (0 at start / after a new dest).
unsigned devtool_backbone_udp_establish_step(struct meshlink_handle *mesh);

/// Force-clear a candidate cooldown. Production eligibility is the observation epoch gate.
void devtool_candidate_clear_cooldown(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Simulate a hard UDP send failure on `hop`'s confirmed address.
void devtool_relay_hard_send_error(struct meshlink_handle *mesh, struct meshlink_node *hop);

/// Simulate a hard UDP send failure to an explicit destination on `hop`.
/** Clears readiness only when `addr` is the hop's confirmed destination.
 *  `sock` is unused (last-RX `hop->sock` is not the send-site index).
 *
 *  @param mesh  Mesh handle.
 *  @param hop   Node whose UDP send failed.
 *  @param addr  Attempted destination, including family and port.
 *  @param sock  Attempted listen-socket index (ignored).
 */
void devtool_relay_hard_send_error_at(struct meshlink_handle *mesh, struct meshlink_node *hop, const struct sockaddr *addr, int sock);

/// Under the mesh lock: mark `hop` broadcast, inject a hard send, send a probe.
/** Hits `send_sptps_via_udp` with the broadcast dest. Returns true when the
 *  injected hard-error path ran. False if `hop` has no `prevedge` or no key,
 *  or if the send never reached `send_sptps_via_udp`.
 *
 *  @param mesh  Mesh handle.
 *  @param hop   Confirmed hop to send through.
 *  @return      true if the hard-error path ran.
 */
bool devtool_inject_broadcast_hard_send(struct meshlink_handle *mesh, struct meshlink_node *hop);

/// Build a dest that differs only in port from `src`.
void devtool_fill_port_mismatch(const struct sockaddr_storage *src, struct sockaddr_storage *dst);

/// Build a dest that differs only in host from `src`.
void devtool_fill_host_mismatch(const struct sockaddr_storage *src, struct sockaddr_storage *dst);

/// Build `ff02::1`.
void devtool_fill_mcast_ff02_1(struct sockaddr_storage *dst);

/// Build IPv4 `255.255.255.255`.
void devtool_fill_bcast_ipv4(struct sockaddr_storage *dst);

/// Override the bounded-startup budget (milliseconds). 0 or negative restores 250.
void devtool_set_outgoing_startup_ms(int ms);

#endif
