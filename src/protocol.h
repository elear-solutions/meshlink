#ifndef MESHLINK_PROTOCOL_H
#define MESHLINK_PROTOCOL_H

/*
    protocol.h -- header for protocol.c
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

#include "ecdsa.h"

/* Protocol version. Different major versions are incompatible. */

#define PROT_MAJOR 17
#define PROT_MINOR 8 /* Should not exceed 255! */
/* Direct META upgrades require this minor. Older peers stay on canonical META. */
#define PROT_MINOR_ORDERED_CUTOVER 5
/* One-direction PLPMTU size acks. No mixed-version negotiation. */
#define PROT_MINOR_PLPMTU 6
#define PROT_MINOR_SPTPS_APP 8

/* Silly Windows */

#ifdef ERROR
#undef ERROR
#endif

/* Request numbers */

typedef enum request_t {
	ALL = -1, /* Guardian for allow_request */
	ID = 0, METAKEY, CHALLENGE, CHAL_REPLY, ACK,
	STATUS, ERROR, TERMREQ,
	PING, PONG,
	ADD_SUBNET, DEL_SUBNET,
	ADD_EDGE, DEL_EDGE,
	KEY_CHANGED, REQ_KEY, ANS_KEY,
	PACKET,
	/* Extended requests */
	CONTROL,
	REQ_PUBKEY, ANS_PUBKEY,
	REQ_SPTPS,
	REQ_CANONICAL,
	REQ_EXTERNAL,
	REQ_RELAY_MTU,
	REQ_PUNCH_ENDPOINT,
	REQ_META_CUTOVER_PREPARE,
	REQ_META_CUTOVER_READY,
	REQ_META_CUTOVER_COMMIT,
	REQ_META_CUTOVER_ACK,
	REQ_META_CUTOVER_EMERGENCY, /* primary died before the barrier; sync before ordinary META */
	REQ_SPTPS_APP, /* application-only encrypted datagram envelope */
	NUM_REQUESTS
} request_t;

typedef enum request_error_t {
	NONE = 0,
	BLACKLISTED = 1,
} request_error_t;

typedef struct past_request_t {
	const char *request;
	time_t firstseen;
} past_request_t;

/* Protocol support flags */

static const uint32_t PROTOCOL_TINY = 1; // Peer is using meshlink-tiny
static const uint32_t PROTOCOL_UPGRADE = 2; // Connection replaces the peer's canonical connection to us: hold it as a spare, ACK only once held
static const uint32_t PROTOCOL_VIA_CANONICAL = 4; // Initiator reached us via a relay (canonical or indirect-edge address)

/* Maximum size of strings in a request.
 * scanf terminates %2048s with a NUL character,
 * but the NUL character can be written after the 2048th non-NUL character.
 */

#define MAX_STRING_SIZE 2049
#define MAX_STRING "%2048s"

#include "edge.h"
#include "net.h"
#include "node.h"

/* Basic functions */

bool send_request(struct meshlink_handle *mesh, struct connection_t *, const struct submesh_t *s, const char *, ...) __attribute__((__format__(printf, 4, 5)));
void forward_request(struct meshlink_handle *mesh, struct connection_t *, const struct submesh_t *, const char *);
bool receive_request(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool check_id(const char *);

void init_requests(struct meshlink_handle *mesh);
void exit_requests(struct meshlink_handle *mesh);
bool seen_request(struct meshlink_handle *mesh, const char *);

/* Requests */

bool send_id(struct meshlink_handle *mesh, struct connection_t *);
bool send_ack(struct meshlink_handle *mesh, struct connection_t *);
bool send_error(struct meshlink_handle *mesh, struct connection_t *, request_error_t, const char *);
bool send_ping(struct meshlink_handle *mesh, struct connection_t *);
bool send_pong(struct meshlink_handle *mesh, struct connection_t *);
bool send_add_edge(struct meshlink_handle *mesh, struct connection_t *, const struct edge_t *, int contradictions);
bool send_del_edge(struct meshlink_handle *mesh, struct connection_t *, const struct edge_t *, int contradictions);
bool send_req_key(struct meshlink_handle *mesh, struct node_t *);
bool send_punch_endpoint_request(struct meshlink_handle *mesh, struct node_t *);
bool punch_endpoint_cover_unit(struct meshlink_handle *mesh);
bool rebind_cover_unit(struct meshlink_handle *mesh);
bool node_kex_cover_unit(struct meshlink_handle *mesh);
bool send_canonical_address(struct meshlink_handle *mesh, struct node_t *);
bool send_external_ip_address(struct meshlink_handle *mesh, struct node_t *);
bool send_raw_packet(struct meshlink_handle *mesh, struct connection_t *, const vpn_packet_t *);

/* Request handlers  */

bool id_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool ack_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool status_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool error_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool termreq_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool ping_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool pong_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool add_edge_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool del_edge_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool key_changed_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool req_key_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool ans_key_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool tcppacket_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool raw_packet_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool meta_cutover_prepare_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool meta_cutover_ready_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool meta_cutover_commit_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool meta_cutover_ack_h(struct meshlink_handle *mesh, struct connection_t *, const char *);
bool meta_cutover_emergency_h(struct meshlink_handle *mesh, struct connection_t *, const char *);

/* Node SPTPS recovery. One watchdog, owned by the node, not by a META socket.
   node_kex_clear keeps key_retry_epoch. node_kex_on_session_change zeros it. */
/* Ensure ordinary demand progresses once per deadline; send_req_key forces a
   handshake restart when a known peer changed its listen port or for devtools. */
bool node_kex_ensure(struct meshlink_handle *mesh, struct node_t *n);
void node_kex_clear(struct meshlink_handle *mesh, struct node_t *n);
void node_kex_note_demand(struct meshlink_handle *mesh, struct node_t *n);
void node_kex_mark_uncertain(struct meshlink_handle *mesh, struct node_t *n);
void node_kex_on_session_change(struct meshlink_handle *mesh, struct node_t *n);
void node_kex_consider(struct meshlink_handle *mesh, struct node_t *n);
void node_kex_watchdog(struct meshlink_handle *mesh);

#endif
