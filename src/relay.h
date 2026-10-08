#ifndef MESHLINK_RELAY_H
#define MESHLINK_RELAY_H

/*
    relay.h -- UDP type-8 relay
    Copyright (C) 2026 Elear Solutions / MeshLink contributors

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

#include "sockaddr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct meshlink_handle;
struct node_t;
struct connection_t;

#define RELAY_REPORT_MAX 4096
#define RELAY_REPORT_IDLE_SEC 30
#define RELAY_NAME_MAX 255
#define RELAY_INNER_MIN 21              /* SPTPS_DATAGRAM_OVERHEAD */
#define RELAY_UTCP_HDR 20
#define RELAY_MIN_PAYLOAD 1
#define RELAY_OVERSIZE_COOLDOWN_SEC 1
#define RELAY_CAPTURE_MAX 2048

/* ADR 0012: output proof is bounded separately from shared traffic demand. */
#define RELAY_HOP_DEMAND_SEC 30
#define RELAY_HOP_RETRY_SEC 30
#define RELAY_HOP_DEADLINE_SEC 10
#define RELAY_HOP_MAX_ATTEMPTS 2
#define RELAY_HOP_PROBE_GAP_MS 1000
#define RELAY_HOP_TICK_MS 750
#define RELAY_HOP_TICK_JITTER_MS 250

/* Book-end the mesh thread: report table + idle-prune timer. */
void relay_init(struct meshlink_handle *mesh);
void relay_exit(struct meshlink_handle *mesh);

typedef enum relay_udp_result {
	RELAY_UDP_UNREADY = 0, RELAY_UDP_SENT, RELAY_UDP_OVERSIZE,
	RELAY_UDP_NO_SOCKET, RELAY_UDP_WOULD_BLOCK, RELAY_UDP_EMSGSIZE,
	RELAY_UDP_HARD_ERROR
} relay_udp_result_t;

/* All owner operations run on the mesh thread or with mesh->mutex held.
   Demand belongs only to application forwarding on an NMN output peer. */
bool relay_hop_demanded(const struct meshlink_handle *mesh, const struct node_t *hop);
/* Extend shared demand; expired readiness must be proved again. */
void relay_hop_note_demand(struct meshlink_handle *mesh, struct node_t *hop);
/* Consider a fresh authenticated UDP source only while demand is live. */
void relay_hop_observe(struct meshlink_handle *mesh, struct node_t *hop);
/* Run proof/retry/expiry and settled-size maintenance for a demanded output. */
void relay_hop_tick(struct meshlink_handle *mesh, struct node_t *hop);
/* Caller has authenticated an ECHO_REPLY with purpose RELAY_HOP. Returns true
   only for the current nonce, exact candidate, session, epoch and deadline. */
bool relay_hop_reply(struct meshlink_handle *mesh, struct node_t *hop, const sockaddr_t *from, uint64_t nonce);
/* Cancel owned work and readiness, saving eligible per-IP PLPMTU knowledge. */
void relay_hop_stop(struct meshlink_handle *mesh, struct node_t *hop);
/* Revoke proof and its challenge; generic demotion stops health/size timers. */
void relay_hop_demoted(struct meshlink_handle *mesh, struct node_t *hop);

/* Durable UDP confirmation; NMN output also requires proof for hop->address.
   Forwarding refreshes/checks demand before calling this predicate. */
bool relay_hop_udp_ready(const struct node_t *hop);

/* True when origin+dest names cannot fit a type-8 record under MINMTU. */
bool relay_names_unusable(const char *origin, const char *destination);

/* Live vpn-packet budget: minimum of the forward first-hop PLPMTU (less type-8
   overhead) and this connection's final-hop report, or the legacy floor. */
uint16_t relay_effective_budget(struct meshlink_handle *mesh, const struct node_t *dest);

/* Relay-safe UTCP floor for this name pair: type-8 reservation when the names
   fit under MINMTU, otherwise the direct UDP floor. This is the initial size
   and the META size. Live channels move off it via channel_refresh_mtu(). */
uint16_t relay_fixed_channel_mtu(struct meshlink_handle *mesh, const struct node_t *dest);

/* prefix length + SPTPS datagram overhead. Production and tests. */
bool relay_prefix21(const char *origin, const char *destination, uint32_t *out);

/* Clear hop UDP readiness only when the failed dest is the confirmed address.
   `sock` is the attempted listen index from the send site and is unused:
   hop->sock is last-RX and select_listen_socket may rematch. */
void relay_on_hard_send_error(struct meshlink_handle *mesh, struct node_t *hop, const sockaddr_t *sa, int sock);

void relay_clear_budget_if_nexthop_changed(struct meshlink_handle *mesh, struct node_t *dest);

/* Wire encode: u8 origin_len + origin + u8 dest_len + dest + inner. */
bool relay_encode(const char *origin, const char *destination, const void *inner, size_t inner_len, void *out, size_t *out_len);

/* Query helper: copy dest name out of a type-8 payload. Tests/devtools only; send-path logging uses hop scratch. */
bool relay_payload_destination(const void *data, size_t len, char *destination, size_t destination_size);

/* Stash origin/dest on hop, then sptps_send_record type-8. Names are for the DEBUG log after UDP send. Rejects len > UINT16_MAX. */
bool relay_send_outer_record(struct meshlink_handle *mesh, struct node_t *hop, const char *origin, const char *destination, const void *data, size_t len);

/* Incoming type-8 record from `from`. Malformed / unknown names are quiet drops. */
bool relay_handle_record(struct meshlink_handle *mesh, struct node_t *from, const void *data, uint16_t len);

/* Base64 REQ_SPTPS on an existing META connection. */
bool relay_meta_req_sptps(struct meshlink_handle *mesh, struct connection_t *c, const char *origin, const char *dest_name, const void *data, size_t len);

/* Send unchanged application ciphertext on META; use the marked envelope only
   when the directly connected hop advertises 17.8, otherwise REQ_SPTPS. */
bool relay_meta_app(struct meshlink_handle *mesh, struct connection_t *c, const char *origin, const char *dest_name, const void *data, size_t len);
/* Receive a marked META envelope: authenticate/replay-check application-only
   data locally, or use the shared relay-output decision when forwarding.
   Malformed or unauthorized records are quietly consumed. */
bool relay_handle_meta_app(struct meshlink_handle *mesh, struct connection_t *c, struct node_t *origin, struct node_t *dest, const char *request);
/* Clear accepted budgets and report suppression tied to this replaced/closed
   META hop. Call before installing its replacement connection. */
void relay_invalidate_connection(struct meshlink_handle *mesh, struct node_t *hop);

/* META REQ_SPTPS fallback when the next hop is not UDP-ready. */
bool relay_send_meta_req_sptps(struct meshlink_handle *mesh, const char *origin, struct node_t *dest, const void *inner, size_t inner_len);

void relay_maybe_report(struct meshlink_handle *mesh, const char *origin, struct node_t *dest, bool oversize);
void relay_notify_minmtu_change(struct meshlink_handle *mesh, struct node_t *dest);
void relay_touch_traffic(struct meshlink_handle *mesh, const char *origin, const char *destination);

bool relay_handle_req_relay_mtu(struct meshlink_handle *mesh, struct connection_t *c, const char *request, struct node_t *from);

#endif
