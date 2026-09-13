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

/* Book-end the mesh thread: report table + idle-prune timer. */
void relay_init(struct meshlink_handle *mesh);
void relay_exit(struct meshlink_handle *mesh);

/* Durable hop: udp_confirmed && validkey && !temp_udp_confirmed. */
bool relay_hop_udp_ready(const struct node_t *hop);

/* True when origin+dest names cannot fit a type-8 record under MINMTU. */
bool relay_names_unusable(const char *origin, const char *destination);

/* Dest-wide UTCP MSS from direct UDP, relay budget, or META fallback. */
void relay_update_destination_transport(struct meshlink_handle *mesh, struct node_t *dest);

/* Recompute MSS for every dest whose nexthop is hop (skip udp_confirmed dests). */
void relay_recompute_dependents(struct meshlink_handle *mesh, struct node_t *hop);

void relay_on_hard_send_error(struct meshlink_handle *mesh, struct node_t *hop);

/* Arm hop probes at 0-timeout and kick pselect so the mesh thread runs now. */
void relay_wake_probes(struct meshlink_handle *mesh, struct node_t *hop);

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

/* META REQ_SPTPS fallback when the next hop is not UDP-ready. */
bool relay_send_meta_req_sptps(struct meshlink_handle *mesh, const char *origin, struct node_t *dest, const void *inner, size_t inner_len);

void relay_maybe_report(struct meshlink_handle *mesh, const char *origin, struct node_t *dest, bool oversize);
void relay_notify_minmtu_change(struct meshlink_handle *mesh, struct node_t *dest);
void relay_touch_traffic(struct meshlink_handle *mesh, const char *origin, const char *destination);

bool relay_handle_req_relay_mtu(struct meshlink_handle *mesh, struct connection_t *c, const char *request, struct node_t *from);

#endif
