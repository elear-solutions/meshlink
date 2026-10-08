#ifndef MESHLINK_PATH_LIVENESS_H
#define MESHLINK_PATH_LIVENESS_H

/*
    path_liveness.h -- path liveness, idle keepalive, local discovery
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "event.h"
#include "sockaddr.h"

struct meshlink_handle;
struct node_t;

#define PATH_LIVENESS_TRIES               3
#define PATH_LIVENESS_FALLBACK_PING_TIMEOUT_SEC 5
#define PATH_LIVENESS_TRY_GAP_FLOOR_MS  500
#define PATH_KEEPALIVE_INITIAL_MS     15000
#define PATH_BACKBONE_UDP_KEEPALIVE_SEC  25
#define PATH_KEEPALIVE_BACKBONE_INITIAL_MS (PATH_BACKBONE_UDP_KEEPALIVE_SEC * 1000)
#define PATH_KEEPALIVE_FLOOR_MS        5000
#define PATH_KEEPALIVE_SHRINK_PCT        60
#define PATH_KEEPALIVE_GROW_PCT         120
#define PATH_KEEPALIVE_GROW_SEC        3600
#define PATH_KEEPALIVE_PEER_DEMAND_SEC   60
#define PATH_KEEPALIVE_EXPIRY_CONFIRM_SEC 30
#define PATH_KEEPALIVE_JITTER_PCT        10
#define PATH_LOCAL_DISCOVERY_TRIES       10
#define PATH_LOCAL_DISCOVERY_BROADCAST_TRIES 3
#define PATH_LOCAL_DISCOVERY_REARM_MS  1000

/* Shared by path_liveness.c and path_plpmtu.c. Caller holds mesh->mutex.
   path_timer_arm_ms wakes the mesh loop when the caller is not the mesh thread. */
uint64_t path_probe_fresh_nonce(void);
int64_t path_ms_between(const struct timespec *from, const struct timespec *to);
void path_timer_arm_ms(struct meshlink_handle *mesh, timeout_t *t, timeout_cb_t cb, void *data, int ms);
void path_timer_disarm(struct meshlink_handle *mesh, timeout_t *t);

/* Caller holds mesh->mutex. Ordinary demanded peers only; the backbone node is stopped. */
void path_liveness_on_confirmed(struct meshlink_handle *mesh, struct node_t *n);
/* Caller holds mesh->mutex. Disarms the liveness timer and cancels scheduler work. */
void path_liveness_stop(struct meshlink_handle *mesh, struct node_t *n);
bool path_liveness_outstanding(const struct node_t *n);
/* Any authenticated reply from the confirmed endpoint parks the window. */
void path_liveness_observe_reply(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from, uint64_t nonce, uint8_t purpose);
/* Greater name parks when it sees the peer's liveness request. */
void path_liveness_observe_peer_request(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from);
void path_liveness_tick(struct meshlink_handle *mesh, struct node_t *n);

/* Select the role default on confirmation. A restored interval_ms takes precedence. */
void path_keepalive_on_confirmed(struct meshlink_handle *mesh, struct node_t *n);
void path_keepalive_stop(struct meshlink_handle *mesh, struct node_t *n);
/* Refresh this sender's activity only for a send to the confirmed endpoint. */
void path_keepalive_note_tx(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *to);
void path_keepalive_note_rx(struct meshlink_handle *mesh, struct node_t *n);
/* Same-IP port change within 30s of an idle gap confirms expiry, unless a recent oversize explains it. */
void path_keepalive_observe_local_endpoint(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from, const sockaddr_t *endpoint);
void path_keepalive_tick(struct meshlink_handle *mesh, struct node_t *n);
uint32_t path_keepalive_backbone_interval_ms(struct meshlink_handle *mesh, struct node_t *n);

void path_local_discovery_start(struct meshlink_handle *mesh, struct node_t *n);
void path_local_discovery_stop(struct meshlink_handle *mesh, struct node_t *n);
bool path_local_discovery_accept(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from, uint64_t nonce, uint8_t purpose);
void path_local_discovery_tick(struct meshlink_handle *mesh, struct node_t *n);
/* Last discovery tick on this mesh. Cover witness, not a route decision. */
bool path_local_discovery_did_broadcast(const struct meshlink_handle *mesh);

#endif
