#ifndef MESHLINK_PATH_LIVENESS_H
#define MESHLINK_PATH_LIVENESS_H

/*
    path_liveness.h -- path liveness, idle keepalive, local discovery
    Copyright (C) 2026 Elear Solutions
*/

#include <stdbool.h>
#include <stdint.h>

#include "sockaddr.h"

struct meshlink_handle;
struct node_t;

void path_liveness_on_confirmed(struct meshlink_handle *mesh, struct node_t *n);
void path_liveness_stop(struct meshlink_handle *mesh, struct node_t *n);
bool path_liveness_outstanding(const struct node_t *n);
void path_liveness_observe_reply(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from, uint64_t nonce, uint8_t purpose);
void path_liveness_observe_peer_request(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from);
void path_liveness_tick(struct meshlink_handle *mesh, struct node_t *n);

void path_keepalive_on_confirmed(struct meshlink_handle *mesh, struct node_t *n);
void path_keepalive_stop(struct meshlink_handle *mesh, struct node_t *n);
void path_keepalive_note_tx(struct meshlink_handle *mesh, struct node_t *n);
void path_keepalive_note_rx(struct meshlink_handle *mesh, struct node_t *n);
void path_keepalive_note_giveup(struct meshlink_handle *mesh, struct node_t *n, uint32_t idle_gap_ms);
void path_keepalive_tick(struct meshlink_handle *mesh, struct node_t *n);
uint32_t path_keepalive_backbone_interval_ms(const struct meshlink_handle *mesh, const struct node_t *n);

void path_local_discovery_start(struct meshlink_handle *mesh, struct node_t *n);
void path_local_discovery_stop(struct meshlink_handle *mesh, struct node_t *n);
bool path_local_discovery_accept(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from, uint64_t nonce, uint8_t purpose);
void path_local_discovery_tick(struct meshlink_handle *mesh, struct node_t *n);
bool path_local_discovery_did_broadcast(void);

#endif
