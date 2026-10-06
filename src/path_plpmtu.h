#ifndef MESHLINK_PATH_PLPMTU_H
#define MESHLINK_PATH_PLPMTU_H

/*
    path_plpmtu.h -- per-path packetization-layer MTU
    Copyright (C) 2026 Elear Solutions
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "packmsg.h"
#include "sockaddr.h"

struct meshlink_handle;
struct node_t;

/* Usable payload, or 0 when UDP is not confirmed or PLPMTU is disabled. */
uint16_t path_plpmtu_size(const struct node_t *n);

void path_plpmtu_on_confirmed(struct meshlink_handle *mesh, struct node_t *n);
/* Save into the per-IP cache and disable. Session change and blacklist. */
void path_plpmtu_stop(struct meshlink_handle *mesh, struct node_t *n);
/* Disarm timers but keep the learned size. Liveness give-up and demand idle. */
void path_plpmtu_pause(struct meshlink_handle *mesh, struct node_t *n);
void path_plpmtu_forget(struct meshlink_handle *mesh, struct node_t *n);

void path_plpmtu_observe_ack(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *from, uint64_t nonce, uint16_t len);
void path_plpmtu_note_emsgsize(struct meshlink_handle *mesh, struct node_t *n, uint16_t payload);
void path_plpmtu_note_local_remap(struct meshlink_handle *mesh, struct node_t *n);
void path_plpmtu_note_large_suspect_send(struct meshlink_handle *mesh, struct node_t *n, uint16_t payload);
void path_plpmtu_note_suspect_cleared(struct meshlink_handle *mesh, struct node_t *n);

void path_plpmtu_tick(struct meshlink_handle *mesh, struct node_t *n);

uint32_t path_local_network_fp(const struct meshlink_handle *mesh);

void path_mtu_cache_pack(const struct node_t *n, packmsg_output_t *out);
void path_mtu_cache_unpack(struct node_t *n, packmsg_input_t *in);
/* Rewrite the current IP's cache entry after a keepalive-interval change. */
void path_plpmtu_remember_keepalive(struct meshlink_handle *mesh, struct node_t *n);

bool path_ws1_cover_unit(struct meshlink_handle *mesh);

#endif
