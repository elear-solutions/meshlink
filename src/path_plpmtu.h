#ifndef MESHLINK_PATH_PLPMTU_H
#define MESHLINK_PATH_PLPMTU_H

/*
    path_plpmtu.h -- per-path packetization-layer MTU
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "packmsg.h"
#include "sockaddr.h"

#define PATH_PLPMTU_BASE               1211
#define PATH_PLPMTU_MAX_PROBES            3
#define PATH_PLPMTU_PROBE_TIMEOUT_MS   1000
#define PATH_PLPMTU_STEP_GAP_MS         200
#define PATH_PLPMTU_LIVENESS_GUARD_MS   250
#define PATH_PLPMTU_RAISE_SEC           600
#define PATH_PLPMTU_RAISE_MAX_SEC     86400
#define PATH_PLPMTU_TRUST_SEC           600
#define PATH_PLPMTU_CACHE_MAX_AGE_SEC 86400
#define PATH_MTU_CACHE_ENTRIES            4
#define PATH_MTU_CACHE_HOSTILE         0x01
/* Intervals written by the sender-owned keepalive algorithm (17.7). */
enum { PATH_MTU_CACHE_KEEPALIVE_V2 = 0x02 };
#define PATH_PLPMTU_HOSTILE_WINDOW_MS  2000
#define PATH_PLPMTU_BH_WINDOW_SEC        30
#define PATH_PLPMTU_BH_EVIDENCE           2
#define PATH_PLPMTU_RAISE_BACKOFF_CAP    16
#define PATH_PLPMTU_FNV_OFFSET    2166136261u
#define PATH_PLPMTU_FNV_PRIME       16777619u
#define PATH_PLPMTU_STEP_1259          1259
#define PATH_PLPMTU_STEP_1339          1339
#define PATH_PLPMTU_STEP_1379          1379
#define PATH_PLPMTU_STEP_1399          1399
#define PATH_PLPMTU_STEP_1419          1419
#define PATH_PLPMTU_STEP_1431          1431

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

/* Separate health sends from the last admitted size probe in either timer order. */
bool path_plpmtu_probe_recent(const struct meshlink_handle *mesh, const struct node_t *n);

void path_plpmtu_verify_relay_due(struct meshlink_handle *mesh, struct node_t *n);

void path_plpmtu_tick(struct meshlink_handle *mesh, struct node_t *n);

uint32_t path_local_network_fp(const struct meshlink_handle *mesh);

void path_mtu_cache_pack(const struct node_t *n, packmsg_output_t *out);
void path_mtu_cache_unpack(struct node_t *n, packmsg_input_t *in);
/* Rewrite the current IP's cache entry after a keepalive-interval change. */
void path_plpmtu_remember_keepalive(struct meshlink_handle *mesh, struct node_t *n);

bool path_plpmtu_cover_unit(struct meshlink_handle *mesh);

#endif
