#ifndef MESHLINK_NODE_STORAGE_H
#define MESHLINK_NODE_STORAGE_H

/*
    node_storage.h -- role-aware local node persistence
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "conf.h"
#include "storage_writer.h"

struct meshlink_handle;
struct node_t;

/* Mesh mutex or exclusive stopped-handle ownership is required throughout.
 * This module owns node disk state; jobs own copies and never reference nodes.
 * Close storage before destroying nodes, loop signals, or the handle. */

/* Reasons describe persisted projections, never runtime reachability or proof. */
typedef enum node_storage_reason_t {
	NODE_STORAGE_KEY_POLICY = 1,
	NODE_STORAGE_CONFIG = 2,
	NODE_STORAGE_EDGE = 4,
	NODE_STORAGE_OBSERVATION = 8,
	NODE_STORAGE_ENDPOINTS = 16,
	NODE_STORAGE_PATH_HISTORY = 32,
	NODE_STORAGE_PROFILE = 64,
} node_storage_reason_t;

void node_storage_init(struct node_t *n);
void node_storage_free(struct node_t *n);
void node_storage_mark(struct node_t *n, node_storage_reason_t reason);
bool node_storage_read(struct meshlink_handle *mesh, struct node_t *n);
bool node_storage_read_trust(struct meshlink_handle *mesh, struct node_t *n);
uint64_t node_storage_generation(const struct node_t *n, bool cache);
/* Native durable core commit, subject to the handle's storage policy. */
bool node_storage_write(struct meshlink_handle *mesh, struct node_t *n, bool new_key);
/* Retry explicit configuration without checkpointing observation-only changes. */
bool node_storage_retry_config(struct meshlink_handle *mesh, struct node_t *n, bool new_key);
/* Allocates config->buf on success; the caller releases it with config_free. */
bool node_storage_wire_encode(struct meshlink_handle *mesh, const struct node_t *n, config_t *config);
void node_storage_tick(struct meshlink_handle *mesh, time_t wall_now);
void node_storage_note_seen(struct meshlink_handle *mesh, struct node_t *n, time_t wall_now);
/* Valid down edges retain their sampled time; observations never move back.
 * First positive history is committed natively, subject to storage policy. */
bool node_storage_note_edge(struct meshlink_handle *mesh, struct node_t *n, bool reachable, time_t wall_now);
/* Flush cancels obsolete queued work and commits current full-storage state.
 * Barrier cancels queued work and collects running results without new writes. */
bool node_storage_flush(struct meshlink_handle *mesh);
void node_storage_barrier(struct meshlink_handle *mesh);
void node_storage_close(struct meshlink_handle *mesh);
bool node_storage_forget(struct meshlink_handle *mesh, struct node_t *n);
void node_storage_policy_changed(struct meshlink_handle *mesh);
void node_storage_profile_changed(struct meshlink_handle *mesh);
struct node_storage_state *node_storage_begin_join(struct node_t *n);
void node_storage_end_join(struct node_t *n, struct node_storage_state *previous, bool committed);

/* Internal deterministic inspection seam, used by existing test binaries. */
typedef struct node_storage_stats_t {
	uint64_t core_writes, cache_writes, cache_hits, cache_misses;
	uint64_t errors, admission_failures, noops;
} node_storage_stats_t;
void node_storage_get_stats(struct meshlink_handle *mesh, node_storage_stats_t *stats);
time_t node_storage_checkpoint_interval(const struct node_t *n);
time_t node_storage_checkpoint_deadline(const struct node_t *n);
void node_storage_wait(struct meshlink_handle *mesh);
/* Borrowed backend/clock contexts live until replacement or storage close.
 * Backend replacement drains old work before returning; clock runs on owner. */
void node_storage_set_backend(struct meshlink_handle *mesh, storage_writer_backend_t backend, void *context);
void node_storage_set_clock(struct meshlink_handle *mesh, time_t (*clock)(void *), void *context);

#endif
