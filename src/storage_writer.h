#ifndef MESHLINK_STORAGE_WRITER_H
#define MESHLINK_STORAGE_WRITER_H

/*
    storage_writer.h -- bounded process-wide storage writer
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

/* A process-wide bounded writer. No worker callback may enter Meshlink or take
 * its mutex; notify is exclusively a thread-safe event-loop wakeup. Owners must
 * serialize close against their other API calls. Native commits and owner-wide
 * barrier/collect sequences also require caller serialization for that owner.
 * Notify/backend contexts remain borrowed until owner_close returns. Backends
 * own durability; API success reflects the backend's durable-success contract. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STORAGE_WRITER_MAX_JOBS 256U
#define STORAGE_WRITER_MAX_BYTES (2U * 1024U * 1024U)
#define STORAGE_WRITER_MAX_OWNER_JOBS 32U

typedef struct storage_writer_owner storage_writer_owner_t;

typedef bool (*storage_writer_backend_t)(const char *path, const void *data, size_t len, const void *key, size_t keylen, void *context);
typedef void (*storage_writer_notify_t)(void *context);

typedef struct storage_writer_completion {
	const char *path;
	const void *data;
	size_t len;
	uint64_t generation;
	uint64_t sequence;
	bool success;
	int error;
} storage_writer_completion_t;

typedef void (*storage_writer_completion_cb_t)(const storage_writer_completion_t *completion, void *context);

typedef struct storage_writer_stats {
	size_t jobs;
	size_t bytes;
	size_t peak_jobs;
	size_t peak_bytes;
	uint64_t submitted;
	uint64_t coalesced;
	uint64_t rejected;
	uint64_t committed;
	uint64_t failed;
} storage_writer_stats_t;

storage_writer_owner_t *storage_writer_owner_open(storage_writer_notify_t notify, void *notify_context, storage_writer_backend_t backend, void *backend_context);

/* Copies the complete snapshot before returning. A queued snapshot for this
 * owner's path is replaced in place. Running and uncollected jobs still count
 * toward all limits. Failure never falls back to synchronous I/O. */
bool storage_writer_submit(storage_writer_owner_t *owner, const char *path, const void *data, size_t len, const void *key, size_t keylen, uint64_t generation);

/* Invokes callbacks only on the calling thread, with borrowed completion data.
 * Callers must ignore generations already superseded by a synchronous commit. */
void storage_writer_collect(storage_writer_owner_t *owner, storage_writer_completion_cb_t callback, void *context);

/* Supersedes queued snapshots for this path, waits for any running write, then
 * commits on this thread. New background work for this path cannot pass it.
 * The caller acknowledges generation directly; no completion is generated. */
bool storage_writer_commit(storage_writer_owner_t *owner, const char *path, const void *data, size_t len, const void *key, size_t keylen, uint64_t generation);

/* NULL path selects every record. With cancel=false, drains queued and running
 * work without waiting for collection. With cancel=true, discards queued work
 * and waits for running work. Completions remain available to collect. Callers
 * must freeze new submissions for the selected records across the barrier. */
void storage_writer_barrier(storage_writer_owner_t *owner, const char *path, bool cancel);

/* Cancels queued work, waits for running writes and notifications, and discards
 * completions. The final owner joins the worker; a later owner can restart it. */
void storage_writer_owner_close(storage_writer_owner_t *owner);
void storage_writer_get_stats(storage_writer_owner_t *owner, storage_writer_stats_t *stats);

#endif
