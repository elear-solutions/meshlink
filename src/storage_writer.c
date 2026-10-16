/*
    storage_writer.c -- bounded process-wide storage writer
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

/* Bounded asynchronous persistence shared by all Meshlink handles. */

#include "system.h"
#include "storage_writer.h"

#include <pthread.h>

typedef struct storage_writer_job {
	struct storage_writer_job *next;
	storage_writer_completion_t completion;
	void *payload;
	void *key;
	size_t keylen;
} storage_writer_job_t;

typedef struct storage_writer_gate {
	struct storage_writer_gate *next;
	const char *path;
} storage_writer_gate_t;

struct storage_writer_owner {
	struct storage_writer_owner *next;
	storage_writer_notify_t notify;
	void *notify_context;
	storage_writer_backend_t backend;
	void *backend_context;
	storage_writer_job_t *queued;
	storage_writer_job_t *queued_tail;
	storage_writer_job_t *completed;
	storage_writer_job_t *completed_tail;
	storage_writer_gate_t *gates;
	storage_writer_stats_t stats;
	unsigned notifying;
	bool closing;
};

static struct {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t thread;
	storage_writer_owner_t *owners;
	storage_writer_owner_t *cursor;
	storage_writer_owner_t *running_owner;
	storage_writer_job_t *running;
	storage_writer_stats_t stats;
	uint64_t sequence;
	bool started;
	bool stopping;
} writer = {
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
};

static void lock_writer(void) {
	if(pthread_mutex_lock(&writer.mutex)) {
		abort();
	}
}

static void unlock_writer(void) {
	if(pthread_mutex_unlock(&writer.mutex)) {
		abort();
	}
}

static void wait_writer(void) {
	if(pthread_cond_wait(&writer.cond, &writer.mutex)) {
		abort();
	}
}

static void wake_writer(void) {
	pthread_cond_broadcast(&writer.cond);
}

static bool path_matches(const char *selection, const char *path) {
	return !selection || !strcmp(selection, path);
}

static void job_free(storage_writer_job_t *job) {
	if(job->key) {
		/* Do not leave a copied encryption key in freed heap memory. */
		volatile unsigned char *key = job->key;

		for(size_t i = 0; i < job->keylen; ++i) {
			key[i] = 0;
		}
	}

	free((char *)job->completion.path);
	free(job->payload);
	free(job->key);
	free(job);
}

static storage_writer_job_t *job_new(const char *path, const void *data, size_t len, const void *key, size_t keylen, uint64_t generation) {
	storage_writer_job_t *job = calloc(1, sizeof(*job));

	if(!job) {
		return NULL;
	}

	job->completion.path = strdup(path);
	job->payload = malloc(len ? len : 1);
	job->key = keylen ? malloc(keylen) : NULL;
	job->keylen = keylen;

	if(!job->completion.path || !job->payload || (keylen && !job->key)) {
		job_free(job);
		return NULL;
	}

	if(len) {
		memcpy(job->payload, data, len);
	}

	if(keylen) {
		memcpy(job->key, key, keylen);
	}

	job->completion.data = job->payload;
	job->completion.len = len;
	job->completion.generation = generation;
	return job;
}

static void account_add(storage_writer_owner_t *owner, storage_writer_job_t *job) {
	storage_writer_stats_t *stats[] = {&writer.stats, &owner->stats};

	for(size_t i = 0; i < 2; ++i) {
		stats[i]->jobs++;
		stats[i]->bytes += job->completion.len;

		if(stats[i]->jobs > stats[i]->peak_jobs) {
			stats[i]->peak_jobs = stats[i]->jobs;
		}

		if(stats[i]->bytes > stats[i]->peak_bytes) {
			stats[i]->peak_bytes = stats[i]->bytes;
		}
	}
}

static void account_remove(storage_writer_owner_t *owner, storage_writer_job_t *job) {
	writer.stats.jobs--;
	writer.stats.bytes -= job->completion.len;
	owner->stats.jobs--;
	owner->stats.bytes -= job->completion.len;
}

static bool gated(storage_writer_owner_t *owner, const char *path) {
	for(storage_writer_gate_t *gate = owner->gates; gate; gate = gate->next) {
		if(path_matches(gate->path, path)) {
			return true;
		}
	}

	return false;
}

static void cancel_queued(storage_writer_owner_t *owner, const char *path) {
	storage_writer_job_t **link = &owner->queued;
	storage_writer_job_t *previous = NULL;

	while(*link) {
		storage_writer_job_t *job = *link;

		if(!path_matches(path, job->completion.path)) {
			previous = job;
			link = &job->next;
			continue;
		}

		*link = job->next;

		if(owner->queued_tail == job) {
			owner->queued_tail = previous;
		}

		account_remove(owner, job);
		job_free(job);
	}
}

static bool has_queued(storage_writer_owner_t *owner, const char *path) {
	for(storage_writer_job_t *job = owner->queued; job; job = job->next) {
		if(path_matches(path, job->completion.path)) {
			return true;
		}
	}

	return false;
}

static bool has_running(storage_writer_owner_t *owner, const char *path) {
	return writer.running_owner == owner && path_matches(path, writer.running->completion.path);
}

static void gate_add(storage_writer_owner_t *owner, storage_writer_gate_t *gate) {
	gate->next = owner->gates;
	owner->gates = gate;
}

static void gate_remove(storage_writer_owner_t *owner, storage_writer_gate_t *gate) {
	storage_writer_gate_t **link = &owner->gates;

	while(*link != gate) {
		link = &(*link)->next;
	}

	*link = gate->next;
	wake_writer();
}

/* A selected owner advances the cursor even when other owners have more jobs. */
static storage_writer_job_t *next_job(storage_writer_owner_t **selected) {
	storage_writer_owner_t *first = writer.cursor ? writer.cursor : writer.owners;
	storage_writer_owner_t *owner = first;

	if(!first) {
		return NULL;
	}

	do {
		if(!owner->closing) {
			storage_writer_job_t **link = &owner->queued;
			storage_writer_job_t *previous = NULL;

			while(*link) {
				storage_writer_job_t *job = *link;

				if(!gated(owner, job->completion.path)) {
					*link = job->next;

					if(owner->queued_tail == job) {
						owner->queued_tail = previous;
					}

					job->next = NULL;
					writer.cursor = owner->next ? owner->next : writer.owners;
					*selected = owner;
					return job;
				}

				previous = job;
				link = &job->next;
			}
		}

		owner = owner->next ? owner->next : writer.owners;
	} while(owner != first);

	return NULL;
}

static bool run_backend(storage_writer_owner_t *owner, storage_writer_job_t *job) {
	errno = 0;
	bool success = owner->backend(job->completion.path, job->payload, job->completion.len, job->key, job->keylen, owner->backend_context);
	job->completion.success = success;
	job->completion.error = success ? 0 : (errno ? errno : EIO);
	return success;
}

static void *writer_main(void *unused) {
	(void)unused;
	lock_writer();

	while(!writer.stopping) {
		storage_writer_owner_t *owner;
		storage_writer_job_t *job = next_job(&owner);

		if(!job) {
			wait_writer();
			continue;
		}

		writer.running = job;
		writer.running_owner = owner;
		unlock_writer();
		bool success = run_backend(owner, job);
		lock_writer();
		writer.running = NULL;
		writer.running_owner = NULL;

		if(owner->completed_tail) {
			owner->completed_tail->next = job;
		} else {
			owner->completed = job;
		}

		owner->completed_tail = job;

		if(success) {
			writer.stats.committed++;
			owner->stats.committed++;
		} else {
			writer.stats.failed++;
			owner->stats.failed++;
		}

		if(owner->notify && !owner->closing) {
			owner->notifying++;
			unlock_writer();
			owner->notify(owner->notify_context);
			lock_writer();
			owner->notifying--;
		}

		wake_writer();
	}

	unlock_writer();
	return NULL;
}

storage_writer_owner_t *storage_writer_owner_open(storage_writer_notify_t notify, void *notify_context, storage_writer_backend_t backend, void *backend_context) {
	if(!backend) {
		errno = EINVAL;
		return NULL;
	}

	storage_writer_owner_t *owner = calloc(1, sizeof(*owner));

	if(!owner) {
		return NULL;
	}

	owner->notify = notify;
	owner->notify_context = notify_context;
	owner->backend = backend;
	owner->backend_context = backend_context;
	lock_writer();

	while(writer.stopping) {
		wait_writer();
	}

	owner->next = writer.owners;
	writer.owners = owner;
	unlock_writer();
	return owner;
}

bool storage_writer_submit(storage_writer_owner_t *owner, const char *path, const void *data, size_t len, const void *key, size_t keylen, uint64_t generation) {
	if(!owner || !path || (!data && len) || (!key && keylen)) {
		errno = EINVAL;
		return false;
	}

	lock_writer();
	storage_writer_job_t **replacement = &owner->queued;

	while(*replacement && strcmp((*replacement)->completion.path, path)) {
		replacement = &(*replacement)->next;
	}

	storage_writer_job_t *old = *replacement;
	size_t old_bytes = old ? old->completion.len : 0;

	if(owner->closing || (!old && (writer.stats.jobs >= STORAGE_WRITER_MAX_JOBS || owner->stats.jobs >= STORAGE_WRITER_MAX_OWNER_JOBS)) || len > STORAGE_WRITER_MAX_BYTES - (writer.stats.bytes - old_bytes)) {
		writer.stats.rejected++;
		owner->stats.rejected++;
		unlock_writer();
		errno = EAGAIN;
		return false;
	}

	/* Admission precedes allocation: concurrent callers cannot transiently
	 * allocate an unbounded number of snapshots outside the queue limits. */
	storage_writer_job_t *job = job_new(path, data, len, key, keylen, generation);

	if(!job) {
		unlock_writer();
		return false;
	}

	if(!writer.started) {
		int error = pthread_create(&writer.thread, NULL, writer_main, NULL);

		if(error) {
			unlock_writer();
			job_free(job);
			errno = error;
			return false;
		}

		writer.started = true;
	}

	job->completion.sequence = ++writer.sequence;

	if(old) {
		job->next = old->next;
		*replacement = job;

		if(owner->queued_tail == old) {
			owner->queued_tail = job;
		}

		account_remove(owner, old);
		job_free(old);
		writer.stats.coalesced++;
		owner->stats.coalesced++;
	} else if(owner->queued_tail) {
		owner->queued_tail->next = job;
		owner->queued_tail = job;
	} else {
		owner->queued = owner->queued_tail = job;
	}

	account_add(owner, job);
	writer.stats.submitted++;
	owner->stats.submitted++;
	wake_writer();
	unlock_writer();
	return true;
}

void storage_writer_collect(storage_writer_owner_t *owner, storage_writer_completion_cb_t callback, void *context) {
	if(!owner) {
		return;
	}

	lock_writer();
	storage_writer_job_t *jobs = owner->completed;
	owner->completed = owner->completed_tail = NULL;
	unlock_writer();

	while(jobs) {
		storage_writer_job_t *job = jobs;
		jobs = job->next;

		if(callback) {
			callback(&job->completion, context);
		}

		lock_writer();
		account_remove(owner, job);
		unlock_writer();
		job_free(job);
	}
}

bool storage_writer_commit(storage_writer_owner_t *owner, const char *path, const void *data, size_t len, const void *key, size_t keylen, uint64_t generation) {
	if(!owner || !path || (!data && len) || (!key && keylen)) {
		errno = EINVAL;
		return false;
	}

	storage_writer_job_t *job = job_new(path, data, len, key, keylen, generation);

	if(!job) {
		return false;
	}

	storage_writer_gate_t gate = {.path = path};
	lock_writer();

	/* Other synchronous commits for the same file also obey this gate. */
	while(gated(owner, path)) {
		wait_writer();
	}

	gate_add(owner, &gate);
	cancel_queued(owner, path);

	while(has_running(owner, path)) {
		wait_writer();
	}

	job->completion.sequence = ++writer.sequence;
	unlock_writer();
	bool success = run_backend(owner, job);
	int error = job->completion.error;
	lock_writer();

	if(success) {
		writer.stats.committed++;
		owner->stats.committed++;
	} else {
		writer.stats.failed++;
		owner->stats.failed++;
	}

	gate_remove(owner, &gate);
	unlock_writer();
	job_free(job);

	if(!success) {
		errno = error;
	}

	return success;
}

void storage_writer_barrier(storage_writer_owner_t *owner, const char *path, bool cancel) {
	if(!owner) {
		return;
	}

	lock_writer();

	if(cancel) {
		cancel_queued(owner, path);
	}

	while(has_running(owner, path) || (!cancel && has_queued(owner, path))) {
		wait_writer();
	}

	unlock_writer();
}

void storage_writer_owner_close(storage_writer_owner_t *owner) {
	if(!owner) {
		return;
	}

	lock_writer();
	owner->closing = true;
	cancel_queued(owner, NULL);

	while(has_running(owner, NULL) || owner->notifying) {
		wait_writer();
	}

	for(storage_writer_job_t *job = owner->completed; job;) {
		storage_writer_job_t *next = job->next;
		account_remove(owner, job);
		job_free(job);
		job = next;
	}

	storage_writer_owner_t **link = &writer.owners;

	while(*link != owner) {
		link = &(*link)->next;
	}

	*link = owner->next;

	if(writer.cursor == owner) {
		writer.cursor = owner->next ? owner->next : writer.owners;
	}

	bool join = !writer.owners && writer.started;

	if(join) {
		writer.stopping = true;
		wake_writer();
	}

	unlock_writer();
	free(owner);

	if(join) {
		if(pthread_join(writer.thread, NULL)) {
			abort();
		}

		lock_writer();
		writer.started = false;
		writer.stopping = false;
		wake_writer();
		unlock_writer();
	}
}

void storage_writer_get_stats(storage_writer_owner_t *owner, storage_writer_stats_t *stats) {
	lock_writer();
	*stats = owner ? owner->stats : writer.stats;
	unlock_writer();
}
