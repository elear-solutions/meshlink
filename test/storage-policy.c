#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "meshlink.h"
#include "utils.h"
#include "node-storage-tests.h"
#include "storage_writer.h"
#include "chacha-poly1305/chacha-poly1305.h"

typedef struct writer_fixture {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t collector;
	bool blocked;
	bool entered;
	bool notify_blocked;
	bool notify_entered;
	bool notify_exited;
	bool commit_started;
	bool close_started;
	bool closed;
	unsigned calls;
	unsigned completions;
	unsigned durable_value;
	char paths[512][32];
	unsigned values[512];
} writer_fixture_t;

static bool writer_backend(const char *path, const void *data, size_t len, const void *key, size_t keylen, void *context) {
	writer_fixture_t *fixture = context;
	assert(len >= sizeof(unsigned));

	if(keylen) {
		if(keylen == 4) {
			assert(!memcmp(key, "KEY!", 4));
		} else {
			assert(keylen == CHACHA_POLY1305_KEYLEN);
			for(size_t i = 0; i < keylen; i++) {
				assert(((const uint8_t *)key)[i] == i + 1);
			}
		}
	}

	assert(!pthread_mutex_lock(&fixture->mutex));
	unsigned index = fixture->calls++;
	assert(index < sizeof(fixture->paths) / sizeof(*fixture->paths));
	assert(snprintf(fixture->paths[index], sizeof(fixture->paths[index]), "%s", path) > 0);
	memcpy(&fixture->values[index], data, sizeof(unsigned));

	if(!strcmp(path, "blocked")) {
		fixture->entered = true;
		assert(!pthread_cond_broadcast(&fixture->cond));

		while(fixture->blocked) {
			assert(!pthread_cond_wait(&fixture->cond, &fixture->mutex));
		}
	}

	if(strcmp(path, "failure")) {
		memcpy(&fixture->durable_value, data, sizeof(unsigned));
	}

	assert(!pthread_mutex_unlock(&fixture->mutex));

	if(!strcmp(path, "failure")) {
		errno = ENOSPC;
		return false;
	}

	return true;
}

static void writer_completion(const storage_writer_completion_t *completion, void *context) {
	writer_fixture_t *fixture = context;
	assert(pthread_equal(pthread_self(), fixture->collector));
	assert(completion->sequence);
	fixture->completions++;

	if(!strcmp(completion->path, "failure")) {
		assert(!completion->success && completion->error == ENOSPC);
	} else {
		assert(completion->success && !completion->error);
	}
}

static storage_writer_owner_t *writer_owner(writer_fixture_t *fixture) {
	storage_writer_owner_t *owner = storage_writer_owner_open(NULL, NULL, writer_backend, fixture);
	assert(owner);
	return owner;
}

static void writer_block(writer_fixture_t *fixture, storage_writer_owner_t *owner) {
	assert(!pthread_mutex_lock(&fixture->mutex));
	fixture->blocked = true;
	fixture->entered = false;
	assert(!pthread_mutex_unlock(&fixture->mutex));
	unsigned value = 11;
	assert(storage_writer_submit(owner, "blocked", &value, sizeof(value), "KEY!", 4, 1));
	assert(!pthread_mutex_lock(&fixture->mutex));

	while(!fixture->entered) {
		assert(!pthread_cond_wait(&fixture->cond, &fixture->mutex));
	}

	assert(!pthread_mutex_unlock(&fixture->mutex));
}

static void writer_release(writer_fixture_t *fixture) {
	assert(!pthread_mutex_lock(&fixture->mutex));
	fixture->blocked = false;
	assert(!pthread_cond_broadcast(&fixture->cond));
	assert(!pthread_mutex_unlock(&fixture->mutex));
}

static void writer_collect(writer_fixture_t *fixture, storage_writer_owner_t *owner) {
	storage_writer_barrier(owner, NULL, false);
	storage_writer_collect(owner, writer_completion, fixture);
}

static void writer_notify(void *context) {
	writer_fixture_t *fixture = context;
	assert(!pthread_mutex_lock(&fixture->mutex));
	fixture->notify_entered = true;
	assert(!pthread_cond_broadcast(&fixture->cond));

	while(fixture->notify_blocked) {
		assert(!pthread_cond_wait(&fixture->cond, &fixture->mutex));
	}

	fixture->notify_exited = true;
	assert(!pthread_mutex_unlock(&fixture->mutex));
}

typedef struct writer_thread_args {
	storage_writer_owner_t *owner;
	writer_fixture_t *fixture;
} writer_thread_args_t;

static void *writer_commit_thread(void *context) {
	writer_thread_args_t *args = context;
	writer_fixture_t *fixture = args->fixture;
	assert(!pthread_mutex_lock(&fixture->mutex));
	fixture->commit_started = true;
	assert(!pthread_cond_broadcast(&fixture->cond));
	assert(!pthread_mutex_unlock(&fixture->mutex));
	unsigned latest = 789;
	assert(storage_writer_commit(args->owner, "blocked", &latest, sizeof(latest), NULL, 0, 200));
	return NULL;
}

static void *writer_close_thread(void *context) {
	writer_thread_args_t *args = context;
	writer_fixture_t *fixture = args->fixture;
	assert(!pthread_mutex_lock(&fixture->mutex));
	fixture->close_started = true;
	assert(!pthread_cond_broadcast(&fixture->cond));
	assert(!pthread_mutex_unlock(&fixture->mutex));
	storage_writer_owner_close(args->owner);
	assert(!pthread_mutex_lock(&fixture->mutex));
	assert(fixture->notify_exited);
	fixture->closed = true;
	assert(!pthread_mutex_unlock(&fixture->mutex));
	return NULL;
}

static void test_storage_writer(void) {
	writer_fixture_t fixture = {.collector = pthread_self()};
	assert(!pthread_mutex_init(&fixture.mutex, NULL));
	assert(!pthread_cond_init(&fixture.cond, NULL));
	storage_writer_owner_t *owner = writer_owner(&fixture);
	writer_block(&fixture, owner);

	// Count the in-flight snapshot and permit replacement at the owner limit.
	for(unsigned i = 0; i < STORAGE_WRITER_MAX_OWNER_JOBS - 1; ++i) {
		char path[32];
		assert(snprintf(path, sizeof(path), "file-%u", i) > 0);
		assert(storage_writer_submit(owner, path, &i, sizeof(i), NULL, 0, i + 2));
	}

	unsigned value = 99;
	assert(!storage_writer_submit(owner, "overflow", &value, sizeof(value), NULL, 0, 50));
	assert(errno == EAGAIN);
	char key[] = "KEY!";
	assert(storage_writer_submit(owner, "file-0", &value, sizeof(value), key, 4, 51));
	uint8_t storage_key[CHACHA_POLY1305_KEYLEN];
	for(size_t i = 0; i < sizeof storage_key; i++) {
		storage_key[i] = i + 1;
	}
	assert(storage_writer_submit(owner, "file-1", &value, sizeof(value), storage_key, sizeof storage_key, 51));
	value = 123;
	memset(key, 'x', 4);
	memset(storage_key, 0xee, sizeof storage_key);
	storage_writer_stats_t stats;
	storage_writer_get_stats(owner, &stats);
	assert(stats.jobs == STORAGE_WRITER_MAX_OWNER_JOBS && stats.coalesced == 2 && stats.rejected == 1);
	writer_release(&fixture);
	storage_writer_barrier(owner, NULL, false);

	// Completed snapshots retain their budget until collection. Inputs were copied.
	assert(!storage_writer_submit(owner, "overflow", &value, sizeof(value), NULL, 0, 52));
	assert(errno == EAGAIN);
	storage_writer_collect(owner, writer_completion, &fixture);
	assert(fixture.completions == STORAGE_WRITER_MAX_OWNER_JOBS);
	assert(fixture.calls == STORAGE_WRITER_MAX_OWNER_JOBS && fixture.values[1] == 99);
	storage_writer_get_stats(owner, &stats);
	assert(!stats.jobs && !stats.bytes);
	assert(storage_writer_submit(owner, "failure", &value, sizeof(value), NULL, 0, 53));
	writer_collect(&fixture, owner);
	assert(fixture.completions == STORAGE_WRITER_MAX_OWNER_JOBS + 1);

	// A native commit supersedes a queued version without waiting for other files.
	writer_block(&fixture, owner);
	unsigned first = fixture.calls;
	assert(storage_writer_submit(owner, "sync", &value, sizeof(value), NULL, 0, 54));
	unsigned latest = 456;
	assert(storage_writer_commit(owner, "sync", &latest, sizeof(latest), NULL, 0, 55));
	assert(storage_writer_submit(owner, "canceled", &value, sizeof(value), NULL, 0, 56));
	storage_writer_barrier(owner, "canceled", true);
	writer_release(&fixture);
	writer_collect(&fixture, owner);
	assert(fixture.calls == first + 1);
	assert(!strcmp(fixture.paths[first], "sync") && fixture.values[first] == latest);

	// A running older version must finish before the synchronous version writes.
	writer_block(&fixture, owner);
	assert(storage_writer_submit(owner, "blocked", &value, sizeof(value), NULL, 0, 199));
	writer_thread_args_t args = {.owner = owner, .fixture = &fixture};
	pthread_t thread;
	assert(!pthread_create(&thread, NULL, writer_commit_thread, &args));
	assert(!pthread_mutex_lock(&fixture.mutex));

	while(!fixture.commit_started) {
		assert(!pthread_cond_wait(&fixture.cond, &fixture.mutex));
	}

	assert(!pthread_mutex_unlock(&fixture.mutex));
	writer_release(&fixture);
	assert(!pthread_join(thread, NULL));
	writer_collect(&fixture, owner);
	assert(!strcmp(fixture.paths[fixture.calls - 1], "blocked"));
	assert(fixture.values[fixture.calls - 1] == 789);
	assert(fixture.durable_value == 789);
	storage_writer_owner_close(owner);

	// Fill the global limit, then require one record per owner before a second.
	storage_writer_owner_t *owners[9];

	for(unsigned i = 0; i < 9; ++i) {
		owners[i] = writer_owner(&fixture);
	}

	writer_block(&fixture, owners[0]);
	first = fixture.calls;
	unsigned accepted = 1;

	for(unsigned i = 0; i < 9; ++i) {
		for(unsigned j = 0; j < STORAGE_WRITER_MAX_OWNER_JOBS; ++j) {
			char path[32];
			assert(snprintf(path, sizeof(path), "owner%u-%u", i, j) > 0);

			if(storage_writer_submit(owners[i], path, &value, sizeof(value), NULL, 0, j + 2)) {
				accepted++;
			} else {
				assert(errno == EAGAIN);
			}
		}
	}

	assert(accepted == STORAGE_WRITER_MAX_JOBS);
	storage_writer_get_stats(NULL, &stats);
	assert(stats.jobs == STORAGE_WRITER_MAX_JOBS && stats.peak_jobs == STORAGE_WRITER_MAX_JOBS);
	writer_release(&fixture);

	for(unsigned i = 0; i < 9; ++i) {
		storage_writer_barrier(owners[i], NULL, false);
	}

	unsigned visited = 0;

	for(unsigned i = 0; i < 8; ++i) {
		unsigned owner_index;
		unsigned record_index;
		assert(sscanf(fixture.paths[first + i], "owner%u-%u", &owner_index, &record_index) == 2);
		assert(owner_index < 8 && !record_index);
		assert(!(visited & (1U << owner_index)));
		visited |= 1U << owner_index;
	}

	assert(visited == 255);

	for(unsigned i = 0; i < 9; ++i) {
		storage_writer_owner_close(owners[i]);
	}

	storage_writer_get_stats(NULL, &stats);
	assert(!stats.jobs && !stats.bytes);

	// Payload accounting also includes the in-flight snapshot; close can cancel.
	owner = writer_owner(&fixture);
	writer_block(&fixture, owner);
	void *large = calloc(1, STORAGE_WRITER_MAX_BYTES);
	assert(large);
	assert(!storage_writer_submit(owner, "too-large", large, STORAGE_WRITER_MAX_BYTES, NULL, 0, 99));
	assert(errno == EAGAIN);
	assert(storage_writer_submit(owner, "large", large, STORAGE_WRITER_MAX_BYTES - sizeof(value), NULL, 0, 100));
	assert(!storage_writer_submit(owner, "one-more", &value, sizeof(value), NULL, 0, 101));
	assert(errno == EAGAIN);
	storage_writer_barrier(owner, "large", true);
	free(large);
	writer_release(&fixture);
	storage_writer_owner_close(owner);

	// Closing an owner must wait until its outstanding notifier stops using it.
	fixture.notify_blocked = true;
	owner = storage_writer_owner_open(writer_notify, &fixture, writer_backend, &fixture);
	assert(owner);
	assert(storage_writer_submit(owner, "notify", &value, sizeof(value), NULL, 0, 102));
	assert(!pthread_mutex_lock(&fixture.mutex));

	while(!fixture.notify_entered) {
		assert(!pthread_cond_wait(&fixture.cond, &fixture.mutex));
	}

	assert(!pthread_mutex_unlock(&fixture.mutex));
	args.owner = owner;
	assert(!pthread_create(&thread, NULL, writer_close_thread, &args));
	assert(!pthread_mutex_lock(&fixture.mutex));

	while(!fixture.close_started) {
		assert(!pthread_cond_wait(&fixture.cond, &fixture.mutex));
	}

	fixture.notify_blocked = false;
	assert(!pthread_cond_broadcast(&fixture.cond));
	assert(!pthread_mutex_unlock(&fixture.mutex));
	assert(!pthread_join(thread, NULL));
	assert(fixture.closed);
	storage_writer_get_stats(NULL, &stats);
	assert(!stats.jobs && !stats.bytes);
	assert(!pthread_cond_destroy(&fixture.cond));
	assert(!pthread_mutex_destroy(&fixture.mutex));
}

int main(void) {
	test_node_storage();
	test_node_storage_lifecycle();
	test_node_observation();
	test_storage_writer();

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	meshlink_handle_t *mesh1;
	meshlink_handle_t *mesh2;

	// Open two instances

	assert(meshlink_destroy("storage-policy_conf.1"));
	assert(meshlink_destroy("storage-policy_conf.2"));

	mesh1 = meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_STATIONARY);
	assert(mesh1);
	assert(mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);
	meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_DISABLED);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_DISABLED);

	// KEYS_ONLY intentionally excludes endpoint cache. Bootstrap is explicit
	// canonical configuration, just as it is for a production NLB member.
	assert(meshlink_set_canonical_address(mesh1, meshlink_get_self(mesh1), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh2, meshlink_get_self(mesh2), "localhost", NULL));

	// Exchange data

	char *export1 = meshlink_export(mesh1);
	char *export2 = meshlink_export(mesh2);

	assert(export1);
	assert(export2);

	assert(meshlink_import(mesh1, export2));
	assert(meshlink_import(mesh2, export1));

	// Check that they know each other

	assert(meshlink_get_node(mesh1, "bar"));
	assert(meshlink_get_node(mesh2, "foo"));

	// STORAGE_DISABLED cannot join, so there is no META. Import is in-memory only.

	// Close the instances and reopen them.

	close_meshlink_pair(mesh1, mesh2);

	mesh1 = meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_STATIONARY);
	assert(mesh1);
	assert(mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);
	meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_KEYS_ONLY);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_KEYS_ONLY);

	// Check that the nodes no longer know each other

	assert(!meshlink_get_node(mesh1, "bar"));
	assert(!meshlink_get_node(mesh2, "foo"));

	// Exchange data again

	assert(meshlink_import(mesh1, export2));
	assert(meshlink_import(mesh2, export1));

	free(export1);
	free(export2);

	// Close the instances and reopen them.

	close_meshlink_pair(mesh1, mesh2);

	mesh1 = meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_STATIONARY);
	assert(mesh1);
	assert(mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);
	meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_KEYS_ONLY);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_KEYS_ONLY);

	// Check that the nodes know each other

	assert(meshlink_get_node(mesh1, "bar"));
	assert(meshlink_get_node(mesh2, "foo"));

	// Check that we update reachability

	time_t last_reachable;
	time_t last_unreachable;
	assert(!meshlink_get_node_reachability(mesh1, meshlink_get_node(mesh1, "bar"), &last_reachable, &last_unreachable));
	assert(!last_reachable);
	assert(!last_unreachable);

	start_meshlink_pair(mesh1, mesh2);
	stop_meshlink_pair(mesh1, mesh2);

	assert(!meshlink_get_node_reachability(mesh1, meshlink_get_node(mesh1, "bar"), &last_reachable, &last_unreachable));
	assert(last_reachable);
	assert(last_unreachable);

	// But have not stored it

	close_meshlink_pair(mesh1, mesh2);

	mesh1 = meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_STATIONARY);
	assert(mesh1);
	assert(mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);
	meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_KEYS_ONLY);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_KEYS_ONLY);

	assert(meshlink_get_node(mesh1, "bar"));
	assert(meshlink_get_node(mesh2, "foo"));

	assert(!meshlink_get_node_reachability(mesh1, meshlink_get_node(mesh1, "bar"), &last_reachable, &last_unreachable));
	assert(!last_reachable);
	assert(!last_unreachable);

	// Check that if we change back to STORAGE_ENABLED right before closing, pending changes are still saved

	start_meshlink_pair(mesh1, mesh2);
	stop_meshlink_pair(mesh1, mesh2);

	meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_ENABLED);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_ENABLED);

	close_meshlink_pair(mesh1, mesh2);

	mesh1 = meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_STATIONARY);
	assert(mesh1);
	assert(mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	assert(!meshlink_get_node_reachability(mesh1, meshlink_get_node(mesh1, "bar"), &last_reachable, &last_unreachable));
	assert(last_reachable);
	assert(last_unreachable);

	// Start again from scratch, now use invite/join instead of import/export

	close_meshlink_pair(mesh1, mesh2);

	assert(meshlink_destroy("storage-policy_conf.1"));
	assert(meshlink_destroy("storage-policy_conf.2"));

	mesh1 = meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_STATIONARY);
	assert(mesh1);
	assert(mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);
	meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_DISABLED);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_DISABLED);

	// Check that joining is not possible with storage disabled

	assert(meshlink_set_canonical_address(mesh1, meshlink_get_self(mesh1), "localhost", NULL));
	char *invitation = meshlink_invite(mesh1, NULL, "bar");
	assert(invitation);
	assert(meshlink_start(mesh1));
	assert(!meshlink_join(mesh2, invitation));
	assert(meshlink_errno == MESHLINK_EINVAL);
	meshlink_stop(mesh1);

	// Try again with KEYS_ONLY

	meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_KEYS_ONLY);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_KEYS_ONLY);

	assert(meshlink_start(mesh1));
	assert(meshlink_join(mesh2, invitation));
	assert(meshlink_errno == MESHLINK_EINVAL);
	meshlink_stop(mesh1);

	start_meshlink_pair(mesh1, mesh2);

	// Close the instances and reopen them.

	close_meshlink_pair(mesh1, mesh2);

	mesh1 = meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_STATIONARY);
	assert(mesh1);
	assert(mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);
	meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_KEYS_ONLY);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_KEYS_ONLY);

	// Check that the nodes know each other

	assert(meshlink_get_node(mesh1, "bar"));
	assert(meshlink_get_node(mesh2, "foo"));

	// Done.

	close_meshlink_pair(mesh1, mesh2);
	free(invitation);
}
