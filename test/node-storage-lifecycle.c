#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include <assert.h>

#include "meshlink_internal.h"
#include "node.h"
#include "chacha-poly1305/chacha-poly1305.h"
#include "devtools.h"
#include "node_storage.h"
#include "node-storage-tests.h"
#include "packmsg.h"
#include "path_plpmtu.h"
#include "utils.h"

/* Hold the shared worker on a different owner: target jobs are provably queued,
   while synchronous target lifecycle operations can still commit directly. */
typedef struct worker_blocker {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool entered, released;
	storage_writer_owner_t *owner;
} worker_blocker_t;

typedef struct native_spy {
	pthread_mutex_t mutex;
	unsigned writes;
	uint8_t last_key[CHACHA_POLY1305_KEYLEN];
	size_t last_keylen;
} native_spy_t;

static bool blocking_backend(const char *path, const void *data, size_t len, const void *key, size_t keylen, void *context) {
	(void)path;
	(void)data;
	(void)len;
	(void)key;
	(void)keylen;
	worker_blocker_t *blocker = context;
	assert(!pthread_mutex_lock(&blocker->mutex));
	blocker->entered = true;
	assert(!pthread_cond_broadcast(&blocker->cond));

	while(!blocker->released) {
		assert(!pthread_cond_wait(&blocker->cond, &blocker->mutex));
	}

	assert(!pthread_mutex_unlock(&blocker->mutex));
	return true;
}

static void block_worker(worker_blocker_t *blocker) {
	memset(blocker, 0, sizeof *blocker);
	assert(!pthread_mutex_init(&blocker->mutex, NULL));
	assert(!pthread_cond_init(&blocker->cond, NULL));
	blocker->owner = storage_writer_owner_open(NULL, NULL, blocking_backend, blocker);
	assert(blocker->owner);
	assert(storage_writer_submit(blocker->owner, "lifecycle-blocker", "x", 1, NULL, 0, 1));
	assert(!pthread_mutex_lock(&blocker->mutex));

	while(!blocker->entered) {
		assert(!pthread_cond_wait(&blocker->cond, &blocker->mutex));
	}

	assert(!pthread_mutex_unlock(&blocker->mutex));
}

static void release_worker(worker_blocker_t *blocker) {
	assert(!pthread_mutex_lock(&blocker->mutex));
	blocker->released = true;
	assert(!pthread_cond_broadcast(&blocker->cond));
	assert(!pthread_mutex_unlock(&blocker->mutex));
	storage_writer_owner_close(blocker->owner);
	assert(!pthread_cond_destroy(&blocker->cond));
	assert(!pthread_mutex_destroy(&blocker->mutex));
}

static bool spying_backend(const char *path, const void *data, size_t len, const void *key, size_t keylen, void *context) {
	native_spy_t *spy = context;
	assert(!key || keylen == sizeof spy->last_key);
	assert(!pthread_mutex_lock(&spy->mutex));
	spy->writes++;
	spy->last_keylen = keylen;

	if(keylen) {
		memcpy(spy->last_key, key, keylen);
	}

	assert(!pthread_mutex_unlock(&spy->mutex));
	config_t config = {data, len};
	return config_write_path(path, &config, key);
}

static unsigned spy_writes(native_spy_t *spy) {
	assert(!pthread_mutex_lock(&spy->mutex));
	unsigned writes = spy->writes;
	assert(!pthread_mutex_unlock(&spy->mutex));
	return writes;
}

static meshlink_handle_t *open_owner(const char *conf, const char *key, native_spy_t *spy) {
	assert(meshlink_destroy(conf));
	meshlink_handle_t *mesh = key ? meshlink_open_encrypted(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE, key, strlen(key))
	                              : meshlink_open(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE);
	assert(mesh);
	meshlink_enable_discovery(mesh, false);
	memset(spy, 0, sizeof *spy);
	assert(!pthread_mutex_init(&spy->mutex, NULL));
	node_storage_set_backend(mesh, spying_backend, spy);
	return mesh;
}

static node_t *import_peer(meshlink_handle_t *mesh, const char *exported) {
	assert(meshlink_import(mesh, exported));
	/* Acknowledge the deliberately empty import cache before starting a new batch. */
	assert(node_storage_flush(mesh));
	node_t *peer = (node_t *)meshlink_get_node(mesh, "peer");
	assert(peer);
	return peer;
}

static void queued_jobs(size_t expected) {
	storage_writer_stats_t stats;
	storage_writer_get_stats(NULL, &stats);
	assert(stats.jobs == expected);
}

static void queue_peer_change(meshlink_handle_t *mesh, node_t *peer, time_t seen) {
	peer->last_reachable = seen;
	node_storage_mark(peer, NODE_STORAGE_EDGE);
	path_mtu_cache_entry_t *mtu = &peer->mtu_cache[0];
	memset(mtu, 0, sizeof *mtu);
	mtu->family = AF_INET;
	assert(inet_pton(AF_INET, "198.51.100.7", mtu->addr) == 1);
	mtu->size = PATH_PLPMTU_BASE;
	mtu->flags = PATH_MTU_CACHE_KEEPALIVE_V2;
	mtu->keepalive_ms = 15000;
	mtu->updated_at = seen;
	mtu->net_fp = (uint32_t)seen;
	node_storage_mark(peer, NODE_STORAGE_PATH_HISTORY);
	mesh->loop.now.tv_sec += 6;
	node_storage_tick(mesh, seen);
	queued_jobs(3); // One unrelated running write and the target core/cache jobs.
}

static time_t disk_seen(meshlink_handle_t *mesh, const char *name) {
	config_t config = {0};
	assert(config_read(mesh, "current", name, &config, mesh->config_key));
	packmsg_input_t in = {config.buf, config.len};
	assert(packmsg_get_array(&in) == 10);

	for(unsigned field = 0; field < 8; field++) {
		packmsg_skip_element(&in);
	}

	time_t seen = packmsg_get_int64(&in);
	assert(packmsg_input_ok(&in));
	config_free(&config);
	return seen;
}

static void close_fixture(meshlink_handle_t *mesh, native_spy_t *spy, const char *conf) {
	meshlink_close(mesh);
	assert(!pthread_mutex_destroy(&spy->mutex));
	assert(meshlink_destroy(conf));
}

static time_t reason_clock(void *context) {
	return *(time_t *)context;
}

static void test_reason_acknowledgment(const char *exported) {
	const char *conf = "storage_lifecycle_reason_ack";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
	time_t wall = 1700000000;
	node_storage_set_clock(mesh, reason_clock, &wall);
	node_t *peer = import_peer(mesh, exported);
	worker_blocker_t blocker;
	block_worker(&blocker);
	peer->canonical_address = strdup("203.0.113.21 443");
	assert(peer->canonical_address);
	peer->last_reachable = 1700000000;
	node_storage_mark(peer, NODE_STORAGE_KEY_POLICY | NODE_STORAGE_CONFIG | NODE_STORAGE_EDGE);
	node_storage_tick(mesh, peer->last_reachable);
	queued_jobs(2);
	peer->last_reachable += 120;
	node_storage_mark(peer, NODE_STORAGE_OBSERVATION);
	release_worker(&blocker);
	node_storage_wait(mesh);
	assert(disk_seen(mesh, "peer") == 1700000000);
	unsigned writes = spy_writes(&spy);
	node_storage_tick(mesh, peer->last_reachable);
	node_storage_wait(mesh);
	assert(spy_writes(&spy) == writes);
	assert(meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.21", "443"));
	assert(meshlink_whitelist(mesh, (meshlink_node_t *)peer));
	assert(spy_writes(&spy) == writes); // Only observation remains pending.

	block_worker(&blocker);
	peer->canonical_address[11] = '2';
	node_storage_mark(peer, NODE_STORAGE_CONFIG);
	node_storage_tick(mesh, peer->last_reachable);
	queued_jobs(2);
	peer->canonical_address[11] = '3';
	node_storage_mark(peer, NODE_STORAGE_CONFIG);
	release_worker(&blocker);
	node_storage_wait(mesh);
	writes = spy_writes(&spy);
	node_storage_tick(mesh, peer->last_reachable);
	node_storage_wait(mesh);
	assert(spy_writes(&spy) == writes + 1); // Newer configuration survives acknowledgment.
	close_fixture(mesh, &spy, conf);
}

static void test_policy_cancel(const char *exported) {
	const char *conf = "storage_lifecycle_policy";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
	node_t *peer = import_peer(mesh, exported);
	time_t previous = 0;

	for(unsigned pass = 0; pass < 2; pass++) {
		worker_blocker_t blocker;
		block_worker(&blocker);
		unsigned before = spy_writes(&spy);
		time_t latest = 1700000100 + pass * 120;
		queue_peer_change(mesh, peer, latest);
		meshlink_set_storage_policy(mesh, pass ? MESHLINK_STORAGE_DISABLED : MESHLINK_STORAGE_KEYS_ONLY);
		queued_jobs(1);
		assert(disk_seen(mesh, "peer") == previous);
		release_worker(&blocker);
		node_storage_wait(mesh);
		assert(spy_writes(&spy) == before);
		meshlink_set_storage_policy(mesh, MESHLINK_STORAGE_ENABLED);
		assert(node_storage_flush(mesh));
		assert(disk_seen(mesh, "peer") == latest);
		assert(peer->mtu_cache[0].updated_at == latest);
		previous = latest;
	}

	close_fixture(mesh, &spy, conf);
}

static void test_forget_cancel(const char *exported) {
	const char *conf = "storage_lifecycle_forget";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
	node_t *peer = import_peer(mesh, exported);
	worker_blocker_t blocker;
	block_worker(&blocker);
	queue_peer_change(mesh, peer, 1700000200);
	assert(meshlink_forget_node(mesh, (meshlink_node_t *)peer));
	queued_jobs(1);
	assert(access("storage_lifecycle_forget/current/hosts/peer", F_OK) && errno == ENOENT);
	peer = import_peer(mesh, exported);
	unsigned before = spy_writes(&spy);
	release_worker(&blocker);
	node_storage_wait(mesh);
	assert(spy_writes(&spy) == before);
	assert(!peer->last_reachable && !disk_seen(mesh, "peer"));
	assert(access("storage_lifecycle_forget/current/path-cache/peer", F_OK) && errno == ENOENT);
	close_fixture(mesh, &spy, conf);
}

static void test_failed_forget(const char *exported) {
	const char *conf = "storage_lifecycle_failed_forget";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
	node_t *peer = import_peer(mesh, exported);
	worker_blocker_t blocker;
	block_worker(&blocker);
	queue_peer_change(mesh, peer, 1700000300);
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	assert(!meshlink_forget_node(mesh, (meshlink_node_t *)peer));
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	assert(meshlink_get_node(mesh, "peer") == (meshlink_node_t *)peer);
	queued_jobs(1);
	assert(node_storage_flush(mesh));
	assert(disk_seen(mesh, "peer") == 1700000300);

	/* Even an unchanged record must be rewritten if unlink preceded failed sync. */
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	assert(!meshlink_forget_node(mesh, (meshlink_node_t *)peer));
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	assert(node_storage_flush(mesh));
	assert(disk_seen(mesh, "peer") == 1700000300);
	unsigned before = spy_writes(&spy);
	release_worker(&blocker);
	node_storage_wait(mesh);
	assert(spy_writes(&spy) == before);
	close_fixture(mesh, &spy, conf);
}

static void test_failed_forget_policies(const char *exported) {
	const char *conf = "storage_lifecycle_forget_policies";
	const meshlink_storage_policy_t policies[] = {
		MESHLINK_STORAGE_ENABLED, MESHLINK_STORAGE_KEYS_ONLY, MESHLINK_STORAGE_DISABLED,
	};

	for(unsigned i = 0; i < sizeof policies / sizeof *policies; i++) {
		native_spy_t spy;
		meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
		node_t *peer = import_peer(mesh, exported);
		meshlink_set_storage_policy(mesh, policies[i]);
		worker_blocker_t blocker;
		block_worker(&blocker);
		config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
		assert(!meshlink_forget_node(mesh, (meshlink_node_t *)peer));
		assert(meshlink_errno == MESHLINK_ESTORAGE);
		config_fault_inject(CONFIG_FAULT_NONE, 0);
		assert(meshlink_get_node(mesh, "peer") == (meshlink_node_t *)peer);
		assert(!disk_seen(mesh, "peer"));
		queued_jobs(1);
		meshlink_close(mesh);
		unsigned before = spy_writes(&spy);
		release_worker(&blocker);
		assert(spy_writes(&spy) == before);
		assert(!pthread_mutex_destroy(&spy.mutex));
		mesh = meshlink_open(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE);
		assert(mesh && meshlink_get_node(mesh, "peer"));
		meshlink_close(mesh);
		assert(meshlink_destroy(conf));
	}
}

static void test_close_cancel(const char *exported) {
	const char *conf = "storage_lifecycle_close";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
	node_t *peer = import_peer(mesh, exported);
	worker_blocker_t blocker;
	block_worker(&blocker);
	queue_peer_change(mesh, peer, 1700000400);
	/* Current memory is newer than the queued immutable snapshot. */
	peer->last_reachable += 120;
	node_storage_mark(peer, NODE_STORAGE_OBSERVATION);
	meshlink_close(mesh);
	queued_jobs(1);
	unsigned before = spy_writes(&spy);
	release_worker(&blocker);
	assert(spy_writes(&spy) == before);
	assert(!pthread_mutex_destroy(&spy.mutex));
	mesh = meshlink_open(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE);
	assert(mesh);
	peer = (node_t *)meshlink_get_node(mesh, "peer");
	assert(peer && peer->last_reachable == 1700000520);
	assert(peer->mtu_cache[0].family == AF_INET && peer->mtu_cache[0].keepalive_ms == 15000);
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
}

static void test_port_cancel(const char *exported) {
	const char *conf = "storage_lifecycle_port";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
	node_t *peer = import_peer(mesh, exported);
	worker_blocker_t blocker;
	block_worker(&blocker);
	queue_peer_change(mesh, peer, 1700000550);
	assert(meshlink_set_port(mesh, 0));
	queued_jobs(1);
	peer = (node_t *)meshlink_get_node(mesh, "peer");
	assert(peer && peer->last_reachable == 1700000550);
	assert(peer->mtu_cache[0].family == AF_INET && peer->mtu_cache[0].keepalive_ms == 15000);
	unsigned before = spy_writes(&spy);
	release_worker(&blocker);
	node_storage_wait(mesh);
	assert(spy_writes(&spy) == before);
	assert(disk_seen(mesh, "peer") == 1700000550);
	close_fixture(mesh, &spy, conf);
}

static void fail_port_write(void) {
	config_fault_inject(CONFIG_FAULT_WRITE, 1);
}

static void test_port_write_failure(void) {
	const char *conf = "storage_lifecycle_port_failure";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
	int previous_port = meshlink_get_port(mesh);
	meshlink_handle_t *reservation = meshlink_open_ephemeral("port-reservation", "storage-lifecycle", DEV_CLASS_PORTABLE);
	assert(reservation);
	int new_port = meshlink_get_port(reservation);
	assert(new_port != previous_port);
	meshlink_close(reservation);
	void (*previous_probe)(void) = devtool_trybind_probe;
	devtool_trybind_probe = fail_port_write;
	assert(!meshlink_set_port(mesh, new_port));
	devtool_trybind_probe = previous_probe;
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	assert(meshlink_get_port(mesh) == new_port && mesh->main_config_pending);
	assert(meshlink_set_port(mesh, new_port));
	assert(!mesh->main_config_pending);
	meshlink_set_storage_policy(mesh, MESHLINK_STORAGE_DISABLED);
	meshlink_close(mesh);
	assert(!pthread_mutex_destroy(&spy.mutex));
	mesh = meshlink_open(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE);
	assert(mesh && meshlink_get_port(mesh) == new_port);
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
}

static void test_rotation_cancel(const char *exported) {
	const char *conf = "storage_lifecycle_rotate";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, "old-key", &spy);
	node_t *peer = import_peer(mesh, exported);
	worker_blocker_t blocker;
	block_worker(&blocker);
	queue_peer_change(mesh, peer, 1700000600);
	assert(meshlink_encrypted_key_rotate(mesh, "new-key", 7));
	queued_jobs(1);
	unsigned before = spy_writes(&spy);
	release_worker(&blocker);
	node_storage_wait(mesh);
	assert(spy_writes(&spy) == before);
	peer->last_reachable += 120;
	assert(node_storage_write(mesh, peer, false));
	assert(!pthread_mutex_lock(&spy.mutex));
	assert(spy.last_keylen == sizeof spy.last_key && !memcmp(spy.last_key, mesh->config_key, sizeof spy.last_key));
	assert(!pthread_mutex_unlock(&spy.mutex));
	meshlink_close(mesh);
	assert(!pthread_mutex_destroy(&spy.mutex));
	mesh = meshlink_open_encrypted(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE, "new-key", 7);
	assert(mesh);
	peer = (node_t *)meshlink_get_node(mesh, "peer");
	assert(peer && peer->last_reachable == 1700000720);
	assert(peer->mtu_cache[0].family == AF_INET && peer->mtu_cache[0].keepalive_ms == 15000);
	meshlink_close(mesh);
	assert(!meshlink_open_encrypted(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE, "old-key", 7));
	assert(meshlink_destroy(conf));
}

static meshlink_handle_t *start_inviter(const char *conf) {
	assert(meshlink_destroy(conf));
	meshlink_handle_t *inviter = meshlink_open(conf, "inviter", "storage-lifecycle", DEV_CLASS_BACKBONE);
	assert(inviter);
	inviter->self->mtu_cache[0] = (path_mtu_cache_entry_t) {.family = AF_INET, .addr = {203, 0, 113, 90}, .size = 1280, .updated_at = 1700000000};
	meshlink_enable_discovery(inviter, false);
	assert(meshlink_set_canonical_address(inviter, meshlink_get_self(inviter), "127.0.0.1", NULL));
	/* Keep unrelated inviter maintenance from adding background jobs to this fixture. */
	meshlink_set_storage_policy(inviter, MESHLINK_STORAGE_KEYS_ONLY);
	assert(meshlink_start(inviter));
	return inviter;
}

static void test_join_cancel(void) {
	const char *conf = "storage_lifecycle_join";
	const char *inviter_conf = "storage_lifecycle_inviter";
	native_spy_t spy;
	meshlink_handle_t *mesh = open_owner(conf, NULL, &spy);
	meshlink_handle_t *inviter = start_inviter(inviter_conf);
	char *invitation = meshlink_invite_ex(inviter, NULL, "joined", MESHLINK_INVITE_LOCAL);
	assert(invitation);
	worker_blocker_t blocker;
	block_worker(&blocker);
	mesh->self->last_reachable = 1700000800;
	node_storage_mark(mesh->self, NODE_STORAGE_EDGE);
	node_storage_tick(mesh, 1700000800);
	queued_jobs(2);
	assert(meshlink_join(mesh, invitation));
	free(invitation);
	assert(!strcmp(meshlink_get_self(mesh)->name, "joined"));
	assert(!mesh->self->last_reachable);
	assert(!((node_t *)meshlink_get_node(mesh, "inviter"))->mtu_cache[0].family);
	assert(access("storage_lifecycle_join/current/hosts/owner", F_OK) && errno == ENOENT);
	assert(!access("storage_lifecycle_join/current/hosts/joined", F_OK));
	unsigned before = spy_writes(&spy);
	release_worker(&blocker);
	node_storage_wait(mesh);
	assert(spy_writes(&spy) == before);
	assert(access("storage_lifecycle_join/current/hosts/owner", F_OK) && errno == ENOENT);
	meshlink_close(mesh);
	assert(!pthread_mutex_destroy(&spy.mutex));
	meshlink_close(inviter);
	mesh = meshlink_open(conf, "joined", "storage-lifecycle", DEV_CLASS_PORTABLE);
	assert(mesh && meshlink_get_node(mesh, "inviter"));
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
	assert(meshlink_destroy(inviter_conf));
}

static unsigned activation_fault_stage;
static bool activation_rollback_fault;
static bool activation_keep_new;

static void activation_fault(int stage) {
	if(activation_keep_new && stage == -3) {
		config_fault_inject(CONFIG_FAULT_RENAME, 1);
	} else if((unsigned)stage == activation_fault_stage) {
		config_fault_inject(activation_rollback_fault ? CONFIG_FAULT_RENAME : CONFIG_FAULT_DIR_SYNC,
		                    activation_rollback_fault ? 2 : 1);
	}
}

static void self_incarnation(meshlink_handle_t *mesh, uint8_t id[16]) {
	config_t config = {0};
	assert(config_read(mesh, "current", mesh->name, &config, mesh->config_key));
	packmsg_input_t in = {config.buf, config.len};
	assert(packmsg_get_array(&in) == 10);
	packmsg_skip_element(&in);
	packmsg_skip_element(&in);
	const void *stored = NULL;
	assert(packmsg_get_bin_raw(&in, &stored) == 16);
	memcpy(id, stored, 16);
	config_free(&config);
}

static void test_join_activation_failure(const char *exported) {
	const char *conf = "storage_lifecycle_join_fault";
	const char *inviter_conf = "storage_lifecycle_join_fault_inviter";

	for(unsigned failure = 0; failure < 5; failure++) {
		const char *key = failure == 3 ? "old-key" : NULL;
		native_spy_t spy;
		meshlink_handle_t *mesh = open_owner(conf, key, &spy);
		meshlink_handle_t *inviter = start_inviter(inviter_conf);
		/* Staged main writes must not acknowledge current-epoch retry state. */
		mesh->main_config_pending = true;
		uint8_t before[16], after[16];
		self_incarnation(mesh, before);
		char *invitation = meshlink_invite_ex(inviter, NULL, "joined", MESHLINK_INVITE_LOCAL);
		assert(invitation);
		activation_keep_new = failure == 4;
		activation_rollback_fault = failure == 2 || failure == 3;
		activation_fault_stage = failure == 1 || activation_keep_new ? 3 : 2;
		mesh->storage_activate_probe = activation_fault;
		assert(!meshlink_join(mesh, invitation));
		assert(meshlink_errno == MESHLINK_ESTORAGE);
		mesh->storage_activate_probe = NULL;
		config_fault_inject(CONFIG_FAULT_NONE, 0);
		free(invitation);
		if(activation_keep_new) {
			assert(!mesh->main_config_pending);
			// False is still a storage failure, but continued writes must use
			// the installed joined identity if rollback could not move it.
			assert(!mesh->storage_unavailable && !strcmp(mesh->name, "joined"));
			self_incarnation(mesh, after);
			assert(memcmp(before, after, sizeof before));
			assert(meshlink_set_canonical_address(mesh, meshlink_get_self(mesh), "203.0.113.15", "443"));
			meshlink_close(mesh);
			assert(!pthread_mutex_destroy(&spy.mutex));
			meshlink_close(inviter);
			mesh = meshlink_open(conf, "joined", "storage-lifecycle", DEV_CLASS_PORTABLE);
			assert(mesh && meshlink_get_node(mesh, "inviter"));
			assert(!strcmp(mesh->self->canonical_address, "203.0.113.15 443"));
			assert(access("storage_lifecycle_join_fault/current/hosts/owner", F_OK) && errno == ENOENT);
			meshlink_close(mesh);
			assert(meshlink_destroy(conf));
			assert(meshlink_destroy(inviter_conf));
			continue;
		}
		assert(!strcmp(mesh->name, "owner") && !strcmp(mesh->self->name, "owner"));
		assert(mesh->main_config_pending);

		if(activation_rollback_fault) {
			assert(mesh->storage_unavailable);
			assert(!node_storage_write(mesh, mesh->self, false));
			assert(meshlink_errno == MESHLINK_ESTORAGE);
			assert(access("storage_lifecycle_join_fault/current", F_OK) && errno == ENOENT);
		} else {
			assert(!mesh->storage_unavailable);
			self_incarnation(mesh, after);
			assert(!memcmp(before, after, sizeof before));
			assert(meshlink_set_canonical_address(mesh, meshlink_get_self(mesh), "203.0.113.14", NULL));
			node_t *peer = import_peer(mesh, exported);
			assert(meshlink_blacklist(mesh, (meshlink_node_t *)peer));
			self_incarnation(mesh, after);
			assert(!memcmp(before, after, sizeof before));
			assert(access("storage_lifecycle_join_fault/current/hosts/joined", F_OK) && errno == ENOENT);
		}

		meshlink_close(mesh);
		assert(!pthread_mutex_destroy(&spy.mutex));
		meshlink_close(inviter);
		mesh = key ? meshlink_open_encrypted(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE, key, strlen(key))
		           : meshlink_open(conf, "owner", "storage-lifecycle", DEV_CLASS_PORTABLE);
		assert(mesh && !strcmp(mesh->name, "owner"));
		self_incarnation(mesh, after);
		assert(!memcmp(before, after, sizeof before));

		if(!activation_rollback_fault) {
			node_t *peer = (node_t *)meshlink_get_node(mesh, "peer");
			assert(peer && peer->status.blacklisted);
		}

		meshlink_close(mesh);
		assert(meshlink_destroy(conf));
		assert(meshlink_destroy(inviter_conf));
	}
}

void test_node_storage_lifecycle(void) {
	meshlink_handle_t *remote = meshlink_open_ephemeral("peer", "storage-lifecycle", DEV_CLASS_BACKBONE);
	assert(remote);
	memset(remote->self->recent, 0, sizeof remote->self->recent);
	char *exported = meshlink_export(remote);
	assert(exported);
	meshlink_close(remote);
	test_policy_cancel(exported);
	test_reason_acknowledgment(exported);
	test_forget_cancel(exported);
	test_failed_forget(exported);
	test_failed_forget_policies(exported);
	test_close_cancel(exported);
	test_port_cancel(exported);
	test_port_write_failure();
	test_rotation_cancel(exported);
	test_join_cancel();
	test_join_activation_failure(exported);
	free(exported);
}
