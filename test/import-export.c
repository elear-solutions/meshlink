#ifdef NDEBUG
#undef NDEBUG
#endif

#include "meshlink_internal.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>

#include "net.h"
#include "node_storage.h"
#include "protocol.h"
#include "utils.h"

static struct sync_flag bar_reachable;
static struct sync_flag pmtu_flag;


static const char blocked_io_payload[] = "network delivery while cache I/O is blocked";
enum { IO_ENTERED, IO_RELEASE, IO_REVERT, IO_TICKED, IO_RECEIVED, IO_FLAGS };

typedef struct blocked_io_test {
	meshlink_handle_t *mesh;
	node_t *peer;
	unsigned slot;
	bool sent;
	struct sync_flag flags[IO_FLAGS];
} blocked_io_test_t;

static bool blocked_cache_write(const char *path, const void *data, size_t len, const void *key, size_t keylen, void *context) {
	(void)keylen;
	blocked_io_test_t *test = context;

	if(strstr(path, "/path-cache/")) {
		set_sync_flag(&test->flags[IO_ENTERED], true);

		if(!wait_sync_flag(&test->flags[IO_RELEASE], 30)) {
			errno = ETIMEDOUT;
			return false;
		}
	}

	config_t config = {data, len};
	return config_write_path(path, &config, key);
}

static void blocked_io_receive(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len) {
	blocked_io_test_t *test = mesh->priv;

	if(!strcmp(source->name, "foo") && len == sizeof(blocked_io_payload) && !memcmp(data, blocked_io_payload, len)) {
		set_sync_flag(&test->flags[IO_RECEIVED], true);
	}
}

static void advance_cache_tick(meshlink_handle_t *mesh) {
	node_storage_tick(mesh, time(NULL));
	mesh->loop.now.tv_sec += 5;
	node_storage_tick(mesh, time(NULL));
	event_loop_stamp_now(&mesh->loop);
}

static void *blocked_io_mutate(void *context) {
	blocked_io_test_t *test = context;
	assert(!pthread_mutex_lock(&test->mesh->mutex));
	test->peer->mtu_cache[test->slot].size = 1290;
	node_storage_mark(test->peer, NODE_STORAGE_PATH_HISTORY);
	advance_cache_tick(test->mesh);
	assert(!pthread_mutex_unlock(&test->mesh->mutex));

	if(!wait_sync_flag(&test->flags[IO_REVERT], 30)) {
		return NULL;
	}

	assert(!pthread_mutex_lock(&test->mesh->mutex));
	test->peer->mtu_cache[test->slot].size = 1280;
	node_storage_mark(test->peer, NODE_STORAGE_PATH_HISTORY);
	advance_cache_tick(test->mesh);
	assert(!pthread_mutex_unlock(&test->mesh->mutex));
	set_sync_flag(&test->flags[IO_TICKED], true);
	test->sent = meshlink_send(test->mesh, (meshlink_node_t *)test->peer, blocked_io_payload, sizeof(blocked_io_payload));
	return NULL;
}

static void test_blocked_cache_io(meshlink_handle_t *mesh, meshlink_handle_t *receiver, node_t *peer) {
	blocked_io_test_t test = {.mesh = mesh, .peer = peer, .slot = PATH_MTU_CACHE_ENTRIES - 1};

	for(unsigned i = 0; i < IO_FLAGS; i++) {
		init_sync_flag(&test.flags[i]);
	}

	assert(!pthread_mutex_lock(&mesh->mutex));
	path_mtu_cache_entry_t original = peer->mtu_cache[test.slot];
	assert(!original.family);
	peer->mtu_cache[test.slot] = (path_mtu_cache_entry_t) {
		.family = AF_INET, .addr = {198, 51, 100, 77}, .size = 1280, .updated_at = time(NULL),
	};
	node_storage_mark(peer, NODE_STORAGE_PATH_HISTORY);
	assert(node_storage_flush(mesh));
	node_storage_set_backend(mesh, blocked_cache_write, &test);
	node_storage_stats_t before, after;
	node_storage_get_stats(mesh, &before);
	assert(!pthread_mutex_unlock(&mesh->mutex));
	void *previous_priv = receiver->priv;
	receiver->priv = &test;
	meshlink_set_receive_cb(receiver, blocked_io_receive);
	pthread_t thread;
	assert(!pthread_create(&thread, NULL, blocked_io_mutate, &test));
	bool entered = wait_sync_flag(&test.flags[IO_ENTERED], 5);
	set_sync_flag(&test.flags[IO_REVERT], true);
	bool ticked = entered && wait_sync_flag(&test.flags[IO_TICKED], 5);
	bool received = ticked && wait_sync_flag(&test.flags[IO_RECEIVED], 5);
	bool still_blocked = !check_sync_flag(&test.flags[IO_RELEASE]);

	// Release first, even when a synchronous-I/O regression held the mesh mutex.
	set_sync_flag(&test.flags[IO_RELEASE], true);
	assert(!pthread_join(thread, NULL));
	meshlink_set_receive_cb(receiver, NULL);
	receiver->priv = previous_priv;
	assert(entered && ticked && received && still_blocked && test.sent);
	assert(!pthread_mutex_lock(&mesh->mutex));
	node_storage_wait(mesh);
	node_storage_set_backend(mesh, NULL, NULL);
	node_storage_get_stats(mesh, &after);
	assert(after.core_writes == before.core_writes);
	node_t *restored = new_node();
	restored->name = strdup(peer->name);
	assert(restored->name && node_storage_read(mesh, restored));
	bool reverted = false;

	for(unsigned i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		const path_mtu_cache_entry_t *entry = &restored->mtu_cache[i];

		if(entry->family == AF_INET && !memcmp(entry->addr, peer->mtu_cache[test.slot].addr, 4)) {
			assert(entry->size == peer->mtu_cache[test.slot].size);
			reverted = true;
		}
	}

	assert(reverted);
	free_node(restored);
	peer->mtu_cache[test.slot] = original;
	node_storage_mark(peer, NODE_STORAGE_PATH_HISTORY);
	assert(node_storage_flush(mesh));
	assert(!pthread_mutex_unlock(&mesh->mutex));

	for(unsigned i = 0; i < IO_FLAGS; i++) {
		assert(!pthread_cond_destroy(&test.flags[i].cond));
		assert(!pthread_mutex_destroy(&test.flags[i].mutex));
	}
}

/* Exercise the observation gate without waiting a minute or changing clocks. */
static void test_note_seen(meshlink_handle_t *mesh) {
	time_t now = time(NULL);
	char name[] = "seen";
	node_t n = {.name = name, .last_reachable = now - 60, .last_unreachable = 123};
	connection_t c = {.name = n.name, .node = &n, .allow_request = ALL};
	node_storage_init(&n);
	char pong[16];
	assert(snprintf(pong, sizeof pong, "%d", PONG) > 0);

	// Unhandled requests and inactive sockets must not count as observations.
	assert(receive_request(mesh, &c, pong));
	assert(n.last_reachable == now - 60);
	c.status.active = true;
	assert(!receive_request(mesh, &c, "invalid"));
	assert(n.last_reachable == now - 60);
	assert(!node_storage_generation(&n, false));

	// A handled request refreshes an expired epoch stamp, independent of loop.now.
	assert(receive_request(mesh, &c, pong));
	assert(n.last_reachable >= now && n.last_reachable <= time(NULL));
	assert(n.last_unreachable == 123);
	assert(node_storage_generation(&n, false));
	time_t seen = n.last_reachable;
	uint64_t generation = node_storage_generation(&n, false);
	node_note_seen(mesh, &n);
	assert(n.last_reachable == seen && node_storage_generation(&n, false) == generation);

	// A clock moving backwards must not move an observation backwards.
	n.last_reachable = time(NULL) + 3600;
	seen = n.last_reachable;
	node_note_seen(mesh, &n);
	assert(n.last_reachable == seen && node_storage_generation(&n, false) == generation);

	// Blacklisted peers, self, and NULL are ignored even with an expired stamp.
	n.last_reachable = now - 60;
	n.status.blacklisted = true;
	node_note_seen(mesh, &n);
	assert(n.last_reachable == now - 60 && node_storage_generation(&n, false) == generation);
	node_t *self = mesh->self;
	mesh->self = &n;
	n.status.blacklisted = false;
	node_note_seen(mesh, &n);
	assert(n.last_reachable == now - 60 && node_storage_generation(&n, false) == generation);
	mesh->self = self;
	node_note_seen(mesh, NULL);
	assert(n.last_unreachable == 123);
	node_storage_free(&n);
}

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && !strcmp(node->name, "bar")) {
		set_sync_flag(&bar_reachable, true);
	}
}

static void pmtu_cb(meshlink_handle_t *mesh, meshlink_node_t *node, uint16_t pmtu) {
	(void)mesh;

	if(pmtu && !strcmp(node->name, "foo")) {
		set_sync_flag(&pmtu_flag, true);
	}
}

int main(void) {
	init_sync_flag(&bar_reachable);
	init_sync_flag(&pmtu_flag);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	assert(meshlink_destroy("import_export_conf.1"));
	assert(meshlink_destroy("import_export_conf.2"));

	meshlink_handle_t *mesh1 = meshlink_open("import_export_conf.1", "foo", "import-export", DEV_CLASS_BACKBONE);
	assert(mesh1);
	test_note_seen(mesh1);

	meshlink_handle_t *mesh2 = meshlink_open("import_export_conf.2", "bar", "import-export", DEV_CLASS_STATIONARY);
	assert(mesh2);

	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	assert(meshlink_set_canonical_address(mesh1, meshlink_get_self(mesh1), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh2, meshlink_get_self(mesh2), "localhost", NULL));

	char *data = meshlink_export(mesh1);
	assert(data);

	assert(meshlink_import(mesh2, data));
	free(data);

	data = meshlink_export(mesh2);
	assert(data);

	assert(meshlink_import(mesh1, data));

	/* Importing twice is fine */
	assert(meshlink_import(mesh1, data));
	free(data);

	assert(!meshlink_import(mesh1, "Garbage\n"));

	time_t last_reachable;
	time_t last_unreachable;
	meshlink_node_t *bar = meshlink_get_node(mesh1, "bar");
	assert(bar);
	assert(!meshlink_get_node_reachability(mesh1, bar, &last_reachable, &last_unreachable));
	assert(!last_reachable);
	assert(!last_unreachable);

	/* Import does not elect a backbone. Join so bar owns a BACKBONE_REQUIRED intent. */
	meshlink_close(mesh1);
	meshlink_close(mesh2);
	assert(meshlink_destroy("import_export_conf.1"));
	assert(meshlink_destroy("import_export_conf.2"));

	mesh1 = meshlink_open("import_export_conf.1", "foo", "import-export", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("import_export_conf.2", "bar", "import-export", DEV_CLASS_STATIONARY);
	assert(mesh1 && mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);
	assert(meshlink_set_canonical_address(mesh1, meshlink_get_self(mesh1), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh2, meshlink_get_self(mesh2), "localhost", NULL));
	join_meshlink_peer(mesh1, mesh2);

	bar = meshlink_get_node(mesh1, "bar");
	assert(bar);
	assert(!meshlink_get_node_reachability(mesh1, bar, &last_reachable, &last_unreachable));

	meshlink_set_node_status_cb(mesh1, status_cb);
	meshlink_set_node_pmtu_cb(mesh2, pmtu_cb);

	assert(meshlink_start(mesh2));

	assert(wait_sync_flag(&bar_reachable, 10));
	assert(wait_sync_flag(&pmtu_flag, 10));

	assert(meshlink_get_node_reachability(mesh1, bar, &last_reachable, &last_unreachable));
	assert(last_reachable);
	test_blocked_cache_io(mesh1, mesh2, (node_t *)bar);

	// Keep the real periodic callback to exercise its walk after stopping the worker.
	pthread_mutex_lock(&mesh1->mutex);
	timeout_cb_t periodic = mesh1->periodictimer.cb;
	assert(periodic);
	pthread_mutex_unlock(&mesh1->mutex);

	meshlink_stop(mesh1);
	meshlink_stop(mesh2);

	assert(!meshlink_get_node_reachability(mesh1, bar, &last_reachable, &last_unreachable));
	assert(last_reachable);
	assert(last_unreachable);
	assert(last_reachable <= last_unreachable);

	// Graph-reachable peers without a local socket also refresh and flush to disk.
	node_t *n = (node_t *)bar;
	assert(!n->connection);
	n->last_reachable = time(NULL) - 60;
	n->status.reachable = true;
	time_t before = time(NULL);
	timeout_add(&mesh1->loop, &mesh1->periodictimer, periodic, &mesh1->periodictimer, &(struct timespec) {0, 0});
	periodic(&mesh1->loop, &mesh1->periodictimer);
	timeout_del(&mesh1->loop, &mesh1->periodictimer);
	assert(n->last_reachable >= before && n->last_reachable <= time(NULL));
	assert(n->last_unreachable == last_unreachable);
	assert(node_storage_generation(n, false));
	last_reachable = n->last_reachable;
	n->status.reachable = false;

	meshlink_close(mesh2);
	meshlink_close(mesh1);
	mesh1 = meshlink_open("import_export_conf.1", "foo", "import-export", DEV_CLASS_BACKBONE);
	assert(mesh1);
	time_t restored_reachable, restored_unreachable;
	assert(!meshlink_get_node_reachability(mesh1, meshlink_get_node(mesh1, "bar"), &restored_reachable, &restored_unreachable));
	assert(restored_reachable == last_reachable);
	assert(restored_unreachable == last_unreachable);
	meshlink_close(mesh1);
	assert(meshlink_destroy("import_export_conf.1"));
	assert(meshlink_destroy("import_export_conf.2"));
}
