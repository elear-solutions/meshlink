#ifdef NDEBUG
#undef NDEBUG
#endif

#include "meshlink_internal.h"
#include "node.h"
#include "node_storage.h"
#include "node-storage-tests.h"
#include "net.h"
#include "packmsg.h"
#include "splay_tree.h"
#include "utils.h"

#include <assert.h>
#include <string.h>

static time_t fixed_clock(void *context) {
	return *(time_t *)context;
}

static time_t disk_seen(meshlink_handle_t *mesh, const char *name) {
	config_t config = {0};
	assert(config_read(mesh, "current", name, &config, mesh->config_key));
	packmsg_input_t in = {config.buf, config.len};
	assert(packmsg_get_array(&in) == 10);
	for(unsigned i = 0; i < 8; i++) {
		packmsg_skip_element(&in);
	}
	time_t seen = packmsg_get_int64(&in);
	config_free(&config);
	return seen;
}

static node_t *observed_peer(meshlink_handle_t *mesh, const char *name, time_t wall) {
	node_t *n = new_node();
	n->name = strdup(name);
	assert(n->name);
	node_add(mesh, n);
	n->last_reachable = wall;
	assert(node_storage_write(mesh, n, false));
	n->status.reachable = true;
	return n;
}

static void test_checkpoint(void) {
	const char *base = "observation_conf";
	assert(meshlink_destroy(base));
	meshlink_handle_t *mesh = meshlink_open(base, "owner", "observation", DEV_CLASS_PORTABLE);
	assert(mesh);
	time_t wall = 1700000000;
	time_t clock = wall;
	node_storage_set_clock(mesh, fixed_clock, &clock);
	node_t *n = observed_peer(mesh, "peer", wall);
	time_t monotonic = mesh->loop.now.tv_sec;
	time_t interval = node_storage_checkpoint_interval(n);
	assert(interval >= 23 * 3600 && interval <= 24 * 3600);
	assert(node_storage_checkpoint_deadline(n) == monotonic + interval);
	node_storage_stats_t initial, stats;
	node_storage_get_stats(mesh, &initial);

	// The in-memory gate never changes the unreachable edge or moves backwards.
	n->last_unreachable = 17;
	node_storage_note_seen(mesh, n, wall + 59);
	assert(n->last_reachable == wall);
	node_storage_note_seen(mesh, n, wall + 60);
	assert(n->last_reachable == wall + 60 && n->last_unreachable == 17);
	node_storage_note_seen(mesh, n, wall - 1);
	node_storage_note_seen(mesh, n, (time_t)-1);
	assert(n->last_reachable == wall + 60);
	n->status.blacklisted = true;
	node_storage_note_seen(mesh, n, wall + 120);
	assert(n->last_reachable == wall + 60);
	n->status.blacklisted = false;
	node_storage_note_seen(mesh, NULL, wall + 120);
	node_storage_note_seen(mesh, mesh->self, wall + 120);

	// Disk policy does not suppress observations of graph-only peers.
	meshlink_set_storage_policy(mesh, MESHLINK_STORAGE_KEYS_ONLY);
	mesh->loop.now.tv_sec = monotonic + 120;
	node_storage_tick(mesh, wall + 120);
	assert(n->last_reachable == wall + 120 && !n->connection);
	meshlink_set_storage_policy(mesh, MESHLINK_STORAGE_DISABLED);
	mesh->loop.now.tv_sec = monotonic + 180;
	node_storage_tick(mesh, wall + 180);
	assert(n->last_reachable == wall + 180);
	meshlink_set_storage_policy(mesh, MESHLINK_STORAGE_ENABLED);
	assert(disk_seen(mesh, "peer") == wall);

	// Cache work is independent of daily observation checkpoints.
	n->mtu_cache[0] = (path_mtu_cache_entry_t) {.family = AF_INET, .addr = {203, 0, 113, 1}, .size = 1399, .updated_at = wall};
	node_storage_mark(n, NODE_STORAGE_PATH_HISTORY);
	node_storage_tick(mesh, wall + 180);
	node_storage_wait(mesh);
	node_storage_get_stats(mesh, &stats);
	assert(stats.cache_writes == initial.cache_writes); // Five-second coalescing.
	mesh->loop.now.tv_sec += 5;
	node_storage_tick(mesh, wall + 185);
	node_storage_wait(mesh);
	node_storage_get_stats(mesh, &stats);
	assert(stats.cache_writes == initial.cache_writes + 1);
	assert(stats.core_writes == initial.core_writes);
	assert(disk_seen(mesh, "peer") == wall);

	mesh->loop.now.tv_sec = monotonic + interval - 1;
	node_storage_tick(mesh, wall + interval - 1);
	node_storage_wait(mesh);
	node_storage_get_stats(mesh, &stats);
	assert(stats.core_writes == initial.core_writes);
	mesh->loop.now.tv_sec++;
	clock = wall + interval;
	node_storage_tick(mesh, clock);
	node_storage_wait(mesh);
	node_storage_get_stats(mesh, &stats);
	assert(stats.core_writes == initial.core_writes + 1);
	assert(disk_seen(mesh, "peer") == n->last_reachable);

	// Failure after rename is not an acknowledgment; retry retains history.
	time_t next = node_storage_checkpoint_deadline(n);
	mesh->loop.now.tv_sec = next;
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	clock = wall + 2 * interval;
	node_storage_tick(mesh, clock);
	node_storage_wait(mesh);
	node_storage_get_stats(mesh, &stats);
	assert(stats.core_writes == initial.core_writes + 1 && stats.errors == initial.errors + 1);
	assert(node_storage_checkpoint_deadline(n) == next);
	mesh->loop.now.tv_sec++;
	node_storage_tick(mesh, wall + 2 * interval);
	node_storage_wait(mesh);
	node_storage_get_stats(mesh, &stats);
	assert(stats.core_writes == initial.core_writes + 2);
	n->status.reachable = false;
	mesh->loop.now.tv_sec += 2 * 86400;
	node_storage_tick(mesh, wall + 4 * 86400);
	node_storage_wait(mesh);
	node_storage_get_stats(mesh, &stats);
	assert(stats.core_writes == initial.core_writes + 2);
	assert(node_storage_flush(mesh));
	meshlink_close(mesh);
	assert(meshlink_destroy(base));
}

static void test_edge_clocks(void) {
	const char *base = "observation_edge_conf";
	assert(meshlink_destroy(base));
	meshlink_handle_t *mesh = meshlink_open(base, "owner", "observation", DEV_CLASS_PORTABLE);
	assert(mesh);
	time_t wall = 1700000000;
	node_storage_set_clock(mesh, fixed_clock, &wall);
	for(unsigned walk = 0; walk < 2; walk++) {
		node_t *n = new_node();
		n->name = strdup(walk ? "walk" : "handled");
		assert(n->name);
		node_add(mesh, n);
		assert(node_storage_write(mesh, n, false));
		assert(node_storage_note_edge(mesh, n, true, (time_t)-1));
		assert(!n->last_reachable);
		if(walk) {
			n->status.reachable = true;
			node_storage_tick(mesh, wall);
		} else {
			node_storage_note_seen(mesh, n, wall);
		}
		// First valid history is already durable without waiting for the writer.
		assert(disk_seen(mesh, n->name) == wall);
		assert(node_storage_note_edge(mesh, n, true, wall - 120));
		assert(n->last_reachable == wall);
		assert(node_storage_note_edge(mesh, n, true, wall + 1));
		assert(n->last_reachable == wall + 1); // Edges bypass the observation bucket.
		assert(node_storage_note_edge(mesh, n, false, wall + 2));
		assert(node_storage_note_edge(mesh, n, false, (time_t)-1));
		assert(n->last_unreachable == wall + 2);
		assert(node_storage_note_edge(mesh, n, false, wall - 1));
		assert(n->last_unreachable == wall + 2); // A later down edge is not erased by an earlier sample.
		n->status.reachable = false;
	}
	assert(node_storage_flush(mesh));
	meshlink_close(mesh);
	mesh = meshlink_open(base, "owner", "observation", DEV_CLASS_PORTABLE);
	assert(mesh);
	assert(((node_t *)meshlink_get_node(mesh, "walk"))->last_reachable == wall + 1);
	meshlink_close(mesh);
	assert(meshlink_destroy(base));
}

static bool counting_backend(const char *path, const void *data, size_t len, const void *key, size_t keylen, void *context) {
	(void)path;
	(void)data;
	(void)len;
	(void)key;
	(void)keylen;
	(*(unsigned *)context)++;
	return true;
}

static void test_deployment_schedule(void) {
	const char *base = "observation_scale_conf";
	assert(meshlink_destroy(base));
	meshlink_handle_t *mesh = meshlink_open(base, "owner", "observation", DEV_CLASS_PORTABLE);
	assert(mesh);
	unsigned writes = 0;
	node_storage_set_backend(mesh, counting_backend, &writes);
	time_t wall = 1700000000, clock = wall, monotonic = mesh->loop.now.tv_sec;
	node_storage_set_clock(mesh, fixed_clock, &clock);
	unsigned ongoing = 0;
	// Reuse one lightweight owner: 3,000 independent ten-peer schedules, no
	// 30,000 filesystem commits or 3,000 listener/event-loop instances.
	for(unsigned owner = 0; owner < 3000; owner++) {
		node_t *peers[10];
		mesh->loop.now.tv_sec = monotonic;
		clock = wall;
		for(unsigned i = 0; i < 10; i++) {
			char name[32];
			snprintf(name, sizeof name, "peer%u_%u", owner, i);
			peers[i] = observed_peer(mesh, name, wall);
		}
		unsigned first_seen_writes = writes;
		for(unsigned hour = 1; hour <= 24; hour++) {
			mesh->loop.now.tv_sec = monotonic + hour * 3600;
			clock = wall + hour * 3600;
			node_storage_tick(mesh, clock);
			node_storage_wait(mesh);
		}
		assert(writes - first_seen_writes == 10);
		ongoing += writes - first_seen_writes;
		for(unsigned i = 0; i < 10; i++) {
			peers[i]->status.reachable = false;
			node_del(mesh, peers[i]);
		}
	}
	assert(ongoing == 30000);
	node_storage_set_backend(mesh, NULL, NULL);
	meshlink_close(mesh);
	assert(meshlink_destroy(base));
}

static bool listed(meshlink_node_t **nodes, size_t nmemb, const char *name) {
	for(size_t i = 0; i < nmemb; i++) {
		if(nodes[i] && !strcmp(((node_t *)nodes[i])->name, name)) {
			return true;
		}
	}

	return false;
}

static void test_offline_query_window(void) {
	const char *base = "observation_query_conf";
	assert(meshlink_destroy(base));
	meshlink_handle_t *mesh = meshlink_open(base, "owner", "observation", DEV_CLASS_PORTABLE);
	assert(mesh);
	time_t wall = 1700000000;
	node_t *n = observed_peer(mesh, "peer", wall);
	n->status.reachable = false;
	n->last_reachable = wall + 1;
	n->last_unreachable = wall - 1;
	size_t nmemb = 0;
	meshlink_node_t **nodes = meshlink_get_all_nodes_by_last_reachable(mesh, wall, wall + 10, NULL, &nmemb);
	assert(!listed(nodes, nmemb, "peer"));
	free(nodes);

	n->status.reachable = true;
	time_t now = time(NULL);
	nmemb = 0;
	nodes = meshlink_get_all_nodes_by_last_reachable(mesh, now - 5, now + 5, NULL, &nmemb);
	assert(listed(nodes, nmemb, "peer"));
	free(nodes);
	meshlink_close(mesh);
	assert(meshlink_destroy(base));
}

static unsigned storage_errors;

static void count_storage_error(meshlink_handle_t *mesh, meshlink_errno_t err) {
	(void)mesh;

	if(err == MESHLINK_ESTORAGE) {
		storage_errors++;
	}
}

static void test_stop_flush_reports(void) {
	const char *base = "observation_stop_flush";
	assert(meshlink_destroy(base));
	meshlink_handle_t *mesh = meshlink_open(base, "owner", "observation", DEV_CLASS_PORTABLE);
	assert(mesh);
	meshlink_set_error_cb(mesh, count_storage_error);
	node_t *n = observed_peer(mesh, "peer", 1700000000);
	storage_errors = 0;
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	n->last_reachable += 120;
	node_storage_mark(n, NODE_STORAGE_OBSERVATION);
	mesh->loop.now.tv_sec += 10;
	node_storage_tick(mesh, n->last_reachable);
	node_storage_wait(mesh);
	assert(!storage_errors);
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	meshlink_stop(mesh);
	assert(storage_errors == 1);
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	meshlink_close(mesh);
	assert(meshlink_destroy(base));
}

void test_node_observation(void) {
	test_checkpoint();
	test_edge_clocks();
	test_deployment_schedule();
	test_offline_query_window();
	test_stop_flush_reports();
}
