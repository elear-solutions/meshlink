#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

static struct sync_flag received;
static struct sync_flag bar_learned_baz;
static struct sync_flag baz_learned_bar;

static void receive_cb(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len) {
	(void)mesh;
	(void)source;

	if(len == 5 && !memcmp(data, "Hello", 5)) {
		set_sync_flag(&received, true);
	}
}

static void bar_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;
	(void)reachable;

	if(!strcmp(node->name, "baz")) {
		set_sync_flag(&bar_learned_baz, true);
	}
}

static void baz_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;
	(void)reachable;

	if(!strcmp(node->name, "bar")) {
		set_sync_flag(&baz_learned_bar, true);
	}
}

int main(void) {
	init_sync_flag(&received);
	init_sync_flag(&bar_learned_baz);
	init_sync_flag(&baz_learned_bar);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	// Create three instances.

	const char *name[3] = {"foo", "bar", "baz"};
	meshlink_handle_t *mesh[3];

	for(int i = 0; i < 3; i++) {
		char *path = NULL;
		assert(asprintf(&path, "trio2_conf.%d", i) != -1 && path);

		assert(meshlink_destroy(path));
		mesh[i] = meshlink_open(path, name[i], "trio2", i ? DEV_CLASS_STATIONARY : DEV_CLASS_BACKBONE);
		assert(mesh[i]);
		free(path);

		assert(meshlink_set_canonical_address(mesh[i], meshlink_get_self(mesh[i]), "localhost", NULL));
		meshlink_enable_discovery(mesh[i], false);
	}

	join_meshlink_peer(mesh[0], mesh[1]);
	join_meshlink_peer(mesh[0], mesh[2]);

	assert(meshlink_get_node(mesh[1], name[0]));
	assert(meshlink_get_node(mesh[2], name[0]));

	// second and third node should not know each other yet

	assert(!meshlink_get_node(mesh[1], name[2]));
	assert(!meshlink_get_node(mesh[2], name[1]));

	// start the nodes

	meshlink_set_node_status_cb(mesh[1], bar_status_cb);
	meshlink_set_node_status_cb(mesh[2], baz_status_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(mesh[i]));
	}

	// the nodes should now learn about each other

	assert(wait_sync_flag(&bar_learned_baz, 5));
	assert(wait_sync_flag(&baz_learned_bar, 5));

	assert_after(count_edge_pairs(mesh[1], "foo", "bar") == 1 && count_edge_pairs(mesh[1], "foo", "baz") == 1, 15);
	assert(count_edge_pairs(mesh[1], "bar", "baz") == 0);
	assert(devtool_outgoing_count(mesh[0]) == 0);
	assert(devtool_outgoing_count(mesh[1]) == 1);
	assert(devtool_outgoing_count(mesh[2]) == 1);

	meshlink_set_receive_cb(mesh[1], receive_cb);

	for(int i = 0; i < 25; i++) {
		assert(meshlink_send(mesh[2], meshlink_get_node(mesh[2], name[1]), "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			break;
		}
	}

	assert(wait_sync_flag(&received, 15));
	assert(meshlink_get_node(mesh[1], name[2]));
	assert(meshlink_get_node(mesh[2], name[1]));

	// Clean up.

	for(int i = 0; i < 3; i++) {
		meshlink_close(mesh[i]);
	}
}
