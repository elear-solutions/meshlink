#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "../src/meshlink.h"

static bool saw_multicast_if_error;

static void discovery_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	if(text && strstr(text, "Could not set outgoing multicast interface")) {
		saw_multicast_if_error = true;
	}

	log_cb(mesh, level, text);
}

static void pair_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)node;

	if(reachable && meshlink_get_self(mesh) != node) {
		set_sync_flag(mesh->priv, true);
	}
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, discovery_log_cb);

	// Open two new meshlink instance.

	meshlink_handle_t *mesh_a, *mesh_b;
	open_meshlink_pair(&mesh_a, &mesh_b, "discovery");

	// Forget the canoncial address

	assert(meshlink_clear_canonical_address(mesh_a, meshlink_get_node(mesh_a, "b")));
	assert(meshlink_clear_canonical_address(mesh_b, meshlink_get_node(mesh_b, "a")));

	int port_a = meshlink_get_port(mesh_a);
	int port_b = meshlink_get_port(mesh_b);

	// Swap and change ports

	port_a++;
	port_b++;

	meshlink_close(mesh_a);
	assert(meshlink_set_port(mesh_b, port_a));
	meshlink_close(mesh_b);
	mesh_a = meshlink_open("discovery_conf.1", "a", "discovery", DEV_CLASS_BACKBONE);
	assert(mesh_a);
	assert(meshlink_set_port(mesh_a, port_b));
	mesh_b = meshlink_open("discovery_conf.2", "b", "discovery", DEV_CLASS_BACKBONE);
	assert(mesh_b);

	assert(meshlink_get_port(mesh_a) == port_b);
	assert(meshlink_get_port(mesh_b) == port_a);

	// Verify that the nodes can find each other

	meshlink_enable_discovery(mesh_a, true);
	meshlink_enable_discovery(mesh_b, true);

	struct sync_flag pair_status = {.flag = false};
	init_sync_flag(&pair_status);

	mesh_a->priv = &pair_status;
	meshlink_set_node_status_cb(mesh_a, pair_status_cb);

	assert(meshlink_start(mesh_a));
	assert(meshlink_start(mesh_b));

	if(!wait_sync_flag(&pair_status, 5)) {
		meshlink_set_node_status_cb(mesh_a, NULL);
		mesh_a->priv = NULL;
		close_meshlink_pair(mesh_a, mesh_b);

		if(saw_multicast_if_error) {
			fprintf(stderr, "SKIP: mDNS discovery unavailable (cannot set multicast interface)\n");
			exit(77);
		}

		assert(!"nodes failed to discover each other");
	}

	meshlink_set_node_status_cb(mesh_a, NULL);
	mesh_a->priv = NULL;

	// Clean up.

	close_meshlink_pair(mesh_a, mesh_b);
}
