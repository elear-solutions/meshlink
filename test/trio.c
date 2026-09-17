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
static struct sync_flag saw_type8_relay;
static struct sync_flag leftover_ascii_type8;

static void trio_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	if(text && strstr(text, "Relaying type-8 via UDP")) {
		set_sync_flag(&saw_type8_relay, true);
	}

	if(text && (strstr(text, "Sending REQ_SPTPS via UDP")
	            || strstr(text, "Got REQ_SPTPS via UDP")
	            || strstr(text, "Ignoring failed REQ_SPTPS via UDP"))) {
		set_sync_flag(&leftover_ascii_type8, true);
	}

	log_cb(mesh, level, text);
}

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
	init_sync_flag(&saw_type8_relay);
	init_sync_flag(&leftover_ascii_type8);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, trio_log_cb);

	// Create three instances.

	const char *name[3] = {"foo", "bar", "baz"};
	meshlink_handle_t *mesh[3];

	for(int i = 0; i < 3; i++) {
		char *path = NULL;
		assert(asprintf(&path, "trio_conf.%d", i) != -1 && path);

		assert(meshlink_destroy(path));
		mesh[i] = meshlink_open(path, name[i], "trio", i ? DEV_CLASS_STATIONARY : DEV_CLASS_BACKBONE);
		assert(mesh[i]);
		free(path);

		if(!i) {
			devtool_set_external_ip_address(mesh[i], meshlink_get_self(mesh[i]), "127.0.0.1");
		}

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

	// Send a packet, expect it is received

	meshlink_set_receive_cb(mesh[1], receive_cb);

	for(int i = 0; i < 15; i++) {
		assert(meshlink_send(mesh[2], meshlink_get_node(mesh[2], name[1]), "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			break;
		}
	}

	assert(wait_sync_flag(&received, 15));

	// Star: bar and baz each have a META to foo, not to each other.

	assert(count_edge_pairs(mesh[1], "foo", "bar") == 1);
	assert(count_edge_pairs(mesh[1], "foo", "baz") == 1);
	assert(count_edge_pairs(mesh[1], "bar", "baz") == 0);
	assert(devtool_outgoing_count(mesh[0]) == 0);
	assert(devtool_outgoing_count(mesh[1]) == 1);
	assert(devtool_outgoing_count(mesh[2]) == 1);

	// Dest has no UDP, nexthop does: binary type-8 relay, Hello arrives, no leftover #108 ASCII logs.
	set_sync_flag(&received, false);
	set_sync_flag(&saw_type8_relay, false);
	set_sync_flag(&leftover_ascii_type8, false);

	for(int i = 0; i < 15; i++) {
		assert(devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], name[1]), meshlink_get_node(mesh[2], name[0])));
		assert(meshlink_send(mesh[2], meshlink_get_node(mesh[2], name[1]), "Hello", 5));

		if(wait_sync_flag(&received, 1) && check_sync_flag(&saw_type8_relay)) {
			break;
		}

		set_sync_flag(&received, false);
		set_sync_flag(&saw_type8_relay, false);
	}

	assert(wait_sync_flag(&received, 15));
	assert(check_sync_flag(&saw_type8_relay));
	assert(!check_sync_flag(&leftover_ascii_type8));

	// dest == nexthop is rejected
	assert(!devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], name[1]), meshlink_get_node(mesh[2], name[1])));

	// Negative: nexthop UDP unconfirmed → META only, no type-8 log, Hello still arrives.
	// Drop any late first-loop Hello so this phase cannot pass on a stale flag.
	set_sync_flag(&received, false);
	set_sync_flag(&saw_type8_relay, false);
	set_sync_flag(&leftover_ascii_type8, false);
	usleep(200000);
	set_sync_flag(&received, false);
	set_sync_flag(&saw_type8_relay, false);

	for(int i = 0; i < 15; i++) {
		assert(devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], name[1]), meshlink_get_node(mesh[2], name[0])));
		devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], name[0]), false);
		assert(meshlink_send(mesh[2], meshlink_get_node(mesh[2], name[1]), "Hello", 5));

		if(wait_sync_flag(&received, 1) && !check_sync_flag(&saw_type8_relay)) {
			break;
		}

		set_sync_flag(&received, false);
		set_sync_flag(&saw_type8_relay, false);
	}

	assert(wait_sync_flag(&received, 15));
	assert(!check_sync_flag(&saw_type8_relay));
	assert(!check_sync_flag(&leftover_ascii_type8));

	assert(meshlink_get_node(mesh[1], name[2]));
	assert(meshlink_get_node(mesh[2], name[1]));

	for(int i = 0; i < 3; i++) {
		meshlink_stop(mesh[i]);
	}

	// Clean up.

	for(int i = 0; i < 3; i++) {
		meshlink_close(mesh[i]);
	}
}
