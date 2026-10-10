#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/meshlink.h"
#include "utils.h"

// meshlink_send() datagrams stop reaching the receive callback once the receiver has
// channel state for the sender. The drop must be visible in the log, rate limited.

static struct sync_flag datagram_flag;

static void receive_cb(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len) {
	(void)mesh;

	if(!strcmp(source->name, "a") && len == 5 && !memcmp(data, "hello", 5)) {
		set_sync_flag(&datagram_flag, true);
	}
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)port;
	(void)data;
	(void)len;

	return false;
}

#define DROP_WARNING "b: Dropped 5-byte packet from a that is not a channel segment"

int main(void) {
	init_sync_flag(&datagram_flag);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	meshlink_handle_t *mesh_a, *mesh_b;
	open_meshlink_pair(&mesh_a, &mesh_b, "datagram_channel_mix");

	meshlink_set_receive_cb(mesh_b, receive_cb);
	start_meshlink_pair(mesh_a, mesh_b);

	meshlink_node_t *b = meshlink_get_node(mesh_a, "b");
	assert(b);

	// Without channel state on b, datagrams reach the receive callback.
	// Datagrams sent before the key exchange completes are lost, so retry.

	for(int i = 0; i < 15; i++) {
		assert(meshlink_send(mesh_a, b, "hello", 5));

		if(wait_sync_flag(&datagram_flag, 1)) {
			break;
		}
	}

	assert(check_sync_flag(&datagram_flag));
	assert(!log_contains(DROP_WARNING));

	// An accept callback gives b channel state for every reachable node, including a.

	meshlink_set_channel_accept_cb(mesh_b, accept_cb);
	reset_sync_flag(&datagram_flag);

	size_t mark = log_mark();
	assert(meshlink_send(mesh_a, b, "hello", 5));
	assert_after(log_find(mark, DROP_WARNING " (1 since last report)") >= 0, 5);
	assert(log_count_from(mark, DROP_WARNING) == 1);
	assert(!check_sync_flag(&datagram_flag));

	// A second drop within 10 seconds is counted, not logged.

	assert(meshlink_send(mesh_a, b, "hello", 5));
	sleep(2);
	assert(log_count_from(mark, DROP_WARNING) == 1);
	assert(!check_sync_flag(&datagram_flag));

	// Once the window has passed, the next drop reports both.

	sleep(10);
	assert(meshlink_send(mesh_a, b, "hello", 5));
	assert_after(log_find(mark, DROP_WARNING " (2 since last report)") >= 0, 5);
	assert(log_count_from(mark, DROP_WARNING) == 2);
	assert(!check_sync_flag(&datagram_flag));

	close_meshlink_pair(mesh_a, mesh_b);
	free_captured_log();
}
