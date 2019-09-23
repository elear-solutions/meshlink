#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <pthread.h>

#include "../src/meshlink.h"
#include "utils.h"

static volatile bool b_responded = false;
static volatile bool b_closed = false;
static volatile size_t a_poll_cb_len;

static void log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	static struct timeval tv0;
	struct timeval tv;

	if(tv0.tv_sec == 0) {
		gettimeofday(&tv0, NULL);
	}

	gettimeofday(&tv, NULL);
	fprintf(stderr, "%u.%.03u ", (unsigned int)(tv.tv_sec - tv0.tv_sec), (unsigned int)tv.tv_usec / 1000);

	if(mesh) {
		fprintf(stderr, "(%s) ", mesh->name);
	}

	fprintf(stderr, "[%d] %s\n", level, text);
}

static void a_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;

	if(len == 5 && !memcmp(data, "Hello", 5)) {
		b_responded = true;
	} else if(len == 0) {
		b_closed = true;
		set_sync_flag(channel->priv, true);
	}
}

static void b_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	// Send one message back, then close the channel.
	if(len) {
		meshlink_channel_send(mesh, channel, data, len);
	}

	meshlink_channel_close(mesh, channel);
}

static bool reject_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)port;
	(void)data;
	(void)len;

	return false;
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)port;

	meshlink_set_channel_accept_cb(mesh, NULL);
	meshlink_set_channel_receive_cb(mesh, channel, b_receive_cb);

	if(data) {
		b_receive_cb(mesh, channel, data, len);
	}

	return true;
}

static void poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)len;

	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	set_sync_flag(channel->priv, true);
}

static void poll_cb2(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)mesh;
	(void)channel;

	a_poll_cb_len = len;
	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	set_sync_flag(channel->priv, true);
}

int main() {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	meshlink_handle_t *a, *b;
	open_meshlink_pair(&a, &b, "channels-cornercases");

	// Set the callbacks.

	meshlink_set_channel_accept_cb(a, reject_cb);
	meshlink_set_channel_accept_cb(b, accept_cb);

	// Open a channel from a to b before starting the mesh.

	meshlink_node_t *nb = meshlink_get_node(a, "b");
	assert(nb);

	struct sync_flag channel_opened = {.flag = false};

	meshlink_channel_t *channel = meshlink_channel_open(a, nb, 7, a_receive_cb, NULL, 0);
	assert(channel);

	channel->priv = &channel_opened;
	meshlink_set_channel_poll_cb(a, channel, poll_cb);

	// Start MeshLink and wait for the channel to become connected.
	start_meshlink_pair(a, b);

	assert(wait_sync_flag(&channel_opened, 20));

	// Re-initialize everything
	close_meshlink_pair(a, b, "channels-cornercases");
	b_responded = false;
	b_closed = false;
	channel_opened.flag = false;
	open_meshlink_pair(&a, &b, "channels-cornercases");

	meshlink_set_channel_accept_cb(a, reject_cb);
	meshlink_set_channel_accept_cb(b, accept_cb);

	start_meshlink_pair(a, b);

	// Create a channel to b
	nb = meshlink_get_node(a, "b");
	assert(nb);

	channel = meshlink_channel_open(a, nb, 7, a_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = &channel_opened;
	meshlink_set_channel_poll_cb(a, channel, poll_cb);

	assert(wait_sync_flag(&channel_opened, 20));

	assert(!b_responded);
	assert(!b_closed);

	// Send a message to b

	struct sync_flag channel_closed = {.flag = false};
	channel->priv = &channel_closed;

	meshlink_channel_send(a, channel, "Hello", 5);

	assert(wait_sync_flag(&channel_closed, 20));
	assert(b_responded);
	assert(b_closed);

	// Try to create a second channel

	struct sync_flag channel_polled = {.flag = false};

	meshlink_channel_t *channel2 = meshlink_channel_open(a, nb, 7, a_receive_cb, NULL, 0);
	assert(channel2);
	channel2->priv = &channel_polled;
	meshlink_set_channel_poll_cb(a, channel2, poll_cb2);

	assert(wait_sync_flag(&channel_polled, 20));

	assert(0 == a_poll_cb_len);

	return 0;
}
