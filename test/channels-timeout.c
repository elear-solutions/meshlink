#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>

#include "../src/meshlink.h"
#include "utils.h"

static bool listen_cb(meshlink_handle_t *mesh, meshlink_node_t *node, uint16_t port) {
	(void)mesh;
	(void)node;

	return port == 7 || port == 8;
}

static struct sync_flag accept7_flag;
static struct sync_flag accept8_flag;
static meshlink_channel_t *accepted7;
static meshlink_channel_t *accepted8;

static struct sync_flag a7_closed;
static struct sync_flag a8_closed;
static struct sync_flag b7_closed;
static struct sync_flag b8_closed;
static struct sync_flag b7_data;
static struct sync_flag b8_data;

static struct sync_flag poll7_flag;
static struct sync_flag poll8_flag;
static size_t poll7_len;
static size_t poll8_len;

static void reset_timeout_flags(void) {
	accepted7 = NULL;
	accepted8 = NULL;
	reset_sync_flag(&accept7_flag);
	reset_sync_flag(&accept8_flag);
	reset_sync_flag(&a7_closed);
	reset_sync_flag(&a8_closed);
	reset_sync_flag(&b7_closed);
	reset_sync_flag(&b8_closed);
	reset_sync_flag(&b7_data);
	reset_sync_flag(&b8_data);
	reset_sync_flag(&poll7_flag);
	reset_sync_flag(&poll8_flag);
	poll7_len = 0;
	poll8_len = 0;
}

static void close_if_zero(struct sync_flag *closed, size_t len) {
	if(len == 0) {
		set_sync_flag(closed, true);
	}
}

static void a7_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;
	close_if_zero(&a7_closed, len);
}

static void a8_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;
	close_if_zero(&a8_closed, len);
}

static void b7_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;

	if(len == 0) {
		set_sync_flag(&b7_closed, true);
	} else {
		set_sync_flag(&b7_data, true);
	}
}

static void b8_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;

	if(len == 0) {
		set_sync_flag(&b8_closed, true);
	} else {
		set_sync_flag(&b8_data, true);
	}
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)data;
	(void)len;

	if(port == 7) {
		accepted7 = channel;
		meshlink_set_channel_receive_cb(mesh, channel, b7_receive_cb);
		set_sync_flag(&accept7_flag, true);
		return true;
	}

	if(port == 8) {
		accepted8 = channel;
		meshlink_set_channel_receive_cb(mesh, channel, b8_receive_cb);
		set_sync_flag(&accept8_flag, true);
		return true;
	}

	return false;
}

static void poll7_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	poll7_len = len;
	set_sync_flag(&poll7_flag, true);
}

static void poll8_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	poll8_len = len;
	set_sync_flag(&poll8_flag, true);
}

static void test_per_channel_vs_node_default(void) {
	reset_timeout_flags();

	meshlink_handle_t *mesh_a, *mesh_b;
	open_meshlink_pair(&mesh_a, &mesh_b, "channels_timeout_node");

	meshlink_set_channel_listen_cb(mesh_b, listen_cb);
	meshlink_set_channel_accept_cb(mesh_b, accept_cb);

	meshlink_node_t *b = meshlink_get_node(mesh_a, "b");
	assert(b);

	meshlink_channel_t *ch7 = meshlink_channel_open(mesh_a, b, 7, a7_receive_cb, NULL, 0);
	meshlink_channel_t *ch8 = meshlink_channel_open(mesh_a, b, 8, a8_receive_cb, NULL, 0);
	assert(ch7);
	assert(ch8);

	meshlink_set_channel_poll_cb(mesh_a, ch7, poll7_cb);
	meshlink_set_channel_poll_cb(mesh_a, ch8, poll8_cb);

	start_meshlink_pair(mesh_a, mesh_b);

	assert(wait_sync_flag(&poll7_flag, 10));
	assert(wait_sync_flag(&poll8_flag, 10));
	assert(poll7_len != 0);
	assert(poll8_len != 0);
	assert(wait_sync_flag(&accept7_flag, 10));
	assert(wait_sync_flag(&accept8_flag, 10));

	meshlink_set_channel_timeout(mesh_a, ch7, 1);

	meshlink_stop(mesh_b);

	assert(wait_sync_flag(&a7_closed, 3));
	assert(!check_sync_flag(&a8_closed));

	meshlink_channel_close(mesh_a, ch7);
	meshlink_channel_close(mesh_a, ch8);
	close_meshlink_pair(mesh_a, mesh_b);
}

static void test_idle_dead_while_reachable(void) {
	reset_timeout_flags();

	meshlink_handle_t *mesh_a, *mesh_b;
	open_meshlink_pair(&mesh_a, &mesh_b, "channels_timeout_idle");

	meshlink_set_channel_listen_cb(mesh_b, listen_cb);
	meshlink_set_channel_accept_cb(mesh_b, accept_cb);

	meshlink_node_t *b = meshlink_get_node(mesh_a, "b");
	assert(b);

	meshlink_channel_t *ch7 = meshlink_channel_open(mesh_a, b, 7, a7_receive_cb, NULL, 0);
	meshlink_channel_t *ch8 = meshlink_channel_open(mesh_a, b, 8, a8_receive_cb, NULL, 0);
	assert(ch7);
	assert(ch8);

	meshlink_set_channel_poll_cb(mesh_a, ch7, poll7_cb);
	meshlink_set_channel_poll_cb(mesh_a, ch8, poll8_cb);

	start_meshlink_pair(mesh_a, mesh_b);

	assert(wait_sync_flag(&poll7_flag, 10));
	assert(wait_sync_flag(&poll8_flag, 10));
	assert(wait_sync_flag(&accept7_flag, 10));
	assert(wait_sync_flag(&accept8_flag, 10));

	meshlink_set_channel_timeout(mesh_a, ch7, 1);
	meshlink_set_channel_timeout(mesh_b, accepted7, 1);

	assert(meshlink_channel_send(mesh_a, ch7, "burst7", 6) == 6);
	assert(meshlink_channel_send(mesh_a, ch8, "burst8", 6) == 6);
	assert(wait_sync_flag(&b7_data, 5));
	assert(wait_sync_flag(&b8_data, 5));

	assert(wait_sync_flag(&b7_closed, 5));
	assert(!check_sync_flag(&b8_closed));
	assert(!check_sync_flag(&a8_closed));

	meshlink_channel_close(mesh_a, ch7);
	meshlink_channel_close(mesh_a, ch8);
	close_meshlink_pair(mesh_a, mesh_b);
}

static void test_sendonly_ack_refresh(void) {
	reset_timeout_flags();

	meshlink_handle_t *mesh_a, *mesh_b;
	open_meshlink_pair(&mesh_a, &mesh_b, "channels_timeout_sendonly");

	meshlink_set_channel_listen_cb(mesh_b, listen_cb);
	meshlink_set_channel_accept_cb(mesh_b, accept_cb);

	meshlink_node_t *b = meshlink_get_node(mesh_a, "b");
	assert(b);

	meshlink_channel_t *ch7 = meshlink_channel_open(mesh_a, b, 7, a7_receive_cb, NULL, 0);
	assert(ch7);

	meshlink_set_channel_poll_cb(mesh_a, ch7, poll7_cb);

	start_meshlink_pair(mesh_a, mesh_b);

	assert(wait_sync_flag(&poll7_flag, 10));
	assert(poll7_len != 0);
	assert(wait_sync_flag(&accept7_flag, 10));

	meshlink_set_channel_timeout(mesh_a, ch7, 1);

	for(int i = 0; i < 15; i++) {
		assert(meshlink_channel_send(mesh_a, ch7, "frame", 5) == 5);
		usleep(200000);
		assert(!check_sync_flag(&a7_closed));
	}

	assert(wait_sync_flag(&b7_data, 5));
	assert(!check_sync_flag(&a7_closed));

	assert(wait_sync_flag(&a7_closed, 5));

	meshlink_channel_close(mesh_a, ch7);
	close_meshlink_pair(mesh_a, mesh_b);
}

int main(void) {
	init_sync_flag(&accept7_flag);
	init_sync_flag(&accept8_flag);
	init_sync_flag(&a7_closed);
	init_sync_flag(&a8_closed);
	init_sync_flag(&b7_closed);
	init_sync_flag(&b8_closed);
	init_sync_flag(&b7_data);
	init_sync_flag(&b8_data);
	init_sync_flag(&poll7_flag);
	init_sync_flag(&poll8_flag);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	test_per_channel_vs_node_default();
	test_idle_dead_while_reachable();
	test_sendonly_ack_refresh();

	return 0;
}
