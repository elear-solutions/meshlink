/* A peer restarts (new process, new session) while the other node still holds
   the old channel open. The restarted peer opens its first channel from the same
   utcp port pair and ISN as before: the new SYN must be accepted, not reset, and
   data must flow both ways. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include <assert.h>
#include <string.h>

#include "meshlink_internal.h"
#include "utils.h"
#include "utcp-peek.h"

#define PORT 7
#define PREFIX "channels_session_restart"

struct receiver {
	struct sync_flag flag;
	char data[64];
	size_t len;
	unsigned resets;
};

static struct receiver b_first;
static struct receiver b_second;
static struct receiver a_rx;

static meshlink_channel_t *b_channels[2];
static unsigned b_accepted;
static struct sync_flag b_accept_flag;
static struct sync_flag a_open_flag;
static size_t a_open_len;

static void receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;

	struct receiver *r = channel == b_channels[0] ? &b_first : channel == b_channels[1] ? &b_second : &a_rx;

	if(len == 0) {
		r->resets++;
		set_sync_flag(&r->flag, true);
		return;
	}

	assert(r->len + len <= sizeof(r->data));
	memcpy(r->data + r->len, data, len);
	r->len += len;
	set_sync_flag(&r->flag, true);
}

static bool listen_cb(meshlink_handle_t *mesh, meshlink_node_t *node, uint16_t port) {
	(void)mesh;
	(void)node;

	return port == PORT;
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)port;
	(void)data;
	(void)len;

	assert(b_accepted < 2);
	b_channels[b_accepted++] = channel;
	meshlink_set_channel_receive_cb(mesh, channel, receive_cb);
	set_sync_flag(&b_accept_flag, true);

	return true;
}

static void poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	a_open_len = len;
	set_sync_flag(&a_open_flag, true);
}

static void node_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	if(reachable && node != meshlink_get_self(mesh)) {
		set_sync_flag(mesh->priv, true);
	}
}

static meshlink_channel_t *open_channel(meshlink_handle_t *mesh, meshlink_node_t *b) {
	reset_sync_flag(&a_open_flag);
	a_open_len = 0;

	/* The first channel of a fresh process always gets the same port pair and ISN. A restarted
	   mesh's PRNG is seeded at open, so give it the same state, under the mutex so the mesh
	   thread cannot draw in between. */
	static const uint64_t first_channel_state[4] = {1, 2, 3, 4};

	pthread_mutex_lock(&mesh->mutex);
	memcpy(mesh->prng_state, first_channel_state, sizeof(mesh->prng_state));
	meshlink_channel_t *channel = meshlink_channel_open(mesh, b, PORT, receive_cb, NULL, 0);
	pthread_mutex_unlock(&mesh->mutex);
	assert(channel);

	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);
	assert(wait_sync_flag(&a_open_flag, 10));
	assert(a_open_len != 0);

	return channel;
}

static void send_all(meshlink_handle_t *mesh, meshlink_channel_t *channel, const char *text) {
	assert(meshlink_channel_send(mesh, channel, text, strlen(text)) == (ssize_t)strlen(text));
}

/* Waits up to 10 seconds for the receiver to have exactly text. */
static void expect_data(struct receiver *r, const char *text) {
	for(int i = 0; i < 10 && r->len < strlen(text); i++) {
		wait_sync_flag(&r->flag, 1);
		reset_sync_flag(&r->flag);
	}

	assert(r->len == strlen(text));
	assert(memcmp(r->data, text, r->len) == 0);
}

int main(void) {
	init_sync_flag(&b_first.flag);
	init_sync_flag(&b_second.flag);
	init_sync_flag(&a_rx.flag);
	init_sync_flag(&b_accept_flag);
	init_sync_flag(&a_open_flag);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	meshlink_handle_t *a, *b;
	open_meshlink_pair(&a, &b, PREFIX);

	meshlink_set_channel_listen_cb(b, listen_cb);
	meshlink_set_channel_accept_cb(b, accept_cb);

	start_meshlink_pair(a, b);

	// The first incarnation of a opens a channel to b.

	meshlink_node_t *b_node = meshlink_get_node(a, "b");
	assert(b_node);

	meshlink_channel_t *first = open_channel(a, b_node);
	uint16_t src = utcp_peek_src(first->c);
	uint16_t dst = utcp_peek_dst(first->c);
	uint32_t iss = utcp_peek_iss(first->c);

	assert(wait_sync_flag(&b_accept_flag, 10));
	send_all(a, first, "first");
	expect_data(&b_first, "first");

	// a is killed: no close, no goodbye. b keeps its channel handle open.

	meshlink_close(a);

	// a comes back as a new process: same configuration, new session, same first port pair.

	// open_meshlink_pair() keeps a's configuration in "<prefix>_conf.1".

	a = meshlink_open(PREFIX "_conf.1", "a", PREFIX, DEV_CLASS_BACKBONE);
	assert(a);
	meshlink_enable_discovery(a, false);

	struct sync_flag a_reachable;
	init_sync_flag(&a_reachable);
	a->priv = &a_reachable;
	meshlink_set_node_status_cb(a, node_status_cb);

	assert(meshlink_start(a));
	assert(wait_sync_flag(&a_reachable, 15));

	meshlink_set_node_status_cb(a, NULL);
	a->priv = NULL;

	// Its new channel is accepted by b although b's old channel for that port pair was never closed.

	reset_sync_flag(&b_accept_flag);

	b_node = meshlink_get_node(a, "b");
	assert(b_node);

	meshlink_channel_t *second = open_channel(a, b_node);

	assert(utcp_peek_src(second->c) == src);
	assert(utcp_peek_dst(second->c) == dst);
	assert(utcp_peek_iss(second->c) == iss);

	assert(wait_sync_flag(&b_accept_flag, 10));
	assert(b_accepted == 2);

	// b's old channel was reset by the session change and still belongs to its owner.

	assert(b_first.resets == 1);

	// Data flows both ways on the new channel, and none of it reaches the old one.

	send_all(a, second, "ping");
	expect_data(&b_second, "ping");

	send_all(b, b_channels[1], "pong");
	expect_data(&a_rx, "pong");

	assert(b_first.len == strlen("first"));
	assert(b_first.resets == 1);

	// b's owner closes the old channel; the new one is not affected.

	meshlink_channel_close(b, b_channels[0]);

	send_all(a, second, "more");
	expect_data(&b_second, "pingmore");

	meshlink_channel_close(a, second);
	meshlink_channel_close(b, b_channels[1]);

	close_meshlink_pair(a, b);

	return 0;
}
