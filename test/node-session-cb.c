/* meshlink_set_node_session_cb(): a peer that comes back with a new session is reported once, before
   its channels are reset and before its node status callback reports it reachable again. A peer that
   reconnects with the same session, or is seen for the first time, is not reported. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include <assert.h>
#include <string.h>

#include "meshlink.h"
#include "utils.h"

#define PORT 7
#define PREFIX "node_session_cb"

enum event {
	EVENT_SESSION,
	EVENT_RESET,
	EVENT_UP,
	EVENT_DOWN,
};

#define MAX_EVENTS 64

/* All callbacks run in b's mesh thread, but the test thread reads the events, so lock them. */
static pthread_mutex_t events_mutex = PTHREAD_MUTEX_INITIALIZER;
static enum event events[MAX_EVENTS];
static int num_events;

static struct sync_flag up_flag;
static struct sync_flag down_flag;
static struct sync_flag accept_flag;
static meshlink_handle_t *observer;
static meshlink_channel_t *b_channel;

static void add_event(enum event event) {
	pthread_mutex_lock(&events_mutex);
	assert(num_events < MAX_EVENTS);
	events[num_events++] = event;
	pthread_mutex_unlock(&events_mutex);
}

static int event_count(enum event event, int from) {
	int count = 0;

	pthread_mutex_lock(&events_mutex);

	for(int i = from; i < num_events; i++) {
		if(events[i] == event) {
			count++;
		}
	}

	pthread_mutex_unlock(&events_mutex);

	return count;
}

/* Index of the first event of this kind at or after from, or -1. */
static int event_find(enum event event, int from) {
	int found = -1;

	pthread_mutex_lock(&events_mutex);

	for(int i = from; i < num_events; i++) {
		if(events[i] == event) {
			found = i;
			break;
		}
	}

	pthread_mutex_unlock(&events_mutex);

	return found;
}

static int event_mark(void) {
	pthread_mutex_lock(&events_mutex);
	int mark = num_events;
	pthread_mutex_unlock(&events_mutex);

	return mark;
}

static void session_cb(meshlink_handle_t *mesh, meshlink_node_t *node) {
	assert(mesh == observer);
	assert(!strcmp(node->name, "a"));

	/* The callback runs with the recursive mesh mutex held, so calling back into MeshLink must not deadlock. */
	assert(meshlink_get_node(mesh, "a") == node);

	/* The old session's channel is still there when the callback runs, and the diagnostic call is callback-safe. */
	assert(meshlink_get_node_utcp_live_connection_count(mesh, node) == 1);

	add_event(EVENT_SESSION);
}

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(strcmp(node->name, "a")) {
		return;
	}

	add_event(reachable ? EVENT_UP : EVENT_DOWN);
	set_sync_flag(reachable ? &up_flag : &down_flag, true);
}

static void receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;

	if(len == 0) {
		add_event(EVENT_RESET);
	}
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

	b_channel = channel;
	meshlink_set_channel_receive_cb(mesh, channel, receive_cb);
	set_sync_flag(&accept_flag, true);

	return true;
}

static void open_channel_to_b(meshlink_handle_t *a) {
	reset_sync_flag(&accept_flag);

	meshlink_node_t *b_node = meshlink_get_node(a, "b");
	assert(b_node);

	meshlink_channel_t *channel = meshlink_channel_open(a, b_node, PORT, receive_cb, NULL, 0);
	assert(channel);
	assert(meshlink_channel_send(a, channel, "hi", 2) == 2);
	assert(wait_sync_flag(&accept_flag, 10));
}

int main(void) {
	init_sync_flag(&up_flag);
	init_sync_flag(&down_flag);
	init_sync_flag(&accept_flag);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	meshlink_handle_t *a, *b;
	open_meshlink_pair(&a, &b, PREFIX);

	meshlink_set_channel_listen_cb(b, listen_cb);
	meshlink_set_channel_accept_cb(b, accept_cb);
	meshlink_set_node_session_cb(b, session_cb);
	observer = b;

	// Test case #1: passing a NULL pointer for the mesh returns an error

	meshlink_errno = MESHLINK_OK;
	meshlink_set_node_session_cb(NULL, session_cb);
	assert(meshlink_errno == MESHLINK_EINVAL);

	// Test case #2: seeing a node for the first time is not a session change

	start_meshlink_pair(a, b);
	meshlink_set_node_status_cb(b, status_cb);

	assert(event_count(EVENT_SESSION, 0) == 0);

	// Test case #3: a peer that reconnects with the same session is not reported

	int mark = event_mark();

	reset_sync_flag(&down_flag);
	reset_sync_flag(&up_flag);
	meshlink_stop(a);
	assert(wait_sync_flag(&down_flag, 15));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&up_flag, 15));

	assert(event_count(EVENT_UP, mark) == 1);
	assert(event_count(EVENT_SESSION, 0) == 0);

	// Test case #4: a peer that restarts with a new session is reported exactly once,
	//               before its channels are reset and before it is reported reachable again

	open_channel_to_b(a);

	meshlink_node_t *a_node = meshlink_get_node(b, "a");
	assert(a_node);
	assert(meshlink_get_node_utcp_live_connection_count(b, a_node) == 1);

	reset_sync_flag(&down_flag);
	reset_sync_flag(&up_flag);
	meshlink_close(a);
	assert(wait_sync_flag(&down_flag, 15));
	mark = event_mark();

	// open_meshlink_pair() keeps a's configuration in "<prefix>_conf.1".

	a = meshlink_open(PREFIX "_conf.1", "a", PREFIX, DEV_CLASS_BACKBONE);
	assert(a);
	meshlink_enable_discovery(a, false);
	assert(meshlink_start(a));
	assert(wait_sync_flag(&up_flag, 15));

	assert(event_count(EVENT_SESSION, 0) == 1);
	assert(event_count(EVENT_RESET, mark) == 1);
	assert(event_count(EVENT_UP, mark) == 1);

	int session = event_find(EVENT_SESSION, mark);
	int reset = event_find(EVENT_RESET, mark);
	int up = event_find(EVENT_UP, mark);

	assert(session >= 0);
	assert(session < reset);
	assert(reset < up);

	// Test case #5: a channel that was reset by the session change is CLOSED, so it is no longer live,
	//               and aborting it by its owner keeps the count at 0 immediately

	assert(meshlink_get_node_utcp_live_connection_count(b, a_node) == 0);
	meshlink_channel_abort(b, b_channel);
	assert(meshlink_get_node_utcp_live_connection_count(b, a_node) == 0);

	// Test case #6: invalid arguments return an error

	meshlink_errno = MESHLINK_OK;
	assert(meshlink_get_node_utcp_live_connection_count(NULL, a_node) == (size_t) - 1);
	assert(meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(meshlink_get_node_utcp_live_connection_count(b, NULL) == (size_t) - 1);
	assert(meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(meshlink_get_node_utcp_live_connection_count(a, a_node) == (size_t) - 1);
	assert(meshlink_errno == MESHLINK_EINVAL);

	// Test case #7: a plain open channel is live, and is no longer counted as soon as it is aborted

	open_channel_to_b(a);
	assert(meshlink_get_node_utcp_live_connection_count(b, a_node) == 1);
	meshlink_channel_abort(b, b_channel);
	assert(meshlink_get_node_utcp_live_connection_count(b, a_node) == 0);

	// Test case #8: a channel that is closed is no longer counted as soon as meshlink_channel_close() returns

	open_channel_to_b(a);
	assert(meshlink_get_node_utcp_live_connection_count(b, a_node) == 1);
	meshlink_channel_close(b, b_channel);
	assert(meshlink_get_node_utcp_live_connection_count(b, a_node) == 0);

	// Done.

	close_meshlink_pair(a, b);

	return 0;
}
