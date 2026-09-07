#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* Reconnect backoff after an outgoing connection is dropped right after it activated.

   T17: every address a has for b is a black hole, so a's own outgoing connection to b
        hangs there for the whole address walk. While it does, a's simultaneous-connect
        tie-break ("keep the session initiated by the smaller name") drops each connection
        b makes to it the moment it has been activated. Since ack_h() resets the address
        walk at activation, b's reconnect starts again at recent[0] = a's real address:
        without a backoff it would reconnect, be dropped and reconnect again every round
        trip, with a full SPTPS handshake each time, until a's black hole times out. b
        must instead go through retry_outgoing() and reconnect a bounded number of times. */

#define MEASURE_SECONDS 8
#define MAX_TRIES_IN_WINDOW 4

static void test_drop_after_activate_backs_off(void) {
	printf("\n=== T17: a connection dropped right after activation is retried with backoff ===\n");

	assert(meshlink_destroy("reconnect_backoff_conf.1"));
	assert(meshlink_destroy("reconnect_backoff_conf.2"));

	/* Both STATIONARY, so both autoconnect; "a" is the smaller name and wins the tie-break. */
	meshlink_handle_t *a = meshlink_open("reconnect_backoff_conf.1", "a", "reconnect_backoff", DEV_CLASS_STATIONARY);
	meshlink_handle_t *b = meshlink_open("reconnect_backoff_conf.2", "b", "reconnect_backoff", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int a_port = meshlink_get_port(a);
	assert(a_port > 0);

	exchange_meshlink_pair(a, b);

	meshlink_node_t *a_b = meshlink_get_node(a, "b");
	meshlink_node_t *b_a = meshlink_get_node(b, "a");
	assert(a_b && b_a);
	forget_addresses(a, a_b);
	forget_addresses(b, b_a);

	/* Fill a's recent[] for b with listeners that accept the TCP connection and never
	   answer: each one holds a's outgoing connection for its authentication timeout
	   (about a second), so a has a pending connection to b for the whole walk. */
	int hole_fd[DEVTOOL_MAX_RECENT];

	for(int i = 0; i < DEVTOOL_MAX_RECENT; i++) {
		int hole_port = 0;
		hole_fd[i] = start_black_hole("127.0.0.1", &hole_port);
		hint_address(a, a_b, "127.0.0.1", hole_port);
	}

	hint_address(b, b_a, "127.0.0.1", a_port);

	char try_needle[128];
	snprintf(try_needle, sizeof try_needle, "b: Trying to connect to a at 127.0.0.1 port %d (recent)", a_port);
	const char *activated_needle = "b: Connection with a activated";
	const char *dropped_needle = "a: Dropping duplicate connection with b, keeping the one initiated by a";

	assert(meshlink_start(a));
	assert_after(log_contains("a: Trying to connect to b at 127.0.0.1 port "), 5);

	assert(meshlink_start(b));
	sleep(MEASURE_SECONDS);

	int tries = log_count(try_needle);
	int activations = log_count(activated_needle);
	int drops = log_count(dropped_needle);
	int retries = log_count("b: Trying to re-establish outgoing connection in ");
	printf("T17: in %d s b tried %d times, was activated %d times, dropped by a %d times, backed off %d times\n", MEASURE_SECONDS, tries, activations, drops, retries);

	/* The scenario really happened: b's connection was activated and then dropped by a. */
	assert(activations >= 1);
	assert(drops >= 1);

	/* ... and b did not reconnect in a loop: one initial try plus a retry per backoff step. */
	assert(retries >= 1);
	assert(tries <= MAX_TRIES_IN_WINDOW);
	assert(activations <= MAX_TRIES_IN_WINDOW);
	assert(log_contains("b: Trying to re-establish outgoing connection in 5 seconds"));

	/* Take the black holes away: a's pending connection is reset, its walk ends and backs
	   off, and b's next retry is accepted. */
	for(int i = 0; i < DEVTOOL_MAX_RECENT; i++) {
		close(hole_fd[i]);
	}

	assert_after(meshlink_get_node_reachability(a, a_b, NULL, NULL) && meshlink_get_node_reachability(b, b_a, NULL, NULL), 45);

	/* Whichever side's attempt went through, each has one live meta connection with the other. */
	devtool_node_status_t st;
	devtool_get_node_status(b, b_a, &st);
	assert(st.meta_connected);
	devtool_free_node_status(&st);
	devtool_get_node_status(a, a_b, &st);
	assert(st.meta_connected);
	devtool_free_node_status(&st);

	printf("T17 ok: b backed off instead of looping (%d tries in %d s), mesh converged once a gave up on the black holes\n", tries, MEASURE_SECONDS);

	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("reconnect_backoff_conf.1"));
	assert(meshlink_destroy("reconnect_backoff_conf.2"));
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	test_drop_after_activate_backs_off();

	free_captured_log();
	return 0;
}
