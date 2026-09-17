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

/* Camera→backbone reconnect backoff. Backbone never dual-dials (finding 5).
   Camera↔camera simultaneous-connect drop loops wait for finding 7. */

#define MEASURE_SECONDS 8
#define MAX_TRIES_IN_WINDOW 4

static void test_drop_after_activate_backs_off(void) {
	printf("\n=== T17: camera retries the backbone with backoff while it is down ===\n");

	assert(meshlink_destroy("reconnect_backoff_conf.1"));
	assert(meshlink_destroy("reconnect_backoff_conf.2"));

	meshlink_handle_t *a = meshlink_open("reconnect_backoff_conf.1", "a", "reconnect_backoff", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("reconnect_backoff_conf.2", "b", "reconnect_backoff", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int a_port = meshlink_get_port(a);
	assert(a_port > 0);

	join_meshlink_peer(a, b);

	meshlink_node_t *a_b = meshlink_get_node(a, "b");
	meshlink_node_t *b_a = meshlink_get_node(b, "a");
	assert(a_b && b_a);
	forget_addresses(b, b_a);
	hint_address(b, b_a, "127.0.0.1", a_port);

	meshlink_stop(a);

	char try_needle[128];
	snprintf(try_needle, sizeof try_needle, "b: Trying to connect to a at 127.0.0.1 port %d (recent)", a_port);

	assert(meshlink_start(b));
	sleep(MEASURE_SECONDS);

	int tries = log_count(try_needle);
	int retries = log_count("b: Trying to re-establish outgoing connection in ");
	printf("T17: in %d s camera tried %d times, backed off %d times\n", MEASURE_SECONDS, tries, retries);

	assert(tries >= 1);
	assert(retries >= 1);
	assert(tries <= MAX_TRIES_IN_WINDOW);
	assert(log_contains("b: Trying to re-establish outgoing connection in 5 seconds"));
	assert(devtool_outgoing_count(b) == 1);
	assert(!strcmp(devtool_backbone_intent_name(b), "a"));

	assert(meshlink_start(a));
	assert_after(meshlink_get_node_reachability(a, a_b, NULL, NULL) && meshlink_get_node_reachability(b, b_a, NULL, NULL), 45);

	devtool_node_status_t st;
	devtool_get_node_status(b, b_a, &st);
	assert(st.meta_connected);
	devtool_free_node_status(&st);
	devtool_get_node_status(a, a_b, &st);
	assert(st.meta_connected);
	devtool_free_node_status(&st);

	printf("T17 ok: camera backed off instead of looping (%d tries in %d s)\n", tries, MEASURE_SECONDS);

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
