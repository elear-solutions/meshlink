#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* Bounded sequential startup: one best direct for 250 ms, then canonical. */

static struct sync_flag peer_reachable;
static const char *watched_peer;

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && watched_peer && !strcmp(node->name, watched_peer)) {
		set_sync_flag(&peer_reachable, true);
	}
}

static void test_direct_wins_before_bound(void) {
	printf("\n=== outgoing-bounded: direct authenticates before 250 ms, canonical never dialed ===\n");

	meshlink_handle_t *a, *b;
	open_meshlink_pair(&a, &b, "outgoing_bounded_fast");
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int b_port = meshlink_get_port(b);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	forget_addresses(a, node_b);
	hint_address(a, node_b, "127.0.0.1", b_port);
	assert(meshlink_set_canonical_address(a, node_b, "127.0.0.1", relay_port_str));

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	meshlink_set_node_status_cb(a, status_cb);
	size_t mark = log_mark();
	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));

	char canonical_needle[128];
	snprintf(canonical_needle, sizeof canonical_needle, "Trying to connect to b at 127.0.0.1 port %d (canonical)", relay_port);
	assert(log_find(mark, canonical_needle) < 0);

	printf("outgoing-bounded T1 ok: direct won, canonical not dialed\n");

	meshlink_set_node_status_cb(a, NULL);
	stop_meshlink_pair(a, b);
	close_meshlink_pair(a, b);
	stop_tcp_relay(relay);
}

static void test_black_hole_falls_to_canonical(void) {
	printf("\n=== outgoing-bounded: direct black hole -> canonical at 250 ms ===\n");

	assert(meshlink_destroy("outgoing_bounded_hole_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_hole_conf.2"));

	meshlink_handle_t *a = meshlink_open("outgoing_bounded_hole_conf.1", "a", "outgoing-bounded-hole", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_bounded_hole_conf.2", "b", "outgoing-bounded-hole", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int b_port = meshlink_get_port(b);
	int hole_port = 0;
	int hole_fd = start_black_hole("127.0.0.1", &hole_port);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	exchange_meshlink_pair(a, b);
	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	forget_addresses(a, node_b);
	hint_address(a, node_b, "127.0.0.1", hole_port);
	assert(meshlink_set_canonical_address(a, node_b, "127.0.0.1", relay_port_str));

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	meshlink_set_node_status_cb(a, status_cb);
	devtool_set_outgoing_startup_ms(200);
	size_t mark = log_mark();
	time_t started = time(NULL);
	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));
	devtool_set_outgoing_startup_ms(0);

	char recent_needle[128], canonical_needle[128];
	snprintf(recent_needle, sizeof recent_needle, "Trying to connect to b at 127.0.0.1 port %d (recent)", hole_port);
	snprintf(canonical_needle, sizeof canonical_needle, "Trying to connect to b at 127.0.0.1 port %d (canonical)", relay_port);
	long recent_at = log_find(mark, recent_needle);
	long canonical_at = log_find(mark, canonical_needle);
	assert(recent_at >= 0);
	assert(canonical_at >= 0);
	assert(recent_at < canonical_at);
	assert(time(NULL) - started <= 2);

	printf("outgoing-bounded T2 ok: canonical started after the bound, not the ordinary timeout\n");

	meshlink_set_node_status_cb(a, NULL);
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	close(hole_fd);
	stop_tcp_relay(relay);
	assert(meshlink_destroy("outgoing_bounded_hole_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_hole_conf.2"));
}

static void test_sync_fail_immediate_canonical(void) {
	printf("\n=== outgoing-bounded: direct fails immediately -> canonical now ===\n");

	assert(meshlink_destroy("outgoing_bounded_fail_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_fail_conf.2"));

	meshlink_handle_t *a = meshlink_open("outgoing_bounded_fail_conf.1", "a", "outgoing-bounded-fail", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_bounded_fail_conf.2", "b", "outgoing-bounded-fail", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int b_port = meshlink_get_port(b);
	int dead_port = find_closed_port("127.0.0.1");
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	exchange_meshlink_pair(a, b);
	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	forget_addresses(a, node_b);
	hint_address(a, node_b, "127.0.0.1", dead_port);
	assert(meshlink_set_canonical_address(a, node_b, "127.0.0.1", relay_port_str));

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	meshlink_set_node_status_cb(a, status_cb);
	size_t mark = log_mark();
	time_t started = time(NULL);
	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));
	assert(time(NULL) - started < 2);

	char canonical_needle[128];
	snprintf(canonical_needle, sizeof canonical_needle, "Trying to connect to b at 127.0.0.1 port %d (canonical)", relay_port);
	assert(log_find(mark, canonical_needle) >= 0);

	printf("outgoing-bounded T3 ok: refused direct went to canonical immediately\n");

	meshlink_set_node_status_cb(a, NULL);
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	stop_tcp_relay(relay);
	assert(meshlink_destroy("outgoing_bounded_fail_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_fail_conf.2"));
}

static void test_no_direct_canonical_now(void) {
	printf("\n=== outgoing-bounded: no direct candidate -> canonical immediately ===\n");

	assert(meshlink_destroy("outgoing_bounded_nodirect_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_nodirect_conf.2"));

	meshlink_handle_t *a = meshlink_open("outgoing_bounded_nodirect_conf.1", "a", "outgoing-bounded-nodirect", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_bounded_nodirect_conf.2", "b", "outgoing-bounded-nodirect", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int b_port = meshlink_get_port(b);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	exchange_meshlink_pair(a, b);
	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	forget_addresses(a, node_b);
	assert(meshlink_set_canonical_address(a, node_b, "127.0.0.1", relay_port_str));

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	meshlink_set_node_status_cb(a, status_cb);
	size_t mark = log_mark();
	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));

	char canonical_needle[128];
	snprintf(canonical_needle, sizeof canonical_needle, "Trying to connect to b at 127.0.0.1 port %d (canonical)", relay_port);
	assert(log_find(mark, canonical_needle) >= 0);
	assert(log_find(mark, "(recent)") < 0);
	assert(log_find(mark, "(known)") < 0);

	printf("outgoing-bounded T4 ok: no direct, canonical first\n");

	meshlink_set_node_status_cb(a, NULL);
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	stop_tcp_relay(relay);
	assert(meshlink_destroy("outgoing_bounded_nodirect_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_nodirect_conf.2"));
}

static void test_stop_during_bound(void) {
	printf("\n=== outgoing-bounded: stop during the 250 ms bound does not leak ===\n");

	assert(meshlink_destroy("outgoing_bounded_stop_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_stop_conf.2"));

	meshlink_handle_t *a = meshlink_open("outgoing_bounded_stop_conf.1", "a", "outgoing-bounded-stop", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_bounded_stop_conf.2", "b", "outgoing-bounded-stop", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int hole_port = 0;
	int hole_fd = start_black_hole("127.0.0.1", &hole_port);
	exchange_meshlink_pair(a, b);
	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	forget_addresses(a, node_b);
	hint_address(a, node_b, "127.0.0.1", hole_port);
	assert(meshlink_set_canonical_address(a, node_b, "192.0.2.1", "9"));

	assert(meshlink_start(a));
	usleep(50000);
	meshlink_stop(a);
	meshlink_close(a);
	meshlink_close(b);
	close(hole_fd);
	assert(meshlink_destroy("outgoing_bounded_stop_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_stop_conf.2"));

	printf("outgoing-bounded T5 ok: stop during bound cleaned up\n");
}

static void test_only_best_gets_budget(void) {
	printf("\n=== outgoing-bounded: only the best direct candidate gets the 250 ms budget ===\n");

	assert(meshlink_destroy("outgoing_bounded_best_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_best_conf.2"));

	meshlink_handle_t *a = meshlink_open("outgoing_bounded_best_conf.1", "a", "outgoing-bounded-best", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_bounded_best_conf.2", "b", "outgoing-bounded-best", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int b_port = meshlink_get_port(b);
	int hole1 = 0, hole2 = 0;
	int hole1_fd = start_black_hole("127.0.0.1", &hole1);
	int hole2_fd = start_black_hole("127.0.0.1", &hole2);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	exchange_meshlink_pair(a, b);
	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	forget_addresses(a, node_b);
	hint_address(a, node_b, "127.0.0.1", hole1);
	hint_address(a, node_b, "127.0.0.1", hole2);
	assert(meshlink_set_canonical_address(a, node_b, "127.0.0.1", relay_port_str));

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	meshlink_set_node_status_cb(a, status_cb);
	size_t mark = log_mark();
	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));

	char hole1_needle[128], hole2_needle[128], canonical_needle[128];
	snprintf(hole1_needle, sizeof hole1_needle, "Trying to connect to b at 127.0.0.1 port %d (recent)", hole1);
	snprintf(hole2_needle, sizeof hole2_needle, "Trying to connect to b at 127.0.0.1 port %d (recent)", hole2);
	snprintf(canonical_needle, sizeof canonical_needle, "Trying to connect to b at 127.0.0.1 port %d (canonical)", relay_port);
	long hole2_at = log_find(mark, hole2_needle);
	long hole1_at = log_find(mark, hole1_needle);
	long canonical_at = log_find(mark, canonical_needle);
	assert(hole2_at >= 0);
	assert(canonical_at >= 0);
	assert(hole2_at < canonical_at);
	assert(hole1_at < 0 || hole1_at > canonical_at);

	printf("outgoing-bounded T6 ok: only the front candidate burned the startup budget\n");

	meshlink_set_node_status_cb(a, NULL);
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	close(hole1_fd);
	close(hole2_fd);
	stop_tcp_relay(relay);
	assert(meshlink_destroy("outgoing_bounded_best_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_best_conf.2"));
}

static void test_blacklist_during_bound(void) {
	printf("\n=== outgoing-bounded: blacklist during the 250 ms bound ===\n");

	assert(meshlink_destroy("outgoing_bounded_bl_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_bl_conf.2"));

	meshlink_handle_t *a = meshlink_open("outgoing_bounded_bl_conf.1", "a", "outgoing-bounded-bl", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_bounded_bl_conf.2", "b", "outgoing-bounded-bl", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int hole_port = 0;
	int hole_fd = start_black_hole("127.0.0.1", &hole_port);
	exchange_meshlink_pair(a, b);
	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	forget_addresses(a, node_b);
	hint_address(a, node_b, "127.0.0.1", hole_port);
	assert(meshlink_set_canonical_address(a, node_b, "192.0.2.1", "9"));

	assert(meshlink_start(a));
	usleep(50000);
	assert(meshlink_blacklist(a, node_b));
	usleep(300000);
	meshlink_stop(a);
	meshlink_close(a);
	meshlink_close(b);
	close(hole_fd);
	assert(meshlink_destroy("outgoing_bounded_bl_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_bl_conf.2"));

	printf("outgoing-bounded T7 ok: blacklist during bound cleaned up\n");
}

static void test_upgrade_after_timeout(void) {
	printf("\n=== outgoing-bounded: timed-out direct later upgrades without SPTPS reset ===\n");

	assert(meshlink_destroy("outgoing_bounded_up_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_up_conf.2"));

	meshlink_handle_t *a = meshlink_open("outgoing_bounded_up_conf.1", "a", "outgoing-bounded-up", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_bounded_up_conf.2", "b", "outgoing-bounded-up", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int b_port = meshlink_get_port(b);
	int hole_port = 0;
	int hole_fd = start_black_hole("127.0.0.1", &hole_port);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	devtool_set_external_ip_address(b, meshlink_get_self(b), "127.0.0.1");
	exchange_meshlink_pair(a, b);
	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	meshlink_node_t *node_a = meshlink_get_node(b, "a");
	forget_addresses(a, node_b);
	forget_addresses(b, node_a);
	hint_address(a, node_b, "127.0.0.1", hole_port);
	assert(meshlink_set_canonical_address(a, node_b, "127.0.0.1", relay_port_str));

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	meshlink_set_node_status_cb(a, status_cb);
	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));

	devtool_node_status_t st;
	bool keyed = false;
	uint32_t restarts = 0;

	for(int i = 0; i < 20; i++) {
		devtool_get_node_status(a, node_b, &st);
		keyed = st.validkey;
		restarts = st.sptps_restart_count;
		devtool_free_node_status(&st);

		if(keyed) {
			break;
		}

		usleep(100000);
	}

	assert(keyed);

	bool direct = false;

	for(int i = 0; i < 25; i++) {
		devtool_get_node_status(a, node_b, &st);
		direct = st.meta_connected && !st.meta_via_canonical && port_of(&st.meta_address) == b_port;
		devtool_free_node_status(&st);

		if(direct) {
			break;
		}

		sleep(1);
	}

	assert(direct);

	devtool_get_node_status(a, node_b, &st);
	assert(st.validkey);
	assert(!st.waitingforkey);
	assert(st.sptps_restart_count == restarts);
	devtool_free_node_status(&st);

	printf("outgoing-bounded T8 ok: post-bound upgrade preserved SPTPS\n");

	meshlink_set_node_status_cb(a, NULL);
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	close(hole_fd);
	stop_tcp_relay(relay);
	assert(meshlink_destroy("outgoing_bounded_up_conf.1"));
	assert(meshlink_destroy("outgoing_bounded_up_conf.2"));
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	test_direct_wins_before_bound();
	test_black_hole_falls_to_canonical();
	test_sync_fail_immediate_canonical();
	test_no_direct_canonical_now();
	test_stop_during_bound();
	test_only_best_gets_budget();
	test_blacklist_during_bound();
	test_upgrade_after_timeout();

	free_captured_log();
	return 0;
}
