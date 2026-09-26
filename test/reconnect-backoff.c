#ifdef NDEBUG
#undef NDEBUG
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"
#include "connection_policy.h"

/* Camera→backbone reconnect backoff. Backbone never dual-dials (finding 5).
   Finding 6: telescopic 1,2,5,... not linear +5. */

#define MEASURE_SECONDS 8
#define MAX_TRIES_IN_WINDOW 5

static bool log_has_retry_delay(size_t mark, int seconds) {
	char needle[96];

	snprintf(needle, sizeof needle, "Trying to re-establish outgoing connection in %d seconds", seconds);
	return log_find(mark, needle) >= 0;
}

static void assert_first_retry_is_ladder_start(size_t mark) {
	long d1 = log_find(mark, "Trying to re-establish outgoing connection in 1 seconds");
	long d2 = log_find(mark, "Trying to re-establish outgoing connection in 2 seconds");
	long d5 = log_find(mark, "Trying to re-establish outgoing connection in 5 seconds");

	assert(d1 >= 0 || d2 >= 0);

	if(d5 >= 0) {
		long first = (d1 >= 0 && (d2 < 0 || d1 < d2)) ? d1 : d2;
		assert(first < d5);
	}
}

static void test_drop_after_activate_backs_off(void) {
	printf("\n=== T17: camera retries the backbone with telescopic backoff while it is down ===\n");

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

	size_t mark = log_mark();
	assert(meshlink_start(b));
	sleep(MEASURE_SECONDS);

	int tries = log_count_from(mark, try_needle);
	int retries = log_count_from(mark, "b: Trying to re-establish outgoing connection in ");
	printf("T17: in %d s camera tried %d times, backed off %d times, retry_step=%d\n",
	       MEASURE_SECONDS, tries, retries, devtool_backbone_intent_retry_step(b));

	assert(tries >= 1);
	assert(retries >= 1);
	assert(tries <= MAX_TRIES_IN_WINDOW);
	assert_first_retry_is_ladder_start(mark);
	assert(devtool_outgoing_count(b) == 1);
	assert(!strcmp(devtool_backbone_intent_name(b), "a"));
	assert(devtool_backbone_intent_retry_step(b) >= 1);

	assert(meshlink_start(a));
	assert_after(meshlink_get_node_reachability(a, a_b, NULL, NULL) && meshlink_get_node_reachability(b, b_a, NULL, NULL), 45);

	devtool_node_status_t st;
	devtool_get_node_status(b, b_a, &st);
	assert(st.meta_connected);
	devtool_free_node_status(&st);
	devtool_get_node_status(a, a_b, &st);
	assert(st.meta_connected);
	devtool_free_node_status(&st);
	/* ACK must not zero the ladder; a drop after this short session keeps escalating. */
	assert(devtool_backbone_intent_retry_step(b) >= 1);

	printf("T17 ok: camera backed off on the 1/2s ladder (%d tries in %d s)\n", tries, MEASURE_SECONDS);

	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("reconnect_backoff_conf.1"));
	assert(meshlink_destroy("reconnect_backoff_conf.2"));
}

static void test_stable_drop_restarts_ladder(void) {
	printf("\n=== T18: stable direct drop restarts the ladder at step 0 ===\n");

	assert(meshlink_destroy("reconnect_backoff_stable_conf.1"));
	assert(meshlink_destroy("reconnect_backoff_stable_conf.2"));

	meshlink_handle_t *a = meshlink_open("reconnect_backoff_stable_conf.1", "a", "reconnect_backoff_stable", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("reconnect_backoff_stable_conf.2", "b", "reconnect_backoff_stable", DEV_CLASS_PORTABLE);
	assert(a && b);
	devtool_set_external_ip_address(a, meshlink_get_self(a), NULL);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	join_meshlink_peer(a, b);

	meshlink_node_t *b_a = meshlink_get_node(b, "a");
	assert(b_a);

	assert(meshlink_start(a));
	assert(meshlink_start(b));
	assert_after(meshlink_get_node_reachability(b, b_a, NULL, NULL), 15);
	assert(devtool_backbone_intent_retry_step(b) == 0);
	assert(devtool_outgoing_count(b) == 1);

	sleep(BACKBONE_STABLE_RESET_SEC + 2);
	assert(devtool_backbone_intent_retry_step(b) == 0);

	size_t mark = log_mark();
	meshlink_stop(a);
	assert_after(devtool_backbone_intent_retry_step(b) >= 1, 5);
	assert(devtool_outgoing_count(b) == 1);
	assert_first_retry_is_ladder_start(mark);
	assert(!log_has_retry_delay(mark, 300));

	printf("T18 ok: after a stable session the next drop used step 0\n");

	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("reconnect_backoff_stable_conf.1"));
	assert(meshlink_destroy("reconnect_backoff_stable_conf.2"));
}

static int intent_step(meshlink_handle_t *mesh) {
	return devtool_backbone_intent_retry_step(mesh);
}

static void wait_up(meshlink_handle_t *mesh, meshlink_node_t *node) {
	assert_after(meshlink_get_node_reachability(mesh, node, NULL, NULL), 15);
}

/* Poll tighter than assert_after so a short-flap test cannot accidentally
   cross BACKBONE_STABLE_RESET_SEC while waiting for reachability. */
static void wait_up_quick(meshlink_handle_t *mesh, meshlink_node_t *node) {
	for(int i = 0; i < 300; i++) {
		if(meshlink_get_node_reachability(mesh, node, NULL, NULL)) {
			return;
		}

		usleep(50000);
	}

	assert(meshlink_get_node_reachability(mesh, node, NULL, NULL));
}

static void wait_step(meshlink_handle_t *mesh, int want) {
	assert_after(intent_step(mesh) == want, 5);
}

static void snapshot_meta(meshlink_handle_t *mesh, meshlink_node_t *node,
                         time_t *activated, time_t *renewal, bool *via_canonical) {
	devtool_node_status_t st;

	memset(&st, 0, sizeof st);
	devtool_get_node_status(mesh, node, &st);
	assert(st.meta_connected);

	if(activated) {
		*activated = st.meta_activated_at;
	}

	if(renewal) {
		*renewal = st.meta_last_key_renewal;
	}

	if(via_canonical) {
		*via_canonical = st.meta_via_canonical;
	}

	devtool_free_node_status(&st);
}

static void open_pair(const char *conf_a, const char *conf_b, const char *app,
                     meshlink_handle_t **a, meshlink_handle_t **b, meshlink_node_t **b_a) {
	assert(meshlink_destroy(conf_a));
	assert(meshlink_destroy(conf_b));
	*a = meshlink_open(conf_a, "a", app, DEV_CLASS_BACKBONE);
	*b = meshlink_open(conf_b, "b", app, DEV_CLASS_PORTABLE);
	assert(*a && *b);
	devtool_set_external_ip_address(*a, meshlink_get_self(*a), NULL);
	meshlink_enable_discovery(*a, false);
	meshlink_enable_discovery(*b, false);
	join_meshlink_peer(*a, *b);
	*b_a = meshlink_get_node(*b, "a");
	assert(*b_a);
}

static void close_pair(meshlink_handle_t *a, meshlink_handle_t *b, const char *conf_a, const char *conf_b) {
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy(conf_a));
	assert(meshlink_destroy(conf_b));
}

static void wake_direct(meshlink_handle_t *a, meshlink_handle_t *b, meshlink_node_t *b_a) {
	hint_address(b, b_a, "127.0.0.1", meshlink_get_port(a));
}

/* T19: each short authenticated session advances retry_step. */
static void test_short_flaps_escalate(void) {
	printf("\n=== T19: short authenticated flaps advance the ladder ===\n");

	meshlink_handle_t *a, *b;
	meshlink_node_t *b_a;
	open_pair("reconnect_backoff_t19_conf.1", "reconnect_backoff_t19_conf.2",
	          "reconnect_backoff_t19", &a, &b, &b_a);

	assert(meshlink_start(a));
	assert(meshlink_start(b));
	wait_up_quick(b, b_a);
	assert(intent_step(b) == 0);

	for(int i = 1; i <= 4; i++) {
		meshlink_stop(a);
		wait_step(b, i);

		if(i == 4) {
			break;
		}

		assert(meshlink_start(a));
		wake_direct(a, b, b_a);
		wait_up_quick(b, b_a);
	}

	assert(intent_step(b) == 4);
	printf("T19 ok: four short flaps reached retry_step=4\n");
	close_pair(a, b, "reconnect_backoff_t19_conf.1", "reconnect_backoff_t19_conf.2");
}

/* T20: duplicate hints must not zero retry_step. */
static void test_discovery_does_not_reset(void) {
	printf("\n=== T20: duplicate discovery/hint does not reset retry_step ===\n");

	meshlink_handle_t *a, *b;
	meshlink_node_t *b_a;
	open_pair("reconnect_backoff_t20_conf.1", "reconnect_backoff_t20_conf.2",
	          "reconnect_backoff_t20", &a, &b, &b_a);

	assert(meshlink_start(a));
	assert(meshlink_start(b));
	wait_up_quick(b, b_a);
	meshlink_stop(a);
	wait_step(b, 1);
	assert(meshlink_start(a));
	wake_direct(a, b, b_a);
	wait_up_quick(b, b_a);
	meshlink_stop(a);
	wait_step(b, 2);

	int step = intent_step(b);
	assert(step >= 2);
	wake_direct(a, b, b_a);
	wake_direct(a, b, b_a);
	assert(intent_step(b) >= 2);
	assert(intent_step(b) >= step);

	printf("T20 ok: hints left retry_step at %d\n", intent_step(b));
	close_pair(a, b, "reconnect_backoff_t20_conf.1", "reconnect_backoff_t20_conf.2");
}

static void flap_to_step_2(meshlink_handle_t *a, meshlink_handle_t *b, meshlink_node_t *b_a) {
	assert(meshlink_start(a));
	assert(meshlink_start(b));
	wait_up_quick(b, b_a);
	meshlink_stop(a);
	wait_step(b, 1);
	assert(meshlink_start(a));
	wake_direct(a, b, b_a);
	wait_up_quick(b, b_a);
	meshlink_stop(a);
	wait_step(b, 2);
}

/* T20b: a material new address zeros an armed BACKBONE_REQUIRED retry immediately. */
static void test_material_hint_zeros_armed_retry(void) {
	printf("\n=== T20b: material hint zeros an armed BACKBONE_REQUIRED retry ===\n");

	meshlink_handle_t *a, *b;
	meshlink_node_t *b_a;
	open_pair("reconnect_backoff_t20b_conf.1", "reconnect_backoff_t20b_conf.2",
	          "reconnect_backoff_t20b", &a, &b, &b_a);

	flap_to_step_2(a, b, b_a);
	assert(intent_step(b) >= 2);

	struct timespec before;

	for(int i = 0; i < 50; i++) {
		if(devtool_backbone_intent_retry_deadline(b, &before)) {
			break;
		}

		usleep(100000);
	}

	assert(devtool_backbone_intent_retry_deadline(b, &before));
	int step = intent_step(b);
	assert(step >= 2);

	uint16_t fresh = (uint16_t)find_closed_port("127.0.0.1");
	size_t mark = log_mark();
	hint_address(b, b_a, "127.0.0.1", fresh);

	struct timespec after;

	if(devtool_backbone_intent_retry_deadline(b, &after)) {
		bool sooner = after.tv_sec < before.tv_sec
		              || (after.tv_sec == before.tv_sec && after.tv_nsec < before.tv_nsec);
		assert(sooner || log_find(mark, "Trying to connect to a") >= 0);
	}

	assert_after(log_find(mark, "Trying to connect to a") >= 0, 3);
	assert(intent_step(b) >= step);

	printf("T20b ok: material hint pulled the armed retry forward (step %d)\n", intent_step(b));
	close_pair(a, b, "reconnect_backoff_t20b_conf.1", "reconnect_backoff_t20b_conf.2");
}

/* T21: after escalation, a long-enough session resets; the next drop starts at step 1. */
static void test_stable_after_escalation_resets(void) {
	printf("\n=== T21: stable session after escalation restarts at step 0 ===\n");

	meshlink_handle_t *a, *b;
	meshlink_node_t *b_a;
	open_pair("reconnect_backoff_t21_conf.1", "reconnect_backoff_t21_conf.2",
	          "reconnect_backoff_t21", &a, &b, &b_a);

	flap_to_step_2(a, b, b_a);
	assert(meshlink_start(a));
	wake_direct(a, b, b_a);
	wait_up(b, b_a);
	assert(intent_step(b) >= 2);
	sleep(BACKBONE_STABLE_RESET_SEC + 2);

	size_t mark = log_mark();
	meshlink_stop(a);
	wait_step(b, 1);
	assert_first_retry_is_ladder_start(mark);

	printf("T21 ok: stable drop after escalation used step 0\n");
	close_pair(a, b, "reconnect_backoff_t21_conf.1", "reconnect_backoff_t21_conf.2");
}

/* T22: stable canonical META also resets. */
static void test_stable_canonical_resets(void) {
	printf("\n=== T22: stable canonical drop restarts the ladder ===\n");

	meshlink_handle_t *a, *b;
	meshlink_node_t *b_a;
	open_pair("reconnect_backoff_t22_conf.1", "reconnect_backoff_t22_conf.2",
	          "reconnect_backoff_t22", &a, &b, &b_a);

	int bb_port = meshlink_get_port(a);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", bb_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	forget_addresses(b, b_a);
	assert(meshlink_set_canonical_address(b, b_a, "127.0.0.1", relay_port_str));

	assert(meshlink_start(a));
	assert(meshlink_start(b));
	wait_up(b, b_a);

	bool via_canonical = false;
	snapshot_meta(b, b_a, NULL, NULL, &via_canonical);
	assert(via_canonical);
	assert(intent_step(b) == 0);
	sleep(BACKBONE_STABLE_RESET_SEC + 2);

	size_t mark = log_mark();
	meshlink_stop(a);
	wait_step(b, 1);
	assert_first_retry_is_ladder_start(mark);

	printf("T22 ok: stable canonical drop used step 0\n");
	stop_tcp_relay(relay);
	close_pair(a, b, "reconnect_backoff_t22_conf.1", "reconnect_backoff_t22_conf.2");
}

/* T23: key renewal must not restamp activated_at or turn a stable session into a flap. */
static void test_key_renewal_does_not_restamp(void) {
	printf("\n=== T23: hourly key renewal does not affect activated_at or stability ===\n");

	meshlink_handle_t *a, *b;
	meshlink_node_t *b_a;
	open_pair("reconnect_backoff_t23_conf.1", "reconnect_backoff_t23_conf.2",
	          "reconnect_backoff_t23", &a, &b, &b_a);

	flap_to_step_2(a, b, b_a);
	assert(meshlink_start(a));
	wake_direct(a, b, b_a);
	wait_up(b, b_a);
	sleep(BACKBONE_STABLE_RESET_SEC + 2);

	time_t activated = 0, renewal = 0;
	snapshot_meta(b, b_a, &activated, &renewal, NULL);
	assert(activated > 0);
	devtool_force_sptps_renewal(b, b_a);

	time_t activated2 = 0, renewal2 = 0;

	for(int i = 0; i < 5; i++) {
		snapshot_meta(b, b_a, &activated2, &renewal2, NULL);

		if(renewal2 != renewal && renewal2 != (time_t) -3600) {
			break;
		}

		sleep(1);
	}

	assert(renewal2 != renewal && renewal2 != (time_t) -3600);
	assert(activated2 == activated);

	size_t mark = log_mark();
	meshlink_stop(a);
	wait_step(b, 1);
	assert_first_retry_is_ladder_start(mark);

	printf("T23 ok: renewal restamped last_key_renewal only; drop still reset the ladder\n");
	close_pair(a, b, "reconnect_backoff_t23_conf.1", "reconnect_backoff_t23_conf.2");
}

/* T24: same-session META upgrade (relay→direct) must not restart SPTPS when
   validkey already survives — covers ACK initiator gate (M1 / path_peer_ensure_udp_key). */
static void test_meta_flap_preserves_sptps(void) {
	printf("\n=== T24: META upgrade with same session_id keeps sptps_restart_count ===\n");

	assert(meshlink_destroy("reconnect_backoff_t24_conf.1"));
	assert(meshlink_destroy("reconnect_backoff_t24_conf.2"));

	meshlink_handle_t *a = meshlink_open("reconnect_backoff_t24_conf.1", "a", "reconnect_backoff_t24", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("reconnect_backoff_t24_conf.2", "b", "reconnect_backoff_t24", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int a_port = meshlink_get_port(a);
	int hole_port = 0;
	int hole_fd = start_black_hole("127.0.0.1", &hole_port);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", a_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	devtool_set_external_ip_address(a, meshlink_get_self(a), "127.0.0.1");
	join_meshlink_peer(a, b);
	meshlink_node_t *b_a = meshlink_get_node(b, "a");
	meshlink_node_t *a_b = meshlink_get_node(a, "b");
	assert(b_a && a_b);
	forget_addresses(b, b_a);
	forget_addresses(a, a_b);
	hint_address(b, b_a, "127.0.0.1", hole_port);
	assert(meshlink_set_canonical_address(b, b_a, "127.0.0.1", relay_port_str));

	assert(meshlink_start(a));
	assert(meshlink_start(b));
	wait_up(b, b_a);

	devtool_node_status_t st;
	bool keyed = false;
	uint32_t restarts = 0;

	for(int i = 0; i < 40; i++) {
		devtool_get_node_status(b, b_a, &st);
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

	for(int i = 0; i < 30; i++) {
		devtool_get_node_status(b, b_a, &st);
		direct = st.meta_connected && !st.meta_via_canonical && port_of(&st.meta_address) == a_port;
		devtool_free_node_status(&st);

		if(direct) {
			break;
		}

		sleep(1);
	}

	assert(direct);

	devtool_get_node_status(b, b_a, &st);
	assert(st.validkey);
	assert(!st.waitingforkey);
	assert(st.sptps_restart_count == restarts);
	devtool_free_node_status(&st);

	printf("T24 ok: META upgrade left sptps_restart_count at %u\n", restarts);
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	close(hole_fd);
	stop_tcp_relay(relay);
	assert(meshlink_destroy("reconnect_backoff_t24_conf.1"));
	assert(meshlink_destroy("reconnect_backoff_t24_conf.2"));
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	test_drop_after_activate_backs_off();
	test_stable_drop_restarts_ladder();
	test_short_flaps_escalate();
	test_discovery_does_not_reset();
	test_material_hint_zeros_armed_retry();
	test_stable_after_escalation_resets();
	test_stable_canonical_resets();
	test_key_renewal_does_not_restamp();
	test_meta_flap_preserves_sptps();

	free_captured_log();
	return 0;
}
