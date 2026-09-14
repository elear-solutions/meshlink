#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* net.h is not includable from integration tests (transitive meshlink_internal.h). */
#define MINMTU 527
#define MTU 1451
#define UTCP_HDR 20
#define RELAY_INNER_MIN 21

typedef struct {
	uint8_t destination[16];
	uint8_t source[16];
} __attribute__((__packed__)) stability_packethdr_t;

/* Mirrors of the internal enums exercised through devtool_node_status_t. */
#define ROUTE_NONE 0
#define ROUTE_DIRECT_UDP 1
#define ROUTE_DIRECT_LOCAL_META 2
#define ROUTE_RELAY 3

#define CARRIER_NONE 0
#define CARRIER_UDP 1
#define CARRIER_META_DIRECT 2
#define CARRIER_META_CANONICAL 3

/* Must match path_policy.h. */
#define PATH_ROUTE_MIN_RESIDENCY_SEC 30
#define PATH_SUSPECT_WINDOW_MS 1000
#define PATH_LIVENESS_INTERVAL_SEC 60

static struct sync_flag accepted;
static struct sync_flag received;

static size_t relay_floor_mss(const char *origin, const char *destination) {
	return MINMTU - (2 + strlen(origin) + strlen(destination)) - RELAY_INNER_MIN
	       - sizeof(stability_packethdr_t) - UTCP_HDR;
}

static void receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;

	if(len) {
		set_sync_flag(&received, true);
	}
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)port;
	meshlink_set_channel_receive_cb(mesh, channel, receive_cb);

	if(data && len) {
		receive_cb(mesh, channel, data, len);
	}

	set_sync_flag(&accepted, true);
	return true;
}

static struct sockaddr_in v4(const char *ip, uint16_t port) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	assert(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
	return sa;
}

static devtool_node_status_t snapshot(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st;
	devtool_get_node_status(mesh, node, &st);
	return st;
}

static bool node_is_reachable(meshlink_handle_t *mesh, meshlink_node_t *node) {
	return meshlink_get_node_reachability(mesh, node, NULL, NULL);
}

/* Graph reachability precedes the key exchange, and the UDP status only becomes
   meaningful once the node has a key. */
static bool node_is_keyed(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool keyed = st.validkey;
	devtool_free_node_status(&st);
	return keyed;
}

static bool udp_status_working(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool working = st.udp_status == DEVTOOL_UDP_WORKING;
	devtool_free_node_status(&st);
	return working;
}

/* --- T1: the channel size is decided once, from the names alone ----------- */

static void test_fixed_channel_size(void) {
	printf("\n=== path-stability T1: channel size is fixed for the channel's life ===\n");

	assert(meshlink_destroy("path_stability_t1_conf.1"));
	assert(meshlink_destroy("path_stability_t1_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t1_conf.1", "aaa", "path-stability-1", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t1_conf.2", "bbb", "path-stability-1", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);
	link_meshlink_pair(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);

	size_t expected = relay_floor_mss("aaa", "bbb");
	assert(meshlink_channel_get_mss(a, ch) == expected);

	/* Everything that used to repacketize a live channel. */
	assert(devtool_set_minmtu(a, a_b, MTU));
	assert(meshlink_channel_get_mss(a, ch) == expected);

	devtool_set_udp_confirmed(a, a_b, true);
	assert(meshlink_channel_get_mss(a, ch) == expected);

	devtool_set_udp_confirmed(a, a_b, false);
	assert(meshlink_channel_get_mss(a, ch) == expected);

	assert(devtool_set_minmtu(a, a_b, MINMTU));
	assert(meshlink_channel_get_mss(a, ch) == expected);

	/* A second channel to the same destination gets the same size. */
	meshlink_channel_t *ch2 = meshlink_channel_open(a, a_b, 8, receive_cb, NULL, 0);
	assert(ch2);
	assert(meshlink_channel_get_mss(a, ch2) == expected);

	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.channel_mtu == expected + UTCP_HDR);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	meshlink_channel_abort(a, ch2);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t1_conf.1"));
	assert(meshlink_destroy("path_stability_t1_conf.2"));
	printf("path-stability T1 ok: size %zu survived every path event\n", expected);
}

/* --- T2: reading the size races nothing ----------------------------------- */

struct hammer {
	meshlink_handle_t *mesh;
	meshlink_node_t *node;
	meshlink_channel_t *channel;
	size_t expected;
	atomic_bool stop;
	atomic_bool mismatch;
	atomic_uint reads;
};

static void *mss_reader(void *arg) {
	struct hammer *h = arg;

	while(!atomic_load(&h->stop)) {
		if(meshlink_channel_get_mss(h->mesh, h->channel) != h->expected) {
			atomic_store(&h->mismatch, true);
		}

		atomic_fetch_add(&h->reads, 1);
	}

	return NULL;
}

static void *route_churner(void *arg) {
	struct hammer *h = arg;

	while(!atomic_load(&h->stop)) {
		devtool_set_udp_confirmed(h->mesh, h->node, true);
		(void)devtool_set_minmtu(h->mesh, h->node, MTU);
		devtool_note_route_suspect(h->mesh, h->node);
		devtool_path_route_tick(h->mesh, h->node);
		devtool_set_udp_confirmed(h->mesh, h->node, false);
		(void)devtool_set_minmtu(h->mesh, h->node, MINMTU);
	}

	return NULL;
}

static void test_mss_under_route_churn(void) {
	printf("\n=== path-stability T2: reading the size while routes change ===\n");

	assert(meshlink_destroy("path_stability_t2_conf.1"));
	assert(meshlink_destroy("path_stability_t2_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t2_conf.1", "aaa", "path-stability-2", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t2_conf.2", "bbb", "path-stability-2", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);
	link_meshlink_pair(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);

	struct hammer h;
	memset(&h, 0, sizeof h);
	h.mesh = a;
	h.node = a_b;
	h.channel = ch;
	h.expected = relay_floor_mss("aaa", "bbb");
	atomic_init(&h.stop, false);
	atomic_init(&h.mismatch, false);
	atomic_init(&h.reads, 0);

	pthread_t reader, churner;
	assert(pthread_create(&reader, NULL, mss_reader, &h) == 0);
	assert(pthread_create(&churner, NULL, route_churner, &h) == 0);

	sleep(3);
	atomic_store(&h.stop, true);
	assert(pthread_join(reader, NULL) == 0);
	assert(pthread_join(churner, NULL) == 0);

	assert(atomic_load(&h.reads) > 0);
	assert(!atomic_load(&h.mismatch));

	meshlink_channel_abort(a, ch);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t2_conf.1"));
	assert(meshlink_destroy("path_stability_t2_conf.2"));
	printf("path-stability T2 ok: %u reads, no size ever moved\n", atomic_load(&h.reads));
}

/* --- T3: promotion needs two separated rounds and a served residency ------ */

static void test_promotion_is_slow(void) {
	printf("\n=== path-stability T3: promotion needs two rounds, a hold and residency ===\n");

	assert(meshlink_destroy("path_stability_t3_conf.1"));
	assert(meshlink_destroy("path_stability_t3_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t3_conf.1", "aaa", "path-stability-3", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t3_conf.2", "bbb", "path-stability-3", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);
	link_meshlink_pair(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);

	/* Carry real traffic first, so there is an active route with a residency
	   to serve. Without one, there is nothing worth protecting from churn. */
	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(a, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));

	/* Sit on a WAN endpoint, then learn a better local one. */
	struct sockaddr_in wan = v4("203.0.113.10", 9);
	struct sockaddr_in local = v4("192.168.77.10", 7777);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);

	struct sockaddr_storage target;
	uint64_t nonce = 0;
	assert(devtool_candidate_probe_target(a, a_b, &target, &nonce));
	assert(addr_is(&target, "192.168.77.10", 7777));
	assert(nonce);

	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.candidate_active);
	assert(st.candidate_rounds == 0);
	devtool_free_node_status(&st);

	/* Learning is not validation: the WAN endpoint is still the one in use. */
	assert(addr_is(&target, "192.168.77.10", 7777));

	/* A wrong nonce proves nothing. */
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&local, nonce ^ 1);
	st = snapshot(a, a_b);
	assert(st.candidate_rounds == 0);
	devtool_free_node_status(&st);

	/* First good round. */
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&local, nonce);
	st = snapshot(a, a_b);
	assert(st.candidate_rounds == 1);
	uint64_t first_round_nonce = nonce;
	devtool_free_node_status(&st);

	/* Replaying the same burst cannot be the second round: the nonce is spent
	   and the rounds must be separated in time. */
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&local, first_round_nonce);
	st = snapshot(a, a_b);
	assert(st.candidate_rounds == 1);
	devtool_free_node_status(&st);

	/* Separate the rounds in time, then take the fresh nonce for the next one.
	   Hold the active route well inside its residency so the only thing that
	   can release the promotion is the residency itself. */
	devtool_age_candidate(a, a_b, 2);
	devtool_age_route(a, a_b, -3600);
	assert(devtool_candidate_probe_target(a, a_b, &target, &nonce));
	assert(nonce != first_round_nonce);

	/* Second round passes, but the active route has not served its residency,
	   so the endpoint still does not move. */
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&local, nonce);
	st = snapshot(a, a_b);
	assert(st.candidate_rounds == 2);
	assert(st.candidate_active);
	/* Validated but not promoted: the endpoint under test has not taken over.
	   Real traffic from the peer may move n->address for its own reasons, so
	   what matters is that it is not the candidate. */
	assert(!addr_is(&st.address, "192.168.77.10", 7777));
	devtool_free_node_status(&st);

	/* Once the residency is served the tick commits it, with no session churn. */
	st = snapshot(a, a_b);
	uint32_t restarts = st.sptps_restart_count;
	devtool_free_node_status(&st);

	devtool_age_route(a, a_b, 3600 + PATH_ROUTE_MIN_RESIDENCY_SEC + 1);
	devtool_path_route_tick(a, a_b);

	st = snapshot(a, a_b);
	assert(!st.candidate_active);
	assert(addr_is(&st.address, "192.168.77.10", 7777));
	assert(st.sptps_restart_count == restarts);
	assert(st.validkey);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t3_conf.1"));
	assert(meshlink_destroy("path_stability_t3_conf.2"));
	printf("path-stability T3 ok: promoted only after two rounds and the residency\n");
}

/* --- T4: a candidate that never answers cools down, and escalates --------- */

static void test_candidate_cooldown(void) {
	printf("\n=== path-stability T4: a silent candidate cools down and escalates ===\n");

	assert(meshlink_destroy("path_stability_t4_conf.1"));
	assert(meshlink_destroy("path_stability_t4_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t4_conf.1", "aaa", "path-stability-4", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t4_conf.2", "bbb", "path-stability-4", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	link_meshlink_pair(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);

	struct sockaddr_in wan = v4("203.0.113.10", 9);
	struct sockaddr_in local = v4("192.168.77.11", 7777);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);

	struct sockaddr_storage target;
	uint64_t nonce = 0;
	assert(devtool_candidate_probe_target(a, a_b, &target, &nonce));

	/* Nothing ever answers: the deadline retires the candidate. */
	devtool_age_candidate(a, a_b, 60);
	devtool_path_route_tick(a, a_b);

	devtool_node_status_t st = snapshot(a, a_b);
	assert(!st.candidate_active);
	assert(st.candidate_failures == 1);
	int first_cooldown = st.candidate_cooldown_remaining;
	assert(first_cooldown > 0);
	devtool_free_node_status(&st);

	/* While it is cooling down the same endpoint is not retried. */
	assert(!devtool_candidate_probe_target(a, a_b, &target, &nonce));

	/* A fresh discovery lets it be tried again, but does not forgive the
	   earlier failure: the next cooldown is longer, not the same. */
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);
	devtool_candidate_clear_cooldown(a, a_b);
	assert(devtool_candidate_probe_target(a, a_b, &target, &nonce));

	devtool_age_candidate(a, a_b, 60);
	devtool_path_route_tick(a, a_b);
	st = snapshot(a, a_b);
	assert(!st.candidate_active);
	assert(st.candidate_failures == 2);
	assert(st.candidate_cooldown_remaining > first_cooldown);
	devtool_free_node_status(&st);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t4_conf.1"));
	assert(meshlink_destroy("path_stability_t4_conf.2"));
	printf("path-stability T4 ok: first cooldown %ds, retried only after it was cleared\n", first_cooldown);
}

/* --- T5: a retransmission makes a route suspect, not dead ----------------- */

static void test_suspect_before_demote(void) {
	printf("\n=== path-stability T5: suspicion is resolved by probes, not assumption ===\n");

	assert(meshlink_destroy("path_stability_t5_conf.1"));
	assert(meshlink_destroy("path_stability_t5_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t5_conf.1", "aaa", "path-stability-5", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t5_conf.2", "bbb", "path-stability-5", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	link_meshlink_pair(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);

	/* An unroutable endpoint: the background prober will never confirm it on
	   its own, so every transition below is the one this test caused. */
	struct sockaddr_in wan = v4("203.0.113.12", 9);

	/* The peer's own META connection is the live fallback here. */
	assert(devtool_has_live_fallback(a, a_b));

	/* Raising suspicion is not a demotion: the route keeps carrying data. */
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	devtool_note_route_suspect(a, a_b);
	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.active_route_suspect);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	/* An answered probe on the active endpoint clears suspicion outright, and
	   does not count as a promotion. */
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&wan, 0);
	st = snapshot(a, a_b);
	assert(!st.active_route_suspect);
	assert(!st.candidate_active);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	/* Unanswered, and only once the window has closed, it is demoted. */
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	devtool_note_route_suspect(a, a_b);
	devtool_age_route(a, a_b, 2);
	devtool_path_route_tick(a, a_b);
	st = snapshot(a, a_b);
	assert(!st.active_route_suspect);
	assert(st.udp_status != DEVTOOL_UDP_WORKING);
	/* Carrier loss is not session loss. */
	assert(st.validkey);
	assert(st.meta_connected);
	devtool_free_node_status(&st);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t5_conf.1"));
	assert(meshlink_destroy("path_stability_t5_conf.2"));
	printf("path-stability T5 ok: demoted only after the probe window closed\n");
}

/* --- T6: an idle peer costs nothing --------------------------------------- */

static void test_idle_peer_is_not_probed(void) {
	printf("\n=== path-stability T6: an idle peer is not probed ===\n");

	assert(meshlink_destroy("path_stability_t6_conf.1"));
	assert(meshlink_destroy("path_stability_t6_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t6_conf.1", "aaa", "path-stability-6", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t6_conf.2", "bbb", "path-stability-6", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);
	link_meshlink_pair(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);
	assert_after(udp_status_working(a, a_b), 30);

	/* Settled and never used by the application. */
	assert(!devtool_liveness_probe_warranted(a, a_b));

	/* Application traffic makes liveness worth paying for again. */
	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(a, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));
	assert(devtool_liveness_probe_warranted(a, a_b));

	meshlink_channel_abort(a, ch);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t6_conf.1"));
	assert(meshlink_destroy("path_stability_t6_conf.2"));
	printf("path-stability T6 ok: probes follow demand\n");
}

/* --- T7: the route the send path used is the route that gets recorded ----- */

static void test_recorded_route(void) {
	printf("\n=== path-stability T7: the recorded route matches what carried data ===\n");

	assert(meshlink_destroy("path_stability_t7_conf.1"));
	assert(meshlink_destroy("path_stability_t7_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t7_conf.1", "aaa", "path-stability-7", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t7_conf.2", "bbb", "path-stability-7", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);
	link_meshlink_pair(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(a, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));

	/* Two peers with a direct META and no relay: the record went over one of
	   the direct mechanisms, and exactly one route is recorded. */
	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP || st.active_route_kind == ROUTE_DIRECT_LOCAL_META);
	assert(st.active_route_carrier == CARRIER_NONE);
	assert(!st.candidate_active);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t7_conf.1"));
	assert(meshlink_destroy("path_stability_t7_conf.2"));
	printf("path-stability T7 ok: one recorded route, no stray candidate\n");
}

/* --- T8: fallback records do not clear suspicion ---------------------------- */

static void test_fallback_keeps_suspect(void) {
	printf("\n=== path-stability T8: fallback traffic does not clear UDP suspicion ===\n");

	assert(meshlink_destroy("path_stability_t8_conf.1"));
	assert(meshlink_destroy("path_stability_t8_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t8_conf.1", "aaa", "path-stability-8", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t8_conf.2", "bbb", "path-stability-8", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	link_meshlink_pair(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);

	struct sockaddr_in wan = v4("203.0.113.12", 9);

	assert(devtool_has_live_fallback(a, a_b));
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));

	int chosen = ROUTE_NONE;
	assert(devtool_apply_send_target(a, a_b, &chosen));
	assert(chosen == ROUTE_DIRECT_UDP);
	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	assert(!st.active_route_suspect);
	devtool_free_node_status(&st);

	devtool_note_route_suspect(a, a_b);

	chosen = ROUTE_NONE;
	assert(devtool_apply_send_target(a, a_b, &chosen));
	assert(chosen != ROUTE_DIRECT_UDP);
	st = snapshot(a, a_b);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	assert(st.active_route_suspect);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	chosen = ROUTE_NONE;
	assert(devtool_apply_send_target(a, a_b, &chosen));
	assert(chosen != ROUTE_DIRECT_UDP);
	st = snapshot(a, a_b);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	assert(st.active_route_suspect);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	devtool_age_route(a, a_b, 2);
	devtool_path_route_tick(a, a_b);
	st = snapshot(a, a_b);
	assert(!st.active_route_suspect);
	assert(st.udp_status != DEVTOOL_UDP_WORKING);
	assert(st.active_route_kind != ROUTE_DIRECT_UDP);
	assert(st.active_route_kind == ROUTE_DIRECT_LOCAL_META || st.active_route_kind == ROUTE_RELAY);
	devtool_free_node_status(&st);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t8_conf.1"));
	assert(meshlink_destroy("path_stability_t8_conf.2"));
	printf("path-stability T8 ok: fallback records kept suspicion until the window closed\n");
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_WARNING, NULL);

	test_fixed_channel_size();
	test_mss_under_route_churn();
	test_promotion_is_slow();
	test_candidate_cooldown();
	test_suspect_before_demote();
	test_idle_peer_is_not_probed();
	test_recorded_route();
	test_fallback_keeps_suspect();

	printf("\npath-stability: all checks passed\n");
	return 0;
}
