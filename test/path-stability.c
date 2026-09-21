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
#define PATH_HEALTHY_RESET_SEC 60
#define PATH_PEER_UDP_GRACE_SEC 5

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

static bool pmtu_parked(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool parked = st.udp_status == DEVTOOL_UDP_WORKING && st.mtuprobes >= 31;
	devtool_free_node_status(&st);
	return parked;
}

static bool candidate_is_active(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool active = st.candidate_active;
	devtool_free_node_status(&st);
	return active;
}

static bool candidate_has_two_rounds(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool ok = st.candidate_active && st.candidate_rounds == 2;
	devtool_free_node_status(&st);
	return ok;
}

static bool ss_addr_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
	if(a->ss_family != b->ss_family) {
		return false;
	}

	if(a->ss_family == AF_INET) {
		const struct sockaddr_in *aa = (const struct sockaddr_in *)a;
		const struct sockaddr_in *bb = (const struct sockaddr_in *)b;
		return aa->sin_port == bb->sin_port && aa->sin_addr.s_addr == bb->sin_addr.s_addr;
	}

	if(a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)b;
		return aa->sin6_port == bb->sin6_port && memcmp(&aa->sin6_addr, &bb->sin6_addr, 16) == 0;
	}

	return false;
}

static void stability_destroy_conf(const char *prefix, int count) {
	for(int i = 0; i < count; i++) {
		char path[128];
		snprintf(path, sizeof path, "%s.%d", prefix, i);
		assert(meshlink_destroy(path));
	}
}

static void stability_open_trio(const char *prefix, const char *app,
                meshlink_handle_t **bb, meshlink_handle_t **e1, meshlink_handle_t **e2) {
	const char *names[] = {"foo", "bar", "baz"};
	const int classes[] = {DEV_CLASS_BACKBONE, DEV_CLASS_STATIONARY, DEV_CLASS_STATIONARY};
	meshlink_handle_t *m[3];

	stability_destroy_conf(prefix, 3);

	for(int i = 0; i < 3; i++) {
		char path[128];
		snprintf(path, sizeof path, "%s.%d", prefix, i);
		m[i] = meshlink_open(path, names[i], app, classes[i]);
		assert(m[i]);
		meshlink_enable_discovery(m[i], false);
		assert(meshlink_set_canonical_address(m[i], meshlink_get_self(m[i]), "localhost", NULL));
	}

	join_meshlink_peer(m[0], m[1]);
	join_meshlink_peer(m[0], m[2]);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(m[i]));
	}

	*bb = m[0];
	*e1 = m[1];
	*e2 = m[2];
}

static void stability_close_trio(const char *prefix,
                meshlink_handle_t *bb, meshlink_handle_t *e1, meshlink_handle_t *e2) {
	meshlink_close(bb);
	meshlink_close(e1);
	meshlink_close(e2);
	stability_destroy_conf(prefix, 3);
}

/* --- T1: the channel size is decided once, from the names alone ----------- */

static void test_fixed_channel_size(void) {
	printf("\n=== path-stability T1: channel size is fixed for the channel's life ===\n");

	assert(meshlink_destroy("path_stability_t1_conf.1"));
	assert(meshlink_destroy("path_stability_t1_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t1_conf.1", "aaa", "path-stability-1", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t1_conf.2", "bbb", "path-stability-1", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);
	join_meshlink_peer(a, b);
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
	meshlink_handle_t *b = meshlink_open("path_stability_t2_conf.2", "bbb", "path-stability-2", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);
	join_meshlink_peer(a, b);
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

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t3_conf", "path-stability-3", &bb, &a, &b);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);

	assert_after(meshlink_get_node(a, "baz"), 15);
	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);

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

	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.candidate_active);
	assert(st.candidate_rounds == 0);
	assert(st.candidate_nonce);
	assert(addr_is(&st.candidate_endpoint, "192.168.77.10", 7777));
	uint64_t nonce = st.candidate_nonce;
	devtool_free_node_status(&st);

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
	nonce = st.candidate_nonce;
	assert(nonce != first_round_nonce);
	devtool_free_node_status(&st);

	/* Replaying the same burst cannot be the second round: the nonce is spent
	   and the rounds must be separated in time. */
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&local, first_round_nonce);
	st = snapshot(a, a_b);
	assert(st.candidate_rounds == 1);
	devtool_free_node_status(&st);

	/* Separate the rounds in time. Hold the active route well inside its
	   residency so the only thing that can release the promotion is the residency. */
	devtool_age_candidate(a, a_b, 2);
	devtool_age_route(a, a_b, -3600);

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
	stability_close_trio("path_stability_t3_conf", bb, a, b);
	printf("path-stability T3 ok: promoted only after two rounds and the residency\n");
}

/* --- T4: a candidate that never answers cools down, and escalates --------- */

static void test_candidate_cooldown(void) {
	printf("\n=== path-stability T4: a silent candidate cools down and escalates ===\n");

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t4_conf", "path-stability-4", &bb, &a, &b);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);

	assert_after(meshlink_get_node(a, "baz"), 15);
	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);

	/* Promotion is demand-gated; keep a channel so punching is allowed. */
	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(a, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));

	struct sockaddr_in wan = v4("203.0.113.10", 9);
	struct sockaddr_in local = v4("192.168.77.11", 7777);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);

	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.candidate_active);
	devtool_free_node_status(&st);

	/* Nothing ever answers: the deadline retires the candidate. */
	devtool_age_candidate(a, a_b, 60);
	devtool_path_route_tick(a, a_b);

	st = snapshot(a, a_b);
	assert(!st.candidate_active);
	assert(st.candidate_failures == 1);
	int first_cooldown = st.candidate_cooldown_remaining;
	assert(first_cooldown > 0);
	devtool_free_node_status(&st);

	/* While it is cooling down the same endpoint is not retried. */
	struct sockaddr_storage target;
	uint64_t nonce = 0;
	assert(!devtool_candidate_probe_target(a, a_b, &target, &nonce));
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);
	st = snapshot(a, a_b);
	assert(!st.candidate_active);
	devtool_free_node_status(&st);

	/* A fresh discovery lets it be tried again, but does not forgive the
	   earlier failure: the next cooldown is longer, not the same. */
	devtool_candidate_clear_cooldown(a, a_b);
	st = snapshot(a, a_b);
	assert(st.candidate_active);
	devtool_free_node_status(&st);

	devtool_age_candidate(a, a_b, 60);
	devtool_path_route_tick(a, a_b);
	st = snapshot(a, a_b);
	assert(!st.candidate_active);
	assert(st.candidate_failures == 2);
	assert(st.candidate_cooldown_remaining > first_cooldown);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	stability_close_trio("path_stability_t4_conf", bb, a, b);
	printf("path-stability T4 ok: first cooldown %ds, retried only after it was cleared\n", first_cooldown);
}

/* --- T4b: a long-lived active route must not wipe candidate cooldown ------ */

static void test_candidate_cooldown_survives_old_route(void) {
	printf("\n=== path-stability T4b: long-lived route does not reset candidate cooldown ===\n");

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t4b_conf", "path-stability-4b", &bb, &a, &b);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);

	assert_after(meshlink_get_node(a, "baz"), 15);
	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(a, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));

	struct sockaddr_in wan = v4("203.0.113.10", 9);
	struct sockaddr_in local = v4("192.168.77.11", 7777);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);

	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.candidate_active);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	devtool_free_node_status(&st);

	devtool_age_route(a, a_b, PATH_HEALTHY_RESET_SEC + 1);
	devtool_age_candidate(a, a_b, 60);
	devtool_path_route_tick(a, a_b);

	st = snapshot(a, a_b);
	assert(!st.candidate_active);
	assert(st.candidate_failures == 1);
	int first_cooldown = st.candidate_cooldown_remaining;
	assert(first_cooldown > 0);
	devtool_free_node_status(&st);

	devtool_candidate_clear_cooldown(a, a_b);
	st = snapshot(a, a_b);
	assert(st.candidate_active);
	devtool_free_node_status(&st);

	devtool_age_candidate(a, a_b, 60);
	devtool_path_route_tick(a, a_b);
	st = snapshot(a, a_b);
	assert(!st.candidate_active);
	assert(st.candidate_failures == 2);
	assert(st.candidate_cooldown_remaining > first_cooldown);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	stability_close_trio("path_stability_t4b_conf", bb, a, b);
	printf("path-stability T4b ok: aged route kept cooldown %ds and still escalated\n", first_cooldown);
}

/* --- T5: a retransmission makes a route suspect, not dead ----------------- */

static void test_suspect_before_demote(void) {
	printf("\n=== path-stability T5: suspicion is resolved by probes, not assumption ===\n");

	assert(meshlink_destroy("path_stability_t5_conf.1"));
	assert(meshlink_destroy("path_stability_t5_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t5_conf.1", "aaa", "path-stability-5", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t5_conf.2", "bbb", "path-stability-5", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	join_meshlink_peer(a, b);
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

	struct sockaddr_storage got;
	uint64_t nonce = 0;
	assert(devtool_suspect_probe_target(a, a_b, &got, &nonce));
	assert(nonce);

	/* PMTU-style nonce 0, a wrong nonce, and a matching nonce from another
	   endpoint must not clear this epoch. */
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&wan, 0);
	st = snapshot(a, a_b);
	assert(st.active_route_suspect);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&wan, nonce ^ 1);
	st = snapshot(a, a_b);
	assert(st.active_route_suspect);
	devtool_free_node_status(&st);

	struct sockaddr_in other = v4("203.0.113.99", 9);
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&other, nonce);
	st = snapshot(a, a_b);
	assert(st.active_route_suspect);
	assert(!st.candidate_active);
	devtool_free_node_status(&st);

	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&wan, nonce);
	st = snapshot(a, a_b);
	assert(!st.active_route_suspect);
	assert(!st.candidate_active);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	/* A previous-epoch echo cannot heal a new suspicion. */
	uint64_t first_epoch = nonce;
	devtool_note_route_suspect(a, a_b);
	assert(devtool_suspect_probe_target(a, a_b, &got, &nonce));
	assert(nonce);
	assert(nonce != first_epoch);
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&wan, first_epoch);
	st = snapshot(a, a_b);
	assert(st.active_route_suspect);
	devtool_free_node_status(&st);
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&wan, nonce);
	st = snapshot(a, a_b);
	assert(!st.active_route_suspect);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	/* Unanswered: a late matching reply must not heal, and only once the
	   window has closed is the route demoted. */
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	devtool_note_route_suspect(a, a_b);
	assert(devtool_suspect_probe_target(a, a_b, &got, &nonce));
	assert(nonce);
	devtool_age_route(a, a_b, 2);
	devtool_observe_probe_reply(a, a_b, (struct sockaddr *)&wan, nonce);
	st = snapshot(a, a_b);
	assert(st.active_route_suspect);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);
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

/* --- T6: ordinary-peer UDP punching follows channel demand ---------------- */

static void test_idle_peer_is_not_probed(void) {
	printf("\n=== path-stability T6: ordinary-peer UDP follows channel demand ===\n");

	meshlink_handle_t *bb, *e1, *e2;
	stability_open_trio("path_stability_t6_conf", "path-stability-6", &bb, &e1, &e2);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(e1, accept_cb);
	meshlink_set_channel_accept_cb(e2, accept_cb);

	assert_after(meshlink_get_node(e1, "baz") && meshlink_get_node(e1, "foo")
	             && meshlink_get_node(bb, "bar") && meshlink_get_node(e2, "bar"), 15);

	meshlink_node_t *bb_e1 = meshlink_get_node(bb, "bar");
	meshlink_node_t *bb_e2 = meshlink_get_node(bb, "baz");
	meshlink_node_t *e1_bb = meshlink_get_node(e1, "foo");
	meshlink_node_t *e1_e2 = meshlink_get_node(e1, "baz");
	meshlink_node_t *e2_bb = meshlink_get_node(e2, "foo");
	meshlink_node_t *e2_e1 = meshlink_get_node(e2, "bar");
	assert(bb_e1 && bb_e2 && e1_bb && e1_e2 && e2_bb && e2_e1);
	assert_after(node_is_reachable(e1, e1_e2), 15);
	assert_after(node_is_keyed(e1, e1_bb), 20);

	/* Finding 8: cameras keep backbone UDP warm with no channel. */
	assert_after(udp_status_working(e1, e1_bb), 30);
	assert_after(udp_status_working(e2, e2_bb), 30);
	assert(!udp_status_working(bb, bb_e1));
	assert(!udp_status_working(bb, bb_e2));
	assert(!devtool_liveness_probe_warranted(bb, bb_e1));
	assert(!devtool_liveness_probe_warranted(bb, bb_e2));

	/* Backbone → camera rides META; backbone never starts ordinary-peer UDP. */
	meshlink_channel_t *ch_bb = meshlink_channel_open(bb, bb_e1, 7, receive_cb, NULL, 0);
	assert(ch_bb);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(bb, ch_bb, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));
	assert(!devtool_liveness_probe_warranted(bb, bb_e1));
	assert(!udp_status_working(bb, bb_e1));

	/* Edge-to-edge channel starts punching. */
	reset_sync_flag(&accepted);
	reset_sync_flag(&received);
	meshlink_channel_t *ch = meshlink_channel_open(e1, e1_e2, 8, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(e1, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));
	assert(devtool_liveness_probe_warranted(e1, e1_e2));
	assert_after(udp_status_working(e1, e1_e2), 30);
	assert(!devtool_liveness_probe_warranted(bb, bb_e1));
	assert(!udp_status_working(bb, bb_e1));

	/* A second channel to the same peer shares one punch state. */
	reset_sync_flag(&accepted);
	reset_sync_flag(&received);
	meshlink_channel_t *ch2 = meshlink_channel_open(e1, e1_e2, 9, receive_cb, NULL, 0);
	assert(ch2);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(e1, ch2, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));
	assert(devtool_liveness_probe_warranted(e1, e1_e2));
	assert(udp_status_working(e1, e1_e2));

	meshlink_channel_abort(e1, ch);
	assert(devtool_liveness_probe_warranted(e1, e1_e2));
	assert(udp_status_working(e1, e1_e2));

	meshlink_channel_abort(e1, ch2);
	assert(devtool_liveness_probe_warranted(e1, e1_e2));
	assert_after(!devtool_liveness_probe_warranted(e1, e1_e2) && !udp_status_working(e1, e1_e2), PATH_PEER_UDP_GRACE_SEC + 15);

	/* Incoming accept also acquires and starts punching. */
	reset_sync_flag(&accepted);
	reset_sync_flag(&received);
	meshlink_channel_t *ch_in = meshlink_channel_open(e2, e2_e1, 10, receive_cb, NULL, 0);
	assert(ch_in);
	assert(wait_sync_flag(&accepted, 15));
	assert_after(udp_status_working(e1, e1_e2), 30);
	assert(devtool_liveness_probe_warranted(e1, e1_e2));
	assert(!devtool_liveness_probe_warranted(bb, bb_e1));
	assert(!udp_status_working(bb, bb_e1));

	meshlink_channel_abort(e2, ch_in);
	meshlink_channel_abort(bb, ch_bb);
	stability_close_trio("path_stability_t6_conf", bb, e1, e2);
	printf("path-stability T6 ok: edge punching follows demand, backbone never starts it\n");
}

/* --- T7: the route the send path used is the route that gets recorded ----- */

static void test_recorded_route(void) {
	printf("\n=== path-stability T7: the recorded route matches what carried data ===\n");

	assert(meshlink_destroy("path_stability_t7_conf.1"));
	assert(meshlink_destroy("path_stability_t7_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t7_conf.1", "aaa", "path-stability-7", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t7_conf.2", "bbb", "path-stability-7", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);
	join_meshlink_peer(a, b);
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
	meshlink_handle_t *b = meshlink_open("path_stability_t8_conf.2", "bbb", "path-stability-8", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	join_meshlink_peer(a, b);
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

/* --- T9: parked PMTU still completes two production-path rounds ----------- */

static void test_parked_pmtu_promotes_local(void) {
	printf("\n=== path-stability T9: parked PMTU still completes two promotion rounds ===\n");

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t9_conf", "path-stability-9", &bb, &a, &b);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, accept_cb);

	assert_after(meshlink_get_node(a, "baz") && meshlink_get_node(b, "bar"), 15);
	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	meshlink_node_t *b_a = meshlink_get_node(b, "bar");
	assert(a_b && b_a);
	assert_after(node_is_reachable(a, a_b), 15);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(a, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));
	assert_after(node_is_keyed(a, a_b), 20);
	assert_after(udp_status_working(a, a_b), 30);
	assert_after(pmtu_parked(a, a_b), 40);

	devtool_node_status_t st = snapshot(a, a_b);
	struct sockaddr_storage local = st.address;
	int parked = st.mtuprobes;
	uint32_t restarts = st.sptps_restart_count;
	assert(parked >= 31);
	assert(local.ss_family == AF_INET || local.ss_family == AF_INET6);
	devtool_free_node_status(&st);

	/* Both peers sit on WAN. A's probe is forced to B's local; B must reply
	   to last_udp_from, not n->address, or the round never counts. */
	struct sockaddr_in wan_b = v4("203.0.113.10", 9);
	struct sockaddr_in wan_a = v4("203.0.113.11", 9);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan_b, 1));
	assert(devtool_confirm_udp_from(b, b_a, (struct sockaddr *)&wan_a, 1));
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);

	assert_after(candidate_is_active(a, a_b), 2);
	assert_after(candidate_has_two_rounds(a, a_b), 6);

	st = snapshot(a, a_b);
	assert(st.mtuprobes >= 31);
	assert(st.candidate_rounds == 2);
	assert(st.candidate_active);
	assert(!ss_addr_equal(&st.address, &local));
	devtool_free_node_status(&st);

	devtool_age_candidate(a, a_b, 2);
	devtool_age_route(a, a_b, PATH_ROUTE_MIN_RESIDENCY_SEC + 1);
	devtool_path_route_tick(a, a_b);

	st = snapshot(a, a_b);
	assert(!st.candidate_active);
	assert(ss_addr_equal(&st.address, &local));
	assert(st.sptps_restart_count == restarts);
	assert(st.mtuprobes >= 31);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	stability_close_trio("path_stability_t9_conf", bb, a, b);
	printf("path-stability T9 ok: two rounds completed while PMTU stayed parked\n");
}

/* --- T10: receive EOF does not drop demand on a half-open channel --------- */

static meshlink_channel_t *t10_peer_ch;
static struct sync_flag eof_seen;
static struct sync_flag hello_seen;
static struct sync_flag more_seen;

static void t10_local_recv(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;

	if(!len) {
		set_sync_flag(&eof_seen, true);
	}
}

static void t10_remote_recv(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;

	if(len == 5 && data && !memcmp(data, "Hello", 5)) {
		set_sync_flag(&hello_seen, true);
	}

	if(len == 4 && data && !memcmp(data, "More", 4)) {
		set_sync_flag(&more_seen, true);
	}
}

static bool t10_accept(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)port;
	(void)data;
	(void)len;
	t10_peer_ch = channel;
	meshlink_set_channel_receive_cb(mesh, channel, t10_remote_recv);
	set_sync_flag(&accepted, true);
	return true;
}

static void test_half_open_keeps_demand(void) {
	printf("\n=== path-stability T10: half-close does not drop UDP demand ===\n");

	meshlink_handle_t *bb, *e1, *e2;
	stability_open_trio("path_stability_t10_conf", "path-stability-10", &bb, &e1, &e2);

	init_sync_flag(&accepted);
	init_sync_flag(&eof_seen);
	init_sync_flag(&hello_seen);
	init_sync_flag(&more_seen);
	t10_peer_ch = NULL;
	meshlink_set_channel_accept_cb(e2, t10_accept);

	assert_after(meshlink_get_node(e1, "baz"), 15);
	meshlink_node_t *e1_e2 = meshlink_get_node(e1, "baz");
	assert(e1_e2);
	assert_after(node_is_reachable(e1, e1_e2), 15);

	meshlink_channel_t *ch = meshlink_channel_open(e1, e1_e2, 7, t10_local_recv, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(t10_peer_ch);
	assert(meshlink_channel_send(e1, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&hello_seen, 15));
	assert(devtool_liveness_probe_warranted(e1, e1_e2));
	assert_after(udp_status_working(e1, e1_e2), 30);

	meshlink_channel_shutdown(e2, t10_peer_ch, SHUT_WR);
	assert(wait_sync_flag(&eof_seen, 15));
	assert(meshlink_channel_send(e1, ch, "More", 4) == 4);
	assert(wait_sync_flag(&more_seen, 15));
	assert(devtool_liveness_probe_warranted(e1, e1_e2));
	assert(udp_status_working(e1, e1_e2));

	meshlink_channel_close(e1, ch);
	assert_after(!devtool_liveness_probe_warranted(e1, e1_e2), PATH_PEER_UDP_GRACE_SEC + 15);

	stability_close_trio("path_stability_t10_conf", bb, e1, e2);
	printf("path-stability T10 ok: EOF kept demand until local close\n");
}

/* --- T11: release still drops demand after the peer's class changes ----- */

static void test_release_after_reclassify(void) {
	printf("\n=== path-stability T11: close after reclassify does not leak demand ===\n");

	meshlink_handle_t *bb, *e1, *e2;
	stability_open_trio("path_stability_t11_conf", "path-stability-11", &bb, &e1, &e2);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(e2, accept_cb);

	assert_after(meshlink_get_node(e1, "baz"), 15);
	meshlink_node_t *e1_e2 = meshlink_get_node(e1, "baz");
	assert(e1_e2);
	assert_after(node_is_reachable(e1, e1_e2), 15);

	meshlink_channel_t *ch = meshlink_channel_open(e1, e1_e2, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(e1, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));
	assert(devtool_liveness_probe_warranted(e1, e1_e2));

	devtool_set_node_devclass(e1, e1_e2, DEV_CLASS_UNKNOWN);
	assert(!devtool_liveness_probe_warranted(e1, e1_e2));

	meshlink_channel_close(e1, ch);

	devtool_set_node_devclass(e1, e1_e2, DEV_CLASS_STATIONARY);
	assert(!devtool_liveness_probe_warranted(e1, e1_e2));
	assert_after(!devtool_liveness_probe_warranted(e1, e1_e2) && !udp_status_working(e1, e1_e2), PATH_PEER_UDP_GRACE_SEC + 5);

	devtool_set_node_devclass(e1, e1_e2, DEV_CLASS_BACKBONE);
	reset_sync_flag(&accepted);
	reset_sync_flag(&received);
	meshlink_set_channel_accept_cb(e2, accept_cb);
	ch = meshlink_channel_open(e1, e1_e2, 8, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(!devtool_liveness_probe_warranted(e1, e1_e2));
	meshlink_channel_close(e1, ch);
	devtool_set_node_devclass(e1, e1_e2, DEV_CLASS_STATIONARY);
	assert(!devtool_liveness_probe_warranted(e1, e1_e2));

	stability_close_trio("path_stability_t11_conf", bb, e1, e2);
	printf("path-stability T11 ok: reclassify then close left no demand\n");
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_WARNING, NULL);

	test_fixed_channel_size();
	test_mss_under_route_churn();
	test_promotion_is_slow();
	test_candidate_cooldown();
	test_candidate_cooldown_survives_old_route();
	test_suspect_before_demote();
	test_idle_peer_is_not_probed();
	test_recorded_route();
	test_fallback_keeps_suspect();
	test_parked_pmtu_promotes_local();
	test_half_open_keeps_demand();
	test_release_after_reclassify();

	printf("\npath-stability: all checks passed\n");
	return 0;
}
