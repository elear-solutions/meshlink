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
#include "netns_utils.h"

/* net.h is not includable from integration tests (transitive meshlink_internal.h). */
#define MINMTU 527
#define MTU 1451
#define PATH_PLPMTU_BASE 1211
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
#define PATH_ROUTE_MIN_RESIDENCY_SEC 10
#define PATH_SUSPECT_WINDOW_MS 1000
#define PATH_LIVENESS_INTERVAL_SEC 60
#define PATH_HEALTHY_RESET_SEC 60
#define PATH_PEER_UDP_GRACE_SEC 5
#define PATH_PROMOTION_MAX_REQUESTS 8
#define PATH_SCHED_MAX_TRANSACTIONS 2
#define PATH_SCHED_PACKETS_PER_SEC 4
#define PATH_BUDGET_PEERS 4

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

/* Per-node send_mtu_probe state for that peer only — not backbone keepalive. */
static bool plpmtu_idle(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool idle = st.plpmtu_state == DEVTOOL_PLPMTU_DISABLED
	            && st.liveness_state == 0
	            && st.liveness_probes_sent == 0;
	devtool_free_node_status(&st);
	return idle;
}

static bool pmtu_parked(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool parked = st.udp_status == DEVTOOL_UDP_WORKING && st.plpmtu_state == DEVTOOL_PLPMTU_COMPLETE;
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
		/* Ordinary peers need a canonical address distinct from loopback
		   discovery and UDP reply sources. Otherwise key exchange sanitizes
		   the discovered listen address and two source interfaces can win
		   opposite sides of the liveness test. */
		const char *canonical = i == 0 ? "localhost" : "127.0.0.2";
		assert(meshlink_set_canonical_address(m[i], meshlink_get_self(m[i]), canonical, NULL));
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

static size_t direct_mss(uint16_t payload) {
	return payload - sizeof(stability_packethdr_t) - UTCP_HDR;
}

static size_t relay_inner_mss(uint16_t hop_minmtu, const char *origin, const char *destination) {
	size_t prefix21 = 2 + strlen(origin) + strlen(destination) + RELAY_INNER_MIN;
	size_t overhead = prefix21 + sizeof(stability_packethdr_t) + UTCP_HDR;

	if(hop_minmtu <= overhead) {
		return 0;
	}

	return hop_minmtu - overhead;
}

/* --- T1: channel size follows the settled carrier ------------------------- */

static void test_fixed_channel_size(void) {
	printf("\n=== path-stability T1: channel size tracks the active carrier ===\n");

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

	/* META, so an already-parked direct PMTU cannot raise the channel at open. */
	devtool_force_meta(a, a_b, true);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);

	size_t floor = relay_floor_mss("aaa", "bbb");
	assert(meshlink_channel_get_mss(a, ch) == floor);

	/* A measurement alone does not settle the route. */
	assert(devtool_set_plpmtu(a, a_b, MTU));
	assert(meshlink_channel_get_mss(a, ch) == floor);

	devtool_force_meta(a, a_b, false);
	struct sockaddr_in wan = v4("203.0.113.10", 9);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));

	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	devtool_free_node_status(&st);

	assert(devtool_set_plpmtu(a, a_b, 1008));
	size_t raised = direct_mss(1008);
	assert(meshlink_channel_get_mss(a, ch) == raised);

	/* Eight probes is enough once minmtu has met maxmtu. */
	assert(devtool_set_plpmtu(a, a_b, 1200));
	size_t early = direct_mss(1200);
	assert(meshlink_channel_get_mss(a, ch) == early);

	meshlink_channel_t *ch2 = meshlink_channel_open(a, a_b, 8, receive_cb, NULL, 0);
	assert(ch2);
	assert(meshlink_channel_get_mss(a, ch2) == early);

	st = snapshot(a, a_b);
	assert(st.channel_mtu == early + UTCP_HDR);
	assert(st.plpmtu_state == DEVTOOL_PLPMTU_COMPLETE);
	devtool_free_node_status(&st);

	/* Clearing the measurement drops back to the floor on the same direct route. */
	assert(devtool_set_plpmtu(a, a_b, 0));
	assert(meshlink_channel_get_mss(a, ch) == floor);
	assert(meshlink_channel_get_mss(a, ch2) == floor);

	assert(devtool_set_plpmtu(a, a_b, 1200));
	assert(meshlink_channel_get_mss(a, ch) == early);

	devtool_force_meta(a, a_b, true);
	assert(meshlink_channel_get_mss(a, ch) == floor);
	assert(meshlink_channel_get_mss(a, ch2) == floor);

	meshlink_channel_abort(a, ch);
	meshlink_channel_abort(a, ch2);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t1_conf.1"));
	assert(meshlink_destroy("path_stability_t1_conf.2"));
	printf("path-stability T1 ok: floor %zu, settled %zu, demoted back\n", floor, early);
}

/* --- T14: a channel from another mesh is rejected ------------------------- */

static void test_mss_rejects_foreign_mesh(void) {
	printf("\n=== path-stability T14: get_mss rejects a channel from another mesh ===\n");

	assert(meshlink_destroy("path_stability_t14_conf.1"));
	assert(meshlink_destroy("path_stability_t14_conf.2"));
	assert(meshlink_destroy("path_stability_t14_conf.foreign"));

	meshlink_handle_t *a = meshlink_open("path_stability_t14_conf.1", "aaa", "path-stability-14", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t14_conf.2", "bbb", "path-stability-14", DEV_CLASS_STATIONARY);
	meshlink_handle_t *foreign = meshlink_open("path_stability_t14_conf.foreign", "zzz", "path-stability-14", DEV_CLASS_STATIONARY);
	assert(a && b && foreign);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	meshlink_enable_discovery(foreign, false);

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

	/* Park on META so a localhost PMTU settle cannot raise this channel first. */
	devtool_force_meta(a, a_b, true);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);

	size_t expected = relay_floor_mss("aaa", "bbb");
	assert(meshlink_channel_get_mss(a, ch) == expected);

	meshlink_errno = MESHLINK_OK;
	assert(meshlink_channel_get_mss(foreign, ch) == (size_t) - 1);
	assert(meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(meshlink_channel_get_mss(foreign, ch) == (size_t) - 1);
	assert(meshlink_errno == MESHLINK_EINVAL);

	assert(meshlink_channel_get_mss(a, ch) == expected);

	assert(meshlink_channel_get_mss(NULL, ch) == (size_t) - 1);
	assert(meshlink_channel_get_mss(a, NULL) == (size_t) - 1);

	meshlink_channel_abort(a, ch);
	meshlink_close(a);
	meshlink_close(b);
	meshlink_close(foreign);
	assert(meshlink_destroy("path_stability_t14_conf.1"));
	assert(meshlink_destroy("path_stability_t14_conf.2"));
	assert(meshlink_destroy("path_stability_t14_conf.foreign"));
	printf("path-stability T14 ok: foreign mesh returned EINVAL without touching the owner\n");
}

/* --- T2: reading the size races nothing ----------------------------------- */

struct hammer {
	meshlink_handle_t *mesh;
	meshlink_node_t *node;
	meshlink_channel_t *channel;
	size_t floor;
	atomic_bool stop;
	atomic_bool mismatch;
	atomic_uint reads;
};

static bool mss_is_legal(size_t got, size_t floor) {
	size_t lo = MINMTU - sizeof(stability_packethdr_t) - UTCP_HDR;
	size_t hi = MTU - sizeof(stability_packethdr_t) - UTCP_HDR;
	return got == floor || (got >= lo && got <= hi);
}

static void *mss_reader(void *arg) {
	struct hammer *h = arg;

	while(!atomic_load(&h->stop)) {
		size_t got = meshlink_channel_get_mss(h->mesh, h->channel);

		if(!mss_is_legal(got, h->floor)) {
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
		(void)devtool_set_plpmtu(h->mesh, h->node, MTU);
		devtool_note_route_suspect(h->mesh, h->node);
		devtool_path_route_tick(h->mesh, h->node);
		devtool_set_udp_confirmed(h->mesh, h->node, false);
		(void)devtool_set_plpmtu(h->mesh, h->node, MINMTU);
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
	h.floor = relay_floor_mss("aaa", "bbb");
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
	printf("path-stability T2 ok: %u reads, only floor or a settled direct size\n", atomic_load(&h.reads));
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

	/* A network-generation change plus a fresh observation of the same
	   endpoint lets it be tried again, but does not forgive the earlier
	   failure: the next cooldown is longer, not the same. */
	meshlink_hint_network_change(a);
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);
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
	printf("path-stability T4 ok: first cooldown %ds, retried only after network-generation change\n", first_cooldown);
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

	/* Cameras keep backbone UDP warm with no channel. */
	assert_after(udp_status_working(e1, e1_bb), 30);
	assert_after(udp_status_working(e2, e2_bb), 30);
	assert(!udp_status_working(bb, bb_e1));
	assert(!udp_status_working(bb, bb_e2));
	assert(!devtool_liveness_probe_warranted(bb, bb_e1));
	assert(!devtool_liveness_probe_warranted(bb, bb_e2));

	/* Idle ordinary peers emit zero UDP probes. mtuprobes on
	   e1↔e2 is peer-specific (send_mtu_probe for that node); backbone warm uses e*_bb. */
	assert(!devtool_liveness_probe_warranted(e1, e1_e2));
	assert(!devtool_liveness_probe_warranted(e2, e2_e1));
	assert(!udp_status_working(e1, e1_e2));
	assert(!udp_status_working(e2, e2_e1));
	assert(plpmtu_idle(e1, e1_e2));
	assert(plpmtu_idle(e2, e2_e1));
	sleep(5);
	assert(!devtool_liveness_probe_warranted(e1, e1_e2));
	assert(!devtool_liveness_probe_warranted(e2, e2_e1));
	assert(!udp_status_working(e1, e1_e2));
	assert(!udp_status_working(e2, e2_e1));
	assert(plpmtu_idle(e1, e1_e2));
	assert(plpmtu_idle(e2, e2_e1));

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
	/* Relay output may prove and maintain a demanded final hop while punching is
	   still pending. This is relay ownership, never ordinary-peer demand. */
	devtool_node_status_t relay_st = snapshot(bb, bb_e1);
	assert(relay_st.peer_udp_channel_count == 0 && !relay_st.punch_challenge_active);
	devtool_free_node_status(&relay_st);

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
	relay_st = snapshot(bb, bb_e1);
	assert(relay_st.peer_udp_channel_count == 0 && !relay_st.punch_challenge_active);
	devtool_free_node_status(&relay_st);

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

/* --- T7b: relay first hop is always the configured backbone ---------------- */

static void packet_receive_cb(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len) {
	(void)mesh;
	(void)source;
	(void)data;

	if(len) {
		set_sync_flag(&received, true);
	}
}

/* Production meshlink_send between stationary peers with no
   peer channel records a RELAY route whose first hop is connection_policy_backbone
   (path_app_relay_hop), not a planted forced hop. */
static void test_relay_carrier_is_backbone(void) {
	printf("\n=== path-stability T7b: relay first hop is the configured backbone ===\n");

	meshlink_handle_t *bb, *e1, *e2;
	stability_open_trio("path_stability_t7b_conf", "path-stability-7b", &bb, &e1, &e2);

	init_sync_flag(&received);
	meshlink_set_receive_cb(e2, packet_receive_cb);

	assert_after(meshlink_get_node(e1, "baz") && meshlink_get_node(e2, "bar"), 15);
	meshlink_node_t *e1_e2 = meshlink_get_node(e1, "baz");
	assert(e1_e2);
	assert_after(node_is_reachable(e1, e1_e2), 15);
	assert_after(node_is_keyed(e1, meshlink_get_node(e1, "foo")), 20);
	assert_after(udp_status_working(e1, meshlink_get_node(e1, "foo")), 30);

	assert(!devtool_liveness_probe_warranted(e1, e1_e2));
	assert(!strcmp(devtool_get_backbone_name(e1), "foo"));

	for(int i = 0; i < 30; i++) {
		assert(meshlink_send(e1, e1_e2, "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			break;
		}
	}

	assert(wait_sync_flag(&received, 15));

	devtool_node_status_t st = snapshot(e1, e1_e2);
	assert(st.active_route_kind == ROUTE_RELAY);
	assert(st.active_route_first_hop);
	assert(!strcmp(st.active_route_first_hop, "foo"));
	assert(!strcmp(st.active_route_first_hop, devtool_get_backbone_name(e1)));
	assert(st.active_route_carrier == CARRIER_UDP);
	devtool_free_node_status(&st);

	assert(!devtool_liveness_probe_warranted(e1, e1_e2));

	stability_close_trio("path_stability_t7b_conf", bb, e1, e2);
	printf("path-stability T7b ok: relay first hop is foo (configured backbone)\n");
}

/* ADR 0005: live meshlink_send must not relay via a conflict_backbone hop. */
static void test_conflict_backbone_skips_relay_hop(void) {
	printf("\n=== path-stability T7c: conflict_backbone skips relay hop ===\n");

	meshlink_handle_t *bb, *e1, *e2;
	stability_open_trio("path_stability_t7c_conf", "path-stability-7c", &bb, &e1, &e2);

	init_sync_flag(&received);
	meshlink_set_receive_cb(e2, packet_receive_cb);

	assert_after(meshlink_get_node(e1, "baz") && meshlink_get_node(e2, "bar"), 15);
	meshlink_node_t *e1_e2 = meshlink_get_node(e1, "baz");
	meshlink_node_t *e1_bb = meshlink_get_node(e1, "foo");
	assert(e1_e2 && e1_bb);
	assert_after(node_is_reachable(e1, e1_e2), 15);
	assert_after(node_is_keyed(e1, e1_bb), 20);
	assert_after(udp_status_working(e1, e1_bb), 30);

	for(int i = 0; i < 30; i++) {
		assert(meshlink_send(e1, e1_e2, "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			break;
		}
	}

	assert(wait_sync_flag(&received, 15));

	devtool_node_status_t st = snapshot(e1, e1_e2);
	assert(st.active_route_kind == ROUTE_RELAY);
	assert(st.active_route_first_hop);
	assert(!strcmp(st.active_route_first_hop, "foo"));
	devtool_free_node_status(&st);

	/* Wrong-class stored backbone → conflict_backbone. Tick drops the reserved
	   META; any later successful send target must not use foo as relay hop. */
	devtool_set_node_devclass(e1, e1_bb, DEV_CLASS_STATIONARY);
	assert(devtool_node_has_conflict_backbone(e1, e1_bb));

	int chosen = ROUTE_NONE;
	bool ok = devtool_apply_send_target(e1, e1_e2, &chosen);

	if(ok) {
		st = snapshot(e1, e1_e2);
		assert(chosen != ROUTE_RELAY || !st.active_route_first_hop
		                || strcmp(st.active_route_first_hop, "foo"));
		assert(st.active_route_kind != ROUTE_RELAY || !st.active_route_first_hop
		                || strcmp(st.active_route_first_hop, "foo"));
		devtool_free_node_status(&st);
	}

	init_sync_flag(&received);
	bool delivered = false;

	for(int i = 0; i < 15; i++) {
		if(meshlink_send(e1, e1_e2, "Nope", 4) && wait_sync_flag(&received, 1)) {
			delivered = true;
			break;
		}

		usleep(100000);
	}

	if(delivered) {
		st = snapshot(e1, e1_e2);
		assert(st.active_route_kind != ROUTE_RELAY || !st.active_route_first_hop
		                || strcmp(st.active_route_first_hop, "foo"));
		devtool_free_node_status(&st);
	} else {
		/* No alternate carrier after the conflicted hop is skipped — send fails
		   rather than continuing to use foo. */
		assert(!ok || chosen != ROUTE_RELAY);
	}

	stability_close_trio("path_stability_t7c_conf", bb, e1, e2);
	printf("path-stability T7c ok: conflict_backbone hop is not used for relay\n");
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
	uint16_t parked_size = st.plpmtu_size;
	devtool_plpmtu_state_t parked_state = st.plpmtu_state;
	uint32_t restarts = st.sptps_restart_count;
	assert(parked_state == DEVTOOL_PLPMTU_COMPLETE);
	assert(local.ss_family == AF_INET || local.ss_family == AF_INET6);
	devtool_free_node_status(&st);

	/* localhost is this node's canonical, so a 127.0.0.1 UDP socket cannot
	   be learned as a promotion candidate. Point canonical at the blackhole
	   before the hint. */
	assert(meshlink_set_canonical_address(a, a_b, "203.0.113.50", "9"));

	/* Both peers sit on WAN. A's probe is forced to B's local; B must reply
	   to last_udp_from, not n->address, or the round never counts. */
	struct sockaddr_in wan_b = v4("203.0.113.10", 9);
	struct sockaddr_in wan_a = v4("203.0.113.11", 9);
	bool candidate_up = false;

	/* A blackhole WAN raises suspect and can sit next to the backbone
	   transaction. This case is parked PMTU, so give the promotion its own
	   slot, then disarm the suspect timer while the real rounds finish. */
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan_b, 1));
	assert(devtool_confirm_udp_from(b, b_a, (struct sockaddr *)&wan_a, 1));
	devtool_set_probe_budget(a, 1000, 1000, PATH_SCHED_MAX_TRANSACTIONS + 2);

	for(int i = 0; i < 80 && !candidate_up; i++) {
		/* Expiry on a live META fallback drops the candidate. Hold the
		   timer off before each hint so the check can observe it. */
		devtool_disarm_suspect_timer(a, a_b);
		meshlink_hint_address(a, a_b, (struct sockaddr *)&local);
		candidate_up = candidate_is_active(a, a_b);

		if(!candidate_up) {
			usleep(50000);
		}
	}

	assert(candidate_up);

	for(int i = 0; i < 60 && !candidate_has_two_rounds(a, a_b); i++) {
		devtool_disarm_suspect_timer(a, a_b);
		usleep(100000);
	}

	assert(candidate_has_two_rounds(a, a_b));

	st = snapshot(a, a_b);
	assert(st.plpmtu_size == parked_size);
	assert(st.plpmtu_state == parked_state);
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
	assert(st.plpmtu_size == parked_size);
	assert(st.plpmtu_state == parked_state);
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

static void test_backbone_not_starved(void) {
	printf("\n=== path-stability T12: optional probe budget cannot starve backbone UDP ===\n");

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t12_conf", "path-stability-12", &bb, &a, &b);
	devtool_set_backbone_udp_keepalive(a, 1);

	init_sync_flag(&accepted);
	meshlink_set_channel_accept_cb(b, accept_cb);

	assert_after(meshlink_get_node(a, "foo"), 15);
	assert_after(devtool_backbone_udp_confirmed(a), 20);
	assert(devtool_backbone_udp_timer_armed(a));

	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));

	struct sockaddr_in wan = v4("203.0.113.12", 9);
	struct sockaddr_in local = v4("192.168.77.12", 7777);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);
	assert(candidate_is_active(a, a_b));

	devtool_set_probe_budget(a, 0, 0, 1);
	sleep(3);
	assert(devtool_backbone_udp_timer_armed(a));
	assert(devtool_backbone_udp_confirmed(a));

	meshlink_channel_abort(a, ch);
	stability_close_trio("path_stability_t12_conf", bb, a, b);
	printf("path-stability T12 ok: backbone UDP stayed warm under an empty optional budget\n");
}

static void test_promotion_request_cap(void) {
	printf("\n=== path-stability T13: a candidate is capped at eight probe requests ===\n");

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t13_conf", "path-stability-13", &bb, &a, &b);

	init_sync_flag(&accepted);
	meshlink_set_channel_accept_cb(b, accept_cb);

	assert_after(meshlink_get_node(a, "baz"), 15);
	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));

	struct sockaddr_in wan = v4("203.0.113.13", 9);
	struct sockaddr_in local = v4("192.168.77.13", 7777);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	meshlink_hint_address(a, a_b, (struct sockaddr *)&local);
	assert(candidate_is_active(a, a_b));

	unsigned max_sent = 0;

	for(int i = 0; i < 12; i++) {
		unsigned sent = devtool_candidate_requests_sent(a, a_b);

		if(sent > max_sent) {
			max_sent = sent;
		}

		if(max_sent >= PATH_PROMOTION_MAX_REQUESTS) {
			break;
		}

		sleep(1);
	}

	assert(max_sent <= PATH_PROMOTION_MAX_REQUESTS);
	assert(max_sent == PATH_PROMOTION_MAX_REQUESTS);
	assert(candidate_is_active(a, a_b));
	/* Production deadline retires the silent candidate — no age_candidate. */
	assert_after(!candidate_is_active(a, a_b), 15);

	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.candidate_failures >= 1);
	assert(st.candidate_cooldown_remaining > 0);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	stability_close_trio("path_stability_t13_conf", bb, a, b);
	printf("path-stability T13 ok: silent candidate capped then cooled down via deadline\n");
}

/* --- T18a: reliable retransmit raises suspect; later send does not clear it --- */

static bool route_is_suspect(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool suspect = st.active_route_suspect;
	devtool_free_node_status(&st);
	return suspect;
}

static struct sync_flag retransmit_suspect_log;

static void t18a_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	(void)level;

	if(text && strstr(text, "route-suspect") && strstr(text, "reliable retransmit")) {
		set_sync_flag(&retransmit_suspect_log, true);
	}
}

static void test_retransmit_raises_suspect(void) {
	printf("\n=== path-stability T18a: channel retransmit raises suspect ===\n");

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t18a_conf", "path-stability-18a", &bb, &a, &b);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	init_sync_flag(&retransmit_suspect_log);
	meshlink_set_channel_accept_cb(b, accept_cb);
	meshlink_set_log_cb(a, MESHLINK_INFO, t18a_log_cb);

	assert_after(meshlink_get_node(a, "baz"), 15);
	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, meshlink_get_node(a, "foo")), 20);
	assert(devtool_has_live_fallback(a, a_b));

	/* Edge↔edge channel starts punching; wait until PMTU is parked so a
	   blackhole redirect is not immediately demoted by probe failure. */
	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(meshlink_channel_send(a, ch, "hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));
	assert_after(udp_status_working(a, a_b), 30);
	assert_after(pmtu_parked(a, a_b), 60);

	/* Blackhole plant only — must not itself mark suspect. */
	struct sockaddr_in dead = v4("127.0.0.1", 1);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&dead, 0));
	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	assert(!st.active_route_suspect);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	/* Unacked reliable data → channel_retransmit → path_note_route_suspect. */
	set_sync_flag(&received, false);
	assert(meshlink_channel_send(a, ch, "blackhole", 9) == 9);
	assert(wait_sync_flag(&retransmit_suspect_log, 30));
	assert(route_is_suspect(a, a_b));

	st = snapshot(a, a_b);
	assert(st.active_route_suspect);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	/* Later production send must not clear suspicion (fallback may carry it). */
	ssize_t nch = meshlink_channel_send(a, ch, "still", 5);
	ssize_t ndg = meshlink_send(a, a_b, "meta", 4);
	assert(nch >= 0 || ndg >= 0);
	st = snapshot(a, a_b);
	assert(st.active_route_suspect);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	stability_close_trio("path_stability_t18a_conf", bb, a, b);
	printf("path-stability T18a ok: retransmit raised suspect; later send left it set\n");
}

/* --- T22: an MSS-sized retransmit still arrives while the route is suspect --- */

static uint8_t t22_buf[2048];
static size_t t22_got;
static size_t t22_expect;
static struct sync_flag t22_suspect;

static void t22_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;

	if(data && t22_got + len <= sizeof t22_buf) {
		memcpy(t22_buf + t22_got, data, len);
		t22_got += len;
	}
}

static bool t22_accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)port;
	(void)data;
	(void)len;
	meshlink_set_channel_receive_cb(mesh, channel, t22_receive_cb);
	set_sync_flag(&accepted, true);
	return true;
}

static void t22_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	(void)level;

	if(text && strstr(text, "route-suspect") && strstr(text, "reliable retransmit")) {
		set_sync_flag(&t22_suspect, true);
	}
}

static bool t22_arrived(void) {
	return t22_got == t22_expect;
}

static bool route_is_direct_udp(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool ok = st.active_route_kind == ROUTE_DIRECT_UDP
	          && st.udp_status == DEVTOOL_UDP_WORKING
	          && st.plpmtu_state == DEVTOOL_PLPMTU_COMPLETE;
	devtool_free_node_status(&st);
	return ok;
}

static void test_oversize_suspect_retransmit(void) {
	printf("\n=== path-stability T22: oversize suspect retransmit still arrives ===\n");

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t22_conf", "path-stability-22", &bb, &a, &b);

	init_sync_flag(&accepted);
	init_sync_flag(&t22_suspect);
	meshlink_set_channel_accept_cb(b, t22_accept_cb);
	meshlink_set_log_cb(a, MESHLINK_INFO, t22_log_cb);

	assert_after(meshlink_get_node(a, "baz") && meshlink_get_node(a, "foo"), 15);
	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	meshlink_node_t *a_bb = meshlink_get_node(a, "foo");
	assert(a_b && a_bb);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_bb), 20);
	assert(devtool_has_live_fallback(a, a_b));

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, t22_receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	/* Residency has to expire before the channel MSS is the direct one. */
	assert_after(route_is_direct_udp(a, a_b), 70);

	devtool_node_status_t hop = snapshot(a, a_bb);
	size_t mss = meshlink_channel_get_mss(a, ch);
	size_t relay_mss = relay_inner_mss(hop.plpmtu_size, "bar", "baz");
	devtool_free_node_status(&hop);
	assert(mss > relay_mss);
	assert(mss <= sizeof t22_buf);

	/* A retransmit during setup may already have marked the route. The drop
	   below has to be the one that raises suspicion, so wait until it is clear. */
	assert_after(!route_is_suspect(a, a_b), 5);

	uint8_t payload[2048];

	for(size_t i = 0; i < mss; i++) {
		payload[i] = (uint8_t)(i * 17 + 3);
	}

	t22_got = 0;
	t22_expect = mss;
	set_sync_flag(&t22_suspect, false);
	assert(devtool_drop_next_direct_udp_records(a, a_b, 1));
	{
		ssize_t sent = 0;

		for(int i = 0; i < 50 && sent <= 0; i++) {
			sent = meshlink_channel_send(a, ch, payload, mss);

			if(sent <= 0) {
				usleep(100000);
			}
		}

		assert(sent == (ssize_t)mss);
	}
	assert_after(t22_arrived(), 6);
	assert(check_sync_flag(&t22_suspect));
	assert(memcmp(t22_buf, payload, mss) == 0);

	devtool_node_status_t st = snapshot(a, a_b);
	assert(st.fallback_oversize_redirects >= 1);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);

	meshlink_channel_abort(a, ch);
	stability_close_trio("path_stability_t22_conf", bb, a, b);
	printf("path-stability T22 ok: %zu-byte retransmit arrived, redirects %u\n", mss, 1);
}

/* --- T19: many peers stay inside global txn + packet budgets -------------- */

static unsigned count_active_candidates(meshlink_handle_t *mesh, meshlink_node_t **peers, int n) {
	unsigned active = 0;

	for(int i = 0; i < n; i++) {
		if(candidate_is_active(mesh, peers[i])) {
			active++;
		}
	}

	return active;
}

static void test_many_peers_stay_in_budget(void) {
	printf("\n=== path-stability T19: many peers stay inside scheduler budgets ===\n");

	const char *prefix = "path_stability_t19_conf";
	const char *names[] = {"foo", "cam", "p0", "p1", "p2", "p3"};
	const int classes[] = {
		DEV_CLASS_BACKBONE, DEV_CLASS_STATIONARY,
		DEV_CLASS_STATIONARY, DEV_CLASS_STATIONARY,
		DEV_CLASS_STATIONARY, DEV_CLASS_STATIONARY
	};
	meshlink_handle_t *m[6];
	meshlink_channel_t *ch[PATH_BUDGET_PEERS];
	meshlink_node_t *peers[PATH_BUDGET_PEERS];
	uint64_t prev_optional;

	stability_destroy_conf(prefix, 6);

	for(int i = 0; i < 6; i++) {
		char path[128];
		snprintf(path, sizeof path, "%s.%d", prefix, i);
		m[i] = meshlink_open(path, names[i], "path-stability-19", classes[i]);
		assert(m[i]);
		meshlink_enable_discovery(m[i], false);
		assert(meshlink_set_canonical_address(m[i], meshlink_get_self(m[i]), "localhost", NULL));
	}

	meshlink_handle_t *bb = m[0];
	meshlink_handle_t *cam = m[1];

	for(int i = 1; i < 6; i++) {
		join_meshlink_peer(bb, m[i]);
	}

	for(int i = 0; i < 6; i++) {
		assert(meshlink_start(m[i]));
	}

	init_sync_flag(&accepted);

	for(int i = 0; i < PATH_BUDGET_PEERS; i++) {
		meshlink_set_channel_accept_cb(m[i + 2], accept_cb);
	}

	meshlink_node_t *cam_bb = meshlink_get_node(cam, "foo");
	assert(cam_bb);
	assert_after(node_is_reachable(cam, cam_bb), 15);
	assert_after(node_is_keyed(cam, cam_bb), 20);

	devtool_set_backbone_udp_keepalive(cam, 1);
	assert_after(devtool_backbone_udp_confirmed(cam), 20);
	assert(devtool_backbone_udp_timer_armed(cam));

	/* 4 peers > PATH_SCHED_MAX_TRANSACTIONS: production channel + WAN plant +
	   local hint starts promotion; the scheduler admits the transaction. */
	for(int i = 0; i < PATH_BUDGET_PEERS; i++) {
		assert_after(meshlink_get_node(cam, names[i + 2]), 15);
		peers[i] = meshlink_get_node(cam, names[i + 2]);
		assert(peers[i]);
		assert_after(node_is_reachable(cam, peers[i]), 15);

		reset_sync_flag(&accepted);
		ch[i] = meshlink_channel_open(cam, peers[i], (uint16_t)(7 + i), receive_cb, NULL, 0);
		assert(ch[i]);
		assert(wait_sync_flag(&accepted, 20));
		assert_after(node_is_keyed(cam, peers[i]), 20);

		char wan_ip[32];
		char lan_ip[32];
		snprintf(wan_ip, sizeof wan_ip, "203.0.113.%d", 20 + i);
		snprintf(lan_ip, sizeof lan_ip, "192.168.77.%d", 20 + i);
		struct sockaddr_in wan = v4(wan_ip, 9);
		struct sockaddr_in local = v4(lan_ip, (uint16_t)(7770 + i));
		assert(devtool_confirm_udp_from(cam, peers[i], (struct sockaddr *)&wan, 1));
		meshlink_hint_address(cam, peers[i], (struct sockaddr *)&local);
	}

	/* At least one candidate must start under the default txn cap (not forced). */
	assert_after(count_active_candidates(cam, peers, PATH_BUDGET_PEERS) >= 1, 10);
	assert(count_active_candidates(cam, peers, PATH_BUDGET_PEERS) <= PATH_SCHED_MAX_TRANSACTIONS);
	assert(devtool_probe_active_transactions(cam) <= PATH_SCHED_MAX_TRANSACTIONS);

	/* Freeze refill an hour out so one sleep cannot span two token windows. */
	devtool_set_probe_budget(cam, PATH_SCHED_PACKETS_PER_SEC, 20, PATH_SCHED_MAX_TRANSACTIONS);
	prev_optional = devtool_probe_optional_packets_sent(cam);

	for(int sec = 0; sec < 10; sec++) {
		sleep(1);

		assert(devtool_probe_active_transactions(cam) <= PATH_SCHED_MAX_TRANSACTIONS);
		assert(count_active_candidates(cam, peers, PATH_BUDGET_PEERS) <= PATH_SCHED_MAX_TRANSACTIONS);
		assert(devtool_backbone_udp_confirmed(cam));
		assert(devtool_backbone_udp_timer_armed(cam));
	}

	{
		uint64_t sent = devtool_probe_optional_packets_sent(cam);
		assert(sent >= prev_optional);
		assert(sent - prev_optional <= PATH_SCHED_PACKETS_PER_SEC);
	}

	for(int i = 0; i < PATH_BUDGET_PEERS; i++) {
		meshlink_channel_abort(cam, ch[i]);
	}

	for(int i = 0; i < 6; i++) {
		meshlink_close(m[i]);
	}

	stability_destroy_conf(prefix, 6);
	printf("path-stability T19 ok: txn<=%d pkt/s<=%d with %d peers; backbone stayed warm\n",
	       PATH_SCHED_MAX_TRANSACTIONS, PATH_SCHED_PACKETS_PER_SEC, PATH_BUDGET_PEERS);
}

/* --- Delivery over the six route classes --------------------------------- */

static bool node_meta_up(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool up = st.meta_connected;
	devtool_free_node_status(&st);
	return up;
}

static bool route_kind_local_meta(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool ok = st.active_route_kind == ROUTE_DIRECT_LOCAL_META && st.active_route_local;
	devtool_free_node_status(&st);
	return ok;
}

static bool route_relay_carrier(meshlink_handle_t *mesh, meshlink_node_t *node, int carrier, const char *hop) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool ok = st.active_route_kind == ROUTE_RELAY
	          && st.active_route_carrier == carrier
	          && st.active_route_first_hop
	          && hop && !strcmp(st.active_route_first_hop, hop);
	devtool_free_node_status(&st);
	return ok;
}

static bool candidate_validated(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool ok = st.candidate_active && st.candidate_rounds >= 2;
	devtool_free_node_status(&st);
	return ok;
}

static void plant_lan_localhost(meshlink_handle_t *viewer, meshlink_handle_t *peer) {
	meshlink_node_t *n = meshlink_get_node(viewer, meshlink_get_self(peer)->name);
	struct sockaddr_in sa = ipv4("127.0.0.1", (uint16_t)meshlink_get_port(peer));

	assert(n);
	assert(devtool_learn_discovery_address(viewer, n, (struct sockaddr *)&sa));
}

/* Class 3: local peer META — discovery plant only; no channel so UDP cannot win. */
static void test_local_peer_meta_route(void) {
	printf("\n=== path-stability T17c: local peer META delivers ===\n");

	meshlink_handle_t *bb, *e1, *e2;
	stability_open_trio("path_stability_t17c_conf", "path-stability-17c", &bb, &e1, &e2);

	init_sync_flag(&received);
	meshlink_set_receive_cb(e2, packet_receive_cb);

	assert_after(meshlink_get_node(e1, "baz") && meshlink_get_node(e2, "bar"), 15);
	meshlink_node_t *e1_e2 = meshlink_get_node(e1, "baz");
	assert(e1_e2);
	assert_after(node_is_reachable(e1, e1_e2), 15);
	assert_after(node_is_keyed(e1, meshlink_get_node(e1, "foo")), 20);

	plant_lan_localhost(e1, e2);
	plant_lan_localhost(e2, e1);
	assert_after(node_meta_up(e1, e1_e2), 15);
	assert(!devtool_liveness_probe_warranted(e1, e1_e2));

	for(int i = 0; i < 30; i++) {
		assert(meshlink_send(e1, e1_e2, "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			break;
		}
	}

	assert(wait_sync_flag(&received, 15));
	assert_after(route_kind_local_meta(e1, e1_e2), 5);

	stability_close_trio("path_stability_t17c_conf", bb, e1, e2);
	printf("path-stability T17c ok: DIRECT_LOCAL_META\n");
}

/* Class 2: WAN peer UDP — netns with 203.0.113 (not RFC1918), channel demand. */
static void test_wan_peer_udp_route(void) {
	printf("\n=== path-stability T17b: WAN peer UDP delivers ===\n");

	peer_config_t *peers = setup_relay_peer_nut_wan("pathstab17b");

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(peers[2].mesh, accept_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after(meshlink_get_node(peers[1].mesh, "nut") && meshlink_get_node(peers[2].mesh, "peer"), 20);
	meshlink_node_t *peer_nut = meshlink_get_node(peers[1].mesh, "nut");
	meshlink_node_t *nut_peer = meshlink_get_node(peers[2].mesh, "peer");
	assert(peer_nut && nut_peer);
	assert_after(node_is_reachable(peers[1].mesh, peer_nut), 15);
	assert_after(node_is_keyed(peers[1].mesh, meshlink_get_node(peers[1].mesh, "relay")), 20);

	hint_address(peers[1].mesh, peer_nut, peers[2].ip, meshlink_get_port(peers[2].mesh));
	hint_address(peers[2].mesh, nut_peer, peers[1].ip, meshlink_get_port(peers[1].mesh));

	meshlink_channel_t *ch = meshlink_channel_open(peers[1].mesh, peer_nut, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 20));
	assert(meshlink_channel_send(peers[1].mesh, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));
	assert(devtool_liveness_probe_warranted(peers[1].mesh, peer_nut));
	assert_after(udp_status_working(peers[1].mesh, peer_nut), 45);

	/* A RELAY_UDP candidate can win first (backbone warm). Commit it, then wait
	   for the better DIRECT_UDP candidate and commit that. */
	for(int pass = 0; pass < 2; pass++) {
		assert_after(candidate_validated(peers[1].mesh, peer_nut), 30);
		devtool_age_route(peers[1].mesh, peer_nut, PATH_ROUTE_MIN_RESIDENCY_SEC + 1);
		devtool_age_candidate(peers[1].mesh, peer_nut, 2);
		devtool_path_route_tick(peers[1].mesh, peer_nut);

		devtool_node_status_t st = snapshot(peers[1].mesh, peer_nut);
		bool done = st.active_route_kind == ROUTE_DIRECT_UDP && !st.active_route_local;
		devtool_free_node_status(&st);

		if(done) {
			break;
		}
	}

	reset_sync_flag(&received);
	assert(meshlink_channel_send(peers[1].mesh, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&received, 15));

	{
		devtool_node_status_t st = snapshot(peers[1].mesh, peer_nut);
		assert(st.active_route_kind == ROUTE_DIRECT_UDP);
		assert(!st.active_route_local);
		devtool_free_node_status(&st);
	}

	meshlink_channel_abort(peers[1].mesh, ch);
	close_relay_peer_nut(peers);
	printf("path-stability T17b ok: DIRECT_UDP WAN (!local)\n");
}

/* Keys are already valid. Opening a channel still requests the endpoint once, and does not restart SPTPS. */
static void test_punch_demand_keeps_key(void) {
	printf("\n=== path-stability T22b: punch request with a valid key ===\n");

	peer_config_t *peers = setup_relay_peer_nut_wan("pathstab22");
	meshlink_node_t *peer_nut;
	meshlink_node_t *nut_peer;
	meshlink_channel_t *ch;
	meshlink_channel_t *ch2;
	uint32_t restarts;
	uint32_t requests;

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(peers[2].mesh, accept_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after(meshlink_get_node(peers[1].mesh, "nut") && meshlink_get_node(peers[2].mesh, "peer"), 20);
	peer_nut = meshlink_get_node(peers[1].mesh, "nut");
	nut_peer = meshlink_get_node(peers[2].mesh, "peer");
	assert(peer_nut && nut_peer);
	assert_after(node_is_reachable(peers[1].mesh, peer_nut), 15);

	/* Ordinary-peer SPTPS starts on channel demand. Prime a key while UDP
	   probes are held, then open again: the new demand must request an
	   endpoint without restarting that key. */
	devtool_force_meta(peers[1].mesh, peer_nut, true);
	devtool_force_meta(peers[2].mesh, nut_peer, true);
	ch = meshlink_channel_open(peers[1].mesh, peer_nut, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 20));
	assert_after(node_is_keyed(peers[1].mesh, peer_nut) && node_is_keyed(peers[2].mesh, nut_peer), 20);
	meshlink_channel_abort(peers[1].mesh, ch);
	reset_sync_flag(&accepted);

	{
		devtool_node_status_t st = snapshot(peers[1].mesh, peer_nut);
		restarts = st.sptps_restart_count;
		requests = st.punch_requests_sent;
		devtool_free_node_status(&st);
	}

	ch = meshlink_channel_open(peers[1].mesh, peer_nut, 7, receive_cb, NULL, 0);
	assert(ch);

	{
		devtool_node_status_t st = snapshot(peers[1].mesh, peer_nut);
		assert(st.punch_requests_sent == requests + 1);
		assert(st.sptps_restart_count == restarts);
		assert(st.validkey);
		requests = st.punch_requests_sent;
		devtool_free_node_status(&st);
	}

	ch2 = meshlink_channel_open(peers[1].mesh, peer_nut, 8, receive_cb, NULL, 0);
	assert(ch2);

	{
		devtool_node_status_t st = snapshot(peers[1].mesh, peer_nut);
		assert(st.punch_requests_sent == requests);
		assert(st.sptps_restart_count == restarts);
		devtool_free_node_status(&st);
	}

	assert(wait_sync_flag(&accepted, 20));

	devtool_force_meta(peers[1].mesh, peer_nut, false);
	devtool_force_meta(peers[2].mesh, nut_peer, false);
	meshlink_channel_abort(peers[1].mesh, ch);
	meshlink_channel_abort(peers[1].mesh, ch2);
	close_relay_peer_nut(peers);
	printf("path-stability T22 ok: one punch request, SPTPS kept\n");
}

/* Class 5: backbone direct-META relay — UDP dropped, no camera LAN META. */
static void test_relay_meta_direct_route(void) {
	printf("\n=== path-stability T17e: backbone META_DIRECT relay delivers ===\n");

	peer_config_t *peers = setup_relay_peer_nut_indirect("pathstab17e");

	if(!set_peers_tcponly(peers, 3)) {
		close_relay_peer_nut(peers);
		printf("SKIP path-stability T17e: iptables UDP drop unavailable\n");
		return;
	}

	init_sync_flag(&received);
	meshlink_set_receive_cb(peers[2].mesh, packet_receive_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after(meshlink_get_node(peers[1].mesh, "nut") && meshlink_get_node(peers[2].mesh, "peer"), 20);
	meshlink_node_t *peer_nut = meshlink_get_node(peers[1].mesh, "nut");
	meshlink_node_t *peer_relay = meshlink_get_node(peers[1].mesh, "relay");
	assert(peer_nut && peer_relay);
	assert_after(node_is_reachable(peers[1].mesh, peer_nut), 15);
	assert_after(node_meta_up(peers[1].mesh, peer_relay), 20);
	assert(!devtool_liveness_probe_warranted(peers[1].mesh, peer_nut));

	for(int i = 0; i < 40; i++) {
		assert(meshlink_send(peers[1].mesh, peer_nut, "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			break;
		}
	}

	assert(wait_sync_flag(&received, 20));
	assert_after(route_relay_carrier(peers[1].mesh, peer_nut, CARRIER_META_DIRECT, "relay"), 10);

	close_relay_peer_nut(peers);
	printf("path-stability T17e ok: RELAY META_DIRECT via relay\n");
}

/* Class 6: backbone canonical-META relay — UDP dropped, META dialed via canonical. */
static void test_relay_meta_canonical_route(void) {
	printf("\n=== path-stability T17f: backbone META_CANONICAL relay delivers ===\n");

	peer_config_t *peers = setup_relay_peer_nut_indirect("pathstab17f");

	if(!set_peers_tcponly(peers, 3)) {
		close_relay_peer_nut(peers);
		printf("SKIP path-stability T17f: iptables UDP drop unavailable\n");
		return;
	}

	char port_str[16];
	snprintf(port_str, sizeof port_str, "%d", meshlink_get_port(peers[0].mesh));

	/* Invite already joined; before start, pin the backbone META dial to canonical. */
	meshlink_node_t *peer_relay = meshlink_get_node(peers[1].mesh, "relay");
	meshlink_node_t *nut_relay = meshlink_get_node(peers[2].mesh, "relay");
	assert(peer_relay && nut_relay);
	assert(meshlink_set_canonical_address(peers[1].mesh, peer_relay, "192.168.1.1", port_str));
	assert(meshlink_set_canonical_address(peers[2].mesh, nut_relay, "192.168.2.1", port_str));
	forget_addresses(peers[1].mesh, peer_relay);
	forget_addresses(peers[2].mesh, nut_relay);

	init_sync_flag(&received);
	meshlink_set_receive_cb(peers[2].mesh, packet_receive_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after(meshlink_get_node(peers[1].mesh, "nut") && meshlink_get_node(peers[2].mesh, "peer"), 20);
	meshlink_node_t *peer_nut = meshlink_get_node(peers[1].mesh, "nut");
	peer_relay = meshlink_get_node(peers[1].mesh, "relay");
	assert(peer_nut && peer_relay);
	assert_after(node_is_reachable(peers[1].mesh, peer_nut), 15);
	assert_after(node_meta_up(peers[1].mesh, peer_relay), 30);

	{
		devtool_node_status_t st = snapshot(peers[1].mesh, peer_relay);
		assert(st.meta_connected);
		assert(st.meta_via_canonical);
		devtool_free_node_status(&st);
	}

	assert(!devtool_liveness_probe_warranted(peers[1].mesh, peer_nut));

	for(int i = 0; i < 40; i++) {
		assert(meshlink_send(peers[1].mesh, peer_nut, "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			break;
		}
	}

	assert(wait_sync_flag(&received, 20));
	assert_after(route_relay_carrier(peers[1].mesh, peer_nut, CARRIER_META_CANONICAL, "relay"), 10);

	close_relay_peer_nut(peers);
	printf("path-stability T17f ok: RELAY META_CANONICAL via relay\n");
}

static void set_fast_pings(meshlink_handle_t *mesh) {
	meshlink_set_dev_class_timeouts(mesh, DEV_CLASS_BACKBONE, 2, 1);
	meshlink_set_dev_class_timeouts(mesh, DEV_CLASS_STATIONARY, 2, 1);
	meshlink_set_dev_class_timeouts(mesh, DEV_CLASS_PORTABLE, 2, 1);
}

/* A received META request resets the peer's ping timer, so only one side pings. */
static void test_meta_ping_is_one_sided(void) {
	printf("\n=== path-stability T20: one META ping per interval ===\n");

	assert(meshlink_destroy("path_stability_t20_conf.1"));
	assert(meshlink_destroy("path_stability_t20_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_t20_conf.1", "aaa", "path-stability-20", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_t20_conf.2", "bbb", "path-stability-20", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	set_fast_pings(a);
	set_fast_pings(b);
	join_meshlink_peer(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	meshlink_node_t *b_a = meshlink_get_node(b, "aaa");
	assert(a_b && b_a);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_meta_up(a, a_b) && node_meta_up(b, b_a), 15);

	/* Let the first exchange pick a single pinger. */
	sleep(3);

	unsigned a0 = devtool_meta_pings_sent(a, a_b);
	unsigned b0 = devtool_meta_pings_sent(b, b_a);
	sleep(7);
	unsigned a_sent = devtool_meta_pings_sent(a, a_b) - a0;
	unsigned b_sent = devtool_meta_pings_sent(b, b_a) - b0;
	unsigned lo = a_sent < b_sent ? a_sent : b_sent;
	unsigned hi = a_sent > b_sent ? a_sent : b_sent;

	assert(hi >= 2);
	assert(lo <= 1);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_t20_conf.1"));
	assert(meshlink_destroy("path_stability_t20_conf.2"));
	printf("path-stability T20 ok: pings %u/%u\n", a_sent, b_sent);
}

/* Channel UDP liveness is one direction plus the echo. LAN META stays silent
   while that UDP is healthy, and pings again once UDP is pinned off. A +8
   PMTU reply parks instead of reopening discovery. */
static void test_idle_channel_traffic(void) {
	printf("\n=== path-stability T21: one-way liveness, quiet LAN META, parked PMTU ===\n");

	meshlink_handle_t *bb, *e1, *e2;
	stability_open_trio("path_stability_t21_conf", "path-stability-21", &bb, &e1, &e2);
	set_fast_pings(bb);
	set_fast_pings(e1);
	set_fast_pings(e2);

	init_sync_flag(&accepted);
	meshlink_set_channel_accept_cb(e2, accept_cb);

	assert_after(meshlink_get_node(e1, "baz") && meshlink_get_node(e2, "bar"), 15);
	meshlink_node_t *e1_e2 = meshlink_get_node(e1, "baz");
	meshlink_node_t *e2_e1 = meshlink_get_node(e2, "bar");
	assert(e1_e2 && e2_e1);
	assert_after(node_is_reachable(e1, e1_e2), 15);
	assert_after(node_is_keyed(e1, meshlink_get_node(e1, "foo")), 20);

	plant_lan_localhost(e1, e2);
	plant_lan_localhost(e2, e1);
	assert_after(node_meta_up(e1, e1_e2) && node_meta_up(e2, e2_e1), 15);
	assert_after(devtool_local_adjacency_count(e1) >= 1 && devtool_local_adjacency_count(e2) >= 1, 10);

	meshlink_channel_t *ch = meshlink_channel_open(e1, e1_e2, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert_after(pmtu_parked(e1, e1_e2) && pmtu_parked(e2, e2_e1), 60);

	/* Both timers can still fire once after park. That exchange is what
	   makes the greater name yield; count probes only after it. */
	sleep(4);

	unsigned live1 = devtool_liveness_probes_sent(e1, e1_e2);
	unsigned live2 = devtool_liveness_probes_sent(e2, e2_e1);
	unsigned ping1 = devtool_meta_pings_sent(e1, e1_e2);
	unsigned ping2 = devtool_meta_pings_sent(e2, e2_e1);
	sleep(8);

	unsigned dlive1 = devtool_liveness_probes_sent(e1, e1_e2) - live1;
	unsigned dlive2 = devtool_liveness_probes_sent(e2, e2_e1) - live2;
	unsigned dping1 = devtool_meta_pings_sent(e1, e1_e2) - ping1;
	unsigned dping2 = devtool_meta_pings_sent(e2, e2_e1) - ping2;
	unsigned lo = dlive1 < dlive2 ? dlive1 : dlive2;
	unsigned hi = dlive1 > dlive2 ? dlive1 : dlive2;

	fprintf(stderr, "path-stability T21 window: liveness %u/%u pings %u/%u\n", dlive1, dlive2, dping1, dping2);
	/* One stray probe from the greater name can land before its park
	   sticks when the host is busy. A tie (1/1, 2/2) is still a failure. */
	assert(hi >= 1);
	assert(hi > lo);
	assert(lo <= 1);
	assert(dping1 == 0 && dping2 == 0);

	assert(devtool_set_plpmtu(e1, e1_e2, 1000));
	assert(devtool_drop_size_probes_above(e2, e2_e1, 1259));
	assert(devtool_plpmtu_raise_due(e1, e1_e2));
	{
		bool raised = false;

		for(int i = 0; i < 150 && !raised; i++) {
			devtool_node_status_t st = snapshot(e1, e1_e2);
			raised = st.plpmtu_size == 1259 && st.plpmtu_state == DEVTOOL_PLPMTU_COMPLETE;
			devtool_free_node_status(&st);

			if(!raised) {
				usleep(100000);
			}
		}

		assert(raised);
	}

	devtool_force_meta(e1, e1_e2, true);
	devtool_force_meta(e2, e2_e1, true);
	ping1 = devtool_meta_pings_sent(e1, e1_e2);
	ping2 = devtool_meta_pings_sent(e2, e2_e1);
	sleep(5);
	dping1 = devtool_meta_pings_sent(e1, e1_e2) - ping1;
	dping2 = devtool_meta_pings_sent(e2, e2_e1) - ping2;
	assert(dping1 + dping2 >= 1);

	meshlink_channel_abort(e1, ch);
	stability_close_trio("path_stability_t21_conf", bb, e1, e2);
	printf("path-stability T21 ok: liveness %u/%u, resumed pings %u/%u\n", dlive1, dlive2, dping1, dping2);
}

/* --- T23: one lost liveness reply is not a give-up ------------------------ */

static struct sync_flag t23_giveup;

static void t23_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	(void)level;

	if(text && strstr(text, "baz did not respond to UDP ping")) {
		set_sync_flag(&t23_giveup, true);
	}
}

static void test_lost_pmtu_raise_is_not_giveup(void) {
	printf("\n=== path-stability T23: one lost liveness reply is not a give-up ===\n");

	meshlink_handle_t *bb, *a, *b;
	stability_open_trio("path_stability_t23_conf", "path-stability-23", &bb, &a, &b);
	set_fast_pings(bb);
	set_fast_pings(a);
	set_fast_pings(b);

	init_sync_flag(&accepted);
	init_sync_flag(&t23_giveup);
	meshlink_set_channel_accept_cb(b, accept_cb);
	meshlink_set_log_cb(a, MESHLINK_INFO, t23_log_cb);

	assert_after(meshlink_get_node(a, "baz") && meshlink_get_node(b, "bar"), 15);
	meshlink_node_t *a_b = meshlink_get_node(a, "baz");
	meshlink_node_t *b_a = meshlink_get_node(b, "bar");
	assert(a_b && b_a);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, meshlink_get_node(a, "foo")), 20);

	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert_after(route_is_direct_udp(a, a_b) && pmtu_parked(b, b_a), 70);

	devtool_node_status_t before = snapshot(a, a_b);
	uint16_t size = before.plpmtu_size;
	devtool_free_node_status(&before);
	assert(size >= MINMTU);

	set_sync_flag(&t23_giveup, false);
	/* bar probes; baz parks. The reply lands on bar, so the drop is here.
	   Fast pings exceed the parked 20/min budget, and a denied send is not silence. */
	devtool_set_probe_budget(a, 30, 30, 2);
	assert(devtool_drop_liveness_replies(a, a_b, 1));
	sleep(8);
	assert(!check_sync_flag(&t23_giveup));

	before = snapshot(a, a_b);
	assert(before.udp_status == DEVTOOL_UDP_WORKING);
	assert(before.active_route_kind == ROUTE_DIRECT_UDP);
	assert(before.plpmtu_size == size);
	assert(before.plpmtu_state == DEVTOOL_PLPMTU_COMPLETE);
	devtool_free_node_status(&before);

	set_sync_flag(&t23_giveup, false);
	devtool_set_probe_budget(a, 30, 30, 2);
	assert(devtool_drop_liveness_replies(a, a_b, 255));
	assert(wait_sync_flag(&t23_giveup, 15));

	before = snapshot(a, a_b);
	assert(before.plpmtu_size == size);
	assert(before.liveness_giveups >= 1);
	devtool_free_node_status(&before);
	assert(devtool_drop_liveness_replies(a, a_b, 0));

	meshlink_channel_abort(a, ch);
	stability_close_trio("path_stability_t23_conf", bb, a, b);
	printf("path-stability T23 ok: one lost reply kept UDP, silence gave up, size %u\n", size);
}

static uint8_t demote_buf[2048];
static size_t demote_got;

static void demote_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;

	if(data && demote_got + len <= sizeof demote_buf) {
		memcpy(demote_buf + demote_got, data, len);
		demote_got += len;
	}
}

static bool demote_accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)port;
	(void)data;
	(void)len;
	meshlink_set_channel_receive_cb(mesh, channel, demote_receive_cb);
	set_sync_flag(&accepted, true);
	return true;
}

static bool demote_got_all(size_t n) {
	return demote_got == n;
}

/* In-flight data cut at the raised MSS still arrives after the route drops to the floor. */
static void test_demotion_resplits(void) {
	printf("\n=== path-stability: demotion resplits in-flight data ===\n");

	assert(meshlink_destroy("path_stability_demote_conf.1"));
	assert(meshlink_destroy("path_stability_demote_conf.2"));

	meshlink_handle_t *a = meshlink_open("path_stability_demote_conf.1", "aaa", "path-stability-demote", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_stability_demote_conf.2", "bbb", "path-stability-demote", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(b, demote_accept_cb);
	join_meshlink_peer(a, b);
	assert(meshlink_start(a));
	assert(meshlink_start(b));

	meshlink_node_t *a_b = meshlink_get_node(a, "bbb");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	assert_after(node_is_keyed(a, a_b), 20);

	/* Open on the live meta path. A WAN blackhole cannot complete the handshake. */
	meshlink_channel_t *ch = meshlink_channel_open(a, a_b, 7, demote_receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));

	struct sockaddr_in wan = v4("203.0.113.12", 9);
	assert(devtool_confirm_udp_from(a, a_b, (struct sockaddr *)&wan, 1));
	assert(devtool_set_plpmtu(a, a_b, 1200));

	size_t floor = relay_floor_mss("aaa", "bbb");
	size_t raised = direct_mss(1200);
	assert(meshlink_channel_get_mss(a, ch) == raised);
	assert(raised > floor);

	size_t n = floor + 100;
	assert(n < sizeof demote_buf);
	uint8_t payload[1600];

	for(size_t i = 0; i < n; i++) {
		payload[i] = (uint8_t)(i * 17 + 3);
	}

	demote_got = 0;
	assert(meshlink_channel_send(a, ch, payload, n) == (ssize_t)n);
	devtool_force_meta(a, a_b, true);
	assert(meshlink_channel_get_mss(a, ch) == floor);
	assert_after(demote_got_all(n), 15);
	assert(memcmp(demote_buf, payload, n) == 0);

	meshlink_channel_abort(a, ch);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_stability_demote_conf.1"));
	assert(meshlink_destroy("path_stability_demote_conf.2"));
	printf("path-stability demotion ok: %zu bytes arrived after shrink to %zu\n", n, floor);
}

static bool plpmtu_is(meshlink_handle_t *mesh, meshlink_node_t *node, uint16_t size, devtool_plpmtu_state_t state) {
	devtool_node_status_t st = snapshot(mesh, node);
	bool ok = st.udp_status == DEVTOOL_UDP_WORKING && st.plpmtu_size == size && st.plpmtu_state == state;
	devtool_free_node_status(&st);
	return ok;
}

static void wan_start(peer_config_t *peers, meshlink_channel_t **ch, meshlink_node_t **peer_nut) {
	init_sync_flag(&accepted);
	init_sync_flag(&received);
	meshlink_set_channel_accept_cb(peers[2].mesh, accept_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after(meshlink_get_node(peers[1].mesh, "nut"), 20);
	*peer_nut = meshlink_get_node(peers[1].mesh, "nut");
	assert(*peer_nut);
	assert_after(node_is_reachable(peers[1].mesh, *peer_nut), 15);
	hint_address(peers[1].mesh, *peer_nut, peers[2].ip, meshlink_get_port(peers[2].mesh));
	hint_address(peers[2].mesh, meshlink_get_node(peers[2].mesh, "peer"), peers[1].ip, meshlink_get_port(peers[1].mesh));
	*ch = meshlink_channel_open(peers[1].mesh, *peer_nut, 7, receive_cb, NULL, 0);
	assert(*ch);
	assert(wait_sync_flag(&accepted, 20));
	assert_after(udp_status_working(peers[1].mesh, *peer_nut), 45);
}

static void test_plpmtu_link_1280(void) {
	peer_config_t *peers;
	meshlink_channel_t *ch;
	meshlink_node_t *peer_nut;
	devtool_node_status_t st;

	printf("\n=== path-stability T24: link MTU 1280 stays at base ===\n");
	peers = setup_relay_peer_nut_wan("pathstab24");
	assert(peers);
	assert(netns_set_dev_mtu(peers[1].netns_name, "eth0", 1280));
	assert(netns_set_dev_mtu(peers[2].netns_name, "eth0", 1280));
	assert(netns_set_dev_mtu(peers[0].netns_name, "eth1", 1280));
	assert(netns_set_dev_mtu(peers[0].netns_name, "eth2", 1280));
	wan_start(peers, &ch, &peer_nut);
	assert_after(plpmtu_is(peers[1].mesh, peer_nut, PATH_PLPMTU_BASE, DEVTOOL_PLPMTU_COMPLETE), 20);
	st = snapshot(peers[1].mesh, peer_nut);
	assert(st.plpmtu_emsgsize >= 1);
	assert(st.plpmtu_probes_lost == 0);
	devtool_free_node_status(&st);
	meshlink_channel_abort(peers[1].mesh, ch);
	close_relay_peer_nut(peers);
	printf("path-stability T24 ok\n");
}

static void test_plpmtu_link_1492(void) {
	peer_config_t *peers;
	meshlink_channel_t *ch;
	meshlink_node_t *peer_nut;
	devtool_node_status_t st;

	printf("\n=== path-stability T25: link MTU 1492 settles at 1431 ===\n");
	peers = setup_relay_peer_nut_wan("pathstab25");
	assert(peers);
	assert(netns_set_dev_mtu(peers[1].netns_name, "eth0", 1492));
	assert(netns_set_dev_mtu(peers[2].netns_name, "eth0", 1492));
	assert(netns_set_dev_mtu(peers[0].netns_name, "eth1", 1492));
	assert(netns_set_dev_mtu(peers[0].netns_name, "eth2", 1492));
	wan_start(peers, &ch, &peer_nut);
	assert_after(plpmtu_is(peers[1].mesh, peer_nut, 1431, DEVTOOL_PLPMTU_COMPLETE), 25);
	st = snapshot(peers[1].mesh, peer_nut);
	assert(st.plpmtu_emsgsize >= 1);
	devtool_free_node_status(&st);
	meshlink_channel_abort(peers[1].mesh, ch);
	close_relay_peer_nut(peers);
	printf("path-stability T25 ok\n");
}

static void test_plpmtu_base_before_search(void) {
	peer_config_t *peers;
	meshlink_channel_t *ch;
	meshlink_node_t *peer_nut;
	meshlink_node_t *nut_peer;
	devtool_node_status_t st;

	printf("\n=== path-stability T26: base MSS before the search gives up ===\n");
	peers = setup_relay_peer_nut_wan("pathstab26");
	assert(peers);
	init_sync_flag(&accepted);
	meshlink_set_channel_accept_cb(peers[2].mesh, accept_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after(meshlink_get_node(peers[1].mesh, "nut"), 20);
	peer_nut = meshlink_get_node(peers[1].mesh, "nut");
	nut_peer = meshlink_get_node(peers[2].mesh, "peer");
	assert(peer_nut && nut_peer);
	assert(devtool_drop_size_probes_above(peers[2].mesh, nut_peer, PATH_PLPMTU_BASE));
	hint_address(peers[1].mesh, peer_nut, peers[2].ip, meshlink_get_port(peers[2].mesh));
	hint_address(peers[2].mesh, nut_peer, peers[1].ip, meshlink_get_port(peers[1].mesh));
	ch = meshlink_channel_open(peers[1].mesh, peer_nut, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 20));
	assert_after(udp_status_working(peers[1].mesh, peer_nut), 45);

	for(int pass = 0; pass < 2; pass++) {
		assert_after(candidate_validated(peers[1].mesh, peer_nut), 30);
		devtool_age_route(peers[1].mesh, peer_nut, PATH_ROUTE_MIN_RESIDENCY_SEC + 1);
		devtool_age_candidate(peers[1].mesh, peer_nut, 2);
		devtool_path_route_tick(peers[1].mesh, peer_nut);

		st = snapshot(peers[1].mesh, peer_nut);

		if(st.active_route_kind == ROUTE_DIRECT_UDP && !st.active_route_local) {
			devtool_free_node_status(&st);
			break;
		}

		devtool_free_node_status(&st);
	}

	assert(meshlink_channel_get_mss(peers[1].mesh, ch) == direct_mss(PATH_PLPMTU_BASE));
	assert_after(plpmtu_is(peers[1].mesh, peer_nut, PATH_PLPMTU_BASE, DEVTOOL_PLPMTU_COMPLETE), 15);
	st = snapshot(peers[1].mesh, peer_nut);
	assert(st.plpmtu_probes_lost >= 3);
	assert(st.udp_status == DEVTOOL_UDP_WORKING);
	devtool_free_node_status(&st);
	meshlink_channel_abort(peers[1].mesh, ch);
	close_relay_peer_nut(peers);
	printf("path-stability T26 ok\n");
}

static meshlink_handle_t *reopen_named(const char *path, const char *name, const char *app, int devclass, meshlink_storage_policy_t policy) {
	meshlink_open_params_t *params = meshlink_open_params_init(path, name, app, devclass);
	meshlink_handle_t *mesh;

	assert(params);
	assert(meshlink_open_params_set_storage_policy(params, policy));
	mesh = meshlink_open_ex(params);
	assert(mesh);
	meshlink_enable_discovery(mesh, false);
	return mesh;
}

static void test_plpmtu_restart_cache(void) {
	const char *prefix = "path_stability_t27_conf";
	meshlink_handle_t *bb, *a, *b;
	meshlink_node_t *a_b;
	meshlink_node_t *b_a;
	meshlink_channel_t *ch;
	char path[128];

	printf("\n=== path-stability T27: restart restores the per-IP PLPMTU ===\n");
	stability_open_trio(prefix, "path-stability-27", &bb, &a, &b);
	init_sync_flag(&accepted);
	meshlink_set_channel_accept_cb(b, accept_cb);
	assert_after(meshlink_get_node(a, "baz"), 15);
	a_b = meshlink_get_node(a, "baz");
	b_a = meshlink_get_node(b, "bar");
	assert(a_b && b_a);
	assert_after(node_is_reachable(a, a_b), 15);
	ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert(devtool_drop_size_probes_above(b, b_a, 1399));
	assert_after(plpmtu_is(a, a_b, 1399, DEVTOOL_PLPMTU_COMPLETE), 30);
	meshlink_channel_abort(a, ch);
	meshlink_close(a);

	snprintf(path, sizeof path, "%s.1", prefix);
	a = reopen_named(path, "bar", "path-stability-27", DEV_CLASS_STATIONARY, MESHLINK_STORAGE_ENABLED);
	init_sync_flag(&accepted);
	assert(meshlink_start(a));
	assert_after(meshlink_get_node(a, "baz"), 15);
	a_b = meshlink_get_node(a, "baz");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	ch = meshlink_channel_open(a, a_b, 7, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert_after(udp_status_working(a, a_b), 30);
	{
		bool hit = false;

		for(int i = 0; i < 30 && !hit; i++) {
			devtool_node_status_t st = snapshot(a, a_b);

			hit = st.plpmtu_size == 1399 && st.plpmtu_cache_hits >= 1 && st.plpmtu_probes_lost == 0;
			devtool_free_node_status(&st);
			usleep(100000);
		}

		assert(hit);
	}
	meshlink_channel_abort(a, ch);
	meshlink_close(a);

	a = reopen_named(path, "bar", "path-stability-27", DEV_CLASS_STATIONARY, MESHLINK_STORAGE_DISABLED);
	assert(meshlink_start(a));
	assert_after(meshlink_get_node(a, "baz"), 15);
	a_b = meshlink_get_node(a, "baz");
	assert(a_b);
	assert_after(node_is_reachable(a, a_b), 15);
	init_sync_flag(&accepted);
	ch = meshlink_channel_open(a, a_b, 8, receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&accepted, 15));
	assert_after(udp_status_working(a, a_b), 30);
	{
		devtool_node_status_t st = snapshot(a, a_b);

		assert(st.plpmtu_cache_hits == 0);
		devtool_free_node_status(&st);
	}
	meshlink_channel_abort(a, ch);
	meshlink_close(a);
	meshlink_close(b);
	meshlink_close(bb);
	stability_destroy_conf(prefix, 3);
	printf("path-stability T27 ok\n");
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	meshlink_set_log_cb(NULL, MESHLINK_WARNING, NULL);
	if(getenv("MESHLINK_TEST_DEBUG")) {
		meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	}

	/* Keep connection setup and demand cases independently reproducible with
	   carrier and probe logs when diagnosing timing-dependent failures. */
	if(argc == 2 && !strcmp(argv[1], "--peer-demand")) {
		meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
		test_idle_peer_is_not_probed();
		return 0;
	}
	if(argc == 2 && !strcmp(argv[1], "--local-meta")) {
		meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
		test_local_peer_meta_route();
		return 0;
	}
	if(argc == 2 && !strcmp(argv[1], "--half-close")) {
		meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
		test_half_open_keeps_demand();
		return 0;
	}
	if(argc == 2 && !strcmp(argv[1], "--idle-channel")) {
		meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
		test_idle_channel_traffic();
		return 0;
	}
	assert(argc == 1);

	test_fixed_channel_size();
	test_demotion_resplits();
	test_mss_rejects_foreign_mesh();
	test_mss_under_route_churn();
	test_promotion_is_slow();
	test_candidate_cooldown();
	test_candidate_cooldown_survives_old_route();
	test_suspect_before_demote();
	test_idle_peer_is_not_probed();
	test_recorded_route();
	test_relay_carrier_is_backbone();
	test_conflict_backbone_skips_relay_hop();
	test_local_peer_meta_route();

	/* Netns setup calls exit(77). Skip only these cases so the rest of the binary still runs. */
	if(netns_available()) {
		test_wan_peer_udp_route();
		test_punch_demand_keeps_key();
		test_relay_meta_direct_route();
		test_relay_meta_canonical_route();
	} else {
		printf("SKIP path-stability T17b/T17e/T17f: netns unavailable\n");
	}

	test_fallback_keeps_suspect();
	test_parked_pmtu_promotes_local();
	test_half_open_keeps_demand();
	test_release_after_reclassify();
	test_backbone_not_starved();
	test_promotion_request_cap();
	test_retransmit_raises_suspect();
	test_oversize_suspect_retransmit();
	test_meta_ping_is_one_sided();
	test_idle_channel_traffic();
	test_lost_pmtu_raise_is_not_giveup();
	test_many_peers_stay_in_budget();

	if(netns_available()) {
		test_plpmtu_link_1280();
		test_plpmtu_link_1492();
		test_plpmtu_base_before_search();
	} else {
		printf("SKIP path-stability T24/T25/T26: netns unavailable\n");
	}

	test_plpmtu_restart_cache();

	printf("\npath-stability: all checks passed\n");
	return 0;
}
