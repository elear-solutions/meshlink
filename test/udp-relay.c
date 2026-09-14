#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "relay.h"
#include "devtools.h"
#include "utils.h"

/* net.h is not includable from integration tests (transitive meshlink_internal.h). */
#define PKT_COMPRESSED 1
#define PKT_PROBE 4
#define PKT_RELAY_SPTPS 8
#define SPTPS_HANDSHAKE 128
#define MINMTU 527
#define MTU 1451

typedef struct {
	uint8_t destination[16];
	uint8_t source[16];
} __attribute__((__packed__)) udp_relay_packethdr_t;

#define PACKETHDR_BYTES sizeof(udp_relay_packethdr_t)

#define UTCP_HDR 20

static struct sync_flag received;
static struct sync_flag received2;
static struct sync_flag bar_learned;
static struct sync_flag baz_learned;
static struct sync_flag foo_relay_log;
static struct sync_flag baz_relay_log;
static struct sync_flag got_relay_mtu;
static struct sync_flag leftover_udp;
static struct sync_flag dest_got_data;
static struct sync_flag bar_got_relay_mtu;
static struct sync_flag bar_relay_log;
static struct sync_flag foo_down;
static struct sync_flag direct_retransmit_log;
static unsigned relay_mtu_count;
static unsigned bar_relay_mtu_count;

static void reset_logs(void) {
	set_sync_flag(&foo_relay_log, false);
	set_sync_flag(&baz_relay_log, false);
	set_sync_flag(&got_relay_mtu, false);
	set_sync_flag(&leftover_udp, false);
	set_sync_flag(&dest_got_data, false);
	set_sync_flag(&bar_got_relay_mtu, false);
	set_sync_flag(&bar_relay_log, false);
	set_sync_flag(&direct_retransmit_log, false);
	relay_mtu_count = 0;
	bar_relay_mtu_count = 0;
}

static bool leftover(const char *text) {
	return text && (strstr(text, "Ignoring failed REQ_SPTPS via UDP")
	                || strstr(text, "Got REQ_SPTPS via UDP")
	                || strstr(text, "Sending REQ_SPTPS via UDP"));
}

static void foo_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	if(text && strstr(text, "Relaying type-8 via UDP to bar for bar from baz")) {
		set_sync_flag(&foo_relay_log, true);
	}

	if(leftover(text)) {
		set_sync_flag(&leftover_udp, true);
	}

	log_cb(mesh, level, text);
}

static void baz_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	if(text && strstr(text, "Relaying type-8 via UDP") && strstr(text, " for bar") && strstr(text, "from baz")) {
		set_sync_flag(&baz_relay_log, true);
	}

	if(text && strstr(text, "Got REQ_RELAY_MTU")) {
		set_sync_flag(&got_relay_mtu, true);
		relay_mtu_count++;
	}

	if(text && strstr(text, "Path validation: bar route-suspect") && strstr(text, "reliable retransmit")) {
		set_sync_flag(&direct_retransmit_log, true);
	}

	if(leftover(text)) {
		set_sync_flag(&leftover_udp, true);
	}

	log_cb(mesh, level, text);
}

static void bar_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	if(text && strstr(text, "Relaying type-8 via UDP")) {
		set_sync_flag(&bar_relay_log, true);
	}

	if(text && strstr(text, "Got REQ_RELAY_MTU")) {
		set_sync_flag(&bar_got_relay_mtu, true);
		bar_relay_mtu_count++;
	}

	if(leftover(text)) {
		set_sync_flag(&leftover_udp, true);
	}

	log_cb(mesh, level, text);
}

static void receive_cb(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len) {
	(void)mesh;
	(void)source;

	if(len == 5 && !memcmp(data, "Hello", 5)) {
		set_sync_flag(&received, true);
	} else if(len) {
		set_sync_flag(&dest_got_data, true);
	}
}

static void receive2_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;

	if(len == 5 && !memcmp(data, "Hello", 5)) {
		set_sync_flag(&received2, true);
	}
}

static void bar_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;
	(void)reachable;

	if(!strcmp(node->name, "baz") || !strcmp(node->name, "foo")) {
		set_sync_flag(&bar_learned, true);
	}
}

static void baz_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(!strcmp(node->name, "foo") && !reachable) {
		set_sync_flag(&foo_down, true);
	}

	if(!strcmp(node->name, "bar") || !strcmp(node->name, "foo")) {
		set_sync_flag(&baz_learned, true);
	}
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)mesh;
	(void)port;
	(void)data;
	(void)len;
	meshlink_set_channel_receive_cb(mesh, channel, receive2_cb);
	return true;
}

static bool udp_confirmed_flag(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *n = meshlink_get_node(mesh, name);

	if(!n) {
		return false;
	}

	devtool_node_status_t st;
	devtool_get_node_status(mesh, n, &st);
	return st.udp_status == DEVTOOL_UDP_WORKING;
}

static bool mtu_fixed(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *n = meshlink_get_node(mesh, name);

	if(!n) {
		return false;
	}

	devtool_node_status_t st;
	devtool_get_node_status(mesh, n, &st);
	return st.udp_status == DEVTOOL_UDP_WORKING && st.minmtu && st.mtuprobes >= 30;
}

static void wait_keys_and_udp(meshlink_handle_t **mesh) {
	assert_after(mtu_fixed(mesh[2], "foo") && mtu_fixed(mesh[0], "baz")
	             && mtu_fixed(mesh[0], "bar") && mtu_fixed(mesh[1], "foo")
	             && mtu_fixed(mesh[1], "baz") && mtu_fixed(mesh[2], "bar"), 25);
}

static void send_hello(meshlink_handle_t *from, const char *dest) {
	set_sync_flag(&received, false);
	assert(meshlink_send(from, meshlink_get_node(from, dest), "Hello", 5));
	assert(wait_sync_flag(&received, 20));
}

static void pin(meshlink_handle_t *origin, const char *dest, const char *hop) {
	assert(devtool_force_relay_path(origin, meshlink_get_node(origin, dest), meshlink_get_node(origin, hop)));
}

static void confirm_final(meshlink_handle_t *relay, const char *dest, uint16_t minmtu) {
	assert(devtool_set_minmtu(relay, meshlink_get_node(relay, dest), minmtu));
	devtool_set_udp_confirmed(relay, meshlink_get_node(relay, dest), true);
}

static size_t encode_type8(uint8_t *out, const char *origin, const char *dest, const uint8_t *inner, size_t inner_len) {
	size_t out_len = 800;
	assert(relay_encode(origin, dest, inner, inner_len, out, &out_len));
	return out_len;
}

static void expect_hello_after_drop(meshlink_handle_t **mesh) {
	assert(!check_sync_flag(&dest_got_data));
	assert(!check_sync_flag(&leftover_udp));
	assert(udp_confirmed_flag(mesh[2], "foo"));
	send_hello(mesh[2], "bar");
}

static void test_malformed(meshlink_handle_t **mesh) {
	uint8_t buf[128];
	uint8_t inner[10];
	memset(inner, 0x5a, sizeof(inner));

	reset_logs();
	set_sync_flag(&dest_got_data, false);
	const char *text = "0 foo bar 8 AQID";
	assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "foo"), PKT_RELAY_SPTPS, text, strlen(text) + 1));
	usleep(200000);
	expect_hello_after_drop(mesh);

	reset_logs();
	set_sync_flag(&dest_got_data, false);
	buf[0] = 1;
	assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "foo"), PKT_RELAY_SPTPS, buf, 1));
	usleep(200000);
	expect_hello_after_drop(mesh);

	reset_logs();
	set_sync_flag(&dest_got_data, false);
	buf[0] = 40;
	buf[1] = 'a';
	assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "foo"), PKT_RELAY_SPTPS, buf, 2));
	usleep(200000);
	expect_hello_after_drop(mesh);

	reset_logs();
	set_sync_flag(&dest_got_data, false);
	size_t n = encode_type8(buf, "baz", "bar", inner, sizeof(inner));
	assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "foo"), PKT_RELAY_SPTPS, buf, n));
	usleep(200000);
	expect_hello_after_drop(mesh);
}

static void test_inner_types(meshlink_handle_t **mesh) {
	uint8_t types[] = {PKT_PROBE, PKT_RELAY_SPTPS, PKT_COMPRESSED, SPTPS_HANDSHAKE};

	for(size_t i = 0; i < sizeof(types); i++) {
		reset_logs();
		set_sync_flag(&dest_got_data, false);
		pin(mesh[2], "bar", "foo");
		devtool_node_status_t before;
		devtool_get_node_status(mesh[1], meshlink_get_node(mesh[1], "baz"), &before);
		assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "bar"), types[i], NULL, 0));
		usleep(300000);
		devtool_node_status_t after;
		devtool_get_node_status(mesh[1], meshlink_get_node(mesh[1], "baz"), &after);
		assert(after.minmtu == before.minmtu);
		assert(after.udp_status == before.udp_status);
		assert(!check_sync_flag(&dest_got_data));
		expect_hello_after_drop(mesh);
	}

	uint8_t dest_types[] = {PKT_PROBE, PKT_RELAY_SPTPS, PKT_COMPRESSED};

	for(size_t i = 0; i < sizeof(dest_types); i++) {
		reset_logs();
		set_sync_flag(&dest_got_data, false);
		pin(mesh[2], "bar", "foo");
		devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), false);
		devtool_node_status_t before;
		devtool_get_node_status(mesh[1], meshlink_get_node(mesh[1], "baz"), &before);
		assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "bar"), dest_types[i], NULL, 0));
		usleep(300000);
		devtool_node_status_t after;
		devtool_get_node_status(mesh[1], meshlink_get_node(mesh[1], "baz"), &after);
		assert(after.minmtu == before.minmtu);
		assert(after.udp_status == before.udp_status);
		assert(!check_sync_flag(&dest_got_data));
		pin(mesh[2], "bar", "foo");
		expect_hello_after_drop(mesh);
	}
}

static void test_route_matrix(meshlink_handle_t **mesh) {
	/* first down / final up → META, no binary log */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), false);
	send_hello(mesh[2], "bar");
	assert(!check_sync_flag(&baz_relay_log));
	assert(!check_sync_flag(&foo_relay_log));

	/* first up / final down → Hello, binary log on first hop only */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	devtool_set_udp_confirmed(mesh[0], meshlink_get_node(mesh[0], "bar"), false);
	send_hello(mesh[2], "bar");
	assert(check_sync_flag(&baz_relay_log));
	assert(!check_sync_flag(&foo_relay_log));

	/* both up → Hello, binary log on both hops */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	devtool_set_udp_confirmed(mesh[0], meshlink_get_node(mesh[0], "bar"), true);
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	send_hello(mesh[2], "bar");
	assert(check_sync_flag(&baz_relay_log));
	assert(check_sync_flag(&foo_relay_log));

	/* both down → META, no binary log */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), false);
	devtool_set_udp_confirmed(mesh[0], meshlink_get_node(mesh[0], "bar"), false);
	send_hello(mesh[2], "bar");
	assert(!check_sync_flag(&baz_relay_log));
	assert(!check_sync_flag(&foo_relay_log));
}

static void test_ready_unready_ready(meshlink_handle_t **mesh) {
	reset_logs();
	pin(mesh[2], "bar", "foo");
	send_hello(mesh[2], "bar");
	assert(check_sync_flag(&baz_relay_log));

	reset_logs();
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), false);
	send_hello(mesh[2], "bar");
	assert(!check_sync_flag(&baz_relay_log));

	reset_logs();
	pin(mesh[2], "bar", "foo");
	send_hello(mesh[2], "bar");
	assert(check_sync_flag(&baz_relay_log));
}

static void test_force_relay_minmtu(meshlink_handle_t **mesh) {
	devtool_node_status_t hop_before, dest_before;
	devtool_get_node_status(mesh[2], meshlink_get_node(mesh[2], "foo"), &hop_before);
	devtool_get_node_status(mesh[2], meshlink_get_node(mesh[2], "bar"), &dest_before);
	pin(mesh[2], "bar", "foo");
	devtool_node_status_t hop_after, dest_after;
	devtool_get_node_status(mesh[2], meshlink_get_node(mesh[2], "foo"), &hop_after);
	devtool_get_node_status(mesh[2], meshlink_get_node(mesh[2], "bar"), &dest_after);
	assert(hop_after.minmtu == hop_before.minmtu);
	assert(dest_after.minmtu == dest_before.minmtu);
}

static void test_channels_and_mss(meshlink_handle_t **mesh) {
	meshlink_set_channel_accept_cb(mesh[1], accept_cb);
	meshlink_channel_t *ch1 = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 7, receive2_cb, NULL, 0);
	meshlink_channel_t *ch2 = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 8, receive2_cb, NULL, 0);
	assert(ch1);
	assert(ch2);

	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));

	size_t prefix = 2 + strlen("baz") + strlen("bar");
	size_t floor_mss = MINMTU - prefix - 21 - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	assert(meshlink_channel_get_mss(mesh[2], ch1) == floor_mss);
	assert(meshlink_channel_get_mss(mesh[2], ch2) == floor_mss);

	/* A relay budget report and a bigger measurement on either hop are
	   telemetry. Neither may repacketize a channel that is carrying data. */
	reset_logs();
	confirm_final(mesh[0], "bar", 600);
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	set_sync_flag(&received2, false);
	assert(meshlink_channel_send(mesh[2], ch1, "Hello", 5) == 5);
	assert(wait_sync_flag(&received2, 10));
	assert(meshlink_channel_get_mss(mesh[2], ch1) == floor_mss);

	reset_logs();
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	assert(meshlink_channel_send(mesh[2], ch1, "Hello", 5) == 5);
	assert(meshlink_channel_get_mss(mesh[2], ch1) == floor_mss);

	/* two channels leave together on dest probe reply */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "bar"), false);
	assert_after(udp_confirmed_flag(mesh[2], "bar"), 20);
	set_sync_flag(&received2, false);
	assert(meshlink_channel_send(mesh[2], ch1, "Hello", 5) == 5);
	assert(wait_sync_flag(&received2, 10));
	set_sync_flag(&received2, false);
	assert(meshlink_channel_send(mesh[2], ch2, "Hello", 5) == 5);
	assert(wait_sync_flag(&received2, 10));
	assert(!check_sync_flag(&baz_relay_log));

	/* A direct UDP path can become one-way after NAT rebinding. The first
	   reliable-channel retransmit makes it suspect rather than dead: records
	   move to the live relay straight away, and the endpoint is only demoted
	   later if its probes go unanswered. */
	struct sockaddr_in dead = {
		.sin_family = AF_INET,
		.sin_port = htons(1),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	meshlink_node_t *bar = meshlink_get_node(mesh[2], "bar");
	devtool_update_node_udp(mesh[2], bar, (const struct sockaddr *)&dead);
	devtool_set_udp_confirmed(mesh[2], bar, true);
	reset_logs();
	set_sync_flag(&received2, false);
	assert(meshlink_channel_send(mesh[2], ch1, "Hello", 5) == 5);
	assert(wait_sync_flag(&direct_retransmit_log, 10));
	assert(wait_sync_flag(&baz_relay_log, 10));
	assert(wait_sync_flag(&received2, 10));

	meshlink_channel_abort(mesh[2], ch1);
	meshlink_channel_abort(mesh[2], ch2);
}

static void send_oversize_type8(meshlink_handle_t *from, const char *origin, const char *dest) {
	uint8_t big[700];
	memset(big, 0x11, sizeof(big));
	uint8_t payload[800];
	size_t n = encode_type8(payload, origin, dest, big, sizeof(big));
	assert(devtool_send_raw_record(from, meshlink_get_node(from, "foo"), PKT_RELAY_SPTPS, payload, n));
}

static void test_two_pairs_isolated(meshlink_handle_t **mesh) {
	devtool_clear_relay_reports(mesh[0]);
	pin(mesh[2], "bar", "foo");
	pin(mesh[1], "baz", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	assert(devtool_set_minmtu(mesh[1], meshlink_get_node(mesh[1], "foo"), MTU));
	confirm_final(mesh[0], "bar", MINMTU);
	confirm_final(mesh[0], "baz", MINMTU);

	reset_logs();
	send_oversize_type8(mesh[2], "baz", "bar");
	assert(wait_sync_flag(&got_relay_mtu, 5));

	reset_logs();
	send_oversize_type8(mesh[1], "bar", "baz");
	assert(wait_sync_flag(&bar_got_relay_mtu, 5));

	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "baz"), MTU));
}

static void test_failed_send_request_clock(meshlink_handle_t **mesh) {
	devtool_clear_relay_reports(mesh[0]);
	devtool_fail_relay_reports(mesh[0], true);
	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	confirm_final(mesh[0], "bar", MINMTU);

	send_oversize_type8(mesh[2], "baz", "bar");
	usleep(200000);
	assert(devtool_has_relay_report(mesh[0], "baz", "bar"));
	assert(!devtool_relay_report_have_reported(mesh[0], "baz", "bar"));

	devtool_fail_relay_reports(mesh[0], false);
	reset_logs();
	send_oversize_type8(mesh[2], "baz", "bar");
	assert(wait_sync_flag(&got_relay_mtu, 5));
	assert(devtool_relay_report_have_reported(mesh[0], "baz", "bar"));

	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
}

static void test_lru_eviction_rearm(meshlink_handle_t **mesh) {
	devtool_clear_relay_reports(mesh[0]);
	assert(devtool_fill_relay_reports(mesh[0], RELAY_REPORT_MAX - 2, 0, true));
	assert(devtool_seed_relay_report(mesh[0], "a0", "z", 1, true));
	assert(devtool_seed_relay_report(mesh[0], "a1", "a", 1, true));
	assert(devtool_relay_report_count(mesh[0]) == RELAY_REPORT_MAX);

	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	confirm_final(mesh[0], "bar", MTU);

	reset_logs();
	send_hello(mesh[2], "bar");
	assert(wait_sync_flag(&got_relay_mtu, 5));
	assert(!devtool_has_relay_report(mesh[0], "a0", "z"));
	assert(devtool_has_relay_report(mesh[0], "a1", "a"));
	assert(devtool_has_relay_report(mesh[0], "baz", "bar"));

	assert(devtool_seed_relay_report(mesh[0], "a1", "a", 0, true));
	assert(devtool_seed_relay_report(mesh[0], "baz", "bar", 1, true));

	pin(mesh[1], "baz", "foo");
	assert(devtool_set_minmtu(mesh[1], meshlink_get_node(mesh[1], "foo"), MTU));
	confirm_final(mesh[0], "baz", MINMTU);
	send_oversize_type8(mesh[1], "bar", "baz");
	usleep(200000);
	assert(!devtool_has_relay_report(mesh[0], "baz", "bar"));

	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	confirm_final(mesh[0], "bar", MTU);
	reset_logs();
	send_hello(mesh[2], "bar");
	assert(wait_sync_flag(&got_relay_mtu, 5));
	assert(devtool_has_relay_report(mesh[0], "baz", "bar"));

	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "baz"), MTU));
}

static void test_oversize_and_reports(meshlink_handle_t **mesh) {
	uint8_t big[700];
	memset(big, 0x11, sizeof(big));
	uint8_t payload[800];
	size_t n = encode_type8(payload, "baz", "bar", big, sizeof(big));

	reset_logs();
	pin(mesh[2], "bar", "foo");
	confirm_final(mesh[0], "bar", MTU);
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MINMTU));
	assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "foo"), PKT_RELAY_SPTPS, payload, n));
	usleep(200000);
	assert(!check_sync_flag(&got_relay_mtu));
	expect_hello_after_drop(mesh);

	reset_logs();
	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	confirm_final(mesh[0], "bar", MINMTU);
	assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "foo"), PKT_RELAY_SPTPS, payload, n));
	assert(wait_sync_flag(&got_relay_mtu, 5));
	reset_logs();
	assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "foo"), PKT_RELAY_SPTPS, payload, n));
	usleep(200000);
	assert(relay_mtu_count == 0);
	expect_hello_after_drop(mesh);
}

static void test_origin_eq_from_unwrap(meshlink_handle_t **mesh) {
	uint8_t inner[32];
	memset(inner, 0xa5, sizeof(inner));
	uint8_t payload[128];
	size_t n = encode_type8(payload, "baz", "foo", inner, sizeof(inner));

	reset_logs();
	set_sync_flag(&dest_got_data, false);
	assert(devtool_handle_relay_aliased(mesh[0], meshlink_get_node(mesh[0], "baz"), payload, n));
	usleep(200000);
	expect_hello_after_drop(mesh);
}

static void test_dest_meta_type8_quiet(meshlink_handle_t **mesh) {
	uint8_t inner[32];
	memset(inner, 0x5a, sizeof(inner));
	uint8_t payload[128];
	size_t n = encode_type8(payload, "baz", "foo", inner, sizeof(inner));

	reset_logs();
	set_sync_flag(&dest_got_data, false);
	pin(mesh[2], "bar", "foo");
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), false);
	assert(devtool_send_meta_sptps(mesh[2], meshlink_get_node(mesh[2], "bar"), PKT_RELAY_SPTPS, payload, n));
	usleep(300000);
	assert(!check_sync_flag(&bar_relay_log));
	assert(!check_sync_flag(&dest_got_data));
	pin(mesh[2], "bar", "foo");
	expect_hello_after_drop(mesh);
}

/* Every hard-send case below must clear hop UDP readiness without ever moving
   the channel MSS: it is fixed at the relay-safe floor for baz -> bar. */
static void test_hard_send_clears_hop(meshlink_handle_t **mesh) {
	size_t prefix = 2 + strlen("baz") + strlen("bar");
	size_t relay_mss = MINMTU - prefix - 21 - sizeof(udp_relay_packethdr_t) - UTCP_HDR;

	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	confirm_final(mesh[0], "bar", MINMTU);

	meshlink_channel_t *ch = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 11, receive2_cb, NULL, 0);
	assert(ch);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == relay_mss);

	meshlink_node_t *hop = meshlink_get_node(mesh[2], "foo");
	devtool_node_status_t st = {0};
	devtool_get_node_status(mesh[2], hop, &st);
	assert(st.address.ss_family == AF_INET || st.address.ss_family == AF_INET6);

	struct sockaddr_storage hop_addr = {0};
	int hop_sock = 0;
	assert(devtool_choose_udp_address(mesh[2], hop, &hop_addr, &hop_sock));

	struct sockaddr_storage mcast = {0};
	devtool_fill_mcast_ff02_1(&mcast);
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&mcast, hop_sock);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == relay_mss);

	struct sockaddr_storage alt = {0};
	devtool_fill_host_mismatch(&st.address, &alt);
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&alt, hop_sock);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == relay_mss);

	struct sockaddr_storage port = {0};
	devtool_fill_port_mismatch(&st.address, &port);
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&port, hop_sock);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == relay_mss);

	struct sockaddr_storage bcast = {0};
	devtool_fill_bcast_ipv4(&bcast);
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&bcast, hop_sock);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == relay_mss);

	assert(udp_confirmed_flag(mesh[2], "foo"));
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&hop_addr, hop_sock + 1);
	assert(!udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == relay_mss);
	devtool_set_udp_confirmed(mesh[2], hop, true);
	assert(devtool_set_minmtu(mesh[2], hop, MTU));
	pin(mesh[2], "bar", "foo");
	assert(udp_confirmed_flag(mesh[2], "foo"));

	assert(devtool_inject_broadcast_hard_send(mesh[2], hop));
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == relay_mss);
	devtool_free_node_status(&st);

	devtool_relay_hard_send_error(mesh[2], hop);
	assert(!udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == relay_mss);

	devtool_set_udp_confirmed(mesh[2], hop, true);
	assert(devtool_set_minmtu(mesh[2], hop, MTU));
	pin(mesh[2], "bar", "foo");
	meshlink_channel_abort(mesh[2], ch);
}

static void test_long_names(meshlink_handle_t **mesh) {
	char long_a[231];
	char long_b[231];
	memset(long_a, 'A', 230);
	long_a[230] = 0;
	memset(long_b, 'B', 230);
	long_b[230] = 0;
	assert(meshlink_destroy("udp_relay_conf.longa"));
	assert(meshlink_destroy("udp_relay_conf.longb"));
	meshlink_handle_t *longa = meshlink_open("udp_relay_conf.longa", long_a, "udp-relay", DEV_CLASS_BACKBONE);
	meshlink_handle_t *longb = meshlink_open("udp_relay_conf.longb", long_b, "udp-relay", DEV_CLASS_BACKBONE);
	assert(longa);
	assert(longb);
	assert(meshlink_set_canonical_address(longa, meshlink_get_self(longa), "localhost", NULL));
	assert(meshlink_set_canonical_address(longb, meshlink_get_self(longb), "localhost", NULL));
	char *longa_export = meshlink_export(longa);
	char *longb_export = meshlink_export(longb);
	char *foo_export = meshlink_export(mesh[0]);
	assert(longa_export && longb_export && foo_export);
	assert(meshlink_import(mesh[0], longa_export));
	assert(meshlink_import(mesh[0], longb_export));
	assert(meshlink_import(longa, foo_export));
	assert(meshlink_import(longa, longb_export));
	assert(meshlink_import(longb, foo_export));
	assert(meshlink_import(longb, longa_export));
	free(longa_export);
	free(longb_export);
	free(foo_export);
	meshlink_set_channel_accept_cb(longb, accept_cb);
	assert(meshlink_start(longa));
	assert(meshlink_start(longb));
	assert_after(meshlink_get_node(longa, long_b) && meshlink_get_node(longa, "foo"), 10);
	assert_after(udp_confirmed_flag(longa, "foo"), 30);

	meshlink_channel_t *ch_long = meshlink_channel_open(longa, meshlink_get_node(longa, long_b), 9, receive2_cb, NULL, 0);
	meshlink_channel_t *ch_short = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 10, receive2_cb, NULL, 0);
	assert(ch_long);
	assert(ch_short);
	/* 230 + 230 character names cannot fit a type-8 prefix under MINMTU, so this
	   pair is never relayed and gets the plain direct floor. The short pair is
	   relayable and pays for the prefix. Both are decided once, from the names
	   alone, and no later path state may move them. */
	size_t long_floor = MINMTU - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	size_t short_prefix = 2 + strlen("baz") + strlen("bar");
	size_t short_floor = MINMTU - short_prefix - 21 - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	assert(meshlink_channel_get_mss(longa, ch_long) == long_floor);
	assert(meshlink_channel_get_mss(mesh[2], ch_short) == short_floor);

	pin(longa, long_b, "foo");
	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(longa, meshlink_get_node(longa, "foo"), MTU));
	assert(meshlink_channel_get_mss(longa, ch_long) == long_floor);
	assert(meshlink_channel_get_mss(mesh[2], ch_short) == short_floor);
	(void)meshlink_channel_send(longa, ch_long, "Hello", 5);
	(void)meshlink_send(longa, meshlink_get_node(longa, long_b), "Hello", 5);

	/* Losing and regaining direct UDP is the event that used to repacketize. */
	devtool_set_udp_confirmed(longa, meshlink_get_node(longa, long_b), false);
	assert(meshlink_channel_get_mss(longa, ch_long) == long_floor);
	assert_after(udp_confirmed_flag(longa, long_b), 20);
	assert(meshlink_channel_get_mss(longa, ch_long) == long_floor);
	assert(devtool_set_minmtu(longa, meshlink_get_node(longa, long_b), MTU));
	assert(meshlink_channel_get_mss(longa, ch_long) == long_floor);
	pin(mesh[2], "bar", "foo");
	assert(meshlink_channel_get_mss(mesh[2], ch_short) == short_floor);

	meshlink_channel_abort(longa, ch_long);
	meshlink_channel_abort(mesh[2], ch_short);
	meshlink_close(longa);
	meshlink_close(longb);
	assert(meshlink_destroy("udp_relay_conf.longa"));
	assert(meshlink_destroy("udp_relay_conf.longb"));
}

static void test_reachability_flip_mss(meshlink_handle_t **mesh) {
	meshlink_set_channel_accept_cb(mesh[1], accept_cb);
	meshlink_channel_t *ch = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 12, receive2_cb, NULL, 0);
	assert(ch);

	pin(mesh[2], "bar", "foo");

	size_t prefix = 2 + strlen("baz") + strlen("bar");
	size_t floor_mss = MINMTU - prefix - 21 - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	assert(meshlink_channel_get_mss(mesh[2], ch) == floor_mss);

	/* Losing the relay hop entirely is the largest route change there is, and
	   it still leaves the channel packetization alone. */
	set_sync_flag(&foo_down, false);
	meshlink_stop(mesh[0]);
	assert(wait_sync_flag(&foo_down, 20));
	assert(meshlink_channel_get_mss(mesh[2], ch) == floor_mss);
	/* Attempt a send so dest META is used; hop is down so do not require delivery. */
	(void)meshlink_channel_send(mesh[2], ch, "Hello", 5);
	assert(!check_sync_flag(&leftover_udp));

	meshlink_channel_abort(mesh[2], ch);
}

static int dest_tier(meshlink_handle_t *mesh, const char *name) {
	devtool_node_status_t st;
	devtool_get_node_status(mesh, meshlink_get_node(mesh, name), &st);
	int tier = st.dest_path_tier;
	devtool_free_node_status(&st);
	return tier;
}

static void test_path_preference(meshlink_handle_t **mesh) {
	printf("=== path preference: local/WAN UDP, relay, mixed META ===\n");

	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)meshlink_get_port(mesh[1])),
	};
	assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);

	/* Earlier cases may have left dest unconfirmed. Re-establish a local UDP dest. */
	assert(devtool_confirm_udp_from(mesh[2], meshlink_get_node(mesh[2], "bar"), (struct sockaddr *)&local, 0));
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), true);
	assert(udp_confirmed_flag(mesh[2], "bar"));
	assert(dest_tier(mesh[2], "bar") == 0); /* PATH_TIER_DIRECT_LOCAL_UDP */

	/* Forced relay: dest unconfirmed, hop confirmed → RELAY_UDP. */
	pin(mesh[2], "bar", "foo");
	assert(dest_tier(mesh[2], "bar") == 2); /* PATH_TIER_RELAY_UDP */

	/* Hop UDP down: mixed UDP-in is origin-side; dest falls to META. */
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), false);
	int hop_meta = dest_tier(mesh[2], "bar");
	assert(hop_meta == 3 || hop_meta == 4); /* META_DIRECT or META_CANONICAL */

	/* A hop META reclassification must not clear dest UDP confirmation. */
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "bar"), true);
	assert(udp_confirmed_flag(mesh[2], "bar"));

	/* Restore hop UDP, then confirm dest again so later tests see a live path. */
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), true);
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "bar"), true);

	/* WAN stays active while an unvalidated local candidate exists. */
	struct sockaddr_in wan = {
		.sin_family = AF_INET,
		.sin_port = htons(9),
	};
	assert(inet_pton(AF_INET, "203.0.113.10", &wan.sin_addr) == 1);
	assert(devtool_confirm_udp_from(mesh[2], meshlink_get_node(mesh[2], "bar"), (struct sockaddr *)&wan, 1));

	meshlink_hint_address(mesh[2], meshlink_get_node(mesh[2], "bar"), (struct sockaddr *)&local);

	devtool_node_status_t st;
	devtool_get_node_status(mesh[2], meshlink_get_node(mesh[2], "bar"), &st);
	assert(st.udp_tier == 1);
	assert(st.would_probe_local_udp);
	devtool_free_node_status(&st);

	struct sockaddr_storage chosen;
	int sock = -1;
	assert(devtool_choose_udp_address(mesh[2], meshlink_get_node(mesh[2], "bar"), &chosen, &sock));
	assert(addr_is(&chosen, "203.0.113.10", 9));

	assert(devtool_confirm_udp_from(mesh[2], meshlink_get_node(mesh[2], "bar"), (struct sockaddr *)&local, 0));
	assert(devtool_choose_udp_address(mesh[2], meshlink_get_node(mesh[2], "bar"), &chosen, &sock));
	assert(addr_is(&chosen, "127.0.0.1", meshlink_get_port(mesh[1])));
	assert(dest_tier(mesh[2], "bar") == 0);

	printf("path preference ok\n");
}

int main(void) {
	init_sync_flag(&received);
	init_sync_flag(&received2);
	init_sync_flag(&bar_learned);
	init_sync_flag(&baz_learned);
	init_sync_flag(&foo_relay_log);
	init_sync_flag(&baz_relay_log);
	init_sync_flag(&got_relay_mtu);
	init_sync_flag(&leftover_udp);
	init_sync_flag(&dest_got_data);
	init_sync_flag(&bar_got_relay_mtu);
	init_sync_flag(&bar_relay_log);
	init_sync_flag(&foo_down);
	init_sync_flag(&direct_retransmit_log);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	const char *name[3] = {"foo", "bar", "baz"};
	meshlink_handle_t *mesh[3];
	char *data[3];

	for(int i = 0; i < 3; i++) {
		char *path = NULL;
		assert(asprintf(&path, "udp_relay_conf.%d", i) != -1 && path);
		assert(meshlink_destroy(path));
		mesh[i] = meshlink_open(path, name[i], "udp-relay", DEV_CLASS_BACKBONE);
		assert(mesh[i]);
		free(path);
		assert(meshlink_set_canonical_address(mesh[i], meshlink_get_self(mesh[i]), "localhost", NULL));
		data[i] = meshlink_export(mesh[i]);
		assert(data[i]);
	}

	for(int i = 0; i < 3; i++) {
		for(int j = 0; j < 3; j++) {
			if(i != j) {
				assert(meshlink_import(mesh[i], data[j]));
			}
		}
	}

	for(int i = 0; i < 3; i++) {
		free(data[i]);
	}

	meshlink_set_log_cb(mesh[0], MESHLINK_DEBUG, foo_log);
	meshlink_set_log_cb(mesh[1], MESHLINK_DEBUG, bar_log);
	meshlink_set_log_cb(mesh[2], MESHLINK_DEBUG, baz_log);
	meshlink_set_node_status_cb(mesh[1], bar_status_cb);
	meshlink_set_node_status_cb(mesh[2], baz_status_cb);
	meshlink_set_receive_cb(mesh[1], receive_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(mesh[i]));
	}

	assert(wait_sync_flag(&bar_learned, 10));
	assert(wait_sync_flag(&baz_learned, 10));
	wait_keys_and_udp(mesh);

	devtool_edge_t *edges = NULL;
	size_t nedges = 0;
	assert_after((edges = devtool_get_all_edges(mesh[0], edges, &nedges), nedges >= 3), 15);
	free(edges);

	send_hello(mesh[2], "bar");

	test_force_relay_minmtu(mesh);
	test_malformed(mesh);
	test_origin_eq_from_unwrap(mesh);
	test_inner_types(mesh);
	test_dest_meta_type8_quiet(mesh);
	test_route_matrix(mesh);
	test_ready_unready_ready(mesh);
	test_oversize_and_reports(mesh);
	test_two_pairs_isolated(mesh);
	test_failed_send_request_clock(mesh);
	test_lru_eviction_rearm(mesh);

	/* 30s idle delete re-arms first-record report — before channels steal receive_cb */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	confirm_final(mesh[0], "bar", 600);
	send_hello(mesh[2], "bar");
	assert(wait_sync_flag(&got_relay_mtu, 10));
	reset_logs();
	sleep(31);
	/* Dest UDP can win during the idle window after a canonical→direct
	   META upgrade. Re-pin so the re-arm still exercises the relay path. */
	pin(mesh[2], "bar", "foo");
	confirm_final(mesh[0], "bar", 600);
	send_hello(mesh[2], "bar");
	assert(wait_sync_flag(&got_relay_mtu, 10));

	test_channels_and_mss(mesh);

	/* devtool: dest==nexthop rejected */
	assert(!devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], "bar"), meshlink_get_node(mesh[2], "bar")));

	test_hard_send_clears_hop(mesh);
	test_long_names(mesh);

	test_path_preference(mesh);
	test_reachability_flip_mss(mesh);

	for(int i = 0; i < 3; i++) {
		meshlink_close(mesh[i]);
		char *path = NULL;
		assert(asprintf(&path, "udp_relay_conf.%d", i) != -1 && path);
		assert(meshlink_destroy(path));
		free(path);
	}

	return 0;
}
