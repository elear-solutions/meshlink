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
	relay_mtu_count = 0;
	bar_relay_mtu_count = 0;
}

static bool leftover(const char *text) {
	return text && (strstr(text, "Ignoring failed REQ_SPTPS via UDP")
	                || strstr(text, "Got REQ_SPTPS via UDP")
	                || strstr(text, "Sending REQ_SPTPS via UDP"));
}

static void foo_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	if(text && strstr(text, "Relaying type-8 via UDP") && strstr(text, " for bar")) {
		set_sync_flag(&foo_relay_log, true);
	}

	if(leftover(text)) {
		set_sync_flag(&leftover_udp, true);
	}

	log_cb(mesh, level, text);
}

static void baz_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	if(text && strstr(text, "Relaying type-8 via UDP") && strstr(text, " for bar")) {
		set_sync_flag(&baz_relay_log, true);
	}

	if(text && strstr(text, "Got REQ_RELAY_MTU")) {
		set_sync_flag(&got_relay_mtu, true);
		relay_mtu_count++;
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
	assert_after(meshlink_channel_get_mss(mesh[2], ch1) == floor_mss, 5);

	size_t mid_mss = 600 - prefix - 21 - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	reset_logs();
	confirm_final(mesh[0], "bar", 600);
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	set_sync_flag(&received2, false);
	assert(meshlink_channel_send(mesh[2], ch1, "Hello", 5) == 5);
	assert_after(meshlink_channel_get_mss(mesh[2], ch1) == mid_mss, 15);
	assert(wait_sync_flag(&received2, 10));

	reset_logs();
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	assert(meshlink_channel_send(mesh[2], ch1, "Hello", 5) == 5);
	assert_after(meshlink_channel_get_mss(mesh[2], ch1) > mid_mss, 15);

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

static void test_hard_send_clears_hop(meshlink_handle_t **mesh) {
	size_t prefix = 2 + strlen("baz") + strlen("bar");
	size_t relay_mss = MINMTU - prefix - 21 - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	size_t meta_mss = MTU - sizeof(udp_relay_packethdr_t) - UTCP_HDR;

	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	confirm_final(mesh[0], "bar", MINMTU);

	meshlink_channel_t *ch = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 11, receive2_cb, NULL, 0);
	assert(ch);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert_after(meshlink_channel_get_mss(mesh[2], ch) == relay_mss, 10);

	devtool_relay_hard_send_error(mesh[2], meshlink_get_node(mesh[2], "foo"));
	assert(!udp_confirmed_flag(mesh[2], "foo"));
	assert_after(meshlink_channel_get_mss(mesh[2], ch) == meta_mss, 10);

	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), true);
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
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
	assert_after(meshlink_channel_get_mss(longa, ch_long) > 0, 10);

	pin(longa, long_b, "foo");
	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(longa, meshlink_get_node(longa, "foo"), MTU));
	size_t meta_mss = MTU - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	size_t short_prefix = 2 + strlen("baz") + strlen("bar");
	size_t short_floor = MINMTU - short_prefix - 21 - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	assert_after(meshlink_channel_get_mss(longa, ch_long) == meta_mss, 5);
	assert_after(meshlink_channel_get_mss(mesh[2], ch_short) == short_floor, 5);
	(void)meshlink_channel_send(longa, ch_long, "Hello", 5);
	(void)meshlink_send(longa, meshlink_get_node(longa, long_b), "Hello", 5);

	devtool_set_udp_confirmed(longa, meshlink_get_node(longa, long_b), false);
	assert_after(udp_confirmed_flag(longa, long_b), 20);
	devtool_node_status_t longst;
	devtool_get_node_status(longa, meshlink_get_node(longa, long_b), &longst);
	uint16_t base = longst.minmtu > MINMTU ? longst.minmtu : MINMTU;
	assert(meshlink_channel_get_mss(longa, ch_long) == (size_t)(base - sizeof(udp_relay_packethdr_t) - UTCP_HDR));
	pin(mesh[2], "bar", "foo");
	assert_after(meshlink_channel_get_mss(mesh[2], ch_short) == short_floor, 5);

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
	size_t meta_mss = MTU - sizeof(udp_relay_packethdr_t) - UTCP_HDR;
	assert_after(meshlink_channel_get_mss(mesh[2], ch) == floor_mss, 5);

	set_sync_flag(&foo_down, false);
	meshlink_stop(mesh[0]);
	assert(wait_sync_flag(&foo_down, 20));
	assert_after(meshlink_channel_get_mss(mesh[2], ch) == meta_mss, 5);
	/* Attempt a send so dest META is used; hop is down so do not require delivery. */
	(void)meshlink_channel_send(mesh[2], ch, "Hello", 5);
	assert(!check_sync_flag(&leftover_udp));

	meshlink_channel_abort(mesh[2], ch);
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
	send_hello(mesh[2], "bar");
	assert(wait_sync_flag(&got_relay_mtu, 10));

	test_channels_and_mss(mesh);

	/* devtool: dest==nexthop rejected */
	assert(!devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], "bar"), meshlink_get_node(mesh[2], "bar")));

	test_hard_send_clears_hop(mesh);
	test_long_names(mesh);

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
