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
#include "netns_utils.h"
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

	if(len == 5 && !memcmp(data, "Hello", 5)) {
		set_sync_flag(&received, true);
	} else if(len && source && strcmp(source->name, "foo")) {
		/* foo→bar channel UTCP is demand-only; dest_got_data is leaked relay payload. */
		set_sync_flag(&dest_got_data, true);
	}
}

static void receive2_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;

	/* Back-to-back sends can share one UTCP segment once the direct route
	   commits, so the record may be Hello or HelloHello. */
	if(len >= 5 && !memcmp(data, "Hello", 5)) {
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
	bool ok = st.udp_status == DEVTOOL_UDP_WORKING;
	devtool_free_node_status(&st);
	return ok;
}

static void wait_keys_and_udp(meshlink_handle_t **mesh) {
	/* Cameras establish backbone UDP on their own. Last-hop camera UDP is
	   demand-gated; plant it so relay tests don't need live channels (those
	   keep PMTU climbing and spuriously refresh relay reports). */
	assert_after(udp_confirmed_flag(mesh[2], "foo") && udp_confirmed_flag(mesh[1], "foo"), 25);
	devtool_set_udp_confirmed(mesh[0], meshlink_get_node(mesh[0], "bar"), true);
	devtool_set_udp_confirmed(mesh[0], meshlink_get_node(mesh[0], "baz"), true);
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "baz"), MTU));
}

static void send_hello(meshlink_handle_t *from, const char *dest) {
	meshlink_node_t *dst = meshlink_get_node(from, dest);
	assert(dst);

	for(int i = 0; i < 10; i++) {
		set_sync_flag(&received, false);
		assert(meshlink_send(from, dst, "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			return;
		}
	}

	assert(wait_sync_flag(&received, 5));
}

static void send_hello_once(meshlink_handle_t *from, const char *dest) {
	set_sync_flag(&received, false);
	meshlink_node_t *dst = meshlink_get_node(from, dest);
	assert(dst);
	assert(meshlink_send(from, dst, "Hello", 5));
	assert(wait_sync_flag(&received, 5));
}

#define ROUTE_DIRECT_UDP 1
#define ROUTE_RELAY 3
#define CARRIER_UDP 1

static bool relay_names_too_long(const char *origin, const char *dest) {
	size_t need = 2 + strlen(origin) + strlen(dest) + 21 + PACKETHDR_BYTES + UTCP_HDR + 1;
	return MINMTU < need;
}

static size_t carrier_floor_mss(const char *origin, const char *dest) {
	if(relay_names_too_long(origin, dest)) {
		return MINMTU - PACKETHDR_BYTES - UTCP_HDR;
	}

	return MINMTU - (2 + strlen(origin) + strlen(dest)) - 21 - PACKETHDR_BYTES - UTCP_HDR;
}

/* MSS the channel must have for whatever carrier is committed right now. */
static size_t expected_channel_mss(meshlink_handle_t *mesh, const char *dest_name) {
	meshlink_node_t *self = meshlink_get_self(mesh);
	meshlink_node_t *dest = meshlink_get_node(mesh, dest_name);
	devtool_node_status_t st;
	size_t floor;
	size_t mss;

	assert(self && dest);
	floor = carrier_floor_mss(self->name, dest_name);
	mss = floor;
	devtool_get_node_status(mesh, dest, &st);

	if(st.active_route_kind == ROUTE_DIRECT_UDP && st.udp_status == DEVTOOL_UDP_WORKING && st.minmtu && st.mtuprobes >= 30) {
		unsigned payload = st.minmtu;

		if(st.mtu && st.mtu < payload) {
			payload = st.mtu;
		}

		if(payload < MINMTU) {
			payload = MINMTU;
		}

		if(payload > MTU) {
			payload = MTU;
		}

		mss = payload - PACKETHDR_BYTES - UTCP_HDR;
	} else if(st.active_route_kind == ROUTE_RELAY && st.active_route_carrier == CARRIER_UDP && !relay_names_too_long(self->name, dest_name)) {
		unsigned budget = st.relay_budget;

		if(!budget && st.active_route_first_hop) {
			meshlink_node_t *hop = meshlink_get_node(mesh, st.active_route_first_hop);
			devtool_node_status_t hs;
			unsigned prefix21 = 2 + strlen(self->name) + strlen(dest_name) + 21;

			if(hop) {
				devtool_get_node_status(mesh, hop, &hs);

				if(hs.minmtu && hs.mtuprobes >= 30 && hs.minmtu > prefix21) {
					budget = hs.minmtu - prefix21;
				}

				devtool_free_node_status(&hs);
			}
		}

		if(budget > PACKETHDR_BYTES) {
			size_t raised = budget - PACKETHDR_BYTES - UTCP_HDR;

			if(raised > floor) {
				mss = raised;
			}
		}
	}

	devtool_free_node_status(&st);
	return mss;
}

static void pin(meshlink_handle_t *origin, const char *dest, const char *hop) {
	assert(devtool_force_relay_path(origin, meshlink_get_node(origin, dest), meshlink_get_node(origin, hop)));
}

static void confirm_final(meshlink_handle_t *relay, const char *dest, uint16_t minmtu) {
	assert(devtool_set_minmtu(relay, meshlink_get_node(relay, dest), minmtu));
	devtool_set_udp_confirmed(relay, meshlink_get_node(relay, dest), true);
}

static void send_oversize_type8(meshlink_handle_t *from, const char *origin, const char *dest);

/* Spare promotion / dest-pick can drop last-hop udp_confirmed between steps, and
   then maybe_report is a no-op. Re-pin and confirm immediately before each kick. */
static void arm_bar_via_foo(meshlink_handle_t **mesh, uint16_t dest_minmtu) {
	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	confirm_final(mesh[0], "bar", dest_minmtu);
}

static void arm_baz_via_foo(meshlink_handle_t **mesh, uint16_t dest_minmtu) {
	pin(mesh[1], "baz", "foo");
	assert(devtool_set_minmtu(mesh[1], meshlink_get_node(mesh[1], "foo"), MTU));
	confirm_final(mesh[0], "baz", dest_minmtu);
}

static void oversize_bar_until(meshlink_handle_t **mesh, struct sync_flag *flag, int timeout) {
	for(int i = 0; i < timeout; i++) {
		arm_bar_via_foo(mesh, MINMTU);
		send_oversize_type8(mesh[2], "baz", "bar");

		if(wait_sync_flag(flag, 1) && devtool_has_relay_report(mesh[0], "baz", "bar")) {
			return;
		}

		set_sync_flag(flag, false);
	}

	assert(check_sync_flag(flag));
	assert(devtool_has_relay_report(mesh[0], "baz", "bar"));
}

static void oversize_baz_until(meshlink_handle_t **mesh, struct sync_flag *flag, int timeout) {
	for(int i = 0; i < timeout; i++) {
		arm_baz_via_foo(mesh, MINMTU);
		send_oversize_type8(mesh[1], "bar", "baz");

		if(wait_sync_flag(flag, 1)) {
			return;
		}
	}

	assert(check_sync_flag(flag));
}

static void hello_bar_until_relay_mtu(meshlink_handle_t **mesh, uint16_t dest_minmtu, int timeout) {
	for(int i = 0; i < timeout; i++) {
		reset_logs();
		arm_bar_via_foo(mesh, dest_minmtu);
		set_sync_flag(&received, false);
		assert(meshlink_send(mesh[2], meshlink_get_node(mesh[2], "bar"), "Hello", 5));

		if(wait_sync_flag(&got_relay_mtu, 1) && devtool_has_relay_report(mesh[0], "baz", "bar")) {
			return;
		}

		set_sync_flag(&got_relay_mtu, false);
	}

	assert(devtool_has_relay_report(mesh[0], "baz", "bar"));
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

		/* Camera↔camera UDP PMTU can still be in flight (no META between cameras).
		   Once it has finished, a dest-bound inner type must not move it. */
		if(before.mtuprobes >= 30) {
			assert(after.minmtu == before.minmtu);
			assert(after.udp_status == before.udp_status);
		}

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

		if(before.mtuprobes >= 30) {
			assert(after.minmtu == before.minmtu);
			assert(after.udp_status == before.udp_status);
		}

		assert(!check_sync_flag(&dest_got_data));
		pin(mesh[2], "bar", "foo");
		devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), true);
		expect_hello_after_drop(mesh);
	}
}

static void test_route_matrix(meshlink_handle_t **mesh) {
	meshlink_node_t *bar_from_baz = meshlink_get_node(mesh[2], "bar");
	meshlink_node_t *bar_from_foo = meshlink_get_node(mesh[0], "bar");

	/* first down / final up → META, no binary log */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	devtool_force_meta(mesh[2], bar_from_baz, true);
	devtool_force_meta(mesh[0], bar_from_foo, false);
	devtool_set_udp_confirmed(mesh[0], bar_from_foo, true);
	assert(devtool_set_minmtu(mesh[0], bar_from_foo, MTU));
	send_hello_once(mesh[2], "bar");
	assert(!check_sync_flag(&baz_relay_log));
	assert(!check_sync_flag(&foo_relay_log));

	/* first up / final down → Hello, binary log on first hop only */
	devtool_force_meta(mesh[2], bar_from_baz, false);
	devtool_force_meta(mesh[0], bar_from_foo, true);
	assert_after(udp_confirmed_flag(mesh[2], "foo"), 15);
	reset_logs();
	pin(mesh[2], "bar", "foo");
	send_hello_once(mesh[2], "bar");
	assert(check_sync_flag(&baz_relay_log));
	assert(!check_sync_flag(&foo_relay_log));

	/* both up → Hello, binary log on both hops */
	devtool_force_meta(mesh[2], bar_from_baz, false);
	devtool_force_meta(mesh[0], bar_from_foo, false);
	devtool_set_udp_confirmed(mesh[0], bar_from_foo, true);
	assert(devtool_set_minmtu(mesh[0], bar_from_foo, MTU));
	assert_after(udp_confirmed_flag(mesh[2], "foo") && udp_confirmed_flag(mesh[0], "bar"), 15);
	reset_logs();
	pin(mesh[2], "bar", "foo");
	send_hello_once(mesh[2], "bar");
	assert(check_sync_flag(&baz_relay_log));
	assert(check_sync_flag(&foo_relay_log));

	/* both down → META, no binary log */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	devtool_force_meta(mesh[2], bar_from_baz, true);
	devtool_force_meta(mesh[0], bar_from_foo, true);
	send_hello_once(mesh[2], "bar");
	assert(!check_sync_flag(&baz_relay_log));
	assert(!check_sync_flag(&foo_relay_log));

	devtool_force_meta(mesh[2], bar_from_baz, false);
	devtool_force_meta(mesh[0], bar_from_foo, false);
	assert_after(udp_confirmed_flag(mesh[2], "foo"), 15);
}

static void test_ready_unready_ready(meshlink_handle_t **mesh) {
	reset_logs();
	pin(mesh[2], "bar", "foo");
	send_hello_once(mesh[2], "bar");
	assert(check_sync_flag(&baz_relay_log));

	reset_logs();
	devtool_force_meta(mesh[2], meshlink_get_node(mesh[2], "bar"), true);
	send_hello_once(mesh[2], "bar");
	assert(!check_sync_flag(&baz_relay_log));

	reset_logs();
	devtool_force_meta(mesh[2], meshlink_get_node(mesh[2], "bar"), false);
	pin(mesh[2], "bar", "foo");
	send_hello_once(mesh[2], "bar");
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

	assert(meshlink_channel_get_mss(mesh[2], ch1) == expected_channel_mss(mesh[2], "bar"));
	assert(meshlink_channel_get_mss(mesh[2], ch2) == expected_channel_mss(mesh[2], "bar"));

	/* set_minmtu does not settle probes by itself. A hop that is already
	   parked may raise the relay channel; the assert is the carrier formula. */
	reset_logs();
	confirm_final(mesh[0], "bar", 600);
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	set_sync_flag(&received2, false);
	assert(meshlink_channel_send(mesh[2], ch1, "Hello", 5) == 5);
	assert(wait_sync_flag(&received2, 10));
	assert(meshlink_channel_get_mss(mesh[2], ch1) == expected_channel_mss(mesh[2], "bar"));

	reset_logs();
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	assert(meshlink_channel_send(mesh[2], ch1, "Hello", 5) == 5);
	assert(meshlink_channel_get_mss(mesh[2], ch1) == expected_channel_mss(mesh[2], "bar"));

	/* two channels leave together on dest UDP, not the pinned relay hop */
	reset_logs();
	pin(mesh[2], "bar", "foo");
	{
		struct sockaddr_in local = {
			.sin_family = AF_INET,
			.sin_port = htons((uint16_t)meshlink_get_port(mesh[1])),
		};
		assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);
		assert(devtool_confirm_udp_from(mesh[2], meshlink_get_node(mesh[2], "bar"), (struct sockaddr *)&local, 0));
	}
	assert(udp_confirmed_flag(mesh[2], "bar"));
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
	reset_logs();
	oversize_bar_until(mesh, &got_relay_mtu, 20);
	reset_logs();
	oversize_baz_until(mesh, &bar_got_relay_mtu, 20);

	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "baz"), MTU));
}

static void test_failed_send_request_clock(meshlink_handle_t **mesh) {
	devtool_clear_relay_reports(mesh[0]);
	devtool_fail_relay_reports(mesh[0], true);

	bool parked = false;

	for(int i = 0; i < 20; i++) {
		arm_bar_via_foo(mesh, MINMTU);
		send_oversize_type8(mesh[2], "baz", "bar");

		if(devtool_has_relay_report(mesh[0], "baz", "bar")
		                && !devtool_relay_report_have_reported(mesh[0], "baz", "bar")) {
			parked = true;
			break;
		}

		sleep(1);
	}

	assert(parked);

	devtool_fail_relay_reports(mesh[0], false);
	reset_logs();
	oversize_bar_until(mesh, &got_relay_mtu, 20);
	assert(devtool_relay_report_have_reported(mesh[0], "baz", "bar"));

	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
}

static void test_lru_eviction_rearm(meshlink_handle_t **mesh) {
	devtool_set_udp_confirmed(mesh[0], meshlink_get_node(mesh[0], "bar"), true);
	devtool_set_udp_confirmed(mesh[0], meshlink_get_node(mesh[0], "baz"), true);
	devtool_clear_relay_reports(mesh[0]);
	reset_logs();
	assert(devtool_fill_relay_reports(mesh[0], RELAY_REPORT_MAX - 2, 0, true));
	assert(devtool_seed_relay_report(mesh[0], "a0", "z", 5, true));
	assert(devtool_seed_relay_report(mesh[0], "a1", "a", 1, true));
	assert(devtool_relay_report_count(mesh[0]) == RELAY_REPORT_MAX);

	reset_logs();
	oversize_bar_until(mesh, &got_relay_mtu, 20);
	assert(devtool_has_relay_report(mesh[0], "baz", "bar"));
	assert(!devtool_has_relay_report(mesh[0], "a0", "z"));
	assert(devtool_has_relay_report(mesh[0], "a1", "a"));
	assert(devtool_has_relay_report(mesh[0], "baz", "bar"));

	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	usleep(300000);
	assert(devtool_seed_relay_report(mesh[0], "a1", "a", 0, true));
	assert(devtool_seed_relay_report(mesh[0], "baz", "bar", 1, true));

	arm_baz_via_foo(mesh, MINMTU);
	send_oversize_type8(mesh[1], "bar", "baz");
	assert_after(!devtool_has_relay_report(mesh[0], "baz", "bar"), 5);

	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	hello_bar_until_relay_mtu(mesh, MTU, 20);
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
	assert(wait_sync_flag(&got_relay_mtu, 15));
	reset_logs();
	assert(devtool_set_minmtu(mesh[0], meshlink_get_node(mesh[0], "bar"), MTU));
	(void)wait_sync_flag(&got_relay_mtu, 5);
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
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), true);
	expect_hello_after_drop(mesh);
}

/* Hard-send clears hop UDP readiness. Channel MSS stays on the carrier formula. */
static void test_hard_send_clears_hop(meshlink_handle_t **mesh) {
	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	confirm_final(mesh[0], "bar", MINMTU);

	meshlink_channel_t *ch = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 11, receive2_cb, NULL, 0);
	assert(ch);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));

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
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));

	struct sockaddr_storage alt = {0};
	devtool_fill_host_mismatch(&st.address, &alt);
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&alt, hop_sock);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));

	struct sockaddr_storage port = {0};
	devtool_fill_port_mismatch(&st.address, &port);
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&port, hop_sock);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));

	struct sockaddr_storage bcast = {0};
	devtool_fill_bcast_ipv4(&bcast);
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&bcast, hop_sock);
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));

	assert(udp_confirmed_flag(mesh[2], "foo"));
	devtool_relay_hard_send_error_at(mesh[2], hop, (struct sockaddr *)&hop_addr, hop_sock + 1);
	assert(!udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));
	devtool_set_udp_confirmed(mesh[2], hop, true);
	assert(devtool_set_minmtu(mesh[2], hop, MTU));
	pin(mesh[2], "bar", "foo");
	assert(udp_confirmed_flag(mesh[2], "foo"));

	assert(devtool_inject_broadcast_hard_send(mesh[2], hop));
	assert(udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));
	devtool_free_node_status(&st);

	devtool_relay_hard_send_error(mesh[2], hop);
	assert(!udp_confirmed_flag(mesh[2], "foo"));
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));

	devtool_set_udp_confirmed(mesh[2], hop, true);
	assert(devtool_set_minmtu(mesh[2], hop, MTU));
	pin(mesh[2], "bar", "foo");
	meshlink_channel_abort(mesh[2], ch);
}

static bool long_peer_keyed(meshlink_handle_t *mesh, meshlink_node_t *peer) {
	devtool_node_status_t st;
	bool keyed;

	devtool_get_node_status(mesh, peer, &st);
	keyed = st.validkey;
	devtool_free_node_status(&st);
	return keyed;
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
	meshlink_handle_t *longa = meshlink_open("udp_relay_conf.longa", long_a, "udp-relay", DEV_CLASS_STATIONARY);
	meshlink_handle_t *longb = meshlink_open("udp_relay_conf.longb", long_b, "udp-relay", DEV_CLASS_STATIONARY);
	assert(longa);
	assert(longb);
	assert(meshlink_set_canonical_address(longa, meshlink_get_self(longa), "localhost", NULL));
	assert(meshlink_set_canonical_address(longb, meshlink_get_self(longb), "localhost", NULL));
	meshlink_enable_discovery(longa, false);
	meshlink_enable_discovery(longb, false);
	join_meshlink_peer(mesh[0], longa);
	join_meshlink_peer(mesh[0], longb);
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
	   pair stays on the direct floor until its own PMTU settles and never
	   uses a relay budget. */
	assert(meshlink_channel_get_mss(longa, ch_long) == expected_channel_mss(longa, long_b));
	assert(meshlink_channel_get_mss(mesh[2], ch_short) == expected_channel_mss(mesh[2], "bar"));

	pin(longa, long_b, "foo");
	pin(mesh[2], "bar", "foo");
	assert(devtool_set_minmtu(longa, meshlink_get_node(longa, "foo"), MTU));
	assert(meshlink_channel_get_mss(longa, ch_long) == expected_channel_mss(longa, long_b));
	assert(meshlink_channel_get_mss(mesh[2], ch_short) == expected_channel_mss(mesh[2], "bar"));
	ssize_t ch_sent = meshlink_channel_send(longa, ch_long, "Hello", 5);
	bool pkt_sent = meshlink_send(longa, meshlink_get_node(longa, long_b), "Hello", 5);
	(void)ch_sent;
	(void)pkt_sent;

	/* Losing and regaining direct UDP is the event that used to repacketize. */
	devtool_set_udp_confirmed(longa, meshlink_get_node(longa, long_b), false);
	assert(meshlink_channel_get_mss(longa, ch_long) == expected_channel_mss(longa, long_b));
	{
		struct sockaddr_in local = {
			.sin_family = AF_INET,
			.sin_port = htons((uint16_t)meshlink_get_port(longb)),
		};
		assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);
		(void)devtool_confirm_udp_from(longa, meshlink_get_node(longa, long_b), (struct sockaddr *)&local, 0);
	}
	assert(meshlink_channel_get_mss(longa, ch_long) == expected_channel_mss(longa, long_b));
	assert(devtool_set_minmtu(longa, meshlink_get_node(longa, long_b), MTU));
	assert(meshlink_channel_get_mss(longa, ch_long) == expected_channel_mss(longa, long_b));
	pin(mesh[2], "bar", "foo");
	assert(meshlink_channel_get_mss(mesh[2], ch_short) == expected_channel_mss(mesh[2], "bar"));

	{
		struct sockaddr_in local = {
			.sin_family = AF_INET,
			.sin_port = htons((uint16_t)meshlink_get_port(longb)),
		};
		meshlink_node_t *peer = meshlink_get_node(longa, long_b);
		devtool_node_status_t settled;
		assert(peer);
		assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);
		assert_after(long_peer_keyed(longa, peer), 20);
		assert(devtool_confirm_udp_from(longa, peer, (struct sockaddr *)&local, 0));
		devtool_get_node_status(longa, peer, &settled);
		assert(settled.active_route_kind == ROUTE_DIRECT_UDP);
		devtool_free_node_status(&settled);
		assert(devtool_accept_pmtu_increase(longa, peer, 1000));
		assert(meshlink_channel_get_mss(longa, ch_long) == 1008 - PACKETHDR_BYTES - UTCP_HDR);

		char req[600];
		snprintf(req, sizeof req, "0 foo %s 24 %s 1400", long_a, long_b);
		(void)devtool_handle_req_relay_mtu(longa, meshlink_get_node(longa, "foo"), req);
		assert(meshlink_channel_get_mss(longa, ch_long) == 1008 - PACKETHDR_BYTES - UTCP_HDR);
	}

	meshlink_channel_abort(longa, ch_long);
	meshlink_channel_abort(mesh[2], ch_short);
	meshlink_close(longa);
	meshlink_close(longb);
	assert(meshlink_destroy("udp_relay_conf.longa"));
	assert(meshlink_destroy("udp_relay_conf.longb"));
}

static void test_relay_budget_tracks_mss(meshlink_handle_t **mesh) {
	meshlink_node_t *bar = meshlink_get_node(mesh[2], "bar");
	meshlink_node_t *foo = meshlink_get_node(mesh[2], "foo");
	unsigned prefix21 = 2 + strlen("baz") + strlen("bar") + 21;
	unsigned hi = 1000;
	unsigned lo = MINMTU - prefix21;
	char req[128];
	devtool_node_status_t st;
	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)meshlink_get_port(mesh[1])),
	};

	pin(mesh[2], "bar", "foo");
	devtool_get_node_status(mesh[2], bar, &st);
	assert(st.active_route_kind == ROUTE_RELAY);
	assert(st.active_route_carrier == CARRIER_UDP);
	devtool_free_node_status(&st);

	snprintf(req, sizeof req, "0 foo baz 24 bar %u", hi);
	assert(devtool_handle_req_relay_mtu(mesh[2], foo, req));
	devtool_get_node_status(mesh[2], bar, &st);
	assert(st.relay_budget == hi);
	devtool_free_node_status(&st);

	meshlink_channel_t *ch = meshlink_channel_open(mesh[2], bar, 13, receive2_cb, NULL, 0);
	assert(ch);
	assert(meshlink_channel_get_mss(mesh[2], ch) == hi - PACKETHDR_BYTES - UTCP_HDR);

	snprintf(req, sizeof req, "0 foo baz 24 bar %u", lo);
	assert(devtool_handle_req_relay_mtu(mesh[2], foo, req));
	assert(meshlink_channel_get_mss(mesh[2], ch) == carrier_floor_mss("baz", "bar"));

	assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);
	assert(devtool_confirm_udp_from(mesh[2], bar, (struct sockaddr *)&local, 0));
	devtool_get_node_status(mesh[2], bar, &st);
	assert(st.active_route_kind == ROUTE_DIRECT_UDP);
	devtool_free_node_status(&st);

	assert(devtool_accept_pmtu_increase(mesh[2], bar, 1000));
	snprintf(req, sizeof req, "0 foo baz 24 bar %u", hi);
	(void)devtool_handle_req_relay_mtu(mesh[2], foo, req);
	assert(meshlink_channel_get_mss(mesh[2], ch) == 1008 - PACKETHDR_BYTES - UTCP_HDR);
	devtool_get_node_status(mesh[2], bar, &st);
	assert(st.relay_budget == lo);
	devtool_free_node_status(&st);

	meshlink_channel_abort(mesh[2], ch);
	printf("udp-relay: relay budget raised and direct PMTU ignored it\n");
}

static void test_reachability_flip_mss(meshlink_handle_t **mesh) {
	meshlink_set_channel_accept_cb(mesh[1], accept_cb);
	meshlink_channel_t *ch = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 12, receive2_cb, NULL, 0);
	assert(ch);

	pin(mesh[2], "bar", "foo");

	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));

	/* Losing the relay hop drops any raised budget back through the same formula. */
	set_sync_flag(&foo_down, false);
	meshlink_stop(mesh[0]);
	assert(wait_sync_flag(&foo_down, 20));
	assert(meshlink_channel_get_mss(mesh[2], ch) == expected_channel_mss(mesh[2], "bar"));
	/* Attempt a send so dest META is used; hop is down so do not require delivery. */
	ssize_t leftover_sent = meshlink_channel_send(mesh[2], ch, "Hello", 5);
	(void)leftover_sent;
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

static struct sync_flag nat_accepted;
static struct sync_flag nat_received;

static void nat_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;

	if(len) {
		set_sync_flag(&nat_received, true);
	}
}

static bool nat_accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)port;
	(void)data;
	(void)len;
	meshlink_set_channel_receive_cb(mesh, channel, nat_receive_cb);
	set_sync_flag(&nat_accepted, true);
	return true;
}

static bool nat_route_is(meshlink_handle_t *mesh, meshlink_node_t *node, int kind) {
	devtool_node_status_t st;
	bool match;

	devtool_get_node_status(mesh, node, &st);
	match = st.active_route_kind == kind && (kind != 1 || !st.active_route_local);
	devtool_free_node_status(&st);
	return match;
}

static bool nat_keyed(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st;
	bool keyed;

	devtool_get_node_status(mesh, node, &st);
	keyed = st.validkey;
	devtool_free_node_status(&st);
	return keyed;
}

static uint32_t nat_restarts(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st;
	uint32_t count;

	devtool_get_node_status(mesh, node, &st);
	count = st.sptps_restart_count;
	devtool_free_node_status(&st);
	return count;
}

static uint32_t nat_requests(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st;
	uint32_t count;

	devtool_get_node_status(mesh, node, &st);
	count = st.punch_requests_sent;
	devtool_free_node_status(&st);
	return count;
}

static unsigned nat_reflex_app;
static unsigned nat_reflex_cam;
static unsigned nat_punch_app;
static unsigned nat_punch_cam;
static unsigned nat_mtu_app;
static unsigned nat_mtu_cam;
static unsigned nat_log_seq;
static void nat_count_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)level;

	if(!mesh || !mesh->name || !text) {
		return;
	}

	nat_log_seq++;

	if(strstr(text, "Punch confirmed") && strstr(text, "source=peer-reflexive")) {
		if(!strcmp(mesh->name, "app")) {
			nat_reflex_app++;

			if(!nat_punch_app) {
				nat_punch_app = nat_log_seq;
			}
		} else if(!strcmp(mesh->name, "cam")) {
			nat_reflex_cam++;

			if(!nat_punch_cam) {
				nat_punch_cam = nat_log_seq;
			}
		}
	}

	/* Backbone liveness uses the same probe log. Only the ordinary peer's
	   PMTU counts, and it has to follow that peer's punch confirmation. */
	if(strstr(text, "Sending MTU probe length")) {
		if(!strcmp(mesh->name, "app") && strstr(text, " to cam ") && !nat_mtu_app) {
			nat_mtu_app = nat_log_seq;
		} else if(!strcmp(mesh->name, "cam") && strstr(text, " to app ") && !nat_mtu_cam) {
			nat_mtu_cam = nat_log_seq;
		}
	}
}

/* One production-path punch. Direct UDP in both directions when at least one
   NAT is cone. Two endpoint-dependent NATs stay on relay. */
static bool nat_hole_punch_once(const char *prefix, bool app_symmetric, bool cam_symmetric) {
	peer_config_t *peers = setup_nat_hole_punch_asymm(prefix, app_symmetric, cam_symmetric);
	bool expect_direct = !app_symmetric || !cam_symmetric;
	bool asymmetric = app_symmetric != cam_symmetric;
	meshlink_node_t *app_cam;
	meshlink_node_t *cam_app;
	meshlink_node_t *bb_app;
	meshlink_node_t *bb_cam;
	meshlink_channel_t *ch;
	uint32_t restarts;
	uint32_t requests;
	unsigned bb_probes;
	devtool_node_status_t st;

	if(!peers) {
		fprintf(stderr, "nat hole punch %s: topology unavailable\n", prefix);
		return false;
	}

	nat_reflex_app = nat_reflex_cam = 0;
	nat_punch_app = nat_punch_cam = 0;
	nat_mtu_app = nat_mtu_cam = 0;
	meshlink_set_log_cb(peers[1].mesh, MESHLINK_DEBUG, nat_count_log);
	meshlink_set_log_cb(peers[2].mesh, MESHLINK_DEBUG, nat_count_log);

	init_sync_flag(&nat_accepted);
	init_sync_flag(&nat_received);
	meshlink_set_channel_accept_cb(peers[2].mesh, nat_accept_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after((app_cam = meshlink_get_node(peers[1].mesh, "cam")) != NULL, 20);
	assert_after((cam_app = meshlink_get_node(peers[2].mesh, "app")) != NULL, 20);
	assert_after(meshlink_get_node_reachability(peers[1].mesh, app_cam, NULL, NULL), 20);
	assert_after(devtool_backbone_udp_confirmed(peers[1].mesh) && devtool_backbone_udp_confirmed(peers[2].mesh), 20);

	/* Peer SPTPS starts on demand. Prime it with probes held so the measured
	   channel opens against an already-valid key and still requests the endpoint. */
	devtool_force_meta(peers[1].mesh, app_cam, true);
	devtool_force_meta(peers[2].mesh, cam_app, true);
	ch = meshlink_channel_open(peers[1].mesh, app_cam, 9, nat_receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&nat_accepted, 20));
	assert_after(nat_keyed(peers[1].mesh, app_cam) && nat_keyed(peers[2].mesh, cam_app), 20);
	meshlink_channel_abort(peers[1].mesh, ch);
	reset_sync_flag(&nat_accepted);
	reset_sync_flag(&nat_received);

	hint_address(peers[1].mesh, app_cam, "198.51.100.9", 9);
	hint_address(peers[2].mesh, cam_app, "198.51.100.8", 9);

	restarts = nat_restarts(peers[1].mesh, app_cam);
	requests = nat_requests(peers[1].mesh, app_cam);
	bb_app = meshlink_get_node(peers[0].mesh, "app");
	bb_cam = meshlink_get_node(peers[0].mesh, "cam");
	assert(bb_app && bb_cam);
	bb_probes = devtool_liveness_probes_sent(peers[0].mesh, bb_app) + devtool_liveness_probes_sent(peers[0].mesh, bb_cam);

	ch = meshlink_channel_open(peers[1].mesh, app_cam, 7, nat_receive_cb, NULL, 0);
	assert(ch);
	assert(wait_sync_flag(&nat_accepted, 20));
	assert(meshlink_channel_send(peers[1].mesh, ch, "Hello", 5) == 5);
	assert(wait_sync_flag(&nat_received, 20));
	assert(nat_requests(peers[1].mesh, app_cam) >= requests + 1);
	assert(nat_restarts(peers[1].mesh, app_cam) == restarts);
	assert(devtool_liveness_probes_sent(peers[0].mesh, bb_app) + devtool_liveness_probes_sent(peers[0].mesh, bb_cam) == bb_probes);
	/* Backbone liveness already logged MTU probes. Count only probes from
	   here, so peer PMTU is compared against the punch confirmation. */
	nat_punch_app = nat_punch_cam = 0;
	nat_mtu_app = nat_mtu_cam = 0;
	devtool_force_meta(peers[1].mesh, app_cam, false);
	devtool_force_meta(peers[2].mesh, cam_app, false);
	reset_sync_flag(&nat_received);
	assert(meshlink_channel_send(peers[1].mesh, ch, "World", 5) == 5);
	assert(wait_sync_flag(&nat_received, 20));
	assert(nat_restarts(peers[1].mesh, app_cam) == restarts);

	if(expect_direct) {
		for(int pass = 0; pass < 3; pass++) {
			if(nat_route_is(peers[1].mesh, app_cam, 1) && nat_route_is(peers[2].mesh, cam_app, 1)) {
				break;
			}

			devtool_age_route(peers[1].mesh, app_cam, 31);
			devtool_age_candidate(peers[1].mesh, app_cam, 2);
			devtool_path_route_tick(peers[1].mesh, app_cam);
			devtool_age_route(peers[2].mesh, cam_app, 31);
			devtool_age_candidate(peers[2].mesh, cam_app, 2);
			devtool_path_route_tick(peers[2].mesh, cam_app);
			sleep(2);
		}

		assert_after(nat_route_is(peers[1].mesh, app_cam, 1), 30);
		assert_after(nat_route_is(peers[2].mesh, cam_app, 1), 30);

		assert(nat_reflex_app >= 1);
		assert(nat_reflex_cam >= 1);

		if(asymmetric) {
			assert(nat_punch_app && nat_mtu_app > nat_punch_app);
			assert(nat_punch_cam && nat_mtu_cam > nat_punch_cam);
		}
	} else {
		sleep(8);
		devtool_age_route(peers[1].mesh, app_cam, 31);
		devtool_age_candidate(peers[1].mesh, app_cam, 2);
		devtool_path_route_tick(peers[1].mesh, app_cam);
		devtool_age_route(peers[2].mesh, cam_app, 31);
		devtool_age_candidate(peers[2].mesh, cam_app, 2);
		devtool_path_route_tick(peers[2].mesh, cam_app);
		devtool_get_node_status(peers[1].mesh, app_cam, &st);
		assert(st.active_route_kind != 1);
		devtool_free_node_status(&st);
		devtool_get_node_status(peers[2].mesh, cam_app, &st);
		assert(st.active_route_kind != 1);
		devtool_free_node_status(&st);
	}

	devtool_get_node_status(peers[1].mesh, app_cam, &st);
	assert(!st.punch_challenge_active);
	devtool_free_node_status(&st);
	devtool_get_node_status(peers[2].mesh, cam_app, &st);
	assert(!st.punch_challenge_active);
	devtool_free_node_status(&st);
	assert(nat_restarts(peers[1].mesh, app_cam) == restarts);

	meshlink_channel_abort(peers[1].mesh, ch);
	close_nat_hole_punch(peers);
	return true;
}

static void test_nat_hole_punch(void) {
	if(!netns_available()) {
		fprintf(stderr, "udp-relay NAT hole punch: netns unavailable\n");
		assert(netns_available());
		return;
	}

	for(int i = 0; i < 10; i++) {
		char prefix[32];

		snprintf(prefix, sizeof prefix, "natholeC%d", i);
		printf("\n=== udp-relay NAT cone %d ===\n", i);
		assert(nat_hole_punch_once(prefix, false, false));
	}

	for(int i = 0; i < 5; i++) {
		char prefix[32];

		snprintf(prefix, sizeof prefix, "natholeS%d", i);
		printf("\n=== udp-relay NAT symmetric %d ===\n", i);
		assert(nat_hole_punch_once(prefix, true, true));
	}

	for(int i = 0; i < 3; i++) {
		char prefix[32];

		snprintf(prefix, sizeof prefix, "natholeM%d", i);
		printf("\n=== udp-relay NAT cone to endpoint-dependent %d ===\n", i);
		assert(nat_hole_punch_once(prefix, false, true));
		snprintf(prefix, sizeof prefix, "natholeN%d", i);
		printf("\n=== udp-relay NAT endpoint-dependent to cone %d ===\n", i);
		assert(nat_hole_punch_once(prefix, true, false));
	}

	printf("udp-relay NAT hole punch ok\n");
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

	for(int i = 0; i < 3; i++) {
		char *path = NULL;
		assert(asprintf(&path, "udp_relay_conf.%d", i) != -1 && path);
		assert(meshlink_destroy(path));
		mesh[i] = meshlink_open(path, name[i], "udp-relay", i ? DEV_CLASS_STATIONARY : DEV_CLASS_BACKBONE);
		assert(mesh[i]);
		free(path);

		if(!i) {
			devtool_set_external_ip_address(mesh[i], meshlink_get_self(mesh[i]), "127.0.0.1");
		}

		assert(meshlink_set_canonical_address(mesh[i], meshlink_get_self(mesh[i]), "localhost", NULL));
		meshlink_enable_discovery(mesh[i], false);
	}

	join_meshlink_peer(mesh[0], mesh[1]);
	join_meshlink_peer(mesh[0], mesh[2]);

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
	assert_after((edges = devtool_get_all_edges(mesh[0], edges, &nedges), nedges >= 2), 15);
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
	/* First-record relay report before channels steal receive_cb. */
	hello_bar_until_relay_mtu(mesh, 600, 20);

	test_channels_and_mss(mesh);

	/* devtool: dest==nexthop rejected */
	assert(!devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], "bar"), meshlink_get_node(mesh[2], "bar")));

	test_hard_send_clears_hop(mesh);
	test_long_names(mesh);
	test_relay_budget_tracks_mss(mesh);

	test_path_preference(mesh);
	test_reachability_flip_mss(mesh);
	test_nat_hole_punch();

	for(int i = 0; i < 3; i++) {
		meshlink_close(mesh[i]);
		char *path = NULL;
		assert(asprintf(&path, "udp_relay_conf.%d", i) != -1 && path);
		assert(meshlink_destroy(path));
		free(path);
	}

	return 0;
}
