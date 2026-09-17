#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/*
 * Scenarios covered here + path_policy_cover_unit:

 * Classification
 *   C1  IPv4 local: 127/8, 10/8, 172.16/12 edges, 192.168/16, 169.254/16
 *   C2  IPv4 WAN: 8.8.8.8, 203.0.113.0/24, 172.15 and 172.32
 *   C3  IPv6 local: ::1, fe80::, fec0::, fc00::/7
 *   C4  IPv6 WAN: 2001:db8::
 *   C5  Discovery source on a WAN IP ranks as local UDP
 *   C6  Null / AF_UNSPEC / AF_UNKNOWN rejected as learn and as local

 * Provenance / recent[]
 *   P1  Learn new HINT, AUTH upgrades trust, UNKNOWN/HINT at front is a no-op
 *   P2  Re-learn an older slot: moves to front, keeps higher trust
 *   P3  MAX_RECENT=5 eviction of the oldest
 *   P4  Fallback refuses empty and full recent[], appends when there is a hole
 *   P5  Fallback upgrades source in place, refuses a weaker source
 *   P6  ADDR_SRC_CANONICAL never stored; INDIRECT not stored at the front
 *   P7  Canonical-equivalent numeric address never stored
 *   P8  Sanitize drops planted NLB and CANONICAL; INDIRECT fallback is kept
 *   P9  Hostname canonical does not strip unrelated numeric recent[]
 *   P10 HINT persists across close/reopen
 *   P11 Planted NLB is stripped on reload
 *   P12 Planted NLB-IP/NMN-port hybrid is stripped on reload

 * META classification
 *   M1  via_canonical, meta_dial_tier, or address match => canonical META
 *   M2  Active direct META vs inactive / missing connection => NONE
 *   M3  META-in pins META-out even when hop UDP is confirmed
 *   M4  Dest UDP ready + meta_in => dest's own UDP is ignored

 * Upgrade ladder (validated only)
 *   U0  Dest unconfirmed, hop unconfirmed => META (3 or 4)
 *   U1  Hop UDP confirmed + dest unconfirmed + pin => RELAY_UDP
 *   U2  Dest WAN confirmed => DIRECT_WAN_UDP (pin ignored once dest is ready)
 *   U3  Dest local confirmed => DIRECT_LOCAL_UDP
 *   U4  WAN stays selected while an unvalidated local candidate exists
 *   U5  Local probe reply promotes WAN -> LOCAL
 *   U6  Cover-unit: NONE -> WAN, WAN -> LOCAL via path_promote_udp_if_better

 * Downgrade / refuse
 *   D1  Unconfirm dest while hop UDP is up => RELAY_UDP, not a silent WAN keep
 *   D2  Unconfirm hop => META
 *   D3  Confirm WAN after local (forced) => WAN
 *   D4  Promote refuses: not confirmed, same address, canonical, same-tier WAN, worse WAN-vs-LOCAL
 *   D5  Fail local does not invent a WAN dest; WAN only after re-confirm
 *   D6  Rate-limited local probe while WAN is active
 */

enum {
	TIER_LOCAL = 0,
	TIER_WAN = 1,
	TIER_RELAY = 2,
	TIER_META_DIRECT = 3,
	TIER_META_CANONICAL = 4,
	TIER_NONE = 5
};

static struct sync_flag received;
static struct sync_flag bar_learned;
static struct sync_flag baz_learned;

static void any_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	log_cb(mesh, level, text);
}

static void receive_cb(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len) {
	(void)mesh;
	(void)source;

	if(len == 5 && !memcmp(data, "Hello", 5)) {
		set_sync_flag(&received, true);
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
	(void)reachable;

	if(!strcmp(node->name, "bar") || !strcmp(node->name, "foo")) {
		set_sync_flag(&baz_learned, true);
	}
}

static bool mtu_fixed(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *n = meshlink_get_node(mesh, name);

	if(!n) {
		return false;
	}

	devtool_node_status_t st;
	devtool_get_node_status(mesh, n, &st);
	bool ok = st.udp_status == DEVTOOL_UDP_WORKING && st.minmtu && st.mtuprobes >= 30;
	devtool_free_node_status(&st);
	return ok;
}

static int dest_tier(meshlink_handle_t *mesh, const char *name, bool meta_in) {
	return devtool_select_destination_tier(mesh, meshlink_get_node(mesh, name), meta_in);
}

static int hop_tier(meshlink_handle_t *mesh, const char *name, bool meta_in) {
	return devtool_select_hop_tier(mesh, meshlink_get_node(mesh, name), meta_in);
}

static bool meta_tier(int tier) {
	return tier == TIER_META_DIRECT || tier == TIER_META_CANONICAL;
}

static void pin(meshlink_handle_t *origin, const char *dest, const char *hop) {
	assert(devtool_force_relay_path(origin, meshlink_get_node(origin, dest), meshlink_get_node(origin, hop)));
}

static void confirm_v4(meshlink_handle_t *mesh, const char *name, const char *ip, int port, int tier) {
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)port),
	};
	assert(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
	assert(devtool_confirm_udp_from(mesh, meshlink_get_node(mesh, name), (struct sockaddr *)&sa, tier));
}

static void send_hello(meshlink_handle_t *from, const char *dest) {
	set_sync_flag(&received, false);

	for(int i = 0; i < 15; i++) {
		assert(meshlink_send(from, meshlink_get_node(from, dest), "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			return;
		}
	}

	assert(wait_sync_flag(&received, 10));
}

static void test_einval(void) {
	assert(!devtool_path_policy_cover_unit(NULL, NULL));
	assert(devtool_select_destination_tier(NULL, NULL, false) == TIER_NONE);
	assert(devtool_select_hop_tier(NULL, NULL, false) == TIER_NONE);
	assert(!devtool_plant_recent_address(NULL, NULL, NULL));
	assert(!devtool_confirm_udp_from(NULL, NULL, NULL, 0));
	assert(!devtool_promote_udp_if_better(NULL, NULL, NULL));
}

static void test_live_transitions(meshlink_handle_t **mesh) {
	printf("=== live upgrade / downgrade matrix ===\n");

	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)meshlink_get_port(mesh[1])),
	};
	assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);

	meshlink_node_t *bar = meshlink_get_node(mesh[2], "bar");
	meshlink_node_t *foo = meshlink_get_node(mesh[2], "foo");
	assert(bar && foo);

	/* U1: pin dest via hop. The pin and the read need one lock, otherwise a probe
	   reply already in flight can re-confirm dest before the tier is sampled. */
	devtool_set_udp_confirmed(mesh[2], foo, true);
	pin(mesh[2], "bar", "foo");
	assert(devtool_select_dest_with_udp(mesh[2], bar, false, foo, true, false) == TIER_RELAY);
	assert(hop_tier(mesh[2], "foo", false) == TIER_RELAY);
	printf("U1 dest RELAY_UDP\n");

	/* M3: META-in pins META-out on the hop */
	int hop_meta = hop_tier(mesh[2], "foo", true);
	assert(meta_tier(hop_meta));
	printf("M3 hop META-in=%d (UDP ready but pinned)\n", hop_meta);

	/* U2: dest WAN confirmed => WAN, pin ignored */
	confirm_v4(mesh[2], "bar", "203.0.113.10", 9, TIER_WAN);
	assert(dest_tier(mesh[2], "bar", false) == TIER_WAN);
	printf("U2 dest WAN (pin ignored once dest UDP is ready)\n");

	/* M4: dest UDP ready + meta_in ignores dest UDP */
	assert(meta_tier(dest_tier(mesh[2], "bar", true)));
	printf("M4 dest META-in ignores dest WAN UDP\n");

	/* U4: unvalidated local stays off the dest while WAN is confirmed */
	meshlink_hint_address(mesh[2], meshlink_get_node(mesh[2], "bar"), (struct sockaddr *)&local);
	devtool_node_status_t st;
	devtool_get_node_status(mesh[2], meshlink_get_node(mesh[2], "bar"), &st);
	assert(st.udp_tier == TIER_WAN);
	assert(st.would_probe_local_udp);
	devtool_free_node_status(&st);

	struct sockaddr_storage chosen;
	int sock = -1;
	assert(devtool_choose_udp_address(mesh[2], meshlink_get_node(mesh[2], "bar"), &chosen, &sock));
	assert(addr_is(&chosen, "203.0.113.10", 9));
	printf("U4 WAN stays while local is unvalidated\n");

	/* U5 / U3: validated local replaces WAN. */
	assert(devtool_confirm_udp_from(mesh[2], meshlink_get_node(mesh[2], "bar"), (struct sockaddr *)&local, TIER_LOCAL));
	assert(dest_tier(mesh[2], "bar", false) == TIER_LOCAL);
	assert(devtool_choose_udp_address(mesh[2], meshlink_get_node(mesh[2], "bar"), &chosen, &sock));
	assert(addr_is(&chosen, "127.0.0.1", meshlink_get_port(mesh[1])));
	printf("U5 dest LOCAL after probe reply\n");

	/* D3: forced WAN after local */
	confirm_v4(mesh[2], "bar", "203.0.113.10", 9, TIER_WAN);
	assert(dest_tier(mesh[2], "bar", false) == TIER_WAN);
	printf("D3 forced WAN after local\n");

	/* D1 / D5: dest UDP down, hop UDP up, one lock so inbound probes cannot
	   re-confirm dest before we read the tier. Must be RELAY, not leftover WAN. */
	assert(devtool_select_dest_with_udp(mesh[2], bar, false, foo, true, false) == TIER_RELAY);
	printf("D1/D5 dest RELAY after dest UDP fail (WAN not invented)\n");

	/* D2 / U0: dest+hop UDP down in the same snapshot => META */
	int after_hop_down = devtool_select_dest_with_udp(mesh[2], bar, false, foo, false, false);
	assert(meta_tier(after_hop_down));
	assert(meta_tier(devtool_select_dest_with_udp(mesh[2], bar, false, foo, false, true)));
	printf("D2/U0 dest META=%d after hop UDP fail\n", after_hop_down);

	/* Re-confirm WAN only after a new validation */
	confirm_v4(mesh[2], "bar", "203.0.113.11", 11, TIER_WAN);
	assert(dest_tier(mesh[2], "bar", false) == TIER_WAN);
	printf("D5 WAN only after re-confirm\n");

	/* Restore a working local dest so later hello still works */
	assert(devtool_confirm_udp_from(mesh[2], meshlink_get_node(mesh[2], "bar"), (struct sockaddr *)&local, TIER_LOCAL));
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), true);
	assert(dest_tier(mesh[2], "bar", false) == TIER_LOCAL);
	send_hello(mesh[2], "bar");
	printf("live matrix ok\n");
}

static void test_persist_hint_and_nlb(void) {
	printf("=== P10/P11 persist HINT, sanitize planted NLB on reload ===\n");

	assert(meshlink_destroy("path_policy_persist_a"));
	assert(meshlink_destroy("path_policy_persist_b"));
	meshlink_handle_t *a = meshlink_open("path_policy_persist_a", "a", "path-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("path_policy_persist_b", "b", "path-policy", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	link_meshlink_pair(a, b);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);

	struct sockaddr_in hint = {
		.sin_family = AF_INET,
		.sin_port = htons(4242),
	};
	assert(inet_pton(AF_INET, "203.0.113.80", &hint.sin_addr) == 1);
	meshlink_hint_address(a, node_b, (struct sockaddr *)&hint);

	struct sockaddr_in nlb = {
		.sin_family = AF_INET,
		.sin_port = htons(443),
	};
	assert(inet_pton(AF_INET, "198.51.100.20", &nlb.sin_addr) == 1);
	assert(meshlink_set_canonical_address(a, node_b, "198.51.100.20", "443"));
	assert(devtool_plant_recent_address(a, node_b, (struct sockaddr *)&nlb));

	devtool_node_status_t st;
	devtool_get_node_status(a, node_b, &st);
	assert(st.recent_count >= 2);
	devtool_free_node_status(&st);

	meshlink_close(a);
	a = meshlink_open("path_policy_persist_a", "a", "path-policy", DEV_CLASS_BACKBONE);
	assert(a);
	meshlink_enable_discovery(a, false);
	node_b = meshlink_get_node(a, "b");
	assert(node_b);

	devtool_get_node_status(a, node_b, &st);
	bool saw_hint = false;

	for(size_t i = 0; i < st.recent_count; i++) {
		assert(!addr_is(&st.recent[i], "198.51.100.20", 443));

		if(addr_is(&st.recent[i], "203.0.113.80", 4242)) {
			assert(st.recent_source[i] == 3); /* ADDR_SRC_HINT */
			saw_hint = true;
		}
	}

	assert(saw_hint);
	devtool_free_node_status(&st);

	struct sockaddr_in hybrid = {
		.sin_family = AF_INET,
		.sin_port = htons(23349),
	};
	assert(inet_pton(AF_INET, "198.51.100.20", &hybrid.sin_addr) == 1);
	assert(devtool_plant_recent_address(a, node_b, (struct sockaddr *)&hybrid));
	meshlink_close(a);
	a = meshlink_open("path_policy_persist_a", "a", "path-policy", DEV_CLASS_BACKBONE);
	assert(a);
	meshlink_enable_discovery(a, false);
	node_b = meshlink_get_node(a, "b");
	assert(node_b);
	devtool_get_node_status(a, node_b, &st);

	for(size_t i = 0; i < st.recent_count; i++) {
		assert(!addr_is(&st.recent[i], "198.51.100.20", 23349));
	}

	devtool_free_node_status(&st);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("path_policy_persist_a"));
	assert(meshlink_destroy("path_policy_persist_b"));
	printf("P10/P11/P12 ok\n");
}

static void test_canonical_learn_rejected(meshlink_handle_t **mesh) {
	printf("=== P7 canonical-equivalent learn is rejected ===\n");

	meshlink_node_t *bar = meshlink_get_node(mesh[2], "bar");
	assert(meshlink_set_canonical_address(mesh[2], bar, "198.51.100.30", "9"));

	struct sockaddr_in nlb = {
		.sin_family = AF_INET,
		.sin_port = htons(9),
	};
	assert(inet_pton(AF_INET, "198.51.100.30", &nlb.sin_addr) == 1);
	meshlink_hint_address(mesh[2], bar, (struct sockaddr *)&nlb);

	devtool_node_status_t st;
	devtool_get_node_status(mesh[2], bar, &st);

	for(size_t i = 0; i < st.recent_count; i++) {
		assert(!addr_is(&st.recent[i], "198.51.100.30", 9));
	}

	devtool_free_node_status(&st);
	printf("P7 ok\n");
}

int main(void) {
	init_sync_flag(&received);
	init_sync_flag(&bar_learned);
	init_sync_flag(&baz_learned);

	test_einval();
	test_persist_hint_and_nlb();

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, any_log);

	const char *name[3] = {"foo", "bar", "baz"};
	meshlink_handle_t *mesh[3];

	for(int i = 0; i < 3; i++) {
		char *path = NULL;
		assert(asprintf(&path, "path_policy_conf.%d", i) != -1 && path);
		assert(meshlink_destroy(path));
		mesh[i] = meshlink_open(path, name[i], "path-policy", i ? DEV_CLASS_STATIONARY : DEV_CLASS_BACKBONE);
		assert(mesh[i]);
		free(path);
		assert(meshlink_set_canonical_address(mesh[i], meshlink_get_self(mesh[i]), "localhost", NULL));
	}

	join_meshlink_peer(mesh[0], mesh[1]);
	join_meshlink_peer(mesh[0], mesh[2]);

	meshlink_set_log_cb(mesh[0], MESHLINK_DEBUG, any_log);
	meshlink_set_log_cb(mesh[1], MESHLINK_DEBUG, any_log);
	meshlink_set_log_cb(mesh[2], MESHLINK_DEBUG, any_log);
	meshlink_set_node_status_cb(mesh[1], bar_status_cb);
	meshlink_set_node_status_cb(mesh[2], baz_status_cb);
	meshlink_set_receive_cb(mesh[1], receive_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(mesh[i]));
	}

	assert(wait_sync_flag(&bar_learned, 10));
	assert(wait_sync_flag(&baz_learned, 10));
	assert_after(mtu_fixed(mesh[2], "foo") && mtu_fixed(mesh[0], "baz")
	             && mtu_fixed(mesh[0], "bar") && mtu_fixed(mesh[1], "foo"), 25);

	send_hello(mesh[2], "bar");

	test_live_transitions(mesh);
	test_canonical_learn_rejected(mesh);

	assert(devtool_path_policy_cover_unit(mesh[2], meshlink_get_node(mesh[2], "bar")));
	printf("cover-unit ok\n");

	for(int i = 0; i < 3; i++) {
		meshlink_close(mesh[i]);
		char *path = NULL;
		assert(asprintf(&path, "path_policy_conf.%d", i) != -1 && path);
		assert(meshlink_destroy(path));
		free(path);
	}

	return 0;
}
