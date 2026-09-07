#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* Outgoing connection order: RECENT (direct) -> CANONICAL (relay) -> KNOWN (edges).

   T1: a direct recent[] address wins over the canonical relay.
   T2: a dead recent[] address falls back to the canonical relay.
   T3: no canonical, no recent[]: the KNOWN (edge) path still connects.
   T4: after T2 the relay address must not have ended up in recent[].
   T5: a KNOWN address taken from another node's indirect (relayed) edge is treated
       as canonical: not remembered in recent[], edge marked indirect, upgraded later. */

static struct sync_flag peer_reachable;
static devtool_node_status_t status_at_reachable;
static const char *watched_peer;
static int hint_port_on_reachable;  /* T5: direct address to hint the moment the peer comes up, 0 = none */

static struct sync_flag peer_meta_up;
static devtool_node_status_t status_at_meta_up;

static bool is_rfc1918(const char *ip) {
	struct in_addr in;

	if(inet_pton(AF_INET, ip, &in) != 1) {
		return false;
	}

	uint32_t a = ntohl(in.s_addr);
	return (a & 0xff000000) == 0x0a000000 || (a & 0xfff00000) == 0xac100000 || (a & 0xffff0000) == 0xc0a80000;
}

/* Snapshot the peer's meta connection the moment it becomes reachable, before any
   later upgrade probe can move it. */
static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	if(!reachable || strcmp(node->name, watched_peer) || check_sync_flag(&peer_reachable)) {
		return;
	}

	/* Runs inside ack_h(), before anything was learned over UDP: a hinted address is
	   the only direct one and is probed first. */
	if(hint_port_on_reachable) {
		hint_address(mesh, node, "127.0.0.1", hint_port_on_reachable);
	}

	devtool_get_node_status(mesh, node, &status_at_reachable);
	set_sync_flag(&peer_reachable, true);
}

/* Snapshot the peer's first meta connection as it activates (devtool meta status
   callback, also inside ack_h()), before an upgrade probe can replace it. */
static void meta_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool up) {
	if(!up || strcmp(node->name, watched_peer) || check_sync_flag(&peer_meta_up)) {
		return;
	}

	devtool_get_node_status(mesh, node, &status_at_meta_up);
	set_sync_flag(&peer_meta_up, true);
}

static void open_pair(meshlink_handle_t **a, meshlink_handle_t **b, const char *prefix) {
	char conf_a[64], conf_b[64];
	snprintf(conf_a, sizeof conf_a, "%s_conf.1", prefix);
	snprintf(conf_b, sizeof conf_b, "%s_conf.2", prefix);
	assert(meshlink_destroy(conf_a));
	assert(meshlink_destroy(conf_b));

	/* a (PORTABLE) is the only side that autoconnects to b (STATIONARY). */
	*a = meshlink_open(conf_a, "a", prefix, DEV_CLASS_PORTABLE);
	*b = meshlink_open(conf_b, "b", prefix, DEV_CLASS_STATIONARY);
	assert(*a && *b);

	meshlink_enable_discovery(*a, false);
	meshlink_enable_discovery(*b, false);
}

static void close_pair(meshlink_handle_t *a, meshlink_handle_t *b, const char *prefix) {
	char conf_a[64], conf_b[64];
	snprintf(conf_a, sizeof conf_a, "%s_conf.1", prefix);
	snprintf(conf_b, sizeof conf_b, "%s_conf.2", prefix);

	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy(conf_a));
	assert(meshlink_destroy(conf_b));
}

static void test_recent_wins(void) {
	printf("\n=== T1: recent[] direct address wins over canonical relay ===\n");

	meshlink_handle_t *a, *b;
	open_pair(&a, &b, "outgoing_order_t1");

	int b_port = meshlink_get_port(b);
	assert(b_port > 0);

	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	assert(meshlink_set_canonical_address(b, meshlink_get_self(b), "127.0.0.1", relay_port_str));
	exchange_meshlink_pair(a, b);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);
	hint_address(a, node_b, "127.0.0.1", b_port);

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
	meshlink_set_node_status_cb(a, status_cb);

	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));
	meshlink_set_node_status_cb(a, NULL);

	assert(status_at_reachable.meta_connected);
	assert(status_at_reachable.meta_is_outgoing);
	assert(!status_at_reachable.meta_via_canonical);
	assert(port_of(&status_at_reachable.meta_address) == b_port);
	assert(tcp_relay_accept_count(relay) == 0);
	assert(status_at_reachable.canonical_address && strstr(status_at_reachable.canonical_address, relay_port_str));
	devtool_free_node_status(&status_at_reachable);

	printf("T1 ok: connected directly to port %d, relay untouched\n", b_port);

	close_pair(a, b, "outgoing_order_t1");
	stop_tcp_relay(relay);
}

static void test_fallback_to_canonical_and_recent_stays_direct(void) {
	printf("\n=== T2: dead recent[] address falls back to the canonical relay ===\n");

	meshlink_handle_t *a, *b;
	open_pair(&a, &b, "outgoing_order_t2");

	int b_port = meshlink_get_port(b);
	assert(b_port > 0);

	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	int closed_port = find_closed_port("127.0.0.1");
	assert(closed_port != b_port && closed_port != relay_port);

	assert(meshlink_set_canonical_address(b, meshlink_get_self(b), "127.0.0.1", relay_port_str));
	exchange_meshlink_pair(a, b);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);
	hint_address(a, node_b, "127.0.0.1", closed_port);

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
	meshlink_set_node_status_cb(a, status_cb);

	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));
	meshlink_set_node_status_cb(a, NULL);

	assert(status_at_reachable.meta_connected);
	assert(status_at_reachable.meta_is_outgoing);
	assert(status_at_reachable.meta_via_canonical);
	assert(port_of(&status_at_reachable.meta_address) == relay_port);
	assert(tcp_relay_accept_count(relay) == 1);
	devtool_free_node_status(&status_at_reachable);

	char needle[128];
	snprintf(needle, sizeof needle, "a: Trying to connect to b at 127.0.0.1 port %d (recent)", closed_port);
	assert(log_contains(needle));
	snprintf(needle, sizeof needle, "a: Trying to connect to b at 127.0.0.1 port %d (canonical)", relay_port);
	assert(log_contains(needle));

	printf("T2 ok: recent port %d refused, connected via relay port %d\n", closed_port, relay_port);

	printf("\n=== T4: the relay address never enters recent[] ===\n");

	/* Give UDP a moment to learn b's real address so recent[] is as full as it gets,
	   then check nothing in it points at the relay. */
	sleep(3);

	devtool_node_status_t st;
	devtool_get_node_status(a, node_b, &st);
	assert(st.recent_count >= 1);

	for(size_t i = 0; i < st.recent_count; i++) {
		int port = port_of(&st.recent[i]);
		printf("recent[%zu] = port %d\n", i, port);
		assert(port != relay_port);
		assert(port == b_port || port == closed_port);
	}

	printf("T4 ok: %d entries in recent[], none is the relay\n", (int)st.recent_count);
	devtool_free_node_status(&st);

	close_pair(a, b, "outgoing_order_t2");
	stop_tcp_relay(relay);
}

static void test_known_path(void) {
	printf("\n=== T3: no canonical, no recent[]: KNOWN (edge) path connects ===\n");

	assert(meshlink_destroy("outgoing_order_t3_conf.1"));
	assert(meshlink_destroy("outgoing_order_t3_conf.2"));
	assert(meshlink_destroy("outgoing_order_t3_conf.3"));

	/* a (PORTABLE) autoconnects to b (BACKBONE) first, then to c (STATIONARY).
	   c autoconnects to b only. b initiates nothing. */
	meshlink_handle_t *a = meshlink_open("outgoing_order_t3_conf.1", "a", "outgoing_order_t3", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_order_t3_conf.2", "b", "outgoing_order_t3", DEV_CLASS_BACKBONE);
	meshlink_handle_t *c = meshlink_open("outgoing_order_t3_conf.3", "c", "outgoing_order_t3", DEV_CLASS_STATIONARY);
	assert(a && b && c);

	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	meshlink_enable_discovery(c, false);

	int b_port = meshlink_get_port(b);
	int c_port = meshlink_get_port(c);
	assert(b_port > 0 && c_port > 0);

	exchange_meshlink_pair(a, b);
	exchange_meshlink_pair(a, c);
	exchange_meshlink_pair(b, c);

	/* The edge b->c carries the address b saw c connect from, plus c's port. The graph
	   seeds that address into a's recent[] for c unless it is private (RFC1918): so
	   when c reaches b over a private interface, a's only way to c is the KNOWN list
	   built from the edge. On a loopback-only host the seed lands in recent[] first
	   and the same edge address is tried as RECENT: the KNOWN source itself cannot be
	   exercised there, but which source was used, and why, is asserted either way. */
	char *local = meshlink_get_local_address_for_family(c, AF_INET);
	const char *b_ip = local && is_rfc1918(local) ? local : "127.0.0.1";
	bool edge_is_private = strcmp(b_ip, "127.0.0.1") != 0;
	printf("c connects to b at %s (%s)\n", b_ip, edge_is_private ? "private, KNOWN path provable" : "loopback, edge address is seeded as RECENT");

	meshlink_node_t *a_b = meshlink_get_node(a, "b");
	meshlink_node_t *a_c = meshlink_get_node(a, "c");
	meshlink_node_t *c_b = meshlink_get_node(c, "b");
	assert(a_b && a_c && c_b);

	forget_addresses(a, a_b);
	hint_address(a, a_b, "127.0.0.1", b_port);
	forget_addresses(a, a_c);
	forget_addresses(c, c_b);
	hint_address(c, c_b, b_ip, b_port);

	devtool_node_status_t st;
	devtool_get_node_status(a, a_c, &st);
	assert(st.recent_count == 0);
	assert(!st.canonical_address);
	devtool_free_node_status(&st);

	watched_peer = "c";
	init_sync_flag(&peer_reachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
	meshlink_set_node_status_cb(b, status_cb);

	assert(meshlink_start(b));
	assert(meshlink_start(c));
	assert(wait_sync_flag(&peer_reachable, 15));
	meshlink_set_node_status_cb(b, NULL);
	devtool_free_node_status(&status_at_reachable);

	size_t mark = log_mark();
	assert(meshlink_start(a));

	/* a must end up with its own meta connection to c, made from the edge address. */
	devtool_node_status_t a_view_c;
	memset(&a_view_c, 0, sizeof a_view_c);

	for(int i = 0; i < 30; i++) {
		devtool_get_node_status(a, a_c, &a_view_c);

		if(a_view_c.meta_connected && a_view_c.meta_is_outgoing) {
			break;
		}

		devtool_free_node_status(&a_view_c);
		sleep(1);
	}

	assert(a_view_c.meta_connected);
	assert(a_view_c.meta_is_outgoing);
	assert(!a_view_c.meta_via_canonical);
	assert(port_of(&a_view_c.meta_address) == c_port);
	devtool_free_node_status(&a_view_c);

	char known_needle[128], recent_needle[128];
	snprintf(known_needle, sizeof known_needle, "a: Trying to connect to c at %s port %d (known)", b_ip, c_port);
	snprintf(recent_needle, sizeof recent_needle, "a: Trying to connect to c at %s port %d (recent)", b_ip, c_port);

	if(edge_is_private) {
		/* Nothing was seeded, so the edge address can only have come from KNOWN. */
		assert(log_find(mark, known_needle) >= 0);
		assert(log_find(mark, recent_needle) < 0);
		printf("T3 ok: a connected to c via KNOWN edge address %s port %d\n", b_ip, c_port);
	} else {
		/* The graph seeded the edge address, so it was tried as RECENT and never
		   reached KNOWN; a's recent[] for c must indeed hold it now. */
		assert(log_find(mark, recent_needle) >= 0);
		assert(log_find(mark, known_needle) < 0);

		devtool_get_node_status(a, a_c, &st);
		bool seeded = false;

		for(size_t i = 0; i < st.recent_count; i++) {
			seeded |= addr_is(&st.recent[i], b_ip, c_port);
		}

		assert(seeded);
		devtool_free_node_status(&st);
		printf("T3 ok: a connected to c at port %d from the graph-seeded RECENT entry (KNOWN not reachable on loopback)\n", c_port);
	}

	free(local);

	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_stop(c);
	meshlink_close(a);
	meshlink_close(b);
	meshlink_close(c);
	assert(meshlink_destroy("outgoing_order_t3_conf.1"));
	assert(meshlink_destroy("outgoing_order_t3_conf.2"));
	assert(meshlink_destroy("outgoing_order_t3_conf.3"));
}

/* T5: b sits behind a relay on a second loopback address and a reaches it through that
   relay, so a's edge to b carries the relay's IP with b's port and OPTION_INDIRECT
   (canonical-migrate T15 pins the wire format). d learns b only from that edge: no
   recent[] (indirect edges are never seeded), no canonical address, so its walk ends in
   the KNOWN stage, where the relay's address is all there is. Connecting there must
   count as canonical: the address stays out of d's recent[], d's own edge to b is
   indirect, and the upgrade probe replaces the connection with a direct one as soon as
   UDP has taught d b's real address.

   Left alone a would migrate to b's direct address within a second and replace the
   indirect edge before d gets to use it. Like canonical-migrate T6, a is handed a
   black-hole address the moment b comes up: the probe started from that hint hangs for
   its 5 s timeout and then backs off, which keeps a's edge indirect long enough. */
static void test_known_indirect_counts_as_canonical(void) {
	printf("\n=== T5: KNOWN address from an indirect edge is treated as canonical ===\n");

	const char *relay_ip = "127.0.0.2";

	if(!loopback_alias_available(relay_ip)) {
		printf("T5 skipped: cannot bind %s on this host\n", relay_ip);
		return;
	}

	assert(meshlink_destroy("outgoing_order_t5_conf.1"));
	assert(meshlink_destroy("outgoing_order_t5_conf.2"));
	assert(meshlink_destroy("outgoing_order_t5_conf.3"));

	/* a and d (PORTABLE) autoconnect to everyone, b (STATIONARY) initiates nothing. */
	meshlink_handle_t *a = meshlink_open("outgoing_order_t5_conf.1", "a", "outgoing_order_t5", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("outgoing_order_t5_conf.2", "b", "outgoing_order_t5", DEV_CLASS_STATIONARY);
	meshlink_handle_t *d = meshlink_open("outgoing_order_t5_conf.3", "d", "outgoing_order_t5", DEV_CLASS_PORTABLE);
	assert(a && b && d);

	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	meshlink_enable_discovery(d, false);

	int a_port = meshlink_get_port(a);
	int b_port = meshlink_get_port(b);
	assert(a_port > 0 && b_port > 0);

	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay(relay_ip, &relay_port, "127.0.0.1", b_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);
	assert(meshlink_set_canonical_address(b, meshlink_get_self(b), relay_ip, relay_port_str));

	int hole_port = 0;
	int hole_fd = start_black_hole("127.0.0.1", &hole_port);

	exchange_meshlink_pair(a, b);
	exchange_meshlink_pair(a, d);
	exchange_meshlink_pair(b, d);

	meshlink_node_t *a_b = meshlink_get_node(a, "b");
	meshlink_node_t *d_a = meshlink_get_node(d, "a");
	meshlink_node_t *d_b = meshlink_get_node(d, "b");
	assert(a_b && d_a && d_b);

	/* a reaches b only through the relay. */
	forget_addresses(a, a_b);

	/* d knows where a is and nothing about b: no addresses, no canonical address. b stays
	   blacklisted until d has heard a's edge to it; autoconnect tries STATIONARY nodes
	   before PORTABLE ones, so d would otherwise go for b first, find no address at all
	   and put b on a long retry timer. */
	forget_addresses(d, d_a);
	hint_address(d, d_a, "127.0.0.1", a_port);
	forget_addresses(d, d_b);
	assert(meshlink_clear_canonical_address(d, d_b));
	assert(meshlink_blacklist(d, d_b));

	devtool_node_status_t st;
	devtool_get_node_status(d, d_b, &st);
	assert(st.recent_count == 0);
	assert(!st.canonical_address);
	devtool_free_node_status(&st);

	watched_peer = "b";
	hint_port_on_reachable = hole_port;
	init_sync_flag(&peer_reachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
	meshlink_set_node_status_cb(a, status_cb);

	init_sync_flag(&peer_meta_up);
	memset(&status_at_meta_up, 0, sizeof status_at_meta_up);
	devtool_set_meta_status_cb(d, meta_status_cb);

	/* d is attached to a before b comes up, so it hears a's relay edge the moment a
	   authenticates with b. */
	assert(meshlink_start(a));
	assert(meshlink_start(d));
	assert_after(meshlink_get_node_reachability(d, d_a, NULL, NULL), 15);

	size_t mark = log_mark();
	assert(meshlink_start(b));
	assert(wait_sync_flag(&peer_reachable, 30));
	meshlink_set_node_status_cb(a, NULL);
	hint_port_on_reachable = 0;

	assert(status_at_reachable.meta_connected);
	assert(status_at_reachable.meta_via_canonical);
	assert(port_of(&status_at_reachable.meta_address) == relay_port);
	devtool_free_node_status(&status_at_reachable);

	/* a's edge to b, relay address plus OPTION_INDIRECT, reaches d. Poll fast: a stays on
	   the relay for the black hole's 5 s probe timeout plus a 5 s backoff, and d must have
	   its connection to b up before that. */
	char needle[128];
	snprintf(needle, sizeof needle, " a %d . b %s %d %d . %x ", DEV_CLASS_PORTABLE, relay_ip, b_port, DEV_CLASS_STATIONARY, EDGE_OPTION_INDIRECT | EDGE_OPTION_PMTU_DISCOVERY);

	for(int i = 0; i < 100 && count_edge_pairs(d, "a", "b") != 1; i++) {
		usleep(100000);
	}

	assert(count_edge_pairs(d, "a", "b") == 1);
	assert(log_find(mark, needle) >= 0);

	/* Now let d go for b. Its only lead is the relay's address from a's edge. */
	assert(meshlink_whitelist(d, d_b));
	assert(wait_sync_flag(&peer_meta_up, 15));

	assert(status_at_meta_up.meta_connected);
	assert(status_at_meta_up.meta_is_outgoing);
	assert(status_at_meta_up.meta_via_canonical);
	assert(addr_is(&status_at_meta_up.meta_address, relay_ip, b_port));
	devtool_free_node_status(&status_at_meta_up);

	/* That was the KNOWN_INDIRECT stage, and the only address d ever dialled for b. */
	snprintf(needle, sizeof needle, "d: Trying to connect to b at %s port %d (known-indirect)", relay_ip, b_port);
	assert(log_find(mark, needle) >= 0);
	assert(log_count_from(mark, "d: Trying to connect to b at ") == 1);

	/* d broadcasts its edge to b as indirect, just like a did. */
	snprintf(needle, sizeof needle, " d %d . b %s %d %d . %x ", DEV_CLASS_PORTABLE, relay_ip, b_port, DEV_CLASS_STATIONARY, EDGE_OPTION_INDIRECT | EDGE_OPTION_PMTU_DISCOVERY);
	assert_after(log_find(mark, needle) >= 0, 5);

	/* Counting as canonical, the connection is eligible for the upgrade probe: once UDP
	   has taught d b's real address, d migrates onto it. */
	devtool_node_status_t d_view_b;
	memset(&d_view_b, 0, sizeof d_view_b);

	for(int i = 0; i < 30; i++) {
		devtool_get_node_status(d, d_b, &d_view_b);

		if(d_view_b.meta_connected && !d_view_b.meta_via_canonical) {
			break;
		}

		devtool_free_node_status(&d_view_b);
		sleep(1);
	}

	assert(d_view_b.meta_connected);
	assert(!d_view_b.meta_via_canonical);
	assert(port_of(&d_view_b.meta_address) == b_port);
	assert(!addr_is(&d_view_b.meta_address, relay_ip, b_port));
	devtool_free_node_status(&d_view_b);

	/* Whatever recent[] holds for b by now (learned over UDP, or seeded once a migrated
	   too), the relay's address is not part of it. */
	devtool_get_node_status(d, d_b, &st);
	assert(st.recent_count >= 1);

	for(size_t i = 0; i < st.recent_count; i++) {
		char ip[INET6_ADDRSTRLEN] = "?";
		const struct sockaddr_in *sin = (const struct sockaddr_in *)&st.recent[i];

		if(sin->sin_family == AF_INET) {
			inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip);
		}

		printf("d recent[%zu] for b: %s port %d\n", i, ip, port_of(&st.recent[i]));
		assert(!addr_is(&st.recent[i], relay_ip, b_port));
	}

	printf("T5 ok: d reached b at the relay address from a's indirect edge as canonical, then migrated to port %d; %zu recent[] entries, none the relay's\n", b_port, st.recent_count);
	devtool_free_node_status(&st);

	devtool_set_meta_status_cb(d, NULL);
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_stop(d);
	meshlink_close(a);
	meshlink_close(b);
	meshlink_close(d);
	assert(meshlink_destroy("outgoing_order_t5_conf.1"));
	assert(meshlink_destroy("outgoing_order_t5_conf.2"));
	assert(meshlink_destroy("outgoing_order_t5_conf.3"));
	close(hole_fd);
	stop_tcp_relay(relay);
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	test_recent_wins();
	test_fallback_to_canonical_and_recent_stays_direct();
	test_known_path();
	test_known_indirect_counts_as_canonical();

	free_captured_log();
	return 0;
}
