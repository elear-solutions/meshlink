#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"
#include <unistd.h>

// Note: We cannot directly access internal node_t->external_ip_address 
// because we can't include both meshlink.h and meshlink_internal.h.
// Instead, we'll infer the bug from:
// 1. meshlink_get_port() returning 0 (API bug)
// 2. Log messages showing "port 0" being advertised
// 3. The fact that direct connections fail due to port 0

static struct sync_flag bar_reachable;

static struct sockaddr_in ipv4(const char *ip, uint16_t port) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	assert(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
	return sa;
}

static bool dest_is(const struct sockaddr_storage *dest, const char *ip, uint16_t port) {
	if(dest->ss_family != AF_INET) {
		return false;
	}

	struct sockaddr_in want = ipv4(ip, port);
	const struct sockaddr_in *got = (const struct sockaddr_in *)dest;
	return got->sin_addr.s_addr == want.sin_addr.s_addr && got->sin_port == want.sin_port;
}

static bool dest_is6(const struct sockaddr_storage *dest, const char *ip, uint16_t port) {
	if(dest->ss_family != AF_INET6) {
		return false;
	}

	struct in6_addr want;
	assert(inet_pton(AF_INET6, ip, &want) == 1);
	const struct sockaddr_in6 *got = (const struct sockaddr_in6 *)dest;
	return !memcmp(&got->sin6_addr, &want, sizeof want) && got->sin6_port == htons(port);
}

/* Consume `count` real rotation slots; report which dests showed up. */
static void advance_dests(meshlink_handle_t *mesh, meshlink_node_t *peer, int count, const char *lan_ip, uint16_t lan_port, const char *wan_ip, uint16_t wan_port, const char *self_ip, uint16_t self_port, bool *saw_lan, bool *saw_wan) {
	*saw_lan = false;
	*saw_wan = false;

	for(int i = 0; i < count; i++) {
		struct sockaddr_storage dest;
		int sock = -1;

		if(!devtool_choose_udp_address_advance(mesh, peer, &dest, &sock)) {
			continue;
		}

		assert(sock >= 0);
		assert(!dest_is(&dest, self_ip, self_port));

		if(lan_ip && dest_is(&dest, lan_ip, lan_port)) {
			*saw_lan = true;
		}

		if(wan_ip && dest_is(&dest, wan_ip, wan_port)) {
			*saw_wan = true;
		}
	}
}

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && !strcmp(node->name, "bar")) {
		set_sync_flag(&bar_reachable, true);
	}
}

int main(void) {
	init_sync_flag(&bar_reachable);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	printf("\n=== Testing REQ_EXTERNAL with Port 0 ===\n");
	printf("Testing both BACKBONE+BACKBONE and BACKBONE+PORTABLE scenarios\n\n");

	// Clean up any previous test data
	assert(meshlink_destroy("req_external_conf.1"));
	assert(meshlink_destroy("req_external_conf.2"));

	// === SCENARIO 1: BACKBONE + BACKBONE (both send REQ_EXTERNAL) ===
	printf("=== SCENARIO 1: BACKBONE + BACKBONE ===\n");
	printf("Both nodes send REQ_EXTERNAL messages\n");

	// Open two meshlink instances (both backbone)
	meshlink_handle_t *mesh_foo = meshlink_open("req_external_conf.1", "foo", "req-external", DEV_CLASS_BACKBONE);
	assert(mesh_foo);

	meshlink_handle_t *mesh_bar = meshlink_open("req_external_conf.2", "bar", "req-external", DEV_CLASS_BACKBONE);
	assert(mesh_bar);

	// Disable local discovery
	meshlink_enable_discovery(mesh_foo, false);
	meshlink_enable_discovery(mesh_bar, false);

	// Set mesh_foo to use port 0 (dynamic assignment)
	printf("\nConfiguring mesh_foo (foo) to use port 0...\n");
	assert(meshlink_set_port(mesh_foo, 0));

	// Set up canonical addresses for both nodes
	assert(meshlink_set_canonical_address(mesh_foo, meshlink_get_self(mesh_foo), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh_bar, meshlink_get_self(mesh_bar), "localhost", NULL));

	// Import and export both side's data
	char *data = meshlink_export(mesh_foo);
	assert(data);
	assert(meshlink_import(mesh_bar, data));
	free(data);

	data = meshlink_export(mesh_bar);
	assert(data);
	assert(meshlink_import(mesh_foo, data));
	free(data);

	// Set up status callback for mesh_foo
	meshlink_set_node_status_cb(mesh_foo, status_cb);

	// Start both meshes
	printf("Starting mesh_foo (foo) with port 0...\n");
	assert(meshlink_start(mesh_foo));

	// Get the actual port assigned to mesh_foo
	int foo_port = meshlink_get_port(mesh_foo);
	printf("mesh_foo (foo) meshlink_get_port() returned: %d\n", foo_port);

	// 🔴 BUG: Currently returns 0 instead of actual port
	if(foo_port == 0) {
		printf("❌ BUG CONFIRMED: meshlink_get_port() returns 0\n");
	} else {
		printf("✅ BUG FIXED: meshlink_get_port() returns actual port %d\n", foo_port);
	}

	printf("Starting mesh_bar (bar)...\n");
	assert(meshlink_start(mesh_bar));

	// Wait for bar to become reachable
	printf("Waiting for nodes to connect...\n");
	assert(wait_sync_flag(&bar_reachable, 20));
	printf("✅ Nodes connected successfully\n");

	// Give some time for REQ_EXTERNAL to be exchanged
	sleep(3);

	printf("✅ Verifying REQ_EXTERNAL bidirectional learning...\n");
	
	// Get nodes for testing
	meshlink_node_t *node_foo = meshlink_get_node(mesh_bar, "foo");
	meshlink_node_t *node_bar = meshlink_get_node(mesh_foo, "bar");
	assert(node_foo && node_bar);
	
	// Test bidirectional learning: bar should learn foo's external info
	devtool_node_status_t bar_view_of_foo;
	devtool_get_node_status(mesh_bar, node_foo, &bar_view_of_foo);
	
	// Test bidirectional learning: foo should learn bar's external info  
	devtool_node_status_t foo_view_of_bar;
	devtool_get_node_status(mesh_foo, node_bar, &foo_view_of_bar);
	
	// Verify that REQ_EXTERNAL data was received and parsed correctly
	assert(bar_view_of_foo.external_ip_address != NULL);
	assert(foo_view_of_bar.external_ip_address != NULL);
	
	// Parse and verify the external IP addresses
	char foo_ip[64], foo_port_str[16];
	char bar_ip[64], bar_port_str[16];
	
	assert(sscanf(bar_view_of_foo.external_ip_address, "%s %s", foo_ip, foo_port_str) == 2);
	assert(sscanf(foo_view_of_bar.external_ip_address, "%s %s", bar_ip, bar_port_str) == 2);
	
	int foo_port_learned = atoi(foo_port_str);
	int bar_port_learned = atoi(bar_port_str);
	
	// Verify the learned ports match the actual assigned ports
	assert(foo_port_learned == foo_port);
	assert(bar_port_learned > 0);  // bar should have a valid port
	
	printf("✅ REQ_EXTERNAL bidirectional learning verified:\n");
	printf("   bar learned foo's external address: %s %s\n", foo_ip, foo_port_str);
	printf("   foo learned bar's external address: %s %s\n", bar_ip, bar_port_str);
	printf("   foo's learned port (%d) matches actual port (%d)\n", foo_port_learned, foo_port);
	
	// Clean up allocated strings
	devtool_free_node_status(&bar_view_of_foo);
	devtool_free_node_status(&foo_view_of_bar);

	// Clean up scenario 1
	printf("\n=== Cleaning Up Scenario 1 ===\n");
	meshlink_stop(mesh_foo);
	meshlink_stop(mesh_bar);
	meshlink_close(mesh_foo);
	meshlink_close(mesh_bar);

	assert(meshlink_destroy("req_external_conf.1"));
	assert(meshlink_destroy("req_external_conf.2"));

	// === SCENARIO 2: BACKBONE + PORTABLE (only backbone sends REQ_EXTERNAL) ===
	printf("\n=== SCENARIO 2: BACKBONE + PORTABLE ===\n");
	printf("Only backbone node sends REQ_EXTERNAL messages\n");

	// Clean up any previous test data
	assert(meshlink_destroy("req_external_conf.1"));
	assert(meshlink_destroy("req_external_conf.2"));

	// Open two meshlink instances (backbone + portable)
	mesh_foo = meshlink_open("req_external_conf.1", "foo", "req-external", DEV_CLASS_BACKBONE);
	assert(mesh_foo);

	mesh_bar = meshlink_open("req_external_conf.2", "bar", "req-external", DEV_CLASS_PORTABLE);
	assert(mesh_bar);

	// Disable local discovery
	meshlink_enable_discovery(mesh_foo, false);
	meshlink_enable_discovery(mesh_bar, false);

	// Set mesh_foo (backbone) to use port 0 (dynamic assignment)
	printf("\nConfiguring mesh_foo (backbone) to use port 0...\n");
	assert(meshlink_set_port(mesh_foo, 0));

	// Set up canonical addresses for both nodes
	assert(meshlink_set_canonical_address(mesh_foo, meshlink_get_self(mesh_foo), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh_bar, meshlink_get_self(mesh_bar), "localhost", NULL));

	// Import and export both side's data
	char *data2 = meshlink_export(mesh_foo);
	assert(data2);
	assert(meshlink_import(mesh_bar, data2));
	free(data2);

	data2 = meshlink_export(mesh_bar);
	assert(data2);
	assert(meshlink_import(mesh_foo, data2));
	free(data2);

	// Set up status callback
	meshlink_set_node_status_cb(mesh_foo, status_cb);

	// Start both meshes
	printf("Starting mesh_foo (backbone) with port 0...\n");
	assert(meshlink_start(mesh_foo));

	int foo_port2 = meshlink_get_port(mesh_foo);
	printf("mesh_foo (backbone) meshlink_get_port() returned: %d\n", foo_port2);

	if(foo_port2 == 0) {
		printf("❌ BUG STILL EXISTS: mesh_foo's port is 0\n");
		printf("   REQ_EXTERNAL will send 'IP 0' to mesh_bar\n");
		printf("   mesh_bar cannot establish direct UDP connections\n");
		printf("   Critical bug for NMN architecture with 2000 nodes using port 0\n");
		assert(false);
	} else {
		printf("✅ BUG FIXED: mesh_foo's port is %d\n", foo_port2);
		printf("   REQ_EXTERNAL will send 'IP %d' to mesh_bar\n", foo_port2);
		printf("   mesh_bar can establish direct UDP connections\n");
		printf("   P2P optimization working correctly\n");
	}

	printf("Starting mesh_bar (portable)...\n");
	assert(meshlink_start(mesh_bar));

	// Wait for connection
	printf("Waiting for nodes to connect...\n");
	assert(wait_sync_flag(&bar_reachable, 5));
	printf("✅ Nodes connected successfully\n");

	// Give more time for REQ_EXTERNAL messages to be exchanged
	printf("Waiting for REQ_EXTERNAL message exchange...\n");
	sleep(3);  // Give time for protocol messages to be sent

	printf("✅ Verifying REQ_EXTERNAL bidirectional learning...\n");
	
	// Get nodes for testing
	meshlink_node_t *node_foo2 = meshlink_get_node(mesh_bar, "foo");
	meshlink_node_t *node_bar2 = meshlink_get_node(mesh_foo, "bar");
	assert(node_foo2 && node_bar2);
	
	// Test bidirectional learning: bar should learn foo's external info
	devtool_node_status_t bar_view_of_foo2;
	devtool_get_node_status(mesh_bar, node_foo2, &bar_view_of_foo2);
	
	// Test unidirectional learning: bar (portable) should learn foo's (backbone) external info
	// In BACKBONE + PORTABLE scenario, only backbone sends REQ_EXTERNAL
	devtool_node_status_t foo_view_of_bar2;
	devtool_get_node_status(mesh_foo, node_bar2, &foo_view_of_bar2);
	
	// Verify that REQ_EXTERNAL data was received and parsed correctly
	assert(bar_view_of_foo2.external_ip_address != NULL);
	// Portable nodes don't send REQ_EXTERNAL, so foo shouldn't know bar's external address
	assert(foo_view_of_bar2.external_ip_address == NULL);
	
	// Parse and verify the external IP address that bar learned about foo
	char foo_ip2[64], foo_port_str2[16];
	assert(sscanf(bar_view_of_foo2.external_ip_address, "%s %s", foo_ip2, foo_port_str2) == 2);
	
	int foo_port_learned2 = atoi(foo_port_str2);
	
	// Verify the learned port matches the actual assigned port
	assert(foo_port_learned2 == foo_port2);
	
	printf("✅ REQ_EXTERNAL unidirectional learning verified (BACKBONE + PORTABLE):\n");
	printf("   bar (portable) learned foo's (backbone) external address: %s %s\n", foo_ip2, foo_port_str2);
	printf("   foo (backbone) does NOT know bar's (portable) external address (correct behavior)\n");
	printf("   foo's learned port (%d) matches actual port (%d)\n", foo_port_learned2, foo_port2);
	
	// Clean up allocated strings
	devtool_free_node_status(&bar_view_of_foo2);
	devtool_free_node_status(&foo_view_of_bar2);

	// Clean up scenario 2
	printf("\n=== Cleaning Up Scenario 2 ===\n");
	meshlink_stop(mesh_foo);
	meshlink_stop(mesh_bar);
	meshlink_close(mesh_foo);
	meshlink_close(mesh_bar);

	assert(meshlink_destroy("req_external_conf.1"));
	assert(meshlink_destroy("req_external_conf.2"));

	printf("\n=== REQ_EXTERNAL Port 0 Test Complete ===\n");
	printf("✅ Tested both BACKBONE+BACKBONE and BACKBONE+PORTABLE scenarios\n");
	printf("✅ Bug fix verified in both scenarios\n");

	printf("\n=== Dest pick: REQ_EXTERNAL first, RFC1918 does not win ===\n");

	assert(meshlink_destroy("req_external_conf.1"));
	assert(meshlink_destroy("req_external_conf.2"));

	mesh_foo = meshlink_open("req_external_conf.1", "foo", "req-external", DEV_CLASS_STATIONARY);
	mesh_bar = meshlink_open("req_external_conf.2", "bar", "req-external", DEV_CLASS_STATIONARY);
	assert(mesh_foo && mesh_bar);

	meshlink_enable_discovery(mesh_foo, false);
	meshlink_enable_discovery(mesh_bar, false);
	assert(meshlink_set_canonical_address(mesh_foo, meshlink_get_self(mesh_foo), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh_bar, meshlink_get_self(mesh_bar), "localhost", NULL));

	char *data3 = meshlink_export(mesh_foo);
	assert(data3);
	assert(meshlink_import(mesh_bar, data3));
	free(data3);
	data3 = meshlink_export(mesh_bar);
	assert(data3);
	assert(meshlink_import(mesh_foo, data3));
	free(data3);

	init_sync_flag(&bar_reachable);
	meshlink_set_node_status_cb(mesh_foo, status_cb);
	assert(meshlink_start(mesh_foo));
	assert(meshlink_start(mesh_bar));
	assert(wait_sync_flag(&bar_reachable, 20));

	meshlink_node_t *peer = meshlink_get_node(mesh_foo, "bar");
	meshlink_node_t *self = meshlink_get_self(mesh_foo);
	assert(peer && self);

	struct sockaddr_in rfc1918, rfc172, rfc192, public_dest, canonical_ip;
	struct sockaddr_in6 ula;
	memset(&rfc1918, 0, sizeof rfc1918);
	memset(&rfc172, 0, sizeof rfc172);
	memset(&rfc192, 0, sizeof rfc192);
	memset(&public_dest, 0, sizeof public_dest);
	memset(&canonical_ip, 0, sizeof canonical_ip);
	memset(&ula, 0, sizeof ula);
	rfc1918.sin_family = AF_INET;
	rfc1918.sin_port = htons(32072);
	rfc172.sin_family = AF_INET;
	rfc172.sin_port = htons(32072);
	rfc192.sin_family = AF_INET;
	rfc192.sin_port = htons(32072);
	public_dest.sin_family = AF_INET;
	public_dest.sin_port = htons(32073);
	canonical_ip.sin_family = AF_INET;
	canonical_ip.sin_port = htons(32074);
	ula.sin6_family = AF_INET6;
	ula.sin6_port = htons(32072);
	assert(inet_pton(AF_INET, "10.0.0.254", &rfc1918.sin_addr) == 1);
	assert(inet_pton(AF_INET, "172.16.1.1", &rfc172.sin_addr) == 1);
	assert(inet_pton(AF_INET, "192.168.1.1", &rfc192.sin_addr) == 1);
	assert(inet_pton(AF_INET, "198.51.100.20", &public_dest.sin_addr) == 1);
	assert(inet_pton(AF_INET, "198.51.100.30", &canonical_ip.sin_addr) == 1);
	assert(inet_pton(AF_INET6, "fd00::1", &ula.sin6_addr) == 1);

	devtool_set_udp_confirmed(mesh_foo, peer, false);
	devtool_update_node_udp(mesh_foo, peer, (struct sockaddr *)&rfc1918);
	devtool_set_external_ip_address(mesh_foo, peer, "203.0.113.10 30777");

	struct sockaddr_storage dest, dest2;
	int sock = -1, sock2 = -1;
	struct in_addr expect_ext, expect_rfc, got;

	assert(inet_pton(AF_INET, "203.0.113.10", &expect_ext) == 1);
	assert(inet_pton(AF_INET, "10.0.0.254", &expect_rfc) == 1);

	assert(devtool_choose_udp_address(mesh_foo, peer, &dest, &sock));
	assert(dest.ss_family == AF_INET);
	got = ((struct sockaddr_in *)&dest)->sin_addr;
	assert(got.s_addr == expect_ext.s_addr);
	assert(ntohs(((struct sockaddr_in *)&dest)->sin_port) == 30777);
	assert(sock >= 0);

	/* Peek must not advance per-node rotation / PRNG. */
	assert(devtool_choose_udp_address(mesh_foo, peer, &dest2, &sock2));
	assert(dest2.ss_family == dest.ss_family);
	assert(((struct sockaddr_in *)&dest2)->sin_addr.s_addr == got.s_addr);
	assert(sock2 == sock);

	devtool_node_status_t st;
	devtool_get_node_status(mesh_foo, peer, &st);
	assert(st.address.ss_family == AF_INET);
	assert(((struct sockaddr_in *)&st.address)->sin_addr.s_addr == expect_rfc.s_addr);
	devtool_free_node_status(&st);

	/* Confirmed path uses n->address even when it is RFC1918. */
	devtool_set_udp_confirmed(mesh_foo, peer, true);
	assert(devtool_choose_udp_address(mesh_foo, peer, &dest, &sock));
	assert(((struct sockaddr_in *)&dest)->sin_addr.s_addr == expect_rfc.s_addr);
	devtool_set_udp_confirmed(mesh_foo, peer, false);

	/* RFC1918 / ULA REQ_EXTERNAL is never used as the WAN dest. */
	devtool_set_external_ip_address(mesh_foo, peer, "10.1.2.3 9");
	assert(devtool_choose_udp_address(mesh_foo, peer, &dest, &sock));
	assert(!dest_is(&dest, "10.1.2.3", 9));

	devtool_set_external_ip_address(mesh_foo, peer, "fd00::1 9");
	assert(devtool_choose_udp_address(mesh_foo, peer, &dest, &sock));
	assert(!dest_is6(&dest, "fd00::1", 9));

	devtool_set_external_ip_address(mesh_foo, peer, NULL);

	/* graph_may_seed_udp: reachable + set dest never clobbers; RFC1918/ULA never seed. */
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&rfc1918));
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&rfc172));
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&rfc192));
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&ula));

	devtool_update_node_udp(mesh_foo, peer, (struct sockaddr *)&public_dest);
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&rfc1918));
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&public_dest));

	struct sockaddr_in unset;
	memset(&unset, 0, sizeof unset);
	unset.sin_family = AF_UNSPEC;
	devtool_update_node_udp(mesh_foo, peer, (struct sockaddr *)&unset);
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&rfc1918));
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&rfc172));
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&rfc192));
	assert(!devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&ula));
	assert(devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&public_dest));
	assert(devtool_graph_may_seed_udp(mesh_foo, peer, (struct sockaddr *)&canonical_ip));

	printf("\n=== Dest pick: same public IP rotates LAN and WAN hairpin ===\n");

	/* Rotation is per real send. Stop both meshes so no probe thread advances
	   udp_choice underneath us; listen sockets stay open until meshlink_close(). */
	int self_port = meshlink_get_port(mesh_foo);
	assert(self_port > 0);
	meshlink_stop(mesh_foo);
	meshlink_stop(mesh_bar);

	bool saw_lan, saw_wan;

	/* Case 4: same house, different AP. No LAN address known at all: the WAN
	   hairpin (same IP, peer's port) is the only dest and must actually be tried. */
	devtool_set_udp_confirmed(mesh_foo, peer, false);
	devtool_set_external_ip_address(mesh_foo, self, "203.0.113.10 1");
	devtool_set_external_ip_address(mesh_foo, peer, "203.0.113.10 30777");
	advance_dests(mesh_foo, peer, 2, NULL, 0, "203.0.113.10", 30777, "203.0.113.10", 1, &saw_lan, &saw_wan);
	assert(saw_wan);

	/* Case 1: same LAN. A hinted LAN address is tried, and the WAN hairpin still
	   gets its turn. Peek must equal the next real pick. */
	struct sockaddr_in lan_hint = ipv4("192.0.2.10", 9000);
	meshlink_hint_address(mesh_foo, peer, (struct sockaddr *)&lan_hint);

	struct sockaddr_storage peeked, picked;
	int peek_sock = -1, pick_sock = -1;
	assert(devtool_choose_udp_address(mesh_foo, peer, &peeked, &peek_sock));
	assert(devtool_choose_udp_address_advance(mesh_foo, peer, &picked, &pick_sock));
	assert(peeked.ss_family == picked.ss_family);
	assert(!memcmp(&peeked, &picked, sizeof(struct sockaddr_in)));
	assert(peek_sock == pick_sock);

	advance_dests(mesh_foo, peer, 2, "192.0.2.10", 9000, "203.0.113.10", 30777, "203.0.113.10", 1, &saw_lan, &saw_wan);
	assert(saw_lan);
	assert(saw_wan);

	/* Self dest: peer REQ_EXTERNAL equal to our own IP:port is never a dest,
	   whether self is pinned as "IP PORT" or learned as "IP" (port = myport).
	   A recent[] entry equal to self is skipped too. */
	devtool_set_external_ip_address(mesh_foo, self, "203.0.113.10 30777");
	struct sockaddr_in self_hint = ipv4("203.0.113.10", 30777);
	meshlink_hint_address(mesh_foo, peer, (struct sockaddr *)&self_hint);
	advance_dests(mesh_foo, peer, 4, "192.0.2.10", 9000, NULL, 0, "203.0.113.10", 30777, &saw_lan, &saw_wan);
	assert(saw_lan);

	char peer_ext[64];
	snprintf(peer_ext, sizeof peer_ext, "203.0.113.10 %d", self_port);
	devtool_set_external_ip_address(mesh_foo, self, "203.0.113.10");
	devtool_set_external_ip_address(mesh_foo, peer, peer_ext);

	for(int i = 0; i < 4; i++) {
		assert(devtool_choose_udp_address_advance(mesh_foo, peer, &dest, &sock));
		assert(!dest_is(&dest, "203.0.113.10", (uint16_t)self_port));
	}

	/* Case 5: phone on 4G, camera at home. Different public IPs: REQ_EXTERNAL
	   always wins; a stale LAN hint must not steal the slot. */
	struct sockaddr_in stale_lan = ipv4("192.168.1.50", 9000);
	meshlink_hint_address(mesh_foo, peer, (struct sockaddr *)&stale_lan);
	devtool_set_external_ip_address(mesh_foo, self, "203.0.113.1 1");
	devtool_set_external_ip_address(mesh_foo, peer, "203.0.113.10 30777");

	for(int i = 0; i < 4; i++) {
		assert(devtool_choose_udp_address_advance(mesh_foo, peer, &dest, &sock));
		assert(dest_is(&dest, "203.0.113.10", 30777));
	}

	devtool_set_external_ip_address(mesh_foo, self, NULL);
	devtool_set_external_ip_address(mesh_foo, peer, NULL);

	meshlink_close(mesh_foo);
	meshlink_close(mesh_bar);
	assert(meshlink_destroy("req_external_conf.1"));
	assert(meshlink_destroy("req_external_conf.2"));

	return 0;
}

