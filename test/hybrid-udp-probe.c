#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* Graph-derived NLB-IP/NMN-port hybrids are never UDP candidates.
   Peer-vouched EXTERNAL on the same IP stays eligible. */

static bool choose_is(meshlink_handle_t *mesh, meshlink_node_t *node, const char *ip, int port) {
	struct sockaddr_storage addr;
	int sock = -1;

	if(!devtool_choose_udp_address_advance(mesh, node, &addr, &sock)) {
		return false;
	}

	return addr_is(&addr, ip, port);
}

static bool never_hybrid(meshlink_handle_t *mesh, meshlink_node_t *node, const char *ip, int port, int turns) {
	for(int i = 0; i < turns; i++) {
		if(choose_is(mesh, node, ip, port)) {
			return false;
		}
	}

	return true;
}

static void test_graph_hybrid_rejected(void) {
	printf("\n=== hybrid-udp-probe: graph-derived NLB-IP/NMN-port is never probed ===\n");

	assert(meshlink_destroy("hybrid_udp_conf.1"));
	assert(meshlink_destroy("hybrid_udp_conf.2"));

	meshlink_handle_t *a = meshlink_open("hybrid_udp_conf.1", "a", "hybrid-udp", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("hybrid_udp_conf.2", "b", "hybrid-udp", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	exchange_meshlink_pair(a, b);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);
	assert(meshlink_set_canonical_address(a, node_b, "198.51.100.7", "443"));

	struct sockaddr_in hybrid = ipv4("198.51.100.7", 23349);
	assert(!devtool_graph_may_seed_udp(a, node_b, (const struct sockaddr *)&hybrid));
	assert(devtool_plant_recent_address(a, node_b, (const struct sockaddr *)&hybrid));

	assert(meshlink_start(a));
	assert(never_hybrid(a, node_b, "198.51.100.7", 23349, 16));

	printf("hybrid-udp-probe T1 ok: planted UNKNOWN hybrid is never a UDP dest\n");

	meshlink_stop(a);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("hybrid_udp_conf.1"));
	assert(meshlink_destroy("hybrid_udp_conf.2"));
}

static void test_external_same_ip_allowed(void) {
	printf("\n=== hybrid-udp-probe: REQ_EXTERNAL same-IP/different-port is eligible ===\n");

	assert(meshlink_destroy("hybrid_udp_ext_conf.1"));
	assert(meshlink_destroy("hybrid_udp_ext_conf.2"));

	meshlink_handle_t *a = meshlink_open("hybrid_udp_ext_conf.1", "a", "hybrid-udp-ext", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("hybrid_udp_ext_conf.2", "b", "hybrid-udp-ext", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	exchange_meshlink_pair(a, b);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);
	assert(meshlink_set_canonical_address(a, node_b, "198.51.100.7", "443"));
	devtool_set_external_ip_address(a, node_b, "198.51.100.7 23349");

	assert(meshlink_start(a));

	bool saw = false;

	for(int i = 0; i < 16; i++) {
		if(choose_is(a, node_b, "198.51.100.7", 23349)) {
			saw = true;
			break;
		}
	}

	assert(saw);
	printf("hybrid-udp-probe T2 ok: peer-vouched same-IP/different-port is probe-eligible\n");

	meshlink_stop(a);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("hybrid_udp_ext_conf.1"));
	assert(meshlink_destroy("hybrid_udp_ext_conf.2"));
}

static void test_empty_recent_raw_edge(void) {
	printf("\n=== hybrid-udp-probe: empty recent[] plus hybrid n->address does not bypass ===\n");

	assert(meshlink_destroy("hybrid_udp_empty_conf.1"));
	assert(meshlink_destroy("hybrid_udp_empty_conf.2"));

	meshlink_handle_t *a = meshlink_open("hybrid_udp_empty_conf.1", "a", "hybrid-udp-empty", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("hybrid_udp_empty_conf.2", "b", "hybrid-udp-empty", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	exchange_meshlink_pair(a, b);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);
	assert(meshlink_set_canonical_address(a, node_b, "198.51.100.7", "443"));

	struct sockaddr_in hybrid = ipv4("198.51.100.7", 23349);
	devtool_update_node_udp(a, node_b, (const struct sockaddr *)&hybrid);

	assert(meshlink_start(a));
	assert(never_hybrid(a, node_b, "198.51.100.7", 23349, 16));

	printf("hybrid-udp-probe T3 ok: n->address hybrid does not become a UDP dest\n");

	meshlink_stop(a);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("hybrid_udp_empty_conf.1"));
	assert(meshlink_destroy("hybrid_udp_empty_conf.2"));
}

static void test_persist_hybrid_cleaned(void) {
	printf("\n=== hybrid-udp-probe: restart sanitizes a planted NLB-IP/NMN-port hybrid ===\n");

	assert(meshlink_destroy("hybrid_udp_persist_conf.1"));
	assert(meshlink_destroy("hybrid_udp_persist_conf.2"));

	meshlink_handle_t *a = meshlink_open("hybrid_udp_persist_conf.1", "a", "hybrid-udp-persist", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("hybrid_udp_persist_conf.2", "b", "hybrid-udp-persist", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	exchange_meshlink_pair(a, b);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);
	assert(meshlink_set_canonical_address(a, node_b, "18.60.131.32", "443"));

	struct sockaddr_in hybrid = ipv4("18.60.131.32", 23349);
	assert(devtool_plant_recent_address(a, node_b, (const struct sockaddr *)&hybrid));

	meshlink_close(a);
	a = meshlink_open("hybrid_udp_persist_conf.1", "a", "hybrid-udp-persist", DEV_CLASS_PORTABLE);
	assert(a);
	meshlink_enable_discovery(a, false);
	node_b = meshlink_get_node(a, "b");
	assert(node_b);

	devtool_node_status_t st;
	devtool_get_node_status(a, node_b, &st);

	for(size_t i = 0; i < st.recent_count; i++) {
		assert(!addr_is(&st.recent[i], "18.60.131.32", 23349));
	}

	devtool_free_node_status(&st);

	assert(meshlink_start(a));
	assert(never_hybrid(a, node_b, "18.60.131.32", 23349, 16));

	printf("hybrid-udp-probe T4 ok: 66107782-style hybrid stripped on reload, never probed\n");

	meshlink_stop(a);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("hybrid_udp_persist_conf.1"));
	assert(meshlink_destroy("hybrid_udp_persist_conf.2"));
}

static void test_canonical_change_resanitizes(void) {
	printf("\n=== hybrid-udp-probe: new canonical resolution drops a now-hybrid recent[] ===\n");

	assert(meshlink_destroy("hybrid_udp_resan_conf.1"));
	assert(meshlink_destroy("hybrid_udp_resan_conf.2"));

	meshlink_handle_t *a = meshlink_open("hybrid_udp_resan_conf.1", "a", "hybrid-udp-resan", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("hybrid_udp_resan_conf.2", "b", "hybrid-udp-resan", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	exchange_meshlink_pair(a, b);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);
	assert(meshlink_set_canonical_address(a, node_b, "198.51.100.1", "443"));

	struct sockaddr_in later = ipv4("203.0.113.9", 23349);
	assert(devtool_plant_recent_address(a, node_b, (const struct sockaddr *)&later));
	assert(meshlink_set_canonical_address(a, node_b, "203.0.113.9", "443"));

	devtool_node_status_t st;
	devtool_get_node_status(a, node_b, &st);

	for(size_t i = 0; i < st.recent_count; i++) {
		assert(!addr_is(&st.recent[i], "203.0.113.9", 23349));
	}

	devtool_free_node_status(&st);

	assert(meshlink_start(a));
	assert(never_hybrid(a, node_b, "203.0.113.9", 23349, 16));

	printf("hybrid-udp-probe T5 ok: canonical change re-sanitized the leftover hybrid\n");

	meshlink_stop(a);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("hybrid_udp_resan_conf.1"));
	assert(meshlink_destroy("hybrid_udp_resan_conf.2"));
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	test_graph_hybrid_rejected();
	test_external_same_ip_allowed();
	test_empty_recent_raw_edge();
	test_persist_hybrid_cleaned();
	test_canonical_change_resanitizes();

	free_captured_log();
	return 0;
}
