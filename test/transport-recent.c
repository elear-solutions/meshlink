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

/* Transport-scoped recent[]: UDP-only planted ports are never TCP-dialled,
   capabilities survive close/reopen and export/import. */

static struct sync_flag peer_reachable;

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && !strcmp(node->name, "b")) {
		set_sync_flag(&peer_reachable, true);
	}
}

static void test_udp_only_not_tcp_dialled(void) {
	printf("\n=== transport-recent: UDP-only ports are not TCP-dialled ===\n");

	assert(meshlink_destroy("transport_recent_conf.1"));
	assert(meshlink_destroy("transport_recent_conf.2"));

	meshlink_handle_t *a = meshlink_open("transport_recent_conf.1", "a", "transport-recent", DEV_CLASS_PORTABLE);
	meshlink_handle_t *b = meshlink_open("transport_recent_conf.2", "b", "transport-recent", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int b_port = meshlink_get_port(b);
	assert(b_port > 0);
	join_meshlink_peer(b, a);

	meshlink_node_t *node_b = meshlink_get_node(a, "b");
	assert(node_b);
	forget_addresses(a, node_b);

	int udp_ports[] = {60300, 51803, 31182};

	for(int i = 0; i < 3; i++) {
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_port = htons((uint16_t)udp_ports[i]),
		};
		assert(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) == 1);
		assert(devtool_plant_recent_address(a, node_b, (struct sockaddr *)&sa));
	}

	hint_address(a, node_b, "127.0.0.1", b_port);

	devtool_node_status_t st;
	devtool_get_node_status(a, node_b, &st);
	assert(st.recent_count >= 4);

	for(size_t i = 0; i < st.recent_count; i++) {
		int port = port_of(&st.recent[i]);

		if(port == 60300 || port == 51803 || port == 31182) {
			assert(!(st.recent_cap[i] & 0x01));
		}

		if(port == b_port) {
			assert(st.recent_cap[i] & 0x01);
		}
	}

	devtool_free_node_status(&st);

	init_sync_flag(&peer_reachable);
	meshlink_set_node_status_cb(a, status_cb);
	size_t mark = log_mark();
	assert(meshlink_start(b));
	assert(meshlink_start(a));
	assert(wait_sync_flag(&peer_reachable, 15));
	meshlink_set_node_status_cb(a, NULL);

	for(int i = 0; i < 3; i++) {
		char needle[128];
		snprintf(needle, sizeof needle, "a: Trying to connect to b at 127.0.0.1 port %d (recent)", udp_ports[i]);
		assert(log_find(mark, needle) < 0);
	}

	printf("transport-recent T1 ok: no TCP dials to 60300/51803/31182\n");

	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("transport_recent_conf.1"));
	assert(meshlink_destroy("transport_recent_conf.2"));
}

static void test_caps_survive_export_import(void) {
	printf("\n=== transport-recent: capabilities survive export/import and reopen ===\n");

	assert(meshlink_destroy("transport_recent_exp_conf.1"));
	assert(meshlink_destroy("transport_recent_exp_conf.2"));

	meshlink_handle_t *a = meshlink_open("transport_recent_exp_conf.1", "a", "transport-recent-exp", DEV_CLASS_BACKBONE);
	assert(a);

	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(23349),
	};
	assert(inet_pton(AF_INET, "203.0.113.10", &sa.sin_addr) == 1);
	meshlink_hint_address(a, meshlink_get_self(a), (struct sockaddr *)&sa);

	char *exported = meshlink_export(a);
	assert(exported);

	meshlink_handle_t *b = meshlink_open("transport_recent_exp_conf.2", "b", "transport-recent-exp", DEV_CLASS_BACKBONE);
	assert(b);
	assert(meshlink_import(b, exported));
	free(exported);

	meshlink_node_t *node_a = meshlink_get_node(b, "a");
	assert(node_a);
	devtool_node_status_t st;
	devtool_get_node_status(b, node_a, &st);
	bool found = false;

	for(size_t i = 0; i < st.recent_count; i++) {
		if(addr_is(&st.recent[i], "203.0.113.10", 23349)) {
			found = true;
			assert(st.recent_cap[i] & 0x01);
			assert(st.recent_cap[i] & 0x02);
		}
	}

	assert(found);
	devtool_free_node_status(&st);

	meshlink_close(a);
	a = meshlink_open("transport_recent_exp_conf.1", "a", "transport-recent-exp", DEV_CLASS_BACKBONE);
	assert(a);
	devtool_get_node_status(a, meshlink_get_self(a), &st);
	found = false;

	for(size_t i = 0; i < st.recent_count; i++) {
		if(addr_is(&st.recent[i], "203.0.113.10", 23349)) {
			found = true;
			assert(st.recent_cap[i] != 0);
		}
	}

	assert(found);
	devtool_free_node_status(&st);

	printf("transport-recent T2 ok: caps survived export/import and reopen\n");

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("transport_recent_exp_conf.1"));
	assert(meshlink_destroy("transport_recent_exp_conf.2"));
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);
	test_udp_only_not_tcp_dialled();
	test_caps_survive_export_import();
	free_captured_log();
	return 0;
}
