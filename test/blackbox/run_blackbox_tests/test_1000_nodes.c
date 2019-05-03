/*
    test_1000_nodes.c -- Execution of specific meshlink black box test cases
    Copyright (C) 2019  Guus Sliepen <guus@meshlink.io>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "execute_tests.h"
#include "test_cases.h"
#include "test_1000_nodes.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../common/network_namespace_framework.h"
#include "../../utils.h"

#define str_int_concat(var_name, str, num) assert(snprintf(var_name, sizeof(var_name), "%s_%d", str, num) >= 0)
#define run_node_in_netns(state, netns, node, dev_class, url) node_sim_in_netns(state, netns, netns, node, node, node, dev_class, url)
#define TOTAL_NODES 90
#define DEBUG_NODES 1
#define RELAY_NAME "relay"
#define NUT_NAME "nut"

static bool test_steps_01(void);
static void test_case_01(void **state);
static netns_state_t *test_state;

struct sync_flag launch_nut_node = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
struct sync_flag test_success = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static int setup_topology(void **state) {
	netns_create_topology(test_state);
	fprintf(stderr, "\nCreated topology\n");
	return EXIT_SUCCESS;
}

static int teardown_topology(void **state) {
	netns_destroy_topology(test_state);

	char peer_name[250];
    for(int peer_no = 0; peer_no < TOTAL_NODES; peer_no = peer_no + 1) {
		str_int_concat(peer_name, "peer", peer_no);
		meshlink_destroy(peer_name);
    }
    meshlink_destroy("relay");
	return EXIT_SUCCESS;
}

static void poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)len;
	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	assert(meshlink_channel_send(mesh, channel, "request", 7) > 0);
}

static void channel_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *dat, size_t len) {
	(void)mesh;

	static int count;

	if(len && !channel->node->priv) {
        channel->node->priv = (void *)true;
        count++;
        printf("[%d]Got reply from: %s\n", count, channel->node->name);
	}

	if(count == TOTAL_NODES) {
        set_sync_flag(&test_success, true);
	}
}

static void node_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node,
                           bool reachable) {

    static int count;

    if(reachable) {
        if(!strcmp(mesh->name, RELAY_NAME) && !node->priv) {
            node->priv = (void *)1;
            count++;

#ifdef DEBUG_NODES
                printf("count = %d\n", count);
#endif // DEBUG_NODES_JOINED
        } else if(!strcmp(mesh->name, NUT_NAME) && strcmp(node->name, RELAY_NAME)) {
            meshlink_channel_t *channel = meshlink_channel_open(mesh, node, 8000, channel_receive_cb, NULL, 0);
            assert(channel);
            meshlink_set_channel_poll_cb(mesh, channel, poll_cb);
            return;
        }
    }
    fprintf(stderr, "Node %s is now %s\n", node->name, reachable ? "reachable" : "unreachable");

    if(count == TOTAL_NODES) {
        set_sync_flag(&launch_nut_node, true);
    }
	return;
}

static void log_message(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	const char *levelstr[] = {
		[MESHLINK_DEBUG] = "\x1b[34mDEBUG",
		[MESHLINK_INFO] = "\x1b[32mINFO",
		[MESHLINK_WARNING] = "\x1b[33mWARNING",
		[MESHLINK_ERROR] = "\x1b[31mERROR",
		[MESHLINK_CRITICAL] = "\x1b[31mCRITICAL",
	};
	fprintf(stderr, "(%s)%s:\x1b[0m %s\n", mesh->name, levelstr[level], text);
}

void *nut_thread(void *arg) {
	meshlink_destroy(NUT_NAME);
	char *invitation = (char *)arg;

	meshlink_handle_t *mesh = meshlink_open(NUT_NAME, NUT_NAME, NUT_NAME, DEV_CLASS_STATIONARY);
	assert(mesh);

	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, log_message);
	meshlink_set_node_status_cb(mesh, node_status_cb);
	//meshlink_set_receive_cb(mesh, receive_cb);
	meshlink_enable_discovery(mesh, false);

	assert(meshlink_join(mesh, invitation));
    free(invitation);

	meshlink_start(mesh);
    assert(wait_sync_flag(&test_success, 300));

	meshlink_close(mesh);
	meshlink_destroy(NUT_NAME);
	return 0;
}

void *relay_thread(void *arg) {
    int peer_no;
    char peer_name[100];
	meshlink_handle_t *mesh;

	// Run relay node instance

	meshlink_destroy(RELAY_NAME);
	mesh = meshlink_open(RELAY_NAME, RELAY_NAME, RELAY_NAME, DEV_CLASS_BACKBONE);
	assert(mesh);

	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, log_message);
	meshlink_set_node_status_cb(mesh, node_status_cb);
	meshlink_enable_discovery(mesh, false);

	meshlink_start(mesh);
    for(peer_no = 0; peer_no < TOTAL_NODES; peer_no = peer_no + 1) {
		str_int_concat(peer_name, "peer", peer_no);
		char *invitation = meshlink_invite(mesh, NULL, peer_name);
		fprintf(stdout, "node %s invited with invitation %s\n", peer_name, invitation);

        if(run_node_in_netns(test_state, "peer", peer_name, "1", invitation) < 0) {
            fail();
        }
        if((peer_no % 50) == 0) {
            sleep(1);
        }
    }

    assert(wait_sync_flag(&launch_nut_node, 300));
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, NULL);
	char *invitation = meshlink_invite(mesh, NULL, NUT_NAME);
	netns_thread_t netns_run_nut = {.namespace_name = "nut", .netns_thread = nut_thread, .arg = invitation};
	run_node_in_namespace_thread(&netns_run_nut);
    assert(wait_sync_flag(&test_success, 300));

	meshlink_close(mesh);
	return 0;
}


/* Execute Test Case # 1 - */
static void test_case_01(void **state) {
	netns_thread_t netns_run_relay = {.namespace_name = "relay", .netns_thread = relay_thread, .arg = NULL};
	run_node_in_namespace_thread(&netns_run_relay);

    if(!wait_sync_flag(&test_success, 600)) {
        fail();
    }
	return;
}

int test_1000_nodes(void) {
	interface_t relay_ifs[] = { { .if_peer = "wan_bridge" } };

	interface_t nut_ifs[] = { { .if_peer = "nut_nat", .fetch_ip_netns_name = "nut_nat" } };

	interface_t peer_ifs[] = { { .if_peer = "peer_nat", .fetch_ip_netns_name = "peer_nat" } };

	interface_t wan_ifs[] = { { .if_peer = "peer_nat" }, { .if_peer = "nut_nat" }, { .if_peer = "relay" } };

	//

	netns_fullcone_handle_t nut_nat_fullcone = { .snat_to_source = "wan_bridge", .dnat_to_destination = "nut" };
	netns_fullcone_handle_t *nut_nat_args[] = { &nut_nat_fullcone, NULL };
	interface_t nut_nat_ifs[] = { { .if_peer = "nut", .fetch_ip_netns_name = "nut_nat" }, { .if_peer = "wan_bridge" } };

	netns_fullcone_handle_t peer_nat_fullcone = { .snat_to_source = "wan_bridge", .dnat_to_destination = "peer" };
	netns_fullcone_handle_t *peer_nat_args[] = { &peer_nat_fullcone, NULL };
	interface_t peer_nat_ifs[] = { { .if_peer = "peer", .fetch_ip_netns_name = "peer_nat" }, { .if_peer = "wan_bridge" } };


	namespace_t test_optimal_pmtu_1_nodes[] = {
	    {.name = "nut_nat", .type = FULL_CONE, .nat_arg = nut_nat_args, .interfaces_no = 2,
            .static_config_net_addr = "192.168.1.0/24", .interfaces = nut_nat_ifs},
        {.name = "peer_nat", .type = FULL_CONE, .nat_arg = peer_nat_args, .interfaces_no = 2,
            .static_config_net_addr = "192.168.1.0/24", .interfaces = peer_nat_ifs},
	    {.name = "nut", .type = HOST, .interfaces = nut_ifs, .interfaces_no = 1},
	    {.name = "peer", .type = HOST, .interfaces = peer_ifs, .interfaces_no = 1},
	    {.name = "relay", .type = HOST, .interfaces = relay_ifs, .interfaces_no = 1},
        {.name = "wan_bridge", .type = BRIDGE, .interfaces = wan_ifs, .interfaces_no = 3},
	};

	netns_state_t test_case_1000_nodes_01_state = {
		.test_case_name =  "test_case_1000_nodes_01",
		.namespaces =  test_optimal_pmtu_1_nodes,
		.num_namespaces = 6,
	};

	test_state = &test_case_1000_nodes_01_state;

	const struct CMUnitTest blackbox_1000_nodes_test[] = {
		cmocka_unit_test_prestate_setup_teardown(test_case_01, setup_topology, teardown_topology,
		                (void *)&test_case_1000_nodes_01_state),
	};
	total_tests += sizeof(blackbox_1000_nodes_test) / sizeof(blackbox_1000_nodes_test[0]);

	int failed = cmocka_run_group_tests(blackbox_1000_nodes_test, NULL, NULL);

	return failed;
}
