/*
    test_cases_channel_conn.c -- Execution of specific meshlink black box test cases
    Copyright (C) 2017  Guus Sliepen <guus@meshlink.io>

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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <pthread.h>
#include <cmocka.h>
#include "execute_tests.h"
#include "test_cases_channel_conn.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../common/mesh_event_handler.h"

#define PEER  "peer"
#define RELAY "relay"
#define NUT   "nut"
#define TOTAL_NODES 100

#define NAME_SIZE 50
#define str_int_concat(var_name, str, num) assert(snprintf(var_name, sizeof(var_name), "%s_%d", str, num) >= 0)

static void test_case_01(void **state);
static bool test_steps_01(void);

static char *test_nodes_01[] = { "peer", "relay", "nut" };

static black_box_state_t test_case_01_state = {
	.test_case_name = "test_case_node_cluster_01",
	.node_names = test_nodes_01,
	.num_nodes = 2,
};

static void launch_node_in_container_event(const char *container_name, const char *node, int device_class,
                const char *invite_url, int clientId, const char *import) {
	char node_sim_command[200];

	assert(snprintf(node_sim_command, sizeof(node_sim_command),
	                "LD_LIBRARY_PATH=/home/ubuntu/test/.libs /home/ubuntu/test/node_sim_%s %s %d %d %s %s "
	                "1>&2 2>> node_sim_%s.log", container_name, node, device_class,
	                clientId, import, (invite_url) ? invite_url : "", node) >= 0);
	run_in_container(node_sim_command, container_name, true);
	PRINT_TEST_CASE_MSG("node_sim_%s(Client Id :%d) started in Container with event handling\n",
	                    node, clientId);

	return;
}

static char *invite_node_in_container(const char *container_name, const char *inviter, const char *invitee) {
	char invite_command[200];
	char *invite_url;

	assert(snprintf(invite_command, sizeof(invite_command),
	                "LD_LIBRARY_PATH=/home/ubuntu/test/.libs /home/ubuntu/test/gen_invite %s %s "
	                "2> gen_invite_%s.log", inviter, invitee, invitee) >= 0);
	assert(invite_url = run_in_container(invite_command, container_name, false));

	return invite_url;
}

static int peers_joined;
static int relay_merged;
static bool *joined;
/* Callback function for handling channel connection test cases mesh events */
static void node_conn_cb(mesh_event_payload_t payload) {
	int num = *((int *)payload.payload);
	int i, total;

	switch(payload.mesh_event) {
	case NODE_JOINED            :
		if(payload.client_id != 3000) {
			if(joined[num] == false) {
				joined[num] = true;

				for(i = 0, total = 0; i < TOTAL_NODES; i = i + 1) {
					if(joined[i]) {
						total = total + 1;
					} else {
					  // DEBUG: Print all the peer nodes which didn't join
						fprintf(stderr, "%3d ", i);
					}
				}
				peers_joined = total;
				// DEBUG: Print the peer node which joined
				fprintf(stderr, "\npeer_%d JOINED - %d\n", num, peers_joined);
			}
		} else {
			relay_merged = relay_merged + 1;
			fprintf(stderr, "Total nodes = %d, relays = %d\n", peers_joined, relay_merged);
		}

		break;

	default                     :
		PRINT_TEST_CASE_MSG("Undefined event occurred : %d\n", payload.mesh_event);
	}
}

/* Execute Test Case # 1 - */
static void test_case_01(void **state) {
	execute_test(test_steps_01, state);
	return;
}

/* Test Steps for Test Case # 1

    Test Steps:

    Expected Result:
*/
static bool test_steps_01(void) {
	char peer_name[NAME_SIZE];
	char relay_name[NAME_SIZE];
	int nodes = TOTAL_NODES, n, relay_nodes;
	char *invitations[nodes], *relay_invitaions[nodes / 50];

	/* Create a buffer which stores the meta-connection status of the peer nodes
      TODO: Replace bool array with a small array of int and perform bitwise operation
            for storing node status */
	joined = calloc(nodes, sizeof(*joined));
	assert(joined);

	char *event_handler_export = mesh_event_sock_create(eth_if_name);

	/* Generating Invitations for peer nodes and to a relay node which merges all
      the relay_n nodes at the end to make the cluster */
	for(n = 0, relay_nodes = 0; n < nodes; n += 1) {
		if((n % 50) == 0) {
			str_int_concat(relay_name, "relay", relay_nodes);
			relay_invitaions[relay_nodes] = invite_node_in_container(RELAY, relay_name, RELAY);
			relay_nodes = relay_nodes + 1;
		}

		str_int_concat(peer_name, "peer", n);

		invitations[n] = invite_node_in_container(RELAY, relay_name, peer_name);
		assert(invitations[n]);
		PRINT_TEST_CASE_MSG("node %s invited with invitation %s\n", peer_name, invitations[n]);
	}

	/* Deploying each relay_n node along with it's 50 peer nodes */
	for(n = 0, relay_nodes = 0; n < nodes; n = n + 1) {
		if((n % 50) == 0) {
			str_int_concat(relay_name, "relay", relay_nodes);
			launch_node_in_container_event(RELAY, relay_name, DEV_CLASS_BACKBONE, NULL, relay_nodes, event_handler_export);
			sleep(2);
			relay_nodes = relay_nodes + 1;
		}

		str_int_concat(peer_name, "peer", n);
		launch_node_in_container_event(PEER, peer_name, DEV_CLASS_PORTABLE, invitations[n], n, event_handler_export);
	}

	/* Wait for all peers to be joined or formed a meta-connection with it's respective relay_n
      using mesh event handling */
	while(peers_joined < nodes) {
		wait_for_event(node_conn_cb, 120);
	}

	/* Merge all the relay_n nodes with the main relay node to form the cluster of meshlink nodes */
	for(relay_nodes = 0; relay_nodes < nodes / 50; relay_nodes = relay_nodes + 1) {
		launch_node_in_container_event(RELAY, RELAY, DEV_CLASS_BACKBONE, relay_invitaions[relay_nodes], 3000, event_handler_export);
		alarm(240);

		while(relay_merged <= relay_nodes) {
			wait_for_event(node_conn_cb, 120);
		}

		alarm(0);
		node_step_in_container(RELAY, "SIGTERM");
		sleep(1);
	}

	/* Relaunch the relay node's instance without any invitation */
	launch_node_in_container_event(RELAY, RELAY, DEV_CLASS_BACKBONE, NULL, 3000, event_handler_export);

	/** Node-under-test code for 1000 nodes**/
	//invite_in_container(RELAY, NUT);


	return true;
}

static int black_box_group_setup(void **state) {
	const char *nodes[] = { "peer", "relay", "nut" };
	int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

	printf("Creating Containers\n");
	destroy_containers();
	create_containers(nodes, num_nodes);

	return 0;
}

static int black_box_group_teardown(void **state) {
	printf("Destroying Containers\n");
	destroy_containers();

	return 0;
}

int test_case_nodes_cluster(void) {
	const struct CMUnitTest blackbox_group0_tests[] = {
		cmocka_unit_test_prestate_setup_teardown(test_case_01, setup_test, teardown_test,
		(void *)&test_case_01_state),
	};
	total_tests += sizeof(blackbox_group0_tests) / sizeof(blackbox_group0_tests[0]);

	return cmocka_run_group_tests(blackbox_group0_tests, black_box_group_setup, black_box_group_teardown);
}
