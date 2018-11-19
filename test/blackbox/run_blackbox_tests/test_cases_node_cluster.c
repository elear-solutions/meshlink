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
#define TOTAL_NODES 1000

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

static char *append_invitation(char *inv_buff, char *inv) {
	inv_buff = realloc(inv_buff, (inv_buff ? strlen(inv_buff) : 0) + strlen(inv) + 2);
	assert(inv_buff);
	strcat(inv_buff, " ");
	strcat(inv_buff, inv);
	return inv_buff;
}

static void launch_node_in_container_event(const char *container_name, const char *node, int device_class,
                const char *invite_url, int clientId, const char *import) {
	char node_sim_command[1000];

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
	char invite_command[DAEMON_ARGV_LEN];
	char *invite_url;

	assert(snprintf(invite_command, sizeof(invite_command),
	                "LD_LIBRARY_PATH=/home/ubuntu/test/.libs /home/ubuntu/test/gen_invite %s %s "
	                "2> gen_invite_%s.log", inviter, invitee, invitee) >= 0);
	assert(invite_url = run_in_container(invite_command, container_name, false));

	return invite_url;
}

static bool *peers_joined;
static char *relay_invitaions;
static char *event_handler_export;
static bool test_case_1_result;
static int total_relays = 0;
/* Callback function for handling channel connection test cases mesh events */
static bool node_conn_cb(mesh_event_payload_t payload) {
	int num;
	int i, total;
	static int total_peers;
	static int relay_peers;

	switch(payload.mesh_event) {
	case NODE_JOINED1            :

		// Peer nodes that had made meta-connection with it's invited relay_n node

		if(peers_joined[payload.client_id] == false) {
			peers_joined[payload.client_id] = true;

			for(i = 0, total = 0; i < TOTAL_NODES; i = i + 1) {
				if(peers_joined[i]) {
					total = total + 1;
				} else {
					// DEBUG: Print all the peer nodes which didn't join
					fprintf(stderr, "%3d ", i);
				}
			}

			total_peers = total;
			// DEBUG: Print the peer node which joined
			fprintf(stderr, "\npeer_%d JOINED - %d\n", payload.client_id, total_peers);

			/* main relay node which merges discrete relay_n nodes is deployed
			once peer nodes joined with it's relay_n node equals ROTAL_NODES */
			if(total_peers == TOTAL_NODES) {
				launch_node_in_container_event(RELAY, RELAY, DEV_CLASS_BACKBONE, relay_invitaions, 3000, event_handler_export);
				return true;
			}
		}

		break;

	case NODE_JOINED2           :

		// Peer nodes that are reachable from main relay node for at least once.

		relay_peers = relay_peers + 1;

		if(relay_peers == TOTAL_NODES) {
			test_case_1_result = true;
			return true;
		}

		break;

	default                     :
		PRINT_TEST_CASE_MSG("Undefined event occurred : %d\n", payload.mesh_event);
	}

	return false;
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
	int  peer_no, relay_no;
	char *invitations[TOTAL_NODES];
	char *invitation_ptr;

	/* Create a buffer which stores the meta-connection status of the peer nodes
	TODO: Replace bool array with a small array of int and perform bitwise operation
	    for storing node status */
	peers_joined = calloc(TOTAL_NODES, sizeof(*peers_joined));
	assert(peers_joined);

	event_handler_export = mesh_event_sock_create(eth_if_name);

	/* Generating Invitations for peer nodes and to a relay node which merges all
	the relay_n nodes at the end to make the cluster */
	for(peer_no = 0; peer_no < TOTAL_NODES; peer_no = peer_no + 1) {
		if((peer_no % 50) == 0) {
			relay_no = peer_no / 50;
			str_int_concat(relay_name, "relay", relay_no);
			invitation_ptr = invite_node_in_container(RELAY, relay_name, RELAY);
			relay_invitaions = append_invitation(relay_invitaions, invitation_ptr);
			free(invitation_ptr);
		}

		str_int_concat(peer_name, "peer", peer_no);
		invitations[peer_no] = invite_node_in_container(RELAY, relay_name, peer_name);

		PRINT_TEST_CASE_MSG("node %s invited with invitation %s\n", peer_name, invitations[peer_no]);
	}

	/*for(relay_no = 0; relay_no < TOTAL_NODES / 50; relay_no = relay_no + 1) {
	str_int_concat(relay_name, "relay", relay_no);
	        launch_node_in_container_event(RELAY, relay_name, DEV_CLASS_BACKBONE, NULL, relay_no + TOTAL_NODES, event_handler_export);
	}
	launch_node_in_container_event(RELAY, RELAY, DEV_CLASS_BACKBONE, relay_invitaions, 3000, event_handler_export);*/

	/* Deploying each relay_n node along with it's 50 peer nodes */
	for(peer_no = 0; peer_no < TOTAL_NODES; peer_no = peer_no + 1) {
		if((peer_no % 50) == 0) {
			relay_no = peer_no / 50;
			str_int_concat(relay_name, "relay", relay_no);
			launch_node_in_container_event(RELAY, relay_name, DEV_CLASS_BACKBONE, NULL, relay_no + TOTAL_NODES, event_handler_export);
			sleep(1);
		}

		str_int_concat(peer_name, "peer", peer_no);
		launch_node_in_container_event(PEER, peer_name, DEV_CLASS_PORTABLE, invitations[peer_no], peer_no, event_handler_export);
	}

	wait_for_event(node_conn_cb, 600);
	assert_int_equal(test_case_1_result, true);

	free(relay_invitaions);
	free(peers_joined);
	return true;
}

static int black_box_group_setup(void **state) {
	const char *nodes[] = { "peer", "relay" };
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
