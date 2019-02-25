/*
    test_cases_submesh05.c -- Execution of specific meshlink black box test cases
    Copyright (C) 2018  Guus Sliepen <guus@meshlink.io>

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
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include "execute_tests.h"
#include "test_cases_submesh04.h"
#include "pthread.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../common/mesh_event_handler.h"

#define CORENODE1_ID  "0"
#define APP1NODE1_ID  "1"
#define APP1NODE2_ID  "2"

#define INIT_ST         0

static bool test_case_status = false;

static void test_case_submesh_04(void **state);
static bool test_steps_submesh_04(void);

static char event_node_name[][10] = {"CORENODE1", "APP1NODE1", "APP1NODE2"};
static const char *node_ids[] = { "corenode1", "app1node1", "app1node2" };

static meshlink_node_status_lookup_t core_node1[] = {
	{INIT_ST, NODE_STARTED},
	{NODE_STARTED, CHANNEL_OPENED},
	{CHANNEL_OPENED, CHANNEL_DATA_RECIEVED}
};

static meshlink_node_status_lookup_t app1_node1[] = {
	{INIT_ST, NODE_STARTED},
	{NODE_STARTED, NODE_JOINED},
	{NODE_JOINED, CHANNEL_OPENED},
	{CHANNEL_OPENED, CHANNEL_DATA_RECIEVED}
};

static meshlink_node_status_lookup_t app1_node2[] = {
	{INIT_ST, NODE_STARTED},
	{NODE_STARTED, NODE_JOINED},
	{NODE_JOINED, CHANNEL_OPENED},
	{CHANNEL_OPENED, CHANNEL_DATA_RECIEVED},
	{CHANNEL_DATA_RECIEVED, CHANNEL_OPENED},
	{CHANNEL_OPENED, CHANNEL_DATA_RECIEVED},
	{CHANNEL_DATA_RECIEVED, MESH_EVENT_COMPLETED}
};

/* State structure for SubMesh Test Case #4 */
static char *test_case_submesh_4_nodes[] = { "corenode1", "app1node1", "app1node2" };
static black_box_state_t test_case_submesh_4_state = {
	.test_case_name =  "test_cases_submesh04",
	.node_names =  test_case_submesh_4_nodes,
	.num_nodes =  3
};

static int black_box_group0_setup(void **state) {
	const char *nodes[] = { "corenode1", "app1node1", "app1node2" };
	int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

	PRINT_TEST_CASE_MSG("Creating Containers\n");
	destroy_containers();
	create_containers(nodes, num_nodes);

	return 0;
}

static int black_box_group0_teardown(void **state) {
	PRINT_TEST_CASE_MSG("Destroying Containers\n");
	destroy_containers();

	return 0;
}

static int black_box_all_nodes_setup(void **state) {
	const char *nodes[] = { "corenode1" };
	int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

	PRINT_TEST_CASE_MSG("Creating Containers\n");
	destroy_containers();
	create_containers(nodes, num_nodes);
	PRINT_TEST_CASE_MSG("Created Containers\n");
	return 0;
}

static bool change_state(meshlink_node_status_t *status, mesh_event_t currentEv) {
	meshlink_node_status_lookup_t *lookup = status->lookup;

	fprintf(stderr, "Got Current event as : %d\n", currentEv);

	if(true == status->status) {
		fprintf(stderr, "%s:%d Returning False\n", __func__, __LINE__);
		return false;
	}

	fprintf(stderr, "At state index %d, comaring %d with %d\n", status->current_index,
	        lookup[status->current_index].currentEv, status->currentEv);

	if(lookup[status->current_index].currentEv != status->currentEv) {
		fprintf(stderr, "%s:%d Returning False\n", __func__, __LINE__);
		return false;
	}

	fprintf(stderr, "At state index %d, comaring %d with %d\n", status->current_index,
	        currentEv, lookup[status->current_index].nextEv);

	if(currentEv == lookup[status->current_index].nextEv) {
		status->currentEv = lookup[status->current_index].nextEv;
		status->current_index = status->current_index + 1;
		fprintf(stderr, "%s:%d Updated current_index is : %d\n", __func__, __LINE__, status->current_index);

		if(status->current_index == status->max_events) {
			status->status = true;
		}

		fprintf(stderr, "%s:%d Returning True\n", __func__, __LINE__);
		return true;
	} else {
		fprintf(stderr, "%s:%d Returning False\n", __func__, __LINE__);
		return false;
	}
}

static void signal_node_start(meshlink_node_status_t *node_status, int start,
                              int end) {
	int i;
	fprintf(stderr, "\tChecking if the nodes are ready\n");

	for(i = start; i <= end; i++) {
		if(NODE_JOINED != node_status[i].currentEv) {
			fprintf(stderr, "\tReturning from Send Signal as nodes are not ready\n");
			return;
		}
	}

	fprintf(stderr, "\tSending signals to all the nodes\n");

	for(i = start; i <= end; i++) {
		fprintf(stderr, "\tSending signals to %s\n", event_node_name[i]);
		node_step_in_container(node_ids[i], "SIGIO");
	}

	fprintf(stderr, "\tReturning from Send Signal\n");
	return;
}

static bool event_cb(mesh_event_payload_t payload) {
	static meshlink_node_status_t node_status[3] = { {0, INIT_ST, core_node1, 0, 3, false},
		{1, INIT_ST, app1_node1, 0, 4, false},
		{2, INIT_ST, app1_node2, 0, 7, false}
	};

	fprintf(stderr, "%s(%lu) : ", event_node_name[payload.client_id], time(NULL));

	switch(payload.mesh_event) {
	case NODE_STARTED:
		fprintf(stderr, "Node Started\n");
		assert(change_state(&node_status[payload.client_id], payload.mesh_event));
		fprintf(stderr, "%s:%d Updated current_index is : %d\n", __func__, __LINE__, node_status[payload.client_id].current_index);
		break;

	case NODE_JOINED:
		fprintf(stderr, "Node Joined\n");
		assert(change_state(&node_status[payload.client_id], payload.mesh_event));
		fprintf(stderr, "%s:%d Updated current_index is : %d\n", __func__, __LINE__, node_status[payload.client_id].current_index);
		signal_node_start(node_status, 1, 2);
		break;

	case ERR_NETWORK:
		fprintf(stderr, "Network Error\n");
		assert(false);
		break;

	case CHANNEL_OPENED:
		fprintf(stderr, "Channel Opened\n");
		assert(change_state(&node_status[payload.client_id], payload.mesh_event));
		fprintf(stderr, "%s:%d Updated current_index is : %d\n", __func__, __LINE__, node_status[payload.client_id].current_index);
		break;

	case CHANNEL_DATA_RECIEVED:
		fprintf(stderr, "Channel Data Received\n");
		assert(change_state(&node_status[payload.client_id], payload.mesh_event));
		fprintf(stderr, "%s:%d Updated current_index is : %d\n", __func__, __LINE__, node_status[payload.client_id].current_index);
		break;

	case SIG_ABORT:
		fprintf(stderr, "SIG_ABORT Received\n");
		assert(change_state(&node_status[payload.client_id], payload.mesh_event));
		fprintf(stderr, "%s:%d Updated current_index is : %d\n", __func__, __LINE__, node_status[payload.client_id].current_index);

	case MESH_EVENT_COMPLETED:
		fprintf(stderr, "MESH_EVENT_COMPLETED Received\n");
		assert(change_state(&node_status[payload.client_id], payload.mesh_event));
		fprintf(stderr, "%s:%d Updated current_index is : %d\n", __func__, __LINE__, node_status[payload.client_id].current_index);
	}

	fprintf(stderr, "%s:%d Checking Status\n", __func__, __LINE__);

	if((node_status[0].status == true) && (node_status[1].status == true)
	                && (node_status[2].status == true)) {
		test_case_status = true;
		fprintf(stderr, "%s:%d Returning True\n", __func__, __LINE__);
		return true;
	}

	fprintf(stderr, "%s:%d Returning False\n", __func__, __LINE__);
	return false;
}

/* Execute SubMesh Test Case # 4 */
static void test_case_submesh_04(void **state) {
	execute_test(test_steps_submesh_04, state);
}

/* Test Steps for SubMesh Test Case # 4

    Test Steps:
    1. Run corenode1, app1node1, and app1node2
    2. Generate invites to app1node1, app1node2
        from corenode1 to join corenode1.
    3. After Join is successful start channels from all nodes and exchange data on channels
    4. Black list a node in the submesh and check if it is successful
    5. White list the node and it should be form all the connections again

    Expected Result:
    Channels should be formed between nodes of sub-mesh & coremesh, nodes with in sub-mesh
    and should be able to exchange data. When black listed, other node should not get any 
    from the black listed node. When white listed again it has to form the connections as 
    they were previously before black listing.
*/
static bool test_steps_submesh_04(void) {
	char *invite_app1node1, *invite_app1node2;
	bool result = false;
	int i;
	char *import;
	pthread_t thread1, thread2;

	import = mesh_event_sock_create(eth_if_name);
	invite_app1node1 = invite_in_container("corenode1", "app1node1");
	invite_app1node2 = invite_in_container("corenode1", "app1node2");

	node_sim_in_container_event("corenode1", "1", NULL, CORENODE1_ID, import);
	node_sim_in_container_event("app1node1", "1", invite_app1node1, APP1NODE1_ID, import);
	node_sim_in_container_event("app1node2", "1", invite_app1node2, APP1NODE2_ID, import);

	PRINT_TEST_CASE_MSG("Waiting for nodes to get connected with corenode1\n");

	assert(wait_for_event(event_cb, 120));
	assert(test_case_status);

	free(invite_app1node1);
	free(invite_app1node2);

	mesh_event_destroy();

	return true;
}

int test_cases_submesh04(void) {
	const struct CMUnitTest blackbox_group0_tests[] = {
		cmocka_unit_test_prestate_setup_teardown(test_case_submesh_04, setup_test, teardown_test,
		(void *)&test_case_submesh_4_state)
	};
	total_tests += sizeof(blackbox_group0_tests) / sizeof(blackbox_group0_tests[0]);

	return cmocka_run_group_tests(blackbox_group0_tests, black_box_group0_setup, black_box_group0_teardown);
}