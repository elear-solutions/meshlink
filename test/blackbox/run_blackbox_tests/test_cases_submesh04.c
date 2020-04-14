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

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <linux/limits.h>
#include "execute_tests.h"
#include "test_cases_submesh04.h"
#include "pthread.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../common/mesh_event_handler.h"
#include "../../utils.h"

#define CORENODE1_ID  "0"
#define APP1NODE1_ID  "1"
#define APP1NODE2_ID  "2"

#define INIT_ST         0

#define NUT                         "nut"
#define PEER                        "peer"
#define RELAY                       "relay"
#define SUBMESH_NAME                "submesh"
#define TEST_SUBMESH                "test_submesh"
#define create_path(confbase, node_name, test_case_no)   assert(snprintf(confbase, sizeof(confbase), TEST_SUBMESH "_%ld_%s_%02d", (long) getpid(), node_name, test_case_no) > 0)

static bool test_case_status = false;

static void test_case_submesh_04(void **state);
static bool test_steps_submesh_04(void);
static void test_case_submesh_05(void **state);
static bool test_steps_submesh_05(void);

static char event_node_name[][10] = {"CORENODE1", "APP1NODE1", "APP1NODE2"};
static const char *node_ids[] = { "corenode1", "app1node1", "app1node2" };

static mesh_event_t core_node1[] = { NODE_STARTED, CHANNEL_OPENED, CHANNEL_DATA_RECIEVED };

static mesh_event_t app1_node1[] = { NODE_STARTED, NODE_JOINED, CHANNEL_OPENED, CHANNEL_DATA_RECIEVED };

static mesh_event_t app1_node2[] = { NODE_STARTED, NODE_JOINED, CHANNEL_OPENED, CHANNEL_DATA_RECIEVED, CHANNEL_OPENED, CHANNEL_DATA_RECIEVED, MESH_EVENT_COMPLETED};

/* State structure for SubMesh Test Case #4 */
static char *test_case_submesh_4_nodes[] = { "corenode1", "app1node1", "app1node2" };
static black_box_state_t test_case_submesh_4_state = {
	.test_case_name =  "test_cases_submesh04",
	.node_names =  test_case_submesh_4_nodes,
	.num_nodes =  3
};
static black_box_state_t test_case_submesh_5_state = {
	.test_case_name = "test_cases_submesh05",
};

static int black_box_group0_setup(void **state) {
	(void)state;

	const char *nodes[] = { "corenode1", "app1node1", "app1node2" };
	int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

	PRINT_TEST_CASE_MSG("Creating Containers\n");
	destroy_containers();
	create_containers(nodes, num_nodes);

	return 0;
}

static int black_box_group0_teardown(void **state) {
	(void)state;

	PRINT_TEST_CASE_MSG("Destroying Containers\n");
	destroy_containers();

	return 0;
}

static bool event_cb(mesh_event_payload_t payload) {
	static node_status_t node_status[3] = {
		{core_node1, 0, 3},
		{app1_node1, 0, 4},
		{app1_node2, 0, 7},
	};

	fprintf(stderr, "%s(%lu) : %s\n", event_node_name[payload.client_id], time(NULL), event_status[payload.mesh_event]);
	assert(change_state(&node_status[payload.client_id], payload.mesh_event));

	if(payload.mesh_event == NODE_JOINED) {
		signal_node_start(node_status, 1, 2, (char **)node_ids);
	}

	if(check_nodes_finished(node_status, 3)) {
		test_case_status = true;
		return true;
	}

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
	char *import;

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

static struct sync_flag all_nodes_reachable_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static void meshlink_node_reachable_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable_status) {
	if(meshlink_get_self(mesh) == node) {
		return;
	}

	assert_true(reachable_status);
	static bool nut_status[2] = { 0 };
	static bool peer_status[2] = { 0 };
	static bool relay_status[2] = { 0 };

	if(!strcasecmp(mesh->name, NUT)) {
		if(!strcasecmp(node->name, PEER)) {
			nut_status[0] = true;
		} else if(!strcasecmp(node->name, RELAY)) {
			nut_status[1] = true;
		} else {
			fail();
		}
	} else if(!strcasecmp(mesh->name, PEER)) {
		if(!strcasecmp(node->name, NUT)) {
			peer_status[0] = true;
		} else if(!strcasecmp(node->name, RELAY)) {
			peer_status[1] = true;
		} else {
			fail();
		}
	} else if(!strcasecmp(mesh->name, RELAY)) {
		if(!strcasecmp(node->name, NUT)) {
			relay_status[0] = true;
		} else if(!strcasecmp(node->name, PEER)) {
			relay_status[1] = true;
		} else {
			fail();
		}
	} else {
		fail();
	}

	if(nut_status[0] && nut_status[1] && peer_status[0] && peer_status[1] && relay_status[0] && relay_status[1]) {
		set_sync_flag(&all_nodes_reachable_cond, true);
	}

	return;
}

/* Execute SubMesh Test Case # 5 - Test whether a node can get it's self submesh handle */
static void test_case_submesh_05(void **state) {
	execute_test(test_steps_submesh_05, state);
}

static bool test_steps_submesh_05(void) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	char relay_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 5);
	create_path(peer_confbase, PEER, 5);
	create_path(relay_confbase, RELAY, 5);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_SUBMESH, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_SUBMESH, DEV_CLASS_STATIONARY);
	assert_non_null(mesh_peer);
	meshlink_handle_t *mesh_relay = meshlink_open(relay_confbase, RELAY, TEST_SUBMESH, DEV_CLASS_BACKBONE);
	assert_non_null(mesh_relay);

	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_relay, meshlink_node_reachable_status_cb);

	link_meshlink_pair(mesh_relay, mesh_peer);

	meshlink_submesh_t *submesh = meshlink_submesh_open(mesh_peer, SUBMESH_NAME);
	assert_non_null(submesh);

	char *invitation = meshlink_invite(mesh_peer, submesh, NUT);
	assert_non_null(invitation);

	assert_true(meshlink_start(mesh_peer));
	assert_true(meshlink_start(mesh_relay));

	assert_true(meshlink_join(mesh, invitation));

	// Get submesh name of the self node

	assert_non_null(meshlink_get_node_submesh(mesh, meshlink_get_self(mesh)));
	assert_null(meshlink_get_node_submesh(mesh_peer, meshlink_get_self(mesh_peer)));
	assert_null(meshlink_get_node_submesh(mesh_relay, meshlink_get_self(mesh_relay)));
	assert_non_null(meshlink_get_node_submesh(mesh_peer, meshlink_get_node(mesh_peer, NUT)));

	// Check whether all the node are reachable to each other in this topology

	assert_true(meshlink_start(mesh));
	assert_true(wait_sync_flag(&all_nodes_reachable_cond, 10));

	assert_non_null(meshlink_get_node_submesh(mesh_relay, meshlink_get_node(mesh_relay, NUT)));

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_set_node_status_cb(mesh_relay, NULL);

	// Cleanup

	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	meshlink_close(mesh_relay);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	assert_true(meshlink_destroy(relay_confbase));
	return true;
}

int test_cases_submesh04(void) {
	int failed_test = 0;
	const struct CMUnitTest blackbox_group0_tests[] = {
		cmocka_unit_test_prestate_setup_teardown(test_case_submesh_04, setup_test, teardown_test,
		                (void *)&test_case_submesh_4_state)
	};

	const struct CMUnitTest blackbox_group1_tests[] = {
		cmocka_unit_test_prestate_setup_teardown(test_case_submesh_05, NULL, NULL,
		                (void *)&test_case_submesh_5_state)
	};
	total_tests += (sizeof(blackbox_group0_tests) / sizeof(blackbox_group0_tests[0])) + (sizeof(blackbox_group1_tests) / sizeof(blackbox_group1_tests[0]));

	failed_test += cmocka_run_group_tests(blackbox_group0_tests, black_box_group0_setup, black_box_group0_teardown);

	failed_test += cmocka_run_group_tests(blackbox_group1_tests, NULL, NULL);

	return failed_test;
}
