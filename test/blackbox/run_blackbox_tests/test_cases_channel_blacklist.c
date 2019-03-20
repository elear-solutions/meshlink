/*
    test_cases_channel_blacklist.c -- Execution of specific meshlink black box test cases
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
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <pthread.h>
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../common/network_namespace_framework.h"
#include "../../utils.h"
#include "test_cases_channel_blacklist.h"
#include "../test_case_channel_blacklist_01/node_sim_nut.h"
#include "../test_case_channel_blacklist_01/node_sim_peer.h"
#include "../test_case_channel_blacklist_01/node_sim_relay.h"

typedef bool (*test_step_func_t)(void);

bool test_channel_blacklist_disconnection_relay_running;
bool test_channel_blacklist_disconnection_peer_running;
bool test_channel_blacklist_disconnection_nut2_running;
bool test_channel_blacklist_disconnection_nut_running;
bool test_channel_discon_case_01;
bool test_channel_discon_case_02;
bool test_channel_discon_case_03;
bool test_channel_discon_case_04;
bool nut_peer_metaconn;
bool nut_relay_metaconn;
bool peer_nut_metaconn;
bool peer_relay_metaconn;
bool relay_nut_metaconn;
bool relay_peer_metaconn;

static bool test_steps_channel_blacklist_01(void);
static void test_case_channel_blacklist_01(void **state);
static bool test_steps_channel_blacklist_02(void);
static void test_case_channel_blacklist_02(void **state);
static bool test_steps_channel_blacklist_03(void);
static void test_case_channel_blacklist_03(void **state);
static bool test_steps_channel_blacklist_04(void);
static void test_case_channel_blacklist_04(void **state);
static bool test_steps_channel_blacklist_05(void);
static void test_case_channel_blacklist_05(void **state);

static int setup_test(void **state);
static int teardown_test(void **state);
static void *gen_inv(void *arg);

netns_state_t *test_channel_disconnection_state;

static mesh_arg_t relay_arg = {.node_name = "relay", .confbase = "relay", .app_name = "relay", .dev_class = DEV_CLASS_BACKBONE };
static mesh_arg_t peer_arg = {.node_name = "peer", .confbase = "peer", .app_name = "peer", .dev_class = DEV_CLASS_UNKNOWN };
static mesh_arg_t nut_arg = {.node_name = "nut", .confbase = "nut", .app_name = "nut", .dev_class = DEV_CLASS_STATIONARY };
static mesh_arg_t nut2_arg = {.node_name = "nut2", .confbase = "nut2", .app_name = "nut2", .dev_class = DEV_CLASS_STATIONARY };
static mesh_invite_arg_t relay_nut_invite_arg = {.mesh_arg = &relay_arg, .invitee_name = "nut" };
static mesh_invite_arg_t relay_nut2_invite_arg = {.mesh_arg = &relay_arg, .invitee_name = "nut2" };
static mesh_invite_arg_t relay_peer_invite_arg = {.mesh_arg = &relay_arg, .invitee_name = "peer" };
static mesh_invite_arg_t peer_nut_invite_arg = {.mesh_arg = &peer_arg, .invitee_name = "nut" };
static netns_thread_t netns_relay_nut_invite = {.namespace_name = "relay", .netns_thread = gen_inv, .arg = &relay_nut_invite_arg};
static netns_thread_t netns_relay_peer_invite = {.namespace_name = "relay", .netns_thread = gen_inv, .arg = &relay_peer_invite_arg};
static netns_thread_t netns_relay_nut2_invite = {.namespace_name = "relay", .netns_thread = gen_inv, .arg = &relay_nut2_invite_arg};
static netns_thread_t netns_peer_nut_invite = {.namespace_name = "peer", .netns_thread = gen_inv, .arg = &peer_nut_invite_arg};
static netns_thread_t netns_relay_handle = {.namespace_name = "relay", .arg = &relay_arg};
static netns_thread_t netns_peer_handle = {.namespace_name = "peer", .arg = &peer_arg};
static netns_thread_t netns_nut2_handle = {.namespace_name = "nut", .arg = &nut2_arg};
static netns_thread_t netns_nut_handle = {.namespace_name = "nut", .arg = &nut_arg};

struct sync_flag test_channel_discon_close = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static int setup_test(void **state) {
	netns_state_t *test_state = *((netns_state_t **)state);
	fprintf(stderr, "Running %s\n", test_state->test_case_name);
	netns_create_topology(test_state);
	fprintf(stderr, "\nCreated topology\n");

	meshlink_destroy("nut");
	meshlink_destroy("peer");
	meshlink_destroy("relay");
	set_sync_flag(&test_channel_discon_close, false);
	nut_peer_metaconn = false;
	nut_relay_metaconn = false;
	peer_nut_metaconn = false;
	peer_relay_metaconn = false;
	relay_nut_metaconn = false;
	relay_peer_metaconn = false;
	test_channel_blacklist_disconnection_relay_running = false;
	test_channel_blacklist_disconnection_peer_running = false;
	test_channel_blacklist_disconnection_nut2_running = false;
	test_channel_blacklist_disconnection_nut_running = false;

	return EXIT_SUCCESS;
}

static int teardown_test(void **state) {
	netns_state_t *test_state = *((netns_state_t **)state);

	meshlink_destroy("nut");
	meshlink_destroy("peer");
	meshlink_destroy("relay");
	netns_destroy_topology(test_state);

	return EXIT_SUCCESS;
}

static void execute_test(test_step_func_t step_func, void **state) {

	fprintf(stderr, "\n\x1b[32mRunning Test\x1b[0m\n");
	bool test_result = step_func();

	if(!test_result) {
		fail();
	}
}

static void *gen_inv(void *arg) {
	mesh_invite_arg_t *mesh_invite_arg = (mesh_invite_arg_t *)arg;
	meshlink_handle_t *mesh;
	mesh = meshlink_open(mesh_invite_arg->mesh_arg->node_name , mesh_invite_arg->mesh_arg->confbase, mesh_invite_arg->mesh_arg->app_name, mesh_invite_arg->mesh_arg->dev_class);
	assert(mesh);

	meshlink_submesh_t *submesh;

	if(mesh_invite_arg->submesh) {
		submesh = meshlink_submesh_open(mesh, mesh_invite_arg->submesh);
		assert(submesh);
	} else {
		submesh = NULL;
	}

	char *invitation = meshlink_invite(mesh, submesh, mesh_invite_arg->invitee_name);
	assert(invitation);
	mesh_invite_arg->invite_str = invitation;
	meshlink_close(mesh);
	return NULL;
}

static void launch_3_nodes(void) {
	relay_nut_invite_arg.submesh = NULL;
	run_node_in_namespace_thread(&netns_relay_nut_invite);
	sleep(1);
	assert(relay_nut_invite_arg.invite_str);
	nut_arg.join_invitation = relay_nut_invite_arg.invite_str;

	relay_peer_invite_arg.submesh = NULL;
	run_node_in_namespace_thread(&netns_relay_peer_invite);
	sleep(1);
	assert(relay_peer_invite_arg.invite_str);
	peer_arg.join_invitation = relay_peer_invite_arg.invite_str;

	relay_arg.join_invitation = NULL;

	run_node_in_namespace_thread(&netns_relay_handle);
	sleep(1);

	run_node_in_namespace_thread(&netns_peer_handle);
	sleep(1);

	run_node_in_namespace_thread(&netns_nut_handle);
}

/*
NUT2<--->Relay<--->Peer(Devclass=Unknown)
|         |
-------->NUT
*/
static void launch_4_nodes(void) {
	run_node_in_namespace_thread(&netns_relay_nut_invite);
	sleep(1);
	assert(relay_nut_invite_arg.invite_str);
	nut_arg.join_invitation = relay_nut_invite_arg.invite_str;

	run_node_in_namespace_thread(&netns_relay_peer_invite);
	sleep(1);
	assert(relay_peer_invite_arg.invite_str);
	peer_arg.join_invitation = relay_peer_invite_arg.invite_str;

	run_node_in_namespace_thread(&netns_relay_nut2_invite);
	sleep(1);
	assert(relay_nut2_invite_arg.invite_str);
	nut2_arg.join_invitation = relay_nut2_invite_arg.invite_str;

	relay_arg.join_invitation = NULL;

	run_node_in_namespace_thread(&netns_relay_handle);
	sleep(1);

	run_node_in_namespace_thread(&netns_peer_handle);
	sleep(1);

	run_node_in_namespace_thread(&netns_nut_handle);
	sleep(1);

	run_node_in_namespace_thread(&netns_nut2_handle);
	sleep(1);
}

static void launch_submeshs(void) {
	mesh_arg_t relay_arg = {.node_name = "relay", .confbase = "relay", .app_name = "relay", .dev_class = DEV_CLASS_BACKBONE };
	mesh_arg_t peer1_arg = {.node_name = "peer", .confbase = "peer", .app_name = "peer", .dev_class = DEV_CLASS_STATIONARY };
	mesh_arg_t nut1_arg = {.node_name = "nut", .confbase = "nut", .app_name = "nut", .dev_class = DEV_CLASS_STATIONARY };
	mesh_arg_t peer2_arg = {.node_name = "peer2", .confbase = "peer2", .app_name = "peer", .dev_class = DEV_CLASS_STATIONARY };
	mesh_arg_t nut2_arg = {.node_name = "nut2", .confbase = "nut2", .app_name = "nut", .dev_class = DEV_CLASS_STATIONARY };

	mesh_invite_arg_t relay_nut1_invite_arg = {.mesh_arg = &relay_arg, .invitee_name = "nut", .submesh = "1" };
	mesh_invite_arg_t relay_peer1_invite_arg = {.mesh_arg = &relay_arg, .invitee_name = "peer", .submesh = "1" };
	mesh_invite_arg_t relay_nut2_invite_arg = {.mesh_arg = &relay_arg, .invitee_name = "nut2", .submesh = "2" };
	mesh_invite_arg_t relay_peer2_invite_arg = {.mesh_arg = &relay_arg, .invitee_name = "peer2", .submesh = "2" };

	netns_thread_t netns_relay_nut1_invite = {.namespace_name = "relay", .netns_thread = gen_inv, .arg = &relay_nut1_invite_arg};
	netns_thread_t netns_relay_peer1_invite = {.namespace_name = "relay", .netns_thread = gen_inv, .arg = &relay_peer1_invite_arg};
	netns_thread_t netns_relay_nut2_invite = {.namespace_name = "relay", .netns_thread = gen_inv, .arg = &relay_nut2_invite_arg};
	netns_thread_t netns_relay_peer2_invite = {.namespace_name = "relay", .netns_thread = gen_inv, .arg = &relay_peer2_invite_arg};

	netns_thread_t netns_relay_handle = {.namespace_name = "relay", .arg = &relay_arg};
	netns_thread_t netns_peer1_handle = {.namespace_name = "peer", .arg = &peer1_arg};
	netns_thread_t netns_peer2_handle = {.namespace_name = "peer", .arg = &peer2_arg};
	netns_thread_t netns_nut1_handle = {.namespace_name = "nut", .arg = &nut1_arg};
	netns_thread_t netns_nut2_handle = {.namespace_name = "nut", .arg = &nut2_arg};

	run_node_in_namespace_thread(&netns_relay_nut1_invite);
	sleep(1);
	assert(relay_nut1_invite_arg.invite_str);
	nut1_arg.join_invitation = relay_nut1_invite_arg.invite_str;

	run_node_in_namespace_thread(&netns_relay_peer1_invite);
	sleep(1);
	assert(relay_peer1_invite_arg.invite_str);
	peer1_arg.join_invitation = relay_peer1_invite_arg.invite_str;

	run_node_in_namespace_thread(&netns_relay_nut2_invite);
	sleep(1);
	assert(relay_nut2_invite_arg.invite_str);
	nut2_arg.join_invitation = relay_nut2_invite_arg.invite_str;

	run_node_in_namespace_thread(&netns_relay_peer2_invite);
	sleep(1);
	assert(relay_peer2_invite_arg.invite_str);
	peer2_arg.join_invitation = relay_peer2_invite_arg.invite_str;

	relay_arg.join_invitation = NULL;

	netns_relay_handle.netns_thread = test_channel_blacklist_disconnection_relay_04;
	netns_peer1_handle.netns_thread = test_channel_blacklist_disconnection_peer_02;
	netns_nut1_handle.netns_thread = test_channel_blacklist_disconnection_nut_02;
	netns_peer2_handle.netns_thread = test_channel_blacklist_disconnection_peer_02;
	netns_nut2_handle.netns_thread = test_channel_blacklist_disconnection_nut_02;

	test_channel_blacklist_disconnection_relay_running = true;
	test_channel_blacklist_disconnection_peer_running = true;
	test_channel_blacklist_disconnection_nut_running = true;
	run_node_in_namespace_thread(&netns_relay_handle);
	sleep(1);

	run_node_in_namespace_thread(&netns_peer1_handle);
	sleep(1);

	run_node_in_namespace_thread(&netns_nut1_handle);
	sleep(1);

	/*run_node_in_namespace_thread(&netns_nut2_handle);
	sleep(1);

	run_node_in_namespace_thread(&netns_peer1_handle);
	sleep(1);*/
}

static void test_case_channel_blacklist_01(void **state) {
	execute_test(test_steps_channel_blacklist_01, state);
	return;
}

static bool test_steps_channel_blacklist_01(void) {
	test_channel_blacklist_disconnection_peer_running = true;
	test_channel_blacklist_disconnection_relay_running = true;
	netns_nut_handle.netns_thread = test_channel_blacklist_disconnection_nut_01;
	netns_peer_handle.netns_thread = test_channel_blacklist_disconnection_peer_02;
	netns_relay_handle.netns_thread = test_channel_blacklist_disconnection_relay_04;
	launch_3_nodes();

	wait_sync_flag(&test_channel_discon_close, 300);

	test_channel_blacklist_disconnection_peer_running = false;
	test_channel_blacklist_disconnection_relay_running = false;

	assert_int_equal(test_channel_discon_case_01, true);

	return true;
}

static void test_case_channel_blacklist_02(void **state) {
	execute_test(test_steps_channel_blacklist_02, state);
	return;
}

static bool test_steps_channel_blacklist_02(void) {
	test_channel_blacklist_disconnection_peer_running = true;
	test_channel_blacklist_disconnection_nut2_running = true;
	netns_relay_handle.netns_thread = test_channel_blacklist_disconnection_relay_02;
	netns_peer_handle.netns_thread = test_channel_blacklist_disconnection_peer_02;
	netns_nut_handle.netns_thread = test_channel_blacklist_disconnection_nut_02;
	launch_3_nodes();

	wait_sync_flag(&test_channel_discon_close, 240);

	test_channel_blacklist_disconnection_peer_running = false;
	test_channel_blacklist_disconnection_nut2_running = false;

	assert_int_equal(test_channel_discon_case_02, true);

	return true;
}

static void test_case_channel_blacklist_03(void **state) {
	execute_test(test_steps_channel_blacklist_03, state);
	return;
}

static bool test_steps_channel_blacklist_03(void) {
	test_channel_blacklist_disconnection_peer_running = true;
	test_channel_blacklist_disconnection_relay_running = true;
	netns_relay_handle.netns_thread = test_channel_blacklist_disconnection_relay_04;
	netns_peer_handle.netns_thread = test_channel_blacklist_disconnection_peer_02;
	netns_nut_handle.netns_thread = test_channel_blacklist_disconnection_nut_01;
	launch_3_nodes();

	wait_sync_flag(&test_channel_discon_close, 300);

	test_channel_blacklist_disconnection_peer_running = false;
	test_channel_blacklist_disconnection_relay_running = false;

	assert_int_equal(test_channel_discon_case_01, true);

	return true;
}

static void test_case_channel_blacklist_04(void **state) {
	execute_test(test_steps_channel_blacklist_04, state);
	return;
}

static bool test_steps_channel_blacklist_04(void) {
	test_channel_blacklist_disconnection_peer_running = true;
	test_channel_blacklist_disconnection_relay_running = true;
	test_channel_blacklist_disconnection_nut2_running = true;
	netns_nut_handle.netns_thread = test_channel_blacklist_disconnection_nut_04;
	netns_nut2_handle.netns_thread = test_channel_blacklist_disconnection_nut_02;
	netns_peer_handle.netns_thread = test_channel_blacklist_disconnection_peer_02;
	netns_relay_handle.netns_thread = test_channel_blacklist_disconnection_relay_04;
	launch_4_nodes();

	wait_sync_flag(&test_channel_discon_close, 300);

	test_channel_blacklist_disconnection_peer_running = false;
	test_channel_blacklist_disconnection_nut2_running = false;
	test_channel_blacklist_disconnection_relay_running = false;

	assert_int_equal(test_channel_discon_case_04, true);

	return true;
}

int test_meshlink_channel_blacklist(void) {
	interface_t relay_ifs_01[] = { { .if_peer = "wan_bridge" } };
	namespace_t relay_01 = {
		.name = "relay",
		.type = HOST,
		.interfaces = relay_ifs_01,
		.interfaces_no = 1,
	};

	interface_t peer_ifs_01[] = { { .if_peer = "wan_bridge" } };
	namespace_t peer_01 = {
		.name = "peer",
		.type = HOST,
		.interfaces = peer_ifs_01,
		.interfaces_no = 1,
	};

	interface_t nut_ifs_01[] = { { .if_peer = "wan_bridge" } };
	namespace_t nut_01 = {
		.name = "nut",
		.type = HOST,
		.interfaces = nut_ifs_01,
		.interfaces_no = 1,
	};

	interface_t wan_ifs_01[] = { { .if_peer = "peer" }, { .if_peer = "nut" }, { .if_peer = "relay" } };
	namespace_t wan_bridge_01 = {
		.name = "wan_bridge",
		.type = BRIDGE,
		.interfaces = wan_ifs_01,
		.interfaces_no = 3,
	};

	namespace_t ns_channel_01[] = {  relay_01, wan_bridge_01, nut_01, peer_01 };

	netns_state_t test_channels_ns_01 = {
		.test_case_name =  "test_case_channel_01",
		.namespaces =  ns_channel_01,
		.num_namespaces = 4,
	};


	interface_t nut_ifs_02[] = { { .if_peer = "nut_nat", .fetch_ip_netns_name = "nut_nat" } };
	namespace_t nut_02 = {
		.name = "nut",
		.type = HOST,
		.interfaces = nut_ifs_02,
		.interfaces_no = 1,
	};

	interface_t peer_ifs_02[] = { { .if_peer = "peer_nat", .fetch_ip_netns_name = "peer_nat" } };
	namespace_t peer_02 = {
		.name = "peer",
		.type = HOST,
		.interfaces = peer_ifs_02,
		.interfaces_no = 1,
	};

	interface_t relay_ifs_02[] = { { .if_peer = "wan_bridge" } };
	namespace_t relay_02 = {
		.name = "relay",
		.type = HOST,
		.interfaces = relay_ifs_02,
		.interfaces_no = 1,
	};

	netns_fullcone_handle_t nut_nat_fullcone_02 = { .snat_to_source = "wan_bridge", .dnat_to_destination = "nut" };
	netns_fullcone_handle_t *nut_nat_args_02[] = { &nut_nat_fullcone_02, NULL };
	interface_t nut_nat_ifs_02[] = { { .if_peer = "nut", .fetch_ip_netns_name = "nut_nat" }, { .if_peer = "wan_bridge" } };
	namespace_t nut_nat_02 = {
		.name = "nut_nat",
		.type = PORT_REST,
		.nat_arg = nut_nat_args_02,
		.static_config_net_addr = "192.168.1.0/24",
		.interfaces = nut_nat_ifs_02,
		.interfaces_no = 2,
	};

	netns_fullcone_handle_t peer_nat_fullcone_02 = { .snat_to_source = "wan_bridge", .dnat_to_destination = "peer" };
	netns_fullcone_handle_t *peer_nat_args_02[] = { &peer_nat_fullcone_02, NULL };
	interface_t peer_nat_ifs_02[] = { { .if_peer = "peer", .fetch_ip_netns_name = "peer_nat" }, { .if_peer = "wan_bridge" } };
	namespace_t peer_nat_02 = {
		.name = "peer_nat",
		.type = PORT_REST,
		.nat_arg = peer_nat_args_02,
		.static_config_net_addr = "192.168.1.0/24",
		.interfaces = peer_nat_ifs_02,
		.interfaces_no = 2,
	};

	interface_t wan_ifs_02[] = { { .if_peer = "peer_nat" }, { .if_peer = "nut_nat" }, { .if_peer = "relay" } };
	namespace_t wan_bridge_02 = {
		.name = "wan_bridge",
		.type = BRIDGE,
		.interfaces = wan_ifs_02,
		.interfaces_no = 3,
	};

	namespace_t ns_channel_02[] = { nut_nat_02, peer_nat_02, wan_bridge_02, nut_02, peer_02, relay_02 };

	netns_state_t test_channels_ns_02 = {
		.test_case_name =  "test_case_channel_02",
		.namespaces =  ns_channel_02,
		.num_namespaces = 6,
	};

	netns_state_t test_channels_ns_03 = {
		.test_case_name =  "test_case_channel_03",
		.namespaces =  ns_channel_02,
		.num_namespaces = 6,
	};

	netns_state_t test_channels_ns_04 = {
		.test_case_name =  "test_case_channel_04",
		.namespaces =  ns_channel_01,
		.num_namespaces = 4,
	};

	netns_state_t test_channels_ns_05 = {
		.test_case_name =  "test_case_channel_05",
		.namespaces =  ns_channel_02,
		.num_namespaces = 6,
	};

	const struct CMUnitTest blackbox_group1_tests[] = {
		cmocka_unit_test_prestate_setup_teardown(test_case_channel_blacklist_01, setup_test, teardown_test,
		(void *)&test_channels_ns_01),
		cmocka_unit_test_prestate_setup_teardown(test_case_channel_blacklist_02, setup_test, teardown_test,
		(void *)&test_channels_ns_02),
		cmocka_unit_test_prestate_setup_teardown(test_case_channel_blacklist_03, setup_test, teardown_test,
		(void *)&test_channels_ns_03),
		cmocka_unit_test_prestate_setup_teardown(test_case_channel_blacklist_04, setup_test, teardown_test,
		(void *)&test_channels_ns_04),
	};
	total_tests += sizeof(blackbox_group1_tests) / sizeof(blackbox_group1_tests[0]);

	return cmocka_run_group_tests(blackbox_group1_tests, NULL, NULL);
}
