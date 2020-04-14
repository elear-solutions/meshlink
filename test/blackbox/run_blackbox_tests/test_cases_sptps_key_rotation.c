/*
    test_cases_sptps_key_rotation.c -- Execution of specific meshlink black box test cases
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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>
#include "execute_tests.h"
#include "test_cases_get_node_reachability.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../../utils.h"
#include "../../../src/devtools.h"

#define NUT                                       "nut"
#define PEER                                      "peer"
#define TEST_MESHLINK_SPTPS_KEY_ROTATION          "test_meshlink_sptps_key_rotation"
#define create_path(confbase, node_name, test_case_no)   assert(snprintf(confbase, sizeof(confbase), TEST_MESHLINK_SPTPS_KEY_ROTATION "_%ld_%s_%02d", (long) getpid(), node_name, test_case_no) > 0)
#define TIMEOUT_SEC                                20 // seconds

static struct sync_flag peer_key_renewed = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static int sptps_renewal_probes = 0;

static void sptps_renewal_probe(meshlink_node_t *node) {
	static int total_sptps_renewal_probes_called;

	if(!strcmp(node->name, PEER)) {
		total_sptps_renewal_probes_called++;

		if(total_sptps_renewal_probes_called == sptps_renewal_probes) {
			set_sync_flag(&peer_key_renewed, true);
		} else if(total_sptps_renewal_probes_called > sptps_renewal_probes) {
			fail();
		}
	} else {
		fail();
	}
}

/* Test Steps for SPTPS key rotation Test Case -

    Test Steps:
    1. Open NUT and peer node instances and pair them.
    2. Wait for nodes to form TCP and UDP connections.
    3. Force meshlink to renewal SPTPS key and validate if the probe points are invoked twice,
        i.e, one for meta-connection and another for udp connection.
    4. sleep for 10 seconds and validate that meshlink may invoke further probe function.
*/
static void test_case_meshlink_sptps_key_rotation_01(void **state) {
	(void) state;
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 5);
	create_path(peer_confbase, PEER, 5);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_MESHLINK_SPTPS_KEY_ROTATION, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_MESHLINK_SPTPS_KEY_ROTATION, DEV_CLASS_STATIONARY);
	assert_non_null(mesh_peer);
	devtool_sptps_renewal_probe = sptps_renewal_probe;

	link_meshlink_pair(mesh, mesh_peer);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	assert_non_null(node);
	devtool_node_status_t node_status;
	int timeout_value = TIMEOUT_SEC * 10;

	for(int t = 0; t < timeout_value; t++) {
		devtool_get_node_status(mesh, node, &node_status);

		if(node_status.reachable && (node_status.tcp_status == DEVTOOL_TCP_ACTIVE) && (node_status.udp_status == DEVTOOL_UDP_WORKING)) {
			break;
		} else if(t == timeout_value - 1) {
			fail();  // Timeout
		} else {
			assert_int_equal(usleep(100000), 0);
		}
	}

	sptps_renewal_probes = 2;
	devtool_force_sptps_renewal(mesh, node);
	assert_true(wait_sync_flag(&peer_key_renewed, 10));
	sleep(10);

	// Cleanup

	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

int test_meshlink_sptps_key_rotation(void) {
	const struct CMUnitTest blackbox_sptps_key_rotation_tests[] = {
		cmocka_unit_test(test_case_meshlink_sptps_key_rotation_01)
	};
	total_tests += sizeof(blackbox_sptps_key_rotation_tests) / sizeof(blackbox_sptps_key_rotation_tests[0]);

	return cmocka_run_group_tests(blackbox_sptps_key_rotation_tests, NULL, NULL);
}
