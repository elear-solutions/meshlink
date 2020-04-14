/*
    test_cases_adns.c -- Execution of specific meshlink black box test cases
    Copyright (C) 2020  Guus Sliepen <guus@meshlink.io>

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
#include "test_cases_adns.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../../utils.h"
#include "../../../src/devtools.h"

#define NUT                                       "nut"
#define PEER                                      "peer"
#define RELAY                                     "relay"
#define TEST_MESHLINK_ADNS                        "test_meshlink_adns"
#define create_path(confbase, node_name, test_case_no)   assert(snprintf(confbase, sizeof(confbase), TEST_MESHLINK_ADNS "_%ld_%s_%02d", (long) getpid(), node_name, test_case_no) > 0)

static struct sync_flag peer_reachable = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static int adns_probe_flag;

static void simulate_timeout(void) {
    adns_probe_flag++;
    sleep(20);
}

static void no_op(void) {
    return;
}

static void meshlink_node_reachable_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable_status) {
	if(reachable_status && !strcasecmp(mesh->name, NUT) && !strcasecmp(node->name, PEER)) {
        set_sync_flag(&peer_reachable, true);
	}
}

/* Test Steps for meshlink ADNS address resolution - Nodes merged using export import.

    Test Steps:
    1. Open NUT and peer instances disabling local discovery and set a canonical address before importing them
    2. Set the ADNS probe which sleep()'s for 20 seconds before starting instances.
    3. Nodes should be able to reach each other before 20 seconds and also the ANDS probe should be encountered at least once.
*/
static void test_case_meshlink_adns_01(void **state) {
	(void) state;
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 1);
	create_path(peer_confbase, PEER, 1);
	adns_probe_flag = 0;
	set_sync_flag(&peer_reachable, false);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_MESHLINK_ADNS, DEV_CLASS_STATIONARY);
    assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_MESHLINK_ADNS, DEV_CLASS_BACKBONE);
    assert_non_null(mesh_peer);

    meshlink_enable_discovery(mesh, false);
    meshlink_enable_discovery(mesh_peer, false);

	assert_true(meshlink_set_canonical_address(mesh_peer, meshlink_get_self(mesh_peer), "google.com", "443"));
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);

	char *data = meshlink_export(mesh);
	assert(data);
	assert(meshlink_import(mesh_peer, data));
	free(data);

	data = meshlink_export(mesh_peer);
	assert(data);
	assert(meshlink_import(mesh, data));
	free(data);

	devtool_adns_resolve_probe = simulate_timeout;

	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));

    assert_true(wait_sync_flag(&peer_reachable, 19));
	assert_int_not_equal(adns_probe_flag, 0);

	// Cleanup

	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

/* Test Steps for meshlink ADNS address resolution - Nodes joining mesh using invite-join

    Test Steps:
    1. Open NUT and peer instances disabling local discovery and set a DNS probe
    2. Invite NUT node with public flag i.e, it tries to get it's public address using meshlink.io or findmyip.getcoco.buzz
        which should fail as timeout happens before resolving the hostname, but the time taken should be less than the
        probe block time
    3. Set a canonical address for peer node and invite NUT node with public flag i.e, invitation has non-numerical canonical address only
        Now when NUT tries to join with the invitation the call will eventually fail due to timeout
        However the timeout should be less than the blocking time given in the DNS probe.
    4. Join NUT with peer with along with a canonical address in invitation, start the instances i.e, NUT tries the canonical address first
        Eventually it should timeout and NUT should be able to reach peer before the sleep time specified in the ADNS probe.
*/
static void test_case_meshlink_adns_02(void **state) {
	(void) state;
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	char *invitation;
	time_t start, end;
	create_path(nut_confbase, NUT, 2);
	create_path(peer_confbase, PEER, 2);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_MESHLINK_ADNS, DEV_CLASS_STATIONARY);
    assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_MESHLINK_ADNS, DEV_CLASS_BACKBONE);
    assert_non_null(mesh_peer);

    meshlink_enable_discovery(mesh, false);
    meshlink_enable_discovery(mesh_peer, false);

	devtool_adns_resolve_probe = simulate_timeout;

	// 1. Validate meshlink invite for public address only blocking the DNS probe

	adns_probe_flag = 0;
	start = time(NULL);
	invitation = meshlink_invite_ex(mesh_peer, NULL, NUT, MESHLINK_INVITE_PUBLIC);
	assert_null(invitation);
	end = time(NULL);
	assert_true(end - start < 15);
	assert_int_not_equal(adns_probe_flag, 0);

	// 2. Validate meshlink join with canonical address only blocking the DNS probe

	assert_true(meshlink_set_canonical_address(mesh_peer, meshlink_get_self(mesh_peer), "google.com", "443"));
	invitation = meshlink_invite_ex(mesh_peer, NULL, NUT, MESHLINK_INVITE_PUBLIC);
	assert_non_null(invitation);

	assert_true(meshlink_start(mesh_peer));

	adns_probe_flag = 0;
	start = time(NULL);
	assert_false(meshlink_join(mesh, invitation));
	end = time(NULL);
	assert_true(end - start < 15);
	free(invitation);
	assert_int_not_equal(adns_probe_flag, 0);

	// 3. Validate meshlink outgoing connection where NUT trying the canonical address and the ADNS probe blocking the thread.

	devtool_adns_resolve_probe = no_op;
	invitation = meshlink_invite(mesh_peer, NULL, NUT);
	assert_non_null(invitation);
	assert_true(meshlink_join(mesh, invitation));
	free(invitation);

	devtool_adns_resolve_probe = simulate_timeout;
	adns_probe_flag = 0;
	set_sync_flag(&peer_reachable, false);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);

	assert_true(meshlink_start(mesh));
	assert_true(wait_sync_flag(&peer_reachable, 19));
	assert_int_not_equal(adns_probe_flag, 0);

	// Cleanup

	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

int test_meshlink_adns(void) {
	const struct CMUnitTest blackbox_adns_tests[] = {
		cmocka_unit_test(test_case_meshlink_adns_01),
		cmocka_unit_test(test_case_meshlink_adns_02)
	};
	total_tests += sizeof(blackbox_adns_tests) / sizeof(blackbox_adns_tests[0]);

	int failed_test = cmocka_run_group_tests(blackbox_adns_tests, NULL, NULL);
	devtool_adns_resolve_probe = no_op;

	return failed_test;
}
