/*
    run_blackbox_tests.c -- Implementation of Black Box Test Execution for meshlink
    Copyright (C) 2017  Guus Sliepen <guus@meshlink.io>
                        Manav Kumar Mehta <manavkumarm@yahoo.com>

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
#include "test_cases_add_addr.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>

static void test_case_mesh_add_address_01(void **state);
static bool test_steps_mesh_add_address_01(void);
static void test_case_mesh_add_address_02(void **state);
static bool test_steps_mesh_add_address_02(void);
static void test_case_mesh_add_address_03(void **state);
static bool test_steps_mesh_add_address_03(void);

/* State structure for meshlink_add_address Test Case #1 */
static black_box_state_t test_mesh_add_address_01_state = {
    /* test_case_name = */ "test_case_mesh_add_address_01",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* State structure for meshlink_add_address Test Case #2 */
static black_box_state_t test_mesh_add_address_02_state = {
    /* test_case_name = */ "test_case_mesh_add_address_02",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* State structure for meshlink_add_address Test Case #3 */
static black_box_state_t test_mesh_add_address_03_state = {
    /* test_case_name = */ "test_case_mesh_add_address_03",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* Execute meshlink_add_address Test Case # 1 */
static void test_case_mesh_add_address_01(void **state) {
    execute_test(test_steps_mesh_add_address_01, state);
    return;
}

/* Test Steps for meshlink_add_address Test Case # 1*/
static bool test_steps_mesh_add_address_01(void) {
	bool result = false;

  meshlink_handle_t *mesh1 = meshlink_open("add_conf.1", "foo", "chat", DEV_CLASS_STATIONARY);
	assert(mesh1 != NULL);
	if(!mesh1) {
		fprintf(stderr, "meshlink_open status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	if (!meshlink_start(mesh1)) {
		fprintf(stderr, "meshlink_start status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	
  meshlink_handle_t *mesh2 = meshlink_open("add_conf.2", "bar", "chat", DEV_CLASS_STATIONARY);
	assert(mesh2 != NULL);
	if(!mesh2) {
		fprintf(stderr, "meshlink_open status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	if (!meshlink_start(mesh2)) {
		fprintf(stderr, "meshlink_start status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}

	result = meshlink_add_address(mesh1, "localhost");
	if(!result) {
		fprintf(stderr, "meshlink_add_address status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	} else {
		result = true;
	}
	char *url = meshlink_invite(mesh1, "bar");
		fprintf(stderr, "invitation url: %s\n", url);
sleep(2);
	if(meshlink_join(mesh2, url)) {
		fprintf(stderr, "invitation accepted from foo %s\n", meshlink_strerror(meshlink_errno));
	}

	meshlink_stop(mesh1);
	meshlink_stop(mesh2);
	meshlink_close(mesh1);
	meshlink_close(mesh2);	
	meshlink_destroy("add_conf.1");
	meshlink_destroy("add_conf.2");
  return result;
}

/* Execute meshlink_add_address Test Case # 2 */
static void test_case_mesh_add_address_02(void **state) {
    execute_test(test_steps_mesh_add_address_02, state);
    return;
}

/* Test Steps for meshlink_add_address Test Case # 2*/
static bool test_steps_mesh_add_address_02(void) {
	bool result = false;

  meshlink_handle_t *mesh = meshlink_open("add_conf.3", "foo", "chat", DEV_CLASS_STATIONARY);
	assert(mesh != NULL);
	if(!mesh) {
		fprintf(stderr, "meshlink_open status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	if(!meshlink_start(mesh)) {
		fprintf(stderr, "meshlink_start status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	
	result = meshlink_add_address(NULL, "localhost");
	if(!result) {
		fprintf(stderr, "meshlink_send status: %s\n", meshlink_strerror(meshlink_errno));
		result = true;
	} else {
		result = false;
	}

	meshlink_stop(mesh);
	meshlink_close(mesh);
	meshlink_destroy("add_conf.3");
  return result;
}

/* Execute meshlink_add_address Test Case # 3 */
static void test_case_mesh_add_address_03(void **state) {
    execute_test(test_steps_mesh_add_address_03, state);
    return;
}

/* Test Steps for meshlink_add_address Test Case # 3*/
static bool test_steps_mesh_add_address_03(void) {
	bool result = false;

  meshlink_handle_t *mesh = meshlink_open("add_conf.4", "foo", "chat", DEV_CLASS_STATIONARY);
	assert(mesh != NULL);
	if(!mesh) {
		fprintf(stderr, "meshlink_open status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	if(!meshlink_start(mesh)) {
		fprintf(stderr, "meshlink_start status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	
	result = !meshlink_add_address(mesh, NULL);
	if(!result) {
		fprintf(stderr, "meshlink_send status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}	else {
		result = true;
	}

	meshlink_stop(mesh);
	meshlink_close(mesh);
	meshlink_destroy("add_conf.4");
  return result;
}

int test_meshlink_add_address(void) {
	const struct CMUnitTest blackbox_add_addr_tests[] = {
			cmocka_unit_test_prestate_setup_teardown(test_case_mesh_add_address_01, NULL, NULL,
           (void *)&test_mesh_add_address_01_state),
			cmocka_unit_test_prestate_setup_teardown(test_case_mesh_add_address_02, NULL, NULL,
           (void *)&test_mesh_add_address_02_state),
			cmocka_unit_test_prestate_setup_teardown(test_case_mesh_add_address_03, NULL, NULL,
           (void *)&test_mesh_add_address_03_state)
	};

  total_tests += sizeof(blackbox_add_addr_tests) / sizeof(blackbox_add_addr_tests[0]);

  return cmocka_run_group_tests(blackbox_add_addr_tests, NULL, NULL);
}

