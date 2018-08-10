/*
    test_cases_get_node.c -- Implementation of Black Box Test Execution for meshlink
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
#include "test_cases_get_node.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <string.h>

static void test_case_mesh_get_node_01(void **state);
static bool test_steps_mesh_get_node_01(void);
static void test_case_mesh_get_node_02(void **state);
static bool test_steps_mesh_get_node_02(void);
static void test_case_mesh_get_node_03(void **state);
static bool test_steps_mesh_get_node_03(void);
static void test_case_mesh_get_node_04(void **state);
static bool test_steps_mesh_get_node_04(void);

/* State structure for meshlink_get_node Test Case #1 */
static black_box_state_t test_mesh_get_node_01_state = {
    /* test_case_name = */ "test_case_mesh_get_node_01",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* State structure for meshlink_get_node Test Case #2 */
static black_box_state_t test_mesh_get_node_02_state = {
    /* test_case_name = */ "test_case_mesh_get_node_02",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* State structure for meshlink_get_node Test Case #3 */
static black_box_state_t test_mesh_get_node_03_state = {
    /* test_case_name = */ "test_case_mesh_get_node_03",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* State structure for meshlink_get_node Test Case #4 */
static black_box_state_t test_mesh_get_node_04_state = {
    /* test_case_name = */ "test_case_mesh_get_node_04",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* Execute meshlink_get_node Test Case # 1 */
static void test_case_mesh_get_node_01(void **state) {
    execute_test(test_steps_mesh_get_node_01, state);
    return;
}

/* Test Steps for meshlink_get_node Test Case # 1*/
static bool test_steps_mesh_get_node_01(void) {
	bool result = false;
  meshlink_handle_t *mesh = NULL;
	meshlink_node_t *get_node = NULL;
	int pmtu;
	mesh = meshlink_open("node_conf.1", "foo", "chat", DEV_CLASS_STATIONARY);
	assert(mesh != NULL);
	if(!mesh) {
		fprintf(stderr, "meshlink_open status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	if(!meshlink_start(mesh)) {
		fprintf(stderr, "meshlink_start status: %s\n", meshlink_strerror(meshlink_errno));
		return false;	
	}

	get_node = meshlink_get_node(mesh, "foo");
	assert(get_node != NULL);
	if(!get_node) {
		fprintf(stderr, "meshlink_get_self status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	} else {
		result = true;
	}

	meshlink_stop(mesh);
	meshlink_close(mesh);
	meshlink_destroy("node_conf.1");
  return result;
}

/* Execute meshlink_get_node Test Case # 2 */
static void test_case_mesh_get_node_02(void **state) {
    execute_test(test_steps_mesh_get_node_02, state);
    return;
}

/* Test Steps for meshlink_get_node Test Case # 2*/
static bool test_steps_mesh_get_node_02(void) {
	bool result = false;
  meshlink_handle_t *mesh = NULL;
	meshlink_node_t *get_node = NULL;
	int pmtu;
	mesh = meshlink_open("node_conf.2", "foo", "chat", DEV_CLASS_STATIONARY);
	assert(mesh != NULL);
	if(!mesh) {
		fprintf(stderr, "meshlink_open status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	if(!meshlink_start(mesh)) {
		fprintf(stderr, "meshlink_start status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}

	get_node = meshlink_get_node(NULL, "foo");
	assert(get_node == NULL);
	if(!get_node) {
		fprintf(stderr, "meshlink_get_self status2: %s\n", meshlink_strerror(meshlink_errno));
		result = true;
	} else {
		result = false;
	}

	meshlink_stop(mesh);
	meshlink_close(mesh);
	meshlink_destroy("node_conf.2");
  return result;
}

/* Execute meshlink_get_node Test Case # 3 */
static void test_case_mesh_get_node_03(void **state) {
    execute_test(test_steps_mesh_get_node_03, state);
    return;
}

/* Test Steps for meshlink_get_node Test Case # 3*/
static bool test_steps_mesh_get_node_03(void) {
	bool result = false;
  meshlink_handle_t *mesh = NULL;
	meshlink_node_t *get_node = NULL;

	mesh = meshlink_open("node_conf.3", "foo", "chat", DEV_CLASS_STATIONARY);
	assert(mesh != NULL);
	if(!mesh) {
		fprintf(stderr, "meshlink_open status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	if(!meshlink_start(mesh)) {
		fprintf(stderr, "meshlink_start status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}

	get_node = meshlink_get_node(mesh, NULL);
	assert(get_node == NULL);
	if(!get_node) {
		fprintf(stderr, "meshlink_get_self status2: %s\n", meshlink_strerror(meshlink_errno));
		result = true;
	} else {
		result = false;
	}

	meshlink_stop(mesh);
	meshlink_close(mesh);
	meshlink_destroy("node_conf.3");
  return result;
}

/* Execute meshlink_get_node Test Case # 4 */
static void test_case_mesh_get_node_04(void **state) {
    execute_test(test_steps_mesh_get_node_04, state);
    return;
}

/* Test Steps for meshlink_get_node Test Case # 4*/
static bool test_steps_mesh_get_node_04(void) {
	bool result = false;
  meshlink_handle_t *mesh = NULL;
	meshlink_node_t *get_node = NULL;
	const char *unknown_name;

	mesh = meshlink_open("node_conf.4", "foo", "chat", DEV_CLASS_STATIONARY);
	assert(mesh != NULL);
	if(!mesh) {
		fprintf(stderr, "meshlink_open status2: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}
	if(!meshlink_start(mesh)) {
		fprintf(stderr, "meshlink_start status: %s\n", meshlink_strerror(meshlink_errno));
		return false;
	}

	get_node = meshlink_get_node(mesh, unknown_name);
	assert(get_node == NULL);
	if(!get_node) {
		fprintf(stderr, "meshlink_get_self status2: %s\n", meshlink_strerror(meshlink_errno));
		result = true;
	} else {
		result = false;
	}

	meshlink_stop(mesh);
	meshlink_close(mesh);
	meshlink_destroy("node_conf.4");
  return result;
}

int test_meshlink_get_node(void) {
		const struct CMUnitTest blackbox_get_node_tests[] = {
				cmocka_unit_test_prestate_setup_teardown(test_case_mesh_get_node_01, NULL, NULL,
            (void *)&test_mesh_get_node_01_state),
				cmocka_unit_test_prestate_setup_teardown(test_case_mesh_get_node_02, NULL, NULL,
            (void *)&test_mesh_get_node_02_state),
				cmocka_unit_test_prestate_setup_teardown(test_case_mesh_get_node_03, NULL, NULL,
            (void *)&test_mesh_get_node_03_state),
				cmocka_unit_test_prestate_setup_teardown(test_case_mesh_get_node_04, NULL, NULL,
            (void *)&test_mesh_get_node_04_state)
		};

  total_tests += sizeof(blackbox_get_node_tests) / sizeof(blackbox_get_node_tests[0]);

  return cmocka_run_group_tests(blackbox_get_node_tests, NULL, NULL);
}
