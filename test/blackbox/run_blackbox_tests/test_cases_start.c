/*
    test_cases_start.c -- Implementation of Black Box Test Execution for meshlink
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
#include "test_cases_start.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <string.h>

static void test_case_mesh_start_01(void **state);
static bool test_steps_mesh_start_01(void);
static void test_case_mesh_start_02(void **state);
static bool test_steps_mesh_start_02(void);

/* State structure for meshlink_start Test Case #1 */
static black_box_state_t test_mesh_start_01_state = {
    /* test_case_name = */ "test_case_mesh_start_01",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* State structure for meshlink_start Test Case #2 */
static black_box_state_t test_mesh_start_02_state = {
    /* test_case_name = */ "test_case_mesh_start_02",
    /* node_names = */ NULL,
    /* num_nodes = */ 0,
    /* test_result (defaulted to) = */ false
};

/* Execute meshlink_start Test Case # 1*/
static void test_case_mesh_start_01(void **state) {
	 execute_test(test_steps_mesh_start_01, state);
   return;
}

/* Test Steps for meshlink_start Test Case # 1*/
static bool test_steps_mesh_start_01(void) {
		bool result = false;
		meshlink_handle_t *mesh = NULL;

    mesh = meshlink_open("start_conf.1", "foo", "chat", DEV_CLASS_STATIONARY);
		assert(mesh != NULL);
		result = meshlink_start(mesh);
		if (!result) {
			fprintf(stderr, "meshlink_start status1: %s\n", meshlink_strerror(meshlink_errno));
			return false;	
		} else {
			result = true;
		}
		assert(result != false);
		meshlink_destroy("start_conf.1");	
    return result;
}

/* Execute meshlink_start Test Case # 2*/
static void test_case_mesh_start_02(void **state) {
	 execute_test(test_steps_mesh_start_02, state);
   return;
}

/* Test Steps for meshlink_start Test Case # 2*/
static bool test_steps_mesh_start_02(void) {
		bool result = false;
		meshlink_handle_t *mesh = NULL;

    mesh = meshlink_open("start_conf.2", "foo", "chat", DEV_CLASS_STATIONARY);
		assert(mesh != NULL);	
		result = meshlink_start(NULL);
		if (!result) {
			fprintf(stderr, "meshlink_start status 2: %s\n", meshlink_strerror(meshlink_errno));
			result = true;
		} else {
			result = false;
		}
		assert(result != false);
		meshlink_destroy("start_conf.2");		
    return result;
}

int test_meshlink_start(void) {
		const struct CMUnitTest blackbox_start_tests[] = {
				cmocka_unit_test_prestate_setup_teardown(test_case_mesh_start_01, NULL, NULL,
            (void *)&test_mesh_start_01_state),
				cmocka_unit_test_prestate_setup_teardown(test_case_mesh_start_02, NULL, NULL,
            (void *)&test_mesh_start_02_state)

		};

  total_tests += sizeof(blackbox_start_tests) / sizeof(blackbox_start_tests[0]);

  return cmocka_run_group_tests(blackbox_start_tests, NULL, NULL);
}
