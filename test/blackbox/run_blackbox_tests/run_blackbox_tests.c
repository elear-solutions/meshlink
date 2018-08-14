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
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include "execute_tests.h"
#include "test_cases.h"
#include "test_cases_destroy.h"
#include "test_cases_get_all_nodes.h"
#include "test_cases_get_fingerprint.h"
#include "test_cases_rec_cb.h"
#include "test_cases_sign.h"
#include "test_cases_set_port.h"
#include "test_cases_verify.h"
#include "test_cases_invite.h"
#include "test_cases_export.h"
#include "test_cases_channel_ex.h"
#include "test_cases_channel_get_flags.h"
#include "test_cases_status_cb.h"
#include "test_cases_set_log_cb.h"
#include "test_cases_join.h"
#include "test_cases_import.h"
#include "test_cases_channel_set_accept_cb.h"
#include "test_cases_channel_set_poll_cb.h"
#include "test_cases_hint_address.h"
#include "../common/containers.h"
#include "../common/common_handlers.h"

#define CMD_LINE_ARG_MESHLINK_ROOT_PATH 1
#define CMD_LINE_ARG_LXC_PATH 2
#define CMD_LINE_ARG_LXC_BRIDGE_NAME 3
#define CMD_LINE_ARG_ETH_IF_NAME 4
#define CMD_LINE_ARG_CHOOSE_ARCH 5

char *meshlink_root_path = NULL;
char *choose_arch = NULL;
int total_tests;




/* State structure for Meta-connections Test Case #1 */
static char *test_meta_conn_1_nodes[] = { "relay", "peer", "nut" };
static black_box_state_t test_meta_conn_1_state = {
    /* test_case_name = */ "test_case_meta_conn_01",
    /* node_names = */ test_meta_conn_1_nodes,
    /* num_nodes = */ 3,
    /* test_result (defaulted to) = */ false
};

/* State structure for Meta-connections Test Case #2 */
static char *test_meta_conn_2_nodes[] = { "relay", "peer", "nut" };
static black_box_state_t test_meta_conn_2_state = {
    /* test_case_name = */ "test_case_meta_conn_02",
    /* node_names = */ test_meta_conn_2_nodes,
    /* num_nodes = */ 3,
    /* test_result (defaulted to) = */ false
};

/* State structure for Meta-connections Test Case #3 */
static char *test_meta_conn_3_nodes[] = { "relay", "peer", "nut" };
static black_box_state_t test_meta_conn_3_state = {
    /* test_case_name = */ "test_case_meta_conn_03",
    /* node_names = */ test_meta_conn_3_nodes,
    /* num_nodes = */ 3,
    /* test_result (defaulted to) = */ false
};

/* State structure for Meta-connections Test Case #4 */
static char *test_meta_conn_4_nodes[] = { "peer", "nut" };
static black_box_state_t test_meta_conn_4_state = {
    /* test_case_name = */ "test_case_meta_conn_04",
    /* node_names = */ test_meta_conn_4_nodes,
    /* num_nodes = */ 2,
    /* test_result (defaulted to) = */ false
};

/* State structure for Meta-connections Test Case #5 */
static char *test_meta_conn_5_nodes[] = { "peer", "nut" };
static black_box_state_t test_meta_conn_5_state = {
    /* test_case_name = */ "test_case_meta_conn_05",
    /* node_names = */ test_meta_conn_5_nodes,
    /* num_nodes = */ 2,
    /* test_result (defaulted to) = */ false
};

int black_box_group0_setup(void **state) {
    char *nodes[] = { "peer", "relay", "nut"};
    int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    printf("Creating Containers\n");
    destroy_containers();
    create_containers(nodes, num_nodes);

    return 0;
}

int black_box_group0_teardown(void **state) {
    printf("Destroying Containers\n");
    destroy_containers();

    return 0;
}

int black_box_all_nodes_setup(void **state) {
    char *nodes[] = { "peer" };
    int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    printf("Creating Containers\n");
    destroy_containers();
    create_containers(nodes, num_nodes);
    printf("Created Containers\n");
    return 0;
}




int main(int argc, char *argv[]) {
  /* Set configuration */
  assert(argc >= (CMD_LINE_ARG_CHOOSE_ARCH + 1));
  meshlink_root_path = argv[CMD_LINE_ARG_MESHLINK_ROOT_PATH];
  lxc_path = argv[CMD_LINE_ARG_LXC_PATH];
  lxc_bridge = argv[CMD_LINE_ARG_LXC_BRIDGE_NAME];
  eth_if_name = argv[CMD_LINE_ARG_ETH_IF_NAME];
  choose_arch = argv[CMD_LINE_ARG_CHOOSE_ARCH];

  int failed_tests = 0;




  const struct CMUnitTest blackbox_group0_tests[] = {
        cmocka_unit_test_prestate_setup_teardown(test_case_meta_conn_01, setup_test, teardown_test,
            (void *)&test_meta_conn_1_state),
        cmocka_unit_test_prestate_setup_teardown(test_case_meta_conn_02, setup_test, teardown_test,
            (void *)&test_meta_conn_2_state),
        cmocka_unit_test_prestate_setup_teardown(test_case_meta_conn_03, setup_test, teardown_test,
            (void *)&test_meta_conn_3_state),
        cmocka_unit_test_prestate_setup_teardown(test_case_meta_conn_04, setup_test, teardown_test,
            (void *)&test_meta_conn_4_state),
        cmocka_unit_test_prestate_setup_teardown(test_case_meta_conn_05, setup_test, teardown_test,
            (void *)&test_meta_conn_5_state)
    };
    int num_tests_group0 = sizeof(blackbox_group0_tests) / sizeof(blackbox_group0_tests[0]);

    total_tests += num_tests_group0;

    failed_tests += cmocka_run_group_tests(blackbox_group0_tests, black_box_group0_setup, black_box_group0_teardown);

/*
  failed_tests += test_meshlink_set_status_cb();
  failed_tests += test_meshlink_join();
  failed_tests += test_meshlink_set_channel_poll_cb();
//  failed_tests += test_meshlink_channel_open_ex();
  failed_tests += test_meshlink_channel_get_flags();
  failed_tests += test_meshlink_set_channel_accept_cb();
  failed_tests += test_meshlink_destroy();
  failed_tests += test_meshlink_export();
  failed_tests += test_meshlink_get_fingerprint();
  failed_tests += test_meshlink_get_all_nodes();
  failed_tests += test_meshlink_set_port();
  failed_tests += test_meshlink_sign();
  failed_tests += test_meshlink_verify();
  failed_tests += test_meshlink_import();
  failed_tests += test_meshlink_invite();
  failed_tests += test_meshlink_set_receive_cb();
  failed_tests += test_meshlink_set_log_cb();*/
  //failed_tests += test_meshlink_set_channel_receive_cb();
  //failed_tests += test_meshlink_hint_address();

  printf("[ PASSED ] %d test(s).\n", total_tests - failed_tests);
  printf("[ FAILED ] %d test(s).\n", failed_tests);

  return failed_tests;
}
