/*
    test_cases_channel_set_receive_cb.c -- Execution of specific meshlink black box test cases
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
#include "execute_tests.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "test_cases_channel_set_receive_cb.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>

/* Modify this to change the logging level of Meshlink */
#define TEST_MESHLINK_LOG_LEVEL MESHLINK_DEBUG

/* Modify this to change the port number */
#define PORT 8000

/* Modify this to change the channel receive callback access buffer */
#define TCP_TEST 8000

static void test_case_set_channel_receive_cb_01(void **state);
static bool test_steps_set_channel_receive_cb_01(void);
static void test_case_set_channel_receive_cb_02(void **state);
static bool test_steps_set_channel_receive_cb_02(void);
static void test_case_set_channel_receive_cb_03(void **state);
static bool test_steps_set_channel_receive_cb_03(void);
static void test_case_set_channel_receive_cb_04(void **state);
static bool test_steps_set_channel_receive_cb_04(void);

static void channel_poll(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len);
static bool channel_accept(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len);

static bool rec_stat = false;
static bool accept_stat = false;

/* mutex for the receive callback common resources */
static pthread_mutex_t lock;

static black_box_state_t test_case_channel_set_receive_cb_01_state = {
  .test_case_name = "test_case_channel_set_receive_cb_01",
};
static black_box_state_t test_case_channel_set_receive_cb_02_state = {
  .test_case_name = "test_case_channel_set_receive_cb_02",
};
static black_box_state_t test_case_channel_set_receive_cb_03_state = {
  .test_case_name = "test_case_channel_set_receive_cb_03",
};
static black_box_state_t test_case_channel_set_receive_cb_04_state = {
  .test_case_name = "test_case_channel_set_receive_cb_04",
};


/* channel receive callback */
static void channel_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *dat, size_t len) {
  fprintf(stderr, "In channel receive callback'\n");
  pthread_mutex_lock(&lock);
  rec_stat = true;
  pthread_mutex_unlock(&lock);

  return;
}
static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	meshlink_set_channel_receive_cb(mesh, channel, channel_receive_cb);
	return true;
}

static void poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)len;

	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	assert(meshlink_channel_send(mesh, channel, "Hello", 5) != 5);
}

/* Execute meshlink_channel_set_receive_cb Test Case # 1 */
static void test_case_set_channel_receive_cb_01(void **state) {
  execute_test(test_steps_set_channel_receive_cb_01, state);
  return;
}
/* Test Steps for meshlink_channel_set_receive_cb Test Case # 1 - Valid case

    Test Steps:
    1. Run NUT and Open channel for itself.
    2. Set channel receive callback and send data.

    Expected Result:
    Opens a channel by invoking channel receive callback when data sent to it.
*/
static bool test_steps_set_channel_receive_cb_01(void) {
  meshlink_destroy("channelreceiveconf");
  meshlink_set_log_cb(NULL, TEST_MESHLINK_LOG_LEVEL, meshlink_callback_logger);

  /* Create meshlink instance */
  meshlink_handle_t *mesh_handle = meshlink_open("channelreceiveconf", "nut", "node_sim", 1);
  assert(mesh_handle != NULL);
  meshlink_set_log_cb(mesh_handle, TEST_MESHLINK_LOG_LEVEL, meshlink_callback_logger);
  meshlink_set_channel_accept_cb(mesh_handle, accept_cb);

  assert(meshlink_start(mesh_handle));
  sleep(1);

  meshlink_node_t *node = meshlink_get_self(mesh_handle);
  assert(node != NULL);

  rec_stat = false;
  accept_stat = false;
	meshlink_channel_t *channel = meshlink_channel_open(mesh_handle, node, 8000, NULL, NULL, 0);

	meshlink_set_channel_poll_cb(mesh_handle, channel, poll_cb);
  for(int i = 0; i < 20; i++) {
		sleep(1);

		if(accept_stat) {
			break;
		}
	}
	for(int i = 0; i < 20; i++) {
		sleep(1);

		if(rec_stat) {
			break;
		}
	}
	meshlink_close(mesh_handle);
	meshlink_destroy("channelreceiveconf");

	if(!rec_stat) {
		fprintf(stderr, "NUT didn't respond to the channel message for itself\n");
		return false;
	}
	else {
		fprintf(stderr, "NUT responds to the channel message for itself\n");
		return true;
	}
}

/* Execute meshlink_channel_set_receive_cb Test Case # 2 */
static void test_case_set_channel_receive_cb_02(void **state) {
  execute_test(test_steps_set_channel_receive_cb_02, state);
  return;
}
/* Test Steps for meshlink_channel_set_receive_cb Test Case # 2 - Invalid case

    Test Steps:
    1. Run NUT and Open channel for itself.
    2. Set channel receive callback with NULL as mesh handle.

    Expected Result:
    meshlink_channel_set_receive_cb returning proper meshlink_errno.
*/
static bool test_steps_set_channel_receive_cb_02(void) {
  meshlink_destroy("channelreceiveconf");
  fprintf(stderr, "[ channel receive 02 ] Opening NUT\n");
  /* Set up logging for Meshlink */
  meshlink_set_log_cb(NULL, TEST_MESHLINK_LOG_LEVEL, meshlink_callback_logger);

  /* Create meshlink instance */
  meshlink_handle_t *mesh_handle = meshlink_open("channelreceiveconf", "nut", "node_sim", 1);
  fprintf(stderr, "meshlink_open status: %s\n", meshlink_strerror(meshlink_errno));
  assert(mesh_handle != NULL);

  /* Set up logging for Meshlink with the newly acquired Mesh Handle */
  meshlink_set_log_cb(mesh_handle, TEST_MESHLINK_LOG_LEVEL, meshlink_callback_logger);

  PRINT_TEST_CASE_MSG("disabling channel_accept callback for NUT\n");
  meshlink_set_channel_accept_cb(mesh_handle, accept_cb);

  PRINT_TEST_CASE_MSG("Starting NUT\n");
  assert(meshlink_start(mesh_handle));
  meshlink_node_t *node = meshlink_get_self(mesh_handle);
  assert(node != NULL);
  sleep(1);

  PRINT_TEST_CASE_MSG("Opening channel for NUT(ourself) UDP semantic\n");
  meshlink_channel_t *channel = meshlink_channel_open_ex(mesh_handle, node, 8000, NULL, NULL, 0, MESHLINK_CHANNEL_UDP);
  assert(channel != NULL);
  meshlink_set_channel_poll_cb(mesh_handle, channel, poll_cb);

  PRINT_TEST_CASE_MSG("Setting channel for NUT using meshlink_set_channel_receive_cb API\n");
  meshlink_set_channel_receive_cb(NULL, channel, channel_receive_cb);

  if(meshlink_errno == MESHLINK_EINVAL) {
    PRINT_TEST_CASE_MSG("receive callback reported error successfully when NULL is passed as mesh argument\n");
    meshlink_channel_close(mesh_handle, channel);
    meshlink_stop(mesh_handle);
    meshlink_close(mesh_handle);
    meshlink_destroy("channelreceiveconf");
    return true;
  } else {
    PRINT_TEST_CASE_MSG("receive callback didn't report error when NULL is passed as mesh argument\n");
    meshlink_channel_close(mesh_handle, channel);
    meshlink_stop(mesh_handle);
    meshlink_close(mesh_handle);
    meshlink_destroy("channelreceiveconf");
    return false;
  }
}

/* Execute meshlink_channel_set_receive_cb Test Case # 3 */
static void test_case_set_channel_receive_cb_03(void **state) {
  execute_test(test_steps_set_channel_receive_cb_03, state);
  return;
}
/* Test Steps for meshlink_channel_set_receive_cb Test Case # 3 - Invalid case

    Test Steps:
    1. Run NUT and Open channel for itself.
    2. Set channel receive callback with NULL as channel handle.

    Expected Result:
    meshlink_channel_set_receive_cb returning proper meshlink_errno.
*/
static bool test_steps_set_channel_receive_cb_03(void) {
  meshlink_destroy("channelreceiveconf");
  PRINT_TEST_CASE_MSG("Opening NUT\n");
  /* Set up logging for Meshlink */
  meshlink_set_log_cb(NULL, TEST_MESHLINK_LOG_LEVEL, meshlink_callback_logger);

  /* Create meshlink instance */
  meshlink_handle_t *mesh_handle = meshlink_open("channelreceiveconf", "nut", "node_sim", 1);
  fprintf(stderr, "meshlink_open status: %s\n", meshlink_strerror(meshlink_errno));
  assert(mesh_handle != NULL);

  /* Set up logging for Meshlink with the newly acquired Mesh Handle */
  meshlink_set_log_cb(mesh_handle, TEST_MESHLINK_LOG_LEVEL, meshlink_callback_logger);

  PRINT_TEST_CASE_MSG("disabling channel_accept callback for NUT\n");
  meshlink_set_channel_accept_cb(mesh_handle, accept_cb);

  PRINT_TEST_CASE_MSG("Starting NUT\n");
  assert(meshlink_start(mesh_handle));
  sleep(1);

  PRINT_TEST_CASE_MSG("Setting channel for NUT using meshlink_set_channel_receive_cb API\n");
  meshlink_set_channel_receive_cb(mesh_handle, NULL, channel_receive_cb);

  if(meshlink_errno == MESHLINK_EINVAL) {
    PRINT_TEST_CASE_MSG("receive callback reported error successfully when NULL is passed as channel argument\n");
    meshlink_stop(mesh_handle);
    meshlink_close(mesh_handle);
    meshlink_destroy("channelreceiveconf");
    return true;
  } else {
    PRINT_TEST_CASE_MSG("receive callback didn't report error when NULL is passed as channel argument\n");
    meshlink_stop(mesh_handle);
    meshlink_close(mesh_handle);
    meshlink_destroy("channelreceiveconf");
    return false;
  }
}


int test_meshlink_set_channel_receive_cb(void) {
  const struct CMUnitTest blackbox_channel_set_receive_cb_tests[] = {
    cmocka_unit_test_prestate_setup_teardown(test_case_set_channel_receive_cb_01, NULL, NULL,
            (void *)&test_case_channel_set_receive_cb_01_state),
    cmocka_unit_test_prestate_setup_teardown(test_case_set_channel_receive_cb_02, NULL, NULL,
            (void *)&test_case_channel_set_receive_cb_02_state),
    cmocka_unit_test_prestate_setup_teardown(test_case_set_channel_receive_cb_03, NULL, NULL,
            (void *)&test_case_channel_set_receive_cb_03_state)
  };
  total_tests += sizeof(blackbox_channel_set_receive_cb_tests) / sizeof(blackbox_channel_set_receive_cb_tests[0]);

  assert(pthread_mutex_init(&lock, NULL) == 0);
  int failed = cmocka_run_group_tests(blackbox_channel_set_receive_cb_tests ,NULL , NULL);
  assert(pthread_mutex_destroy(&lock) == 0);

  return failed;
}
