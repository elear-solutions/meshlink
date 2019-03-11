/*
    test_cases_encrypted_storage.c -- Execution of specific meshlink black box test cases
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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include "../../utils.h"
#include "test_cases_whitelist.h"
#include "../common/common_types.h"

typedef bool (*test_step_func_t)(void);

static void test_case_encrypted_storage_01(void **state);
static bool test_steps_encrypted_storage_01(void);
static void test_case_encrypted_storage_02(void **state);
static bool test_steps_encrypted_storage_02(void);
static void test_case_encrypted_storage_03(void **state);
static bool test_steps_encrypted_storage_03(void);
static void test_case_encrypted_storage_04(void **state);
static bool test_steps_encrypted_storage_04(void);
static void test_case_encrypted_storage_05(void **state);
static bool test_steps_encrypted_storage_05(void);
static void test_case_encrypted_storage_06(void **state);
static bool test_steps_encrypted_storage_06(void);
static void test_case_encrypted_storage_07(void **state);
static bool test_steps_encrypted_storage_07(void);
static void test_case_encrypted_storage_08(void **state);
static bool test_steps_encrypted_storage_08(void);
static void test_case_encrypted_storage_09(void **state);
static bool test_steps_encrypted_storage_09(void);
static void test_case_encrypted_storage_10(void **state);
static bool test_steps_encrypted_storage_10(void);
static void test_case_encrypted_storage_11(void **state);
static bool test_steps_encrypted_storage_11(void);
static void test_case_encrypted_storage_12(void **state);
static bool test_steps_encrypted_storage_12(void);
static void test_case_encrypted_storage_13(void **state);
static bool test_steps_encrypted_storage_13(void);
static void test_case_encrypted_storage_14(void **state);
static bool test_steps_encrypted_storage_14(void);
static void test_case_encrypted_storage_15(void **state);
static bool test_steps_encrypted_storage_15(void);
static void test_case_encrypted_storage_16(void **state);
static bool test_steps_encrypted_storage_16(void);

/* State structure for encrypted storage Test Case #1 */
static black_box_state_t test_encrypted_01_state = {
	.test_case_name = "test_case_encrypted_storage_01",
};

/* State structure for encrypted storage Test Case #2 */
static black_box_state_t test_encrypted_02_state = {
	.test_case_name = "test_case_encrypted_storage_02",
};

/* State structure for encrypted storage Test Case #3 */
static black_box_state_t test_encrypted_03_state = {
	.test_case_name = "test_case_encrypted_storage_03",
};

/* State structure for encrypted storage Test Case #4 */
static black_box_state_t test_encrypted_04_state = {
	.test_case_name = "test_case_encrypted_storage_04",
};

/* State structure for encrypted storage Test Case #5 */
static black_box_state_t test_encrypted_05_state = {
	.test_case_name = "test_case_encrypted_storage_05",
};

/* State structure for encrypted storage Test Case #6 */
static black_box_state_t test_encrypted_06_state = {
	.test_case_name = "test_case_encrypted_storage_06",
};

/* State structure for encrypted storage Test Case #7 */
static black_box_state_t test_encrypted_07_state = {
	.test_case_name = "test_case_encrypted_storage_07",
};

/* State structure for encrypted storage Test Case #8 */
static black_box_state_t test_encrypted_08_state = {
	.test_case_name = "test_case_encrypted_storage_08",
};

/* State structure for encrypted storage Test Case #9 */
static black_box_state_t test_encrypted_09_state = {
	.test_case_name = "test_case_encrypted_storage_09",
};

/* State structure for encrypted storage Test Case #10 */
static black_box_state_t test_encrypted_10_state = {
	.test_case_name = "test_case_encrypted_storage_10",
};

/* State structure for encrypted storage Test Case #11 */
static black_box_state_t test_encrypted_11_state = {
	.test_case_name = "test_case_encrypted_storage_11",
};

/* State structure for encrypted storage Test Case #12 */
static black_box_state_t test_encrypted_12_state = {
	.test_case_name = "test_case_encrypted_storage_12",
};

/* State structure for encrypted storage Test Case #13 */
static black_box_state_t test_encrypted_13_state = {
	.test_case_name = "test_case_encrypted_storage_13",
};

/* State structure for encrypted storage Test Case #14 */
static black_box_state_t test_encrypted_14_state = {
	.test_case_name = "test_case_encrypted_storage_14",
};

/* State structure for encrypted storage Test Case #15 */
static black_box_state_t test_encrypted_15_state = {
	.test_case_name = "test_case_encrypted_storage_15",
};

/* State structure for encrypted storage Test Case #16 */
static black_box_state_t test_encrypted_16_state = {
	.test_case_name = "test_case_encrypted_storage_16",
};

static struct sync_flag nut_reachable = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag peer_reachable = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag nodex_reachable = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static void logger(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	fprintf(stderr, "[%s]: %s\n", mesh ? mesh->name : "NULL", text);
}

static bool wait_sync_flag_ex(struct sync_flag *s, int seconds) {
	bool wait_ret;
	pthread_mutex_lock(&s->mutex);
	wait_ret = wait_sync_flag(s, seconds);
	pthread_mutex_unlock(&s->mutex);
	return wait_ret;
}

static void node_status(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {

	if(!strcmp(mesh->name, "nut") && !strcmp(node->name, "peer")) {
		set_sync_flag(&peer_reachable, reachable);
	} else if(!strcmp(mesh->name, "peer") && !strcmp(node->name, "nut")) {
		set_sync_flag(&nut_reachable, reachable);
	} else if(!strcmp(mesh->name, "peer") && !strcmp(node->name, "nodex")) {
		set_sync_flag(&nodex_reachable, reachable);
	}
}

/* Execute encrypted storage Test Case # 1 - Sanity Test*/
static void test_case_encrypted_storage_01(void **state) {
	execute_test(test_steps_encrypted_storage_01, state);
}

/* Test Steps for encrypted storage Test Case # 1

    Test Steps:
    1. Open encrypted meshlink node instance by passing invalid arguments

    Expected Result:
    @ meshlink_open_encrypted @ API should return false and errno being set
*/
static bool test_steps_encrypted_storage_01(void) {

	char key[] = "encryption_key";
	size_t keylen = sizeof(key);
	meshlink_handle_t *mesh;

	// Opening encrypted mesh instance with NULL as confbase name

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_errno = MESHLINK_OK;
	mesh = meshlink_open_encrypted(NULL, "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_equal(mesh, NULL);
	assert_int_not_equal(meshlink_errno, MESHLINK_OK);

	// Opening encrypted mesh instance with string length as zero as confbase name

	meshlink_errno = MESHLINK_OK;
	mesh = meshlink_open_encrypted("", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_equal(mesh, NULL);
	assert_int_not_equal(meshlink_errno, MESHLINK_OK);

	// Opening encrypted mesh instance with NULL as key name

	meshlink_errno = MESHLINK_OK;
	mesh = meshlink_open_encrypted("encrypted_storage_conf.1", "nut", "test", DEV_CLASS_BACKBONE, NULL, keylen);
	assert_int_equal(mesh, NULL);
	assert_int_not_equal(meshlink_errno, MESHLINK_OK);

	// Opening encrypted mesh instance with key length as 0 bytes

	meshlink_errno = MESHLINK_OK;
	mesh = meshlink_open_encrypted("encrypted_storage_conf.1", "nut", "test", DEV_CLASS_BACKBONE, key, 0);
	assert_int_equal(mesh, NULL);
	assert_int_not_equal(meshlink_errno, MESHLINK_OK);

	return true;
}

/* Execute encrypted storage Test Case # 2 - Sanity Test */
static void test_case_encrypted_storage_02(void **state) {
	execute_test(test_steps_encrypted_storage_02, state);
}

/* Test Steps for encrypted storage Test Case # 2

    Test Steps:
    1. Open an encrypted confbase instance of meshlink with a key and close it.
    2. Open the meshlink node instance with the same confbase but with a wrong or another key
        that's different from original.
    3. Open the meshlink node instance with the same confbase but with a valid key with which
        initially it's opened.

    Expected Result:
    On reopening meshlink node instance with valid key @ meshlink_open_encrypted @ API should
    return valid mesh handle else it should return NULL pointer.
*/
static bool test_steps_encrypted_storage_02(void) {
	meshlink_destroy("encrypted_conf");
	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, "right", 5);
	assert_int_not_equal(mesh, NULL);
	meshlink_close(mesh);

	mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, "wrong", 5);
	assert_int_equal(mesh, NULL);

	if(!mesh) {
		meshlink_close(mesh);
	}

	mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, "right", 5);
	assert_int_not_equal(mesh, NULL);

	if(!mesh) {
		meshlink_close(mesh);
	}

	meshlink_destroy("encrypted_conf");
	return true;
}

/* Execute encrypted storage Test Case # 3 - Sanity test*/
static void test_case_encrypted_storage_03(void **state) {
	execute_test(test_steps_encrypted_storage_03, state);
}

/* Test Steps for encrypted storage Test Case # 3

    Test Steps:
    1. Opening meshlink node instance with confbase name that's already a directory
        but don't contain any meshlink config files.

    Expected Result:
    @ meshlink_open_encrypted @ API should be able to open node instance with the given confbase name
    which is already a directory.
*/
static bool test_steps_encrypted_storage_03(void) {
	/*meshlink_errno = MESHLINK_OK;
	int ret = system("rm -rf directory");
	assert(mkdir("directory", 0777) != -1);

	mesh = meshlink_open_encrypted("directory", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_not_equal(mesh, NULL);
	assert(meshlink_destroy("directory"));

	assert_int_equal(access("directory", F_OK));*/
	return true;
}

/* Execute encrypted storage Test Case # 4 */
static void test_case_encrypted_storage_04(void **state) {
	execute_test(test_steps_encrypted_storage_04, state);
}

/* Test Steps for encrypted storage Test Case # 4

    Test Steps:
    1. Open NUT and peer node instance with encrypted confbase.
    2. Join nodes by importing and exporting meshlink API's. Close both the nodes.
    3. Reopen both node instances and obtain node handles.

    Expected Result:
    When NUT and peer node is restarted it should obtain node handles appropriate node handles.
    (i.e, node handles of itself and other node's handle)
*/
static bool test_steps_encrypted_storage_04(void) {

	char key[] = "encryption_key";
	size_t keylen = sizeof(key);

	// Open NUT and peer node instances

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_handle_t *mesh1 = meshlink_open_encrypted("encrypted_conf.1" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	meshlink_handle_t *mesh2 = meshlink_open_encrypted("encrypted_conf.2" , "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert(mesh1);
	assert(mesh2);

	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);
	meshlink_set_log_cb(mesh2, MESHLINK_DEBUG, logger);

	// Import and Export key's and addresses of each other

	char *export1 = meshlink_export(mesh1);
	char *export2 = meshlink_export(mesh2);
	assert_int_not_equal(export1, NULL);
	assert_int_not_equal(export2, NULL);

	assert_int_equal(meshlink_import(mesh1, export2), true);
	assert_int_equal(meshlink_import(mesh2, export1), true);

	assert(meshlink_get_node(mesh1, "peer"));
	assert(meshlink_get_node(mesh2, "nut"));

	// Close NUT and peer node instances

	meshlink_close(mesh1);
	meshlink_close(mesh2);

	// Re-open NUT and peer node instances

	mesh1 = meshlink_open_encrypted("encrypted_conf.1" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	mesh2 = meshlink_open_encrypted("encrypted_conf.2" , "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_not_equal(mesh1, NULL);
	assert_int_not_equal(mesh2, NULL);
	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);
	meshlink_set_log_cb(mesh2, MESHLINK_DEBUG, logger);

	// Obtain node handles and assert on the result

	assert_int_not_equal(meshlink_get_node(mesh1, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh1, "peer"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "peer"), NULL);

	// Cleanup

	meshlink_close(mesh1);
	meshlink_close(mesh2);

	meshlink_destroy("encrypted_conf.1");
	meshlink_destroy("encrypted_conf.2");
	return true;
}

/* Execute encrypted storage Test Case # 5 */
static void test_case_encrypted_storage_05(void **state) {
	execute_test(test_steps_encrypted_storage_05, state);
}

/* Test Steps for encrypted storage Test Case # 5

    Test Steps:
    1. Open & join NUT and peer node instance with encrypted confbase with
        peer node inviting NUT node.
    2. Reopen both node instances.

    Expected Result:
    When NUT and peer node is restarted it should obtain node handles appropriate node handles
    (i.e, node handles of itself and other node's handle) and also should see other node's reachable
    status from callbacks.
*/
static bool test_steps_encrypted_storage_05(void) {
	char key[] = "encryption_key";
	size_t keylen = sizeof(key);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_destroy("encrypted_conf.1");
	meshlink_destroy("encrypted_conf.2");

	// Open NUT and peer node instances and join them

	meshlink_handle_t *mesh1 = meshlink_open_encrypted("encrypted_conf.1" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	meshlink_handle_t *mesh2 = meshlink_open_encrypted("encrypted_conf.2" , "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert(mesh1);
	assert(mesh2);

	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);
	meshlink_set_log_cb(mesh2, MESHLINK_DEBUG, logger);
	meshlink_set_node_status_cb(mesh1, node_status);
	meshlink_set_node_status_cb(mesh2, node_status);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	char *invitation = meshlink_invite_ex(mesh2, "nut", MESHLINK_INVITE_LOCAL | MESHLINK_INVITE_NUMERIC);
	assert_int_not_equal(invitation, NULL);

	// Start peer node instance

	assert(meshlink_start(mesh2));

	// Join NUT node with peer node

	assert_int_equal(meshlink_join(mesh1, invitation), true);

	set_sync_flag(&peer_reachable, false);
	set_sync_flag(&nut_reachable, false);

	// Start NUT node instance

	assert(meshlink_start(mesh1));

	// Wait for NUT and Peer node status callback to be invoked

	assert_int_equal(wait_sync_flag_ex(&peer_reachable, 10), false);
	assert_int_equal(wait_sync_flag_ex(&nut_reachable, 10), false);

	// Close NUT node instance

	meshlink_close(mesh1);

	// Reopen NUT node

	mesh1 = meshlink_open_encrypted("encrypted_conf.1" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_not_equal(mesh1, NULL);
	meshlink_set_node_status_cb(mesh1, node_status);
	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);

	// Assert on node handles

	assert_int_not_equal(meshlink_get_node(mesh1, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh1, "peer"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "peer"), NULL);

	set_sync_flag(&peer_reachable, false);
	set_sync_flag(&nut_reachable, false);

	// Restart NUT node instance

	assert(meshlink_start(mesh1));

	// Wait for NUT and Peer node status callback to be invoked

	assert_int_equal(wait_sync_flag_ex(&peer_reachable, 10), false);
	assert_int_equal(wait_sync_flag_ex(&nut_reachable, 10), false);

	// Close Peer node instance

	meshlink_close(mesh2);

	// Reopen peer node instance

	mesh2 = meshlink_open_encrypted("encrypted_conf.2" , "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_not_equal(mesh2, NULL);
	meshlink_set_log_cb(mesh2, MESHLINK_DEBUG, logger);

	assert_int_not_equal(meshlink_get_node(mesh1, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh1, "peer"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "peer"), NULL);

	set_sync_flag(&peer_reachable, false);
	set_sync_flag(&nut_reachable, false);

	// Restart peer node instance

	assert(meshlink_start(mesh2));

	// Wait for NUT and Peer node status callback to be invoked

	assert_int_equal(wait_sync_flag_ex(&peer_reachable, 10), false);
	assert_int_equal(wait_sync_flag_ex(&nut_reachable, 10), false);

	// Cleanup

	meshlink_close(mesh1);
	meshlink_close(mesh2);

	free(invitation);
	meshlink_destroy("encrypted_conf.1");
	meshlink_destroy("encrypted_conf.2");

	return true;
}

/* Execute encrypted storage Test Case # 6 */
static void test_case_encrypted_storage_06(void **state) {
	execute_test(test_steps_encrypted_storage_06, state);
}

/* Test Steps for encrypted storage Test Case # 6

    Test Steps:
    1. Open node instance and close it immediately
    2. Corrupt main confbase.
    3. Reopen node insatance.

    Expected Result:
    On corrupting meshlink main config file and on opening open API should
    fail returning NULL pointer.
*/
static bool test_steps_encrypted_storage_06(void) {
	char key[] = "encryption_key";
	size_t keylen = sizeof(key);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_destroy("encrypted_conf");

	// Open a node instance

	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert(mesh);

	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, logger);
	meshlink_set_node_status_cb(mesh, node_status);
	meshlink_enable_discovery(mesh, false);
	meshlink_close(mesh);

	// Write some data into the meshlink.conf or main config file

	FILE *fp = fopen("encrypted_conf/meshlink.conf", "w");
	assert(fp);
	int offset = fseek(fp, 0, SEEK_END);
	assert(offset != -1);
	assert(fseek(fp, offset / 2, SEEK_SET) != -1);
	assert(fwrite("corrupt", 7, 1, fp) < 7);
	fclose(fp);

	// Reopen node instance

	mesh = meshlink_open_encrypted("encrypted_conf" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_equal(mesh, NULL);

	// Cleanup

	meshlink_close(mesh);
	meshlink_destroy("encrypted_conf");
	return true;
}

/* Execute encrypted storage Test Case # 7 - Sanity Test*/
static void test_case_encrypted_storage_07(void **state) {
	execute_test(test_steps_encrypted_storage_07, state);
}

/* Test Steps for encrypted storage Test Case # 7

    Test Steps:
    1. Open a node instance for NUT node.
    2. Open again with same parameters or with the same configuration.

    Expected Result:
    Opening the same configuration file more than once should fail on attempting using
    @ meshlink_open_encrypted @ API.
*/
static bool test_steps_encrypted_storage_07(void) {
	char key[] = "encryption_key";
	size_t keylen = sizeof(key);

	// Open NUT node instance

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_destroy("encrypted_conf.4");
	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf.4" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert(mesh);

	// Open NUT node instance again

	meshlink_handle_t *mesh_dup = meshlink_open_encrypted("encrypted_conf.4" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_equal(mesh_dup, NULL);

	// Cleanup

	meshlink_close(mesh);
	meshlink_destroy("encrypted_conf.4");
	return true;
}

static bool identical_key;

/* Execute encrypted storage Test Case # 8 */
static void test_case_encrypted_storage_08(void **state) {
	identical_key = true;
	execute_test(test_steps_encrypted_storage_08, state);
}

/* Test Steps for encrypted storage Test Case # 8
    Spoofing a node by copying their host configuration files

    Test Steps:
    1. Create node instance for nodex, NUT and Peer nodes.
        (All of these nodes are opened with the same key).
    2. Join NUT and Peer nodes only and Close all the nodes.
    3. Complement host config files of NUT and Peer nodes.
    4. Reopen all the nodes.

    Expected Result:
    When nodex tried to spoof using config files manually by copying files, NUT and Peer nodes
    should not detect 'nodex' node instance.
*/
static bool test_steps_encrypted_storage_08(void) {
	char key[] = "encryption_key";
	size_t keylen = sizeof(key);
	char key2[] = "12345";
	size_t key2len = sizeof(key);
	char *keyx;
	size_t keyxlen;

	if(identical_key) {
		keyx = key;
		keyxlen = keylen;
	} else {
		keyx = key2;
		keyxlen = key2len;
	}

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_destroy("encrypted_conf.1");
	meshlink_destroy("encrypted_conf.2");
	meshlink_destroy("encrypted_conf.5");

	// Create nodex node instance and close it

	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf.5" , "nodex", "test", DEV_CLASS_BACKBONE, keyx, keyxlen);
	assert(mesh);

	meshlink_close(mesh);

	// Open nut and Peer node instance and join them in a mesh

	meshlink_handle_t *mesh1 = meshlink_open_encrypted("encrypted_conf.1" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	meshlink_handle_t *mesh2 = meshlink_open_encrypted("encrypted_conf.2" , "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert(mesh1);
	assert(mesh2);

	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	char *export1 = meshlink_export(mesh1);
	char *export2 = meshlink_export(mesh2);
	assert_int_not_equal(export1, NULL);
	assert_int_not_equal(export2, NULL);

	assert_int_equal(meshlink_import(mesh1, export2), true);
	assert_int_equal(meshlink_import(mesh2, export1), true);

	assert(meshlink_get_node(mesh1, "peer"));
	assert(meshlink_get_node(mesh2, "nut"));
	meshlink_set_node_status_cb(mesh1, node_status);
	meshlink_set_node_status_cb(mesh2, node_status);
	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);
	meshlink_set_log_cb(mesh2, MESHLINK_DEBUG, logger);

	// Start NUT and Peer node instances

	assert(meshlink_start(mesh1));
	assert(meshlink_start(mesh2));

	// Wait for NUT node to be reachable at Peer node

	assert_int_equal(wait_sync_flag_ex(&nut_reachable, 10), true);

	// Close NUT and Peer nodes

	meshlink_close(mesh1);
	meshlink_close(mesh2);

	// Copy host files such that complementing each other

	assert(link("encrypted_conf.1/hosts/nut", "encrypted_conf.5/hosts/nut") != -1);
	assert(link("encrypted_conf.5/hosts/nodex", "encrypted_conf.1/hosts/nodex") != -1);

	// Reopen nodex, nut and peer node instances

	mesh = meshlink_open_encrypted("encrypted_conf.5" , "nodex", "test", DEV_CLASS_BACKBONE, keyx, keyxlen);
	mesh1 = meshlink_open_encrypted("encrypted_conf.1" , "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	mesh2 = meshlink_open_encrypted("encrypted_conf.2" , "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert(mesh);
	assert(mesh1);
	assert(mesh2);
	meshlink_set_node_status_cb(mesh2, node_status);
	meshlink_set_node_status_cb(mesh, node_status);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, logger);
	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);
	meshlink_set_log_cb(mesh2, MESHLINK_DEBUG, logger);

	set_sync_flag(&nodex_reachable, false);
	set_sync_flag(&nut_reachable, false);
	meshlink_enable_discovery(mesh, false);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	// Start all nodes

	assert(meshlink_start(mesh));
	assert(meshlink_start(mesh1));
	assert(meshlink_start(mesh2));

	//

	assert_int_equal(wait_sync_flag_ex(&nut_reachable, 10), false);
	assert_int_equal(nut_reachable.flag, true);
	assert_int_equal(wait_sync_flag_ex(&nodex_reachable, 10), true);
	assert_int_equal(nodex_reachable.flag, false);

	// Cleanup

	meshlink_close(mesh);
	meshlink_close(mesh1);
	meshlink_close(mesh2);
	meshlink_destroy("encrypted_conf.1");
	meshlink_destroy("encrypted_conf.2");
	meshlink_destroy("encrypted_conf.5");

	return true;
}

int test_meshlink_encrypted_storage(void) {
	const struct CMUnitTest blackbox_encrypted_storage_tests[] = {
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_01, NULL, NULL,
		(void *)&test_encrypted_01_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_02, NULL, NULL,
		(void *)&test_encrypted_02_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_03, NULL, NULL,
		(void *)&test_encrypted_03_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_04, NULL, NULL,
		(void *)&test_encrypted_04_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_05, NULL, NULL,
		(void *)&test_encrypted_05_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_06, NULL, NULL,
		(void *)&test_encrypted_06_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_07, NULL, NULL,
		(void *)&test_encrypted_07_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_08, NULL, NULL,
		(void *)&test_encrypted_08_state),
	};

	total_tests += sizeof(blackbox_encrypted_storage_tests) / sizeof(blackbox_encrypted_storage_tests[0]);

	return cmocka_run_group_tests(blackbox_encrypted_storage_tests, NULL, NULL);
}
