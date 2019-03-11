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
#include "test_cases_encrypted_storage.h"
#include "execute_tests.h"
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

static struct sync_flag nut_reachable_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag peer_reachable_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static bool nut_reachable_status;
static bool peer_reachable_status;

static void logger(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	fprintf(stderr, "[%s]: %s\n", mesh ? mesh->name : "NULL", text);
}

static void node_status(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	if(!strcmp(mesh->name, "nut") && !strcmp(node->name, "peer")) {
		peer_reachable_status = reachable;
		set_sync_flag(&peer_reachable_cond, true);
	} else if(!strcmp(mesh->name, "peer") && !strcmp(node->name, "nut")) {
		nut_reachable_status = reachable;
		set_sync_flag(&nut_reachable_cond, true);
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

	mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, "right", 5);
	assert_int_not_equal(mesh, NULL);

	meshlink_close(mesh);
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
	meshlink_errno = MESHLINK_OK;
	int ret = system("rm -rf directory");
	assert(mkdir("directory", 0777) != -1);

	meshlink_handle_t *mesh = meshlink_open_encrypted("directory", "nut", "test", DEV_CLASS_BACKBONE, "right", 5);
	assert_int_not_equal(mesh, NULL);

	meshlink_close(mesh);
	assert(meshlink_destroy("directory"));
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
	meshlink_handle_t *mesh1 = meshlink_open_encrypted("encrypted_conf.1", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	meshlink_handle_t *mesh2 = meshlink_open_encrypted("encrypted_conf.2", "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
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

	mesh1 = meshlink_open_encrypted("encrypted_conf.1", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	mesh2 = meshlink_open_encrypted("encrypted_conf.2", "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
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

	meshlink_handle_t *mesh1 = meshlink_open_encrypted("encrypted_conf.1", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	meshlink_handle_t *mesh2 = meshlink_open_encrypted("encrypted_conf.2", "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert(mesh1);
	assert(mesh2);

	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);
	meshlink_set_log_cb(mesh2, MESHLINK_DEBUG, logger);
	meshlink_set_node_status_cb(mesh1, node_status);
	meshlink_set_node_status_cb(mesh2, node_status);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	char *invitation = meshlink_invite_ex(mesh2, NULL, "nut", MESHLINK_INVITE_LOCAL | MESHLINK_INVITE_NUMERIC);
	assert_int_not_equal(invitation, NULL);

	// Start peer node instance

	assert(meshlink_start(mesh2));

	// Join NUT node with peer node

	assert_int_equal(meshlink_join(mesh1, invitation), true);

	set_sync_flag(&peer_reachable_cond, false);
	set_sync_flag(&nut_reachable_cond, false);

	// Start NUT node instance

	assert(meshlink_start(mesh1));

	// Wait for NUT and Peer node status callback to be invoked

	wait_sync_flag(&peer_reachable_cond, 5);
	wait_sync_flag(&nut_reachable_cond, 5);
	assert_int_equal(peer_reachable_status, true);
	assert_int_equal(nut_reachable_status, true);

	// Close NUT node instance

	meshlink_close(mesh1);

	// Reopen NUT node

	mesh1 = meshlink_open_encrypted("encrypted_conf.1", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_not_equal(mesh1, NULL);
	meshlink_set_node_status_cb(mesh1, node_status);
	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);

	// Assert on node handles

	assert_int_not_equal(meshlink_get_node(mesh1, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh1, "peer"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "peer"), NULL);

	set_sync_flag(&peer_reachable_cond, false);
	set_sync_flag(&nut_reachable_cond, false);

	// Restart NUT node instance

	assert(meshlink_start(mesh1));

	// Wait for NUT and Peer node status callback to be invoked

	wait_sync_flag(&peer_reachable_cond, 5);
	wait_sync_flag(&nut_reachable_cond, 5);
	assert_int_equal(peer_reachable_status, true);
	assert_int_equal(nut_reachable_status, true);

	// Close Peer node instance

	meshlink_close(mesh2);

	// Reopen peer node instance

	mesh2 = meshlink_open_encrypted("encrypted_conf.2", "peer", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_not_equal(mesh2, NULL);
	meshlink_set_node_status_cb(mesh2, node_status);
	meshlink_set_log_cb(mesh2, MESHLINK_DEBUG, logger);

	assert_int_not_equal(meshlink_get_node(mesh1, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh1, "peer"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "nut"), NULL);
	assert_int_not_equal(meshlink_get_node(mesh2, "peer"), NULL);

	set_sync_flag(&peer_reachable_cond, false);
	set_sync_flag(&nut_reachable_cond, false);

	// Restart peer node instance

	assert(meshlink_start(mesh2));

	// Wait for NUT and Peer node status callback to be invoked

	wait_sync_flag(&nut_reachable_cond, 5);
	wait_sync_flag(&peer_reachable_cond, 5);
	assert_int_equal(peer_reachable_status, true);
	assert_int_equal(nut_reachable_status, true);

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

	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
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

	mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
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
	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf.4", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert(mesh);

	// Open NUT node instance again

	meshlink_handle_t *mesh_dup = meshlink_open_encrypted("encrypted_conf.4", "nut", "test", DEV_CLASS_BACKBONE, key, keylen);
	assert_int_equal(mesh_dup, NULL);

	// Cleanup

	meshlink_close(mesh);
	meshlink_destroy("encrypted_conf.4");
	return true;
}

/* Execute encrypted storage Test Case # 8 */
static void test_case_encrypted_storage_08(void **state) {
	execute_test(test_steps_encrypted_storage_08, state);
}

/* Test Steps for encrypted storage Test Case # 8
    Entropy test of meshlink's key

    Test Steps:
    1. Open meshlink node instance with encrypted files configuration of key
        with varied sizes i.e 8, 16, 32, ... 2048 bytes.

    Expected Result:
    On opening meshlink with key of varied sizes should succeed.
*/
static bool test_steps_encrypted_storage_08(void) {
	char key[2048];
	int keysize;
	meshlink_handle_t *mesh;
	meshlink_node_t *node;

	memset(key, 'a', 2048);
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);

	for(keysize = 8; keysize <= 2048; keysize = keysize * 2) {
		meshlink_destroy("encrypted_conf");
		mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
		assert_int_not_equal(mesh, NULL);
		node = meshlink_get_self(mesh);
		assert_int_not_equal(node, NULL);
		assert_int_equal(strcmp(node->name, "nut"), 0);
		meshlink_close(mesh);
	}

	meshlink_destroy("encrypted_conf");
	return true;
}

/* Finding edit distance of two encrypted file configurations using Hamming distance of fixed size */
int hamming_distance(uint8_t *x, uint8_t *y, int n) {
	int i, count = 0;

	for(i = 0; i < n; i++) {
		count += __builtin_popcount(x[i] ^ y[i]);
	}

	float coeff;
	coeff = 100 * ((float)count / (n * 8));

	return (int)coeff;
}

/* Execute encrypted storage Test Case # 09 */
static void test_case_encrypted_storage_09(void **state) {
	execute_test(test_steps_encrypted_storage_09, state);
}

/* Test Steps for encrypted storage Test Case # 9
    Updating the encrypted configuration file several times, and the decrypted contents
    of the last version is almost identical to the first but the files on disk will be
    different after all.

    Test Steps:
    1. Open node instance and close the node after creating it.
    2. Allocate and store the encrypted config file.
    3. Reopen the node instance and change the port number and close it.
    4. Repeat step 2.
    5. Repeat step 3 & 4 with a different port number now.
    6. Measure the metric of similarity between 2 encrypted file configurations
        using the Hamming distance.

    Expected Result:
    All the encrypted files should see a difference of at least 25% of the bits.
*/
static bool test_steps_encrypted_storage_09(void) {
	char key[] = "encryptionkey";
	int keysize = sizeof(key);
	int fd, minsize, file_metric;
	uint8_t *conf_file1, *conf_file2, *conf_file3;
	long long conf_file1_size, conf_file2_size, conf_file3_size;
	struct stat file_stat;
	char *host_path = "encrypted_conf.7/hosts/nut";
	meshlink_handle_t *mesh;

	meshlink_destroy("encrypted_conf.7");

	// Open node instance

	mesh = meshlink_open_encrypted("encrypted_conf.7", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert_int_not_equal(mesh, NULL);
	meshlink_close(mesh);

	// Allocate and store the encrypted host file configuration

	assert(!stat(host_path, &file_stat));
	conf_file1_size = file_stat.st_size;
	fprintf(stderr, "file_stat.st_size : %lld\n", conf_file1_size);
	conf_file1 = malloc(conf_file1_size);
	assert(conf_file1);

	fd = open(host_path, O_RDONLY);
	assert(fd != -1);
	assert(read(fd, conf_file1, conf_file1_size) != -1);
	close(fd);

	// Reopen node instance

	mesh = meshlink_open_encrypted("encrypted_conf.7", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert_int_not_equal(mesh, NULL);

	// Change meshlink listening port and close it

	assert(meshlink_set_port(mesh, 1922));
	meshlink_close(mesh);

	// Allocate and store the encrypted host file configuration

	assert(!stat(host_path, &file_stat));
	conf_file2_size = file_stat.st_size;
	conf_file2 = malloc(conf_file2_size);
	assert(conf_file2);

	fd = open(host_path, O_RDONLY);
	assert(fd != -1);
	assert(read(fd, conf_file2, conf_file2_size) != -1);
	close(fd);

	// Reopen node instance

	mesh = meshlink_open_encrypted("encrypted_conf.7", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert_int_not_equal(mesh, NULL);

	// Change meshlink listening port and close it

	assert(meshlink_set_port(mesh, 55922));
	meshlink_close(mesh);

	// Allocate and store the encrypted host file configuration

	assert(!stat(host_path, &file_stat));
	conf_file3_size = file_stat.st_size;
	conf_file3 = malloc(conf_file3_size);
	assert(conf_file3);

	fd = open(host_path, O_RDONLY);
	assert(fd != -1);
	assert(read(fd, conf_file3, conf_file3_size) != -1);
	close(fd);

	// Calculate dissimilarity between 1st encrypted file and 2nd encrypted file

	if(conf_file1_size <= conf_file2_size) {
		minsize = conf_file1_size;
	} else {
		minsize = conf_file2_size;
	}

	file_metric = hamming_distance(conf_file1, conf_file2, minsize);

	assert_in_range(file_metric, 25, 100);

	// Calculate dissimilarity between 1st encrypted file and 3rd encrypted file

	if(conf_file1_size <= conf_file3_size) {
		minsize = conf_file1_size;
	} else {
		minsize = conf_file3_size;
	}

	file_metric = hamming_distance(conf_file1, conf_file3, minsize);

	assert_in_range(file_metric, 25, 100);

	// Cleanup

	free(conf_file1);
	free(conf_file2);
	free(conf_file3);

	return true;
}

/* Execute encrypted storage Test Case # 10 - API synchronization tests */
static void test_case_encrypted_storage_10(void **state) {
	execute_test(test_steps_encrypted_storage_10, state);
}

/* Test Steps for encrypted storage Test Case # 10
    @ meshlink_open_encrypted @ sync test

    Test Steps:
    1. Open node instance using @ meshlink_open_encrypted @ API and terminate immediately
        on API returning by sending SIGINT.
    2. Test driver reopens the node instance

    Expected Result:
    Test driver should successfully be able to open the node which's terminated abruptly after
    calling @ meshlink_open_encrypted @
*/
static bool test_steps_encrypted_storage_10(void) {
	char key[] = "encryptionkey";
	int keysize = sizeof(key);
	int fd, child_ret;
	pid_t pid;
	meshlink_handle_t *mesh;
	meshlink_handle_t *mesh1;
	meshlink_node_t *node;

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_destroy("encrypted_conf");

	// Create node instance in a separate child process

	pid = fork();
	assert(pid != -1);

	if(pid == 0) {
		mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
		assert(mesh);

		// Raise SIGINT signal after opening open API
		assert(!raise(SIGINT));
		abort();
	}

	// Wait for child process to terminate

	assert(waitpid(pid, &child_ret, 0) != -1);

	// Check whether it raised SIGINT or terminated on failure by raising SIGABRT.

	assert(WIFSIGNALED(child_ret) && (WTERMSIG(child_ret) == SIGINT));

	// Reopen node instance

	mesh = meshlink_open_encrypted("encrypted_conf", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert_int_not_equal(mesh, NULL);

	// Cleanup

	meshlink_close(mesh);

	return true;
}

/* Execute encrypted storage Test Case # 11 - API synchronization tests */
static void test_case_encrypted_storage_11(void **state) {
	execute_test(test_steps_encrypted_storage_11, state);
}

/* Test Steps for encrypted storage Test Case # 11
    @ meshlink_join @ sync test

    Test Steps:
    1. In the child process open NUT & peer nodes and on joining then terminate immediately
        on API returning by sending SIGINT.
    2. Test driver reopens the NUT and peer node instances.
    3. Conditional wait for peer node reachable status

    Expected Result:
    Test driver should successfully find peer node reachable status at NUT node which's
    terminated abruptly after calling @ meshlink_join @
*/
static bool test_steps_encrypted_storage_11(void) {
	char key[] = "encryptionkey";
	int keysize = sizeof(key);
	int child_ret;
	pid_t pid;

	meshlink_destroy("encrypted_conf.8");
	meshlink_destroy("encrypted_conf_peer.1");
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_errno = MESHLINK_OK;

	// Create node instance in a separate child process

	pid = fork();
	assert(pid != -1);

	if(pid == 0) {

		// Open, run nut node instance and create invitation for peer node to join

		meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf.8", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
		assert(mesh);
		char *invitation = meshlink_invite(mesh, NULL, "peer");
		meshlink_set_node_status_cb(mesh, node_status);
		meshlink_enable_discovery(mesh, false);
		assert(meshlink_start(mesh));

		// Open peer node and join NUT node

		meshlink_handle_t *mesh1 = meshlink_open_encrypted("encrypted_conf_peer.1", "peer", "test", DEV_CLASS_BACKBONE, key, keysize);
		assert(mesh1);
		meshlink_join(mesh1, invitation);

		// Raise SIGINT signal after opening open API
		assert(!raise(SIGINT));
		abort();
	}

	// Wait for child process to terminate assert on generated signal

	assert(waitpid(pid, &child_ret, 0) != -1);
	assert(WIFSIGNALED(child_ret) && (WTERMSIG(child_ret) == SIGINT));

	// Open NUT and peer node instances

	meshlink_handle_t *mesh1 = meshlink_open_encrypted("encrypted_conf_peer.1", "peer", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert_int_not_equal(mesh1, NULL);
	meshlink_enable_discovery(mesh1, false);
	meshlink_set_log_cb(mesh1, MESHLINK_DEBUG, logger);
	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf.8", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert_int_not_equal(mesh, NULL);
	meshlink_enable_discovery(mesh, false);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, logger);

	set_sync_flag(&peer_reachable_cond, false);

	// Start all nodes

	assert(meshlink_start(mesh));
	assert(meshlink_start(mesh1));

	// Check whether @ meshlink_join @ API succeeded in joining peer node from
	// node reachable callback at nut node.

	wait_sync_flag(&peer_reachable_cond, 5);
	assert_int_equal(peer_reachable_status, true);

	return true;
}

/* Execute encrypted storage Test Case # 12 - API synchronization tests */
static void test_case_encrypted_storage_12(void **state) {
	execute_test(test_steps_encrypted_storage_12, state);
}

/* Test Steps for encrypted storage Test Case # 12
    @ meshlink_invite @ sync test

    Test Steps:
    1. In the child process open NUT node & invite peer node, terminate immediately
        on API returning by sending SIGINT.
    2. Test driver opens the NUT and peer node instances.
    3. Peer node join NUT with invitation generated in child.
    4. Conditional wait for peer node reachable status

    Expected Result:
    @ meshlink_invite @ should generate invitation and save it it's config directory and
    on reusing the generated invitation it should succeed.
*/
static bool test_steps_encrypted_storage_12(void) {
	char key[] = "encryptionkey";
	int keysize = sizeof(key);
	int child_ret;
	pid_t pid;
	meshlink_handle_t *mesh;
	meshlink_handle_t *mesh1;
	meshlink_node_t *node;
	int pipefd[2];

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger);
	meshlink_destroy("encrypted_conf.8");
	meshlink_destroy("encrypted_conf.9");

	// Open a unnamed pipe for IPC

	assert(!pipe(pipefd));

	// Create node instance in a separate child process

	pid = fork();
	assert(pid != -1);

	if(pid == 0) {
		close(pipefd[0]);

		// Open NUT node instance

		mesh = meshlink_open_encrypted("encrypted_conf.8", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
		assert(mesh);

		// Invite peer node and write it into the pipe

		char *invitation = meshlink_invite(mesh, NULL, "peer");
		assert(write(pipefd[1], invitation, strlen(invitation) + 1) != -1);

		// Raise SIGINT signal after opening open API

		assert(!raise(SIGINT));
		abort();
	}

	close(pipefd[1]);

	// Wait for child process to terminate assert on generated signal

	assert(waitpid(pid, &child_ret, 0) != -1);
	assert(WIFSIGNALED(child_ret) && (WTERMSIG(child_ret) == SIGINT));

	// Read the invitation from the pipe

	char invitation_buff[200];
	assert(read(pipefd[0], invitation_buff, 200) != -1);

	// Open peer and NUT node instances and join peer with the obtained invitation.

	mesh = meshlink_open_encrypted("encrypted_conf.8", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert(mesh);
	mesh1 = meshlink_open_encrypted("encrypted_conf.9", "peer", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert(mesh1);
	assert(meshlink_start(mesh));
	bool join_status = meshlink_join(mesh1, invitation_buff);
	assert_int_equal(join_status, true);
	node = meshlink_get_node(mesh, "peer");
	assert_int_not_equal(node, NULL);

	// Cleanup

	meshlink_close(mesh);
	meshlink_close(mesh1);
	meshlink_destroy("encrypted_conf.8");
	meshlink_destroy("encrypted_conf.9");

	return true;
}

/* Execute encrypted storage Test Case # 13 - API synchronization tests */
static void test_case_encrypted_storage_13(void **state) {
	execute_test(test_steps_encrypted_storage_13, state);
}

/* Test Steps for encrypted storage Test Case # 13
    @ meshlink_set_port @ sync test

    Test Steps:
    1. In the child process open NUT node, set new meshlink listening port and terminate
        immediately on API returning by sending SIGINT.
    2. Test driver reopens node and get meshlink listening port

    Expected Result:
    Meshlink should see the new port that's being set as node's listening.
*/
static bool test_steps_encrypted_storage_13(void) {
	char key[] = "encryptionkey";
	int keysize = sizeof(key);
	int child_ret;
	pid_t pid;
	meshlink_handle_t *mesh;

	meshlink_destroy("encrypted_conf.8");

	// Create node instance in a separate child process

	pid = fork();
	assert(pid != -1);

	if(pid == 0) {

		// Open NUT node instance and set a new listening port number
		mesh = meshlink_open_encrypted("encrypted_conf.8", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
		assert(mesh);
		bool set_port_status = meshlink_set_port(mesh, 1111);
		assert(set_port_status);
		assert(!raise(SIGINT));
		abort();
	}

	assert(waitpid(pid, &child_ret, 0) != -1);
	assert(WIFSIGNALED(child_ret) && (WTERMSIG(child_ret) == SIGINT));

	// Reopen NUT node

	mesh = meshlink_open_encrypted("encrypted_conf.8", "nut", "test", DEV_CLASS_BACKBONE, key, keysize);
	assert(mesh);

	// Obtain meshlink listening port and verify the port being set using @ meshlink_set_port @
	// succeeded or not

	int port = meshlink_get_port(mesh);
	assert_int_equal(port, 1111);

	// Cleanup

	meshlink_close(mesh);
	meshlink_destroy("encrypted_conf.8");
	return true;
}

/* Execute encrypted storage Test Case # 14 - API synchronization tests */
static void test_case_encrypted_storage_14(void **state) {
	execute_test(test_steps_encrypted_storage_14, state);
}

/* Test Steps for encrypted storage Test Case # 14
    @ meshlink_set_canonical_address @ sync test

    Test Steps:
    1. In the child process open NUT node, set new canonical address and terminate
        immediately on API returning by sending SIGINT.
    2. Test driver reopens node and generates an invitation.

    Expected Result:
    @ meshlink_set_canonical_address @ should persist the address being set and on restarting
    node the invitation should have the canonical address being set previously.
*/
static bool test_steps_encrypted_storage_14(void) {
	char key[] = "encryptionkey";
	int keysize = sizeof(key);
	int child_ret;
	pid_t pid;
	meshlink_handle_t *mesh;
	meshlink_node_t *node;

	meshlink_destroy("encrypted_conf.8");

	// Create node instance in a separate child process

	pid = fork();
	assert(pid != -1);

	if(pid == 0) {

		// Set canonical address
		mesh = meshlink_open("encrypted_conf.8", "nut", "test", DEV_CLASS_BACKBONE);
		assert(mesh);
		node = meshlink_get_self(mesh);
		meshlink_set_canonical_address(mesh, node, "111.111.111.111", "11111");

		assert(!raise(SIGINT));
		abort();
	}

	assert(waitpid(pid, &child_ret, 0) != -1);
	assert(WIFSIGNALED(child_ret) && (WTERMSIG(child_ret) == SIGINT));

	// Reopen NUT node and generate an invitation

	mesh = meshlink_open("encrypted_conf.8", "nut", "test", DEV_CLASS_BACKBONE);
	assert(mesh);
	char *invitation = meshlink_invite(mesh, NULL, "peer");
	assert(invitation);

	// Check the canonical address is persisted and found in the invitation generated

	char *found = strstr(invitation, "111.111.111.111");
	assert_int_not_equal(found, NULL);

	// Cleanup

	free(invitation);
	meshlink_close(mesh);
	meshlink_destroy("encrypted_conf.8");

	return true;
}

int test_meshlink_encrypted_storage(void) {

	/* State structures for encrypted storage Test Cases */
	black_box_state_t test_encrypted_01_state = {
		.test_case_name = "test_case_encrypted_storage_01",
	};
	black_box_state_t test_encrypted_02_state = {
		.test_case_name = "test_case_encrypted_storage_02",
	};
	black_box_state_t test_encrypted_03_state = {
		.test_case_name = "test_case_encrypted_storage_03",
	};
	black_box_state_t test_encrypted_04_state = {
		.test_case_name = "test_case_encrypted_storage_04",
	};
	black_box_state_t test_encrypted_05_state = {
		.test_case_name = "test_case_encrypted_storage_05",
	};
	black_box_state_t test_encrypted_06_state = {
		.test_case_name = "test_case_encrypted_storage_06",
	};
	black_box_state_t test_encrypted_07_state = {
		.test_case_name = "test_case_encrypted_storage_07",
	};
	black_box_state_t test_encrypted_08_state = {
		.test_case_name = "test_case_encrypted_storage_08",
	};
	black_box_state_t test_encrypted_09_state = {
		.test_case_name = "test_case_encrypted_storage_09",
	};
	black_box_state_t test_encrypted_10_state = {
		.test_case_name = "test_case_encrypted_storage_10",
	};
	black_box_state_t test_encrypted_11_state = {
		.test_case_name = "test_case_encrypted_storage_11",
	};
	black_box_state_t test_encrypted_12_state = {
		.test_case_name = "test_case_encrypted_storage_12",
	};
	black_box_state_t test_encrypted_13_state = {
		.test_case_name = "test_case_encrypted_storage_13",
	};
	black_box_state_t test_encrypted_14_state = {
		.test_case_name = "test_case_encrypted_storage_14",
	};

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
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_09, NULL, NULL,
		                (void *)&test_encrypted_09_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_10, NULL, NULL,
		                (void *)&test_encrypted_10_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_11, NULL, NULL,
		                (void *)&test_encrypted_11_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_12, NULL, NULL,
		                (void *)&test_encrypted_12_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_13, NULL, NULL,
		                (void *)&test_encrypted_13_state),
		cmocka_unit_test_prestate_setup_teardown(test_case_encrypted_storage_14, NULL, NULL,
		                (void *)&test_encrypted_14_state),
	};

	total_tests += sizeof(blackbox_encrypted_storage_tests) / sizeof(blackbox_encrypted_storage_tests[0]);

	return cmocka_run_group_tests(blackbox_encrypted_storage_tests, NULL, NULL);
}
