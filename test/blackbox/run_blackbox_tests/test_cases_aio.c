/*
    test_cases_aio.c -- Execution of specific meshlink black box test cases
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

#include "execute_tests.h"
#include "test_cases_aio.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../../utils.h"
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <pthread.h>
#include <cmocka.h>
#include <limits.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <wait.h>
#include <linux/limits.h>

/* Modify this to change the logging level of Meshlink */
#define TEST_MESHLINK_LOG_LEVEL MESHLINK_DEBUG
/* Modify this to change the port number */
#define PORT 8000

#define NUT                         "nut"
#define PEER                        "peer"
#define TEST_AIO                    "test_aio"
#define AIO_TEST_SEND_FILE_NAME     "file.txt"
#define AIO_TEST_RECV_FILE_NAME     "file_recv.txt"
#define KILO_BYTES                  1024
#define MEGA_BYTES                  1024 * KILO_BYTES
#define GIGA_BYTES                  1024 * MEGA_BYTES
#define PEER_NODES                  5
#define AIO_FILE_SIZE               2 * MEGA_BYTES
#define TOTAL_CHANNELS              5

#define create_path(confbase, node_name, test_case_no)   assert(snprintf(confbase, sizeof(confbase), TEST_AIO "_%ld_%s_%02d", (long) getpid(), node_name, test_case_no) > 0)

static struct sync_flag peer_reachable_status_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static bool peer_reachable_status;
static struct sync_flag nut_reachable_status_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static bool nut_reachable_status;
static struct sync_flag peer_accept_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag send_fd_cb_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag recv_fd_cb_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

typedef struct {
	int fd;
	int expected_aio_cb_len;
	int received_aio_cb_len;
	int cb_count;
	struct sync_flag *cond;
} aio_data_t;

typedef struct {
	int received_channel_cb_len;
	int total_received_channel_cb_len;
	int channel_cb_count;
} channel_recv_data_t;

static long int find_file_size(const char *file_name) {
	struct stat st;

	if(stat(file_name, &st) == 0) {
		return (st.st_size);
	}

	return -1;
}

/* Node reachable status callback which signals the respective conditional varibale */
static void meshlink_node_reachable_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable_status) {
	if(!strcasecmp(mesh->name, NUT)) {
		if(!strcasecmp(node->name, PEER)) {
			peer_reachable_status = reachable_status;
			set_sync_flag(&peer_reachable_status_cond, true);
		}
	} else if(!strcasecmp(mesh->name, PEER)) {
		if(!strcasecmp(node->name, NUT)) {
			nut_reachable_status = reachable_status;
			set_sync_flag(&nut_reachable_status_cond, true);
		}
	}
}

static void channel_receive_fail_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	fail();
}

static void channel_receive_ignore_data_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	if(!len) {
		fail();
	}
}

static void channel_closure_ignore_data_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	if(len) {
		fail();
	}
}

static void node_reachable_fail_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable_status) {
	fail();
}

static bool channel_accept(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;

	//assert_int_equal(port, PORT);
	meshlink_set_channel_receive_cb(mesh, channel, channel_receive_fail_cb);
	channel->node->priv = channel;
	set_sync_flag(&peer_accept_cond, true);
	return true;
}

static void file_allocate(const char *file_name, size_t len) {
	struct stat st;

	char fallocate_cmd[PATH_MAX + 1000];
	snprintf(fallocate_cmd, sizeof(fallocate_cmd), "dd if=/dev/zero of=%s bs=%d count=1", file_name, len);
	//snprintf(fallocate_cmd, sizeof(fallocate_cmd), "fallocate -l %s %lu", file_name, len);
	assert_int_equal(system(fallocate_cmd), 0);
	assert_int_equal(stat(file_name, &st), 0);
	assert_int_equal(st.st_size, len);

}

static void aio_fd_send_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	aio_data_t *aio_data = (aio_data_t *)priv;
	assert(aio_data);
	aio_data->cb_count++;
	assert_int_equal(fd, aio_data->fd);
	assert_int_equal(len, aio_data->expected_aio_cb_len);
	set_sync_flag(&send_fd_cb_cond, true);
	return;
}

static void aio_fd_recv_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	aio_data_t *aio_data = (aio_data_t *)priv;
	assert(aio_data);
	aio_data->cb_count++;
	assert_int_equal(fd, aio_data->fd);
	assert_int_equal(len, aio_data->expected_aio_cb_len);

	if(aio_data->cond) {
		set_sync_flag(aio_data->cond, true);
	}

	set_sync_flag(&recv_fd_cb_cond, true);
	return;
}

static void regular_file_transfer(meshlink_handle_t *mesh, meshlink_channel_t *channel, meshlink_handle_t *mesh_peer, meshlink_channel_t *channel_peer, const char *tx_file_name, const char *rx_file_name, size_t file_len, int timeout) {
	aio_data_t aio_send_data = { 0 };
	aio_data_t aio_recv_data = { 0 };

	file_allocate(tx_file_name, file_len);

	int fd_send = open(tx_file_name, O_RDONLY);
	int fd_recv = open(rx_file_name,  O_CREAT | O_RDWR | O_TRUNC, 0644);


	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	aio_send_data.fd = fd_send;
	aio_recv_data.fd = fd_recv;
	aio_send_data.expected_aio_cb_len = file_len;
	aio_recv_data.expected_aio_cb_len = file_len;

	assert_true(meshlink_channel_aio_fd_receive(mesh_peer, channel_peer, fd_recv, file_len, aio_fd_recv_cb, &aio_recv_data));
	assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd_send, file_len, aio_fd_send_cb, &aio_send_data));

	assert_true(wait_sync_flag(&send_fd_cb_cond, timeout));
	assert_true(wait_sync_flag(&recv_fd_cb_cond, timeout));

	// sleep(5);

	assert_int_equal(aio_send_data.cb_count, 1);
	assert_int_equal(aio_recv_data.cb_count, 1);
	assert_int_equal(close(fd_send), 0);
	assert_int_equal(close(fd_recv), 0);
	assert_int_equal(unlink(tx_file_name), 0);
	assert_int_equal(unlink(rx_file_name), 0);
}

/* Test Steps for meshlink AIO Test Case # 1 - Regular file transfer of varied sized files using AIO
*/
static void test_aio_01(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 5);
	create_path(peer_confbase, PEER, 5);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_channel_accept_cb(mesh_peer, channel_accept);

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	meshlink_node_t *node_peer = meshlink_get_node(mesh_peer, NUT);

	// Bring nodes online.

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));
	assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
	assert_true(peer_reachable_status);
	assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
	assert_true(nut_reachable_status);
	meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
	meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);

	meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
	assert_non_null(channel);

	assert_true(wait_sync_flag(&peer_accept_cond, 10));
	meshlink_channel_t *channel_peer = node_peer->priv;


	// Regular file transfer of 1 byte

	regular_file_transfer(mesh, channel, mesh_peer, channel_peer, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, 1, 60);

	// Regular file transfer of 100 bytes

	regular_file_transfer(mesh, channel, mesh_peer, channel_peer, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, 100, 60);

	// Regular file transfer of 1 kilo byte

	regular_file_transfer(mesh, channel, mesh_peer, channel_peer, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, KILO_BYTES, 60);

	// Regular file transfer of 100 kilo bytes

	regular_file_transfer(mesh, channel, mesh_peer, channel_peer, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, 100 * KILO_BYTES, 60);

	// Regular file transfer of 1 mega byte

	regular_file_transfer(mesh, channel, mesh_peer, channel_peer, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, MEGA_BYTES, 60);

	// Regular file transfer of 100 mega bytes

	regular_file_transfer(mesh, channel, mesh_peer, channel_peer, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, 50 * MEGA_BYTES, 60);

	// Regular file transfer of 1 giga byte

	regular_file_transfer(mesh, channel, mesh_peer, channel_peer, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, GIGA_BYTES, 60);

	// Regular file transfer of 5 giga bytes

	regular_file_transfer(mesh, channel, mesh_peer, channel_peer, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, 5 * GIGA_BYTES, 60);

	// Bidirectional regular file transfer of 1 mega byte

	regular_file_transfer(mesh_peer, channel_peer, mesh, channel, AIO_TEST_SEND_FILE_NAME, AIO_TEST_RECV_FILE_NAME, MEGA_BYTES, 60);

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

/* Test Steps for meshlink AIO Test Case # 2 - Passing an invalid fd at AIO sending end
*/
static void test_aio_02(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 2);
	create_path(peer_confbase, PEER, 2);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_channel_accept_cb(mesh_peer, channel_accept);

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	meshlink_node_t *node_peer = meshlink_get_node(mesh_peer, NUT);

	// Bring nodes online.

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));
	assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
	assert_true(peer_reachable_status);
	assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
	assert_true(nut_reachable_status);
	meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
	meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);

	meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
	assert_non_null(channel);

	assert_true(wait_sync_flag(&peer_accept_cond, 10));
	meshlink_channel_t *channel_peer = node_peer->priv;


	aio_data_t aio_send_data = { 0 };

	int fd_send = 65533;
	set_sync_flag(&send_fd_cb_cond, false);
	aio_send_data.fd = fd_send;
	aio_send_data.expected_aio_cb_len = 0;

	assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd_send, 10000, aio_fd_send_cb, &aio_send_data));

	assert_true(wait_sync_flag(&send_fd_cb_cond, 60));

	// sleep(5);

	assert_int_equal(aio_send_data.cb_count, 1);

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

/* Test Steps for meshlink AIO Test Case # 3 - Passing an invalid fd at AIO receiving end
*/
static void test_aio_03(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 2);
	create_path(peer_confbase, PEER, 2);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_channel_accept_cb(mesh_peer, channel_accept);

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	meshlink_node_t *node_peer = meshlink_get_node(mesh_peer, NUT);

	// Bring nodes online.

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));
	assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
	assert_true(peer_reachable_status);
	assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
	assert_true(nut_reachable_status);
	meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
	meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);

	meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
	assert_non_null(channel);

	assert_true(wait_sync_flag(&peer_accept_cond, 10));
	meshlink_channel_t *channel_peer = node_peer->priv;

	meshlink_set_channel_receive_cb(mesh_peer, channel_peer, channel_receive_ignore_data_cb);

	aio_data_t aio_recv_data = { 0 };
	int fd_recv = 65533;

	set_sync_flag(&recv_fd_cb_cond, false);
	aio_recv_data.fd = fd_recv;
	aio_recv_data.expected_aio_cb_len = 0;
	assert_true(meshlink_channel_aio_fd_receive(mesh_peer, channel_peer, fd_recv, 1000, aio_fd_recv_cb, &aio_recv_data));

	char send_buf[] = "Hello!";
	assert_true(meshlink_channel_send(mesh, channel, send_buf, strlen(send_buf)));

	assert_true(wait_sync_flag(&recv_fd_cb_cond, 60));

	// sleep(5);

	assert_int_equal(aio_recv_data.cb_count, 1);

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

/* Test Steps for meshlink AIO Test Case # 4 - Passing an invalid fd i.e, here a directory file descriptor
*/
static void test_aio_04(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 2);
	create_path(peer_confbase, PEER, 2);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_channel_accept_cb(mesh_peer, channel_accept);

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	meshlink_node_t *node_peer = meshlink_get_node(mesh_peer, NUT);

	// Bring nodes online.

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));
	assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
	assert_true(peer_reachable_status);
	assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
	assert_true(nut_reachable_status);
	meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
	meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);

	meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
	assert_non_null(channel);

	assert_true(wait_sync_flag(&peer_accept_cond, 10));
	meshlink_channel_t *channel_peer = node_peer->priv;


	aio_data_t aio_send_data = { 0 };

	rmdir("test_dir");
	assert_int_equal(mkdir("test_dir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);
	int fd_send = open("test_dir", O_RDONLY);
	assert_int_not_equal(fd_send, -1);

	set_sync_flag(&send_fd_cb_cond, false);
	aio_send_data.fd = fd_send;
	aio_send_data.expected_aio_cb_len = 0;

	assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd_send, 1000, aio_fd_send_cb, &aio_send_data));

	assert_true(wait_sync_flag(&send_fd_cb_cond, 60));

	// sleep(5);

	assert_int_equal(aio_send_data.cb_count, 1);

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

static bool stop_aio_inflight(meshlink_handle_t *mesh, meshlink_channel_t *channel, meshlink_handle_t *mesh_peer, meshlink_channel_t *channel_peer,
                              aio_data_t *aio_send_data, aio_data_t *aio_recv_data, size_t file_len) {
	file_allocate(AIO_TEST_SEND_FILE_NAME, file_len);

	int fd_send = open(AIO_TEST_SEND_FILE_NAME, O_RDONLY);
	assert_int_not_equal(fd_send, -1);
	int fd_recv = open(AIO_TEST_RECV_FILE_NAME,  O_CREAT | O_RDWR | O_TRUNC, 0644);
	assert_int_not_equal(fd_recv, -1);

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	aio_send_data->fd = fd_send;
	aio_recv_data->fd = fd_recv;
	aio_send_data->expected_aio_cb_len = file_len;
	aio_recv_data->expected_aio_cb_len = file_len;

	assert_true(meshlink_channel_aio_fd_receive(mesh_peer, channel_peer, fd_recv, file_len, aio_fd_recv_cb, aio_recv_data));
	assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd_send, file_len, aio_fd_send_cb, aio_send_data));

	srand(getpid());
	//assert_int_equal(usleep(rand() % 1000000), 0);
	usleep(1000);

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_stop(mesh);

	if(check_sync_flag(&send_fd_cb_cond)) {
		meshlink_set_channel_receive_cb(mesh, channel, NULL);
		meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
		meshlink_channel_close(mesh, channel);
		meshlink_channel_close(mesh_peer, channel_peer);

		set_sync_flag(&peer_reachable_status_cond, false);
		set_sync_flag(&nut_reachable_status_cond, false);
		meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
		meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
		meshlink_start(mesh);
		assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
		assert_true(peer_reachable_status);
		assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
		assert_true(nut_reachable_status);
		meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
		meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);
		return false;
	} else {
		return true;
	}
}

/* Test Steps for meshlink AIO Test Case # 5 - Restarting a node while it's doing AIO transfer before 30 seconds
*/
static void test_aio_05(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 5);
	create_path(peer_confbase, PEER, 5);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_channel_accept_cb(mesh_peer, channel_accept);

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	meshlink_node_t *node_peer = meshlink_get_node(mesh_peer, NUT);

	// Bring nodes online.

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));
	assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
	assert_true(peer_reachable_status);
	assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
	assert_true(nut_reachable_status);
	meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
	meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);

	meshlink_channel_t *channel;
	meshlink_channel_t *channel_peer;
	int file_size = 1 * MEGA_BYTES;
	aio_data_t aio_send_data = { 0 };
	aio_data_t aio_recv_data = { 0 };

	unlink(AIO_TEST_SEND_FILE_NAME);
	unlink(AIO_TEST_RECV_FILE_NAME);

	for(int attempts = 0; attempts < 10; attempts++) {
		memset(&aio_send_data, 0, sizeof(aio_send_data));
		memset(&aio_recv_data, 0, sizeof(aio_recv_data));
		channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
		assert_non_null(channel);

		assert_true(wait_sync_flag(&peer_accept_cond, 10));
		channel_peer = node_peer->priv;

		if(stop_aio_inflight(mesh, channel, mesh_peer, channel_peer, &aio_send_data, &aio_recv_data, file_size)) {
			break;
		} else {
			file_size *= 2;
		}

		assert_int_not_equal(attempts, 9);
	}

	sleep(30);

	meshlink_start(mesh);

	assert_true(wait_sync_flag(&send_fd_cb_cond, 120));
	assert_true(wait_sync_flag(&recv_fd_cb_cond, 120));

	// sleep(5);

	assert_int_equal(aio_send_data.cb_count, 1);
	assert_int_equal(aio_recv_data.cb_count, 1);
	assert_int_equal(close(aio_send_data.fd), 0);
	assert_int_equal(close(aio_recv_data.fd), 0);
	assert_int_equal(find_file_size(AIO_TEST_SEND_FILE_NAME), file_size);
	assert_int_equal(find_file_size(AIO_TEST_RECV_FILE_NAME), file_size);
	assert_int_equal(unlink(AIO_TEST_SEND_FILE_NAME), 0);
	assert_int_equal(unlink(AIO_TEST_RECV_FILE_NAME), 0);

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

static void aio_fd_send_partial_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	aio_data_t *aio_data = (aio_data_t *)priv;
	assert(aio_data);
	aio_data->cb_count++;
	assert_int_equal(fd, aio_data->fd);
	aio_data->received_aio_cb_len = len;
	set_sync_flag(&send_fd_cb_cond, true);
	return;
}

static void aio_fd_recv_partial_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	aio_data_t *aio_data = (aio_data_t *)priv;
	assert(aio_data);
	aio_data->cb_count++;
	assert_int_equal(fd, aio_data->fd);
	aio_data->received_aio_cb_len = len;
	set_sync_flag(&recv_fd_cb_cond, true);
	return;
}

static bool close_aio_inflight(meshlink_handle_t *mesh, meshlink_channel_t *channel, meshlink_handle_t *mesh_peer, meshlink_channel_t *channel_peer,
                               aio_data_t *aio_send_data, aio_data_t *aio_recv_data, size_t file_len) {
	file_allocate(AIO_TEST_SEND_FILE_NAME, file_len);

	int fd_send = open(AIO_TEST_SEND_FILE_NAME, O_RDONLY);
	assert_int_not_equal(fd_send, -1);
	int fd_recv = open(AIO_TEST_RECV_FILE_NAME,  O_CREAT | O_RDWR | O_TRUNC, 0644);
	assert_int_not_equal(fd_recv, -1);

	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	aio_send_data->fd = fd_send;
	aio_recv_data->fd = fd_recv;

	assert_true(meshlink_channel_aio_fd_receive(mesh_peer, channel_peer, fd_recv, file_len, aio_fd_recv_partial_cb, aio_recv_data));
	assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd_send, file_len, aio_fd_send_partial_cb, aio_send_data));

	srand(getpid());
	//assert_int_equal(usleep(rand() % 1000000), 0);
	usleep(1000);

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
	meshlink_channel_close(mesh, channel);

	if(check_sync_flag(&recv_fd_cb_cond)) {
		meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
		meshlink_channel_close(mesh_peer, channel_peer);
		return false;
	} else {
		return true;
	}
}

/* Test Steps for meshlink AIO Test Case # 6 - Closing the channel of the node while it's doing AIO transfer
*/
static void test_aio_06(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 5);
	create_path(peer_confbase, PEER, 5);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_channel_accept_cb(mesh_peer, channel_accept);

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	meshlink_node_t *node_peer = meshlink_get_node(mesh_peer, NUT);

	// Bring nodes online.

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));
	assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
	assert_true(peer_reachable_status);
	assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
	assert_true(nut_reachable_status);
	meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
	meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);

	meshlink_channel_t *channel;
	meshlink_channel_t *channel_peer;
	int file_size = 1 * MEGA_BYTES;
	aio_data_t aio_send_data = { 0 };
	aio_data_t aio_recv_data = { 0 };


	for(int attempts = 0; attempts < 10; attempts++) {
		memset(&aio_send_data, 0, sizeof(aio_send_data));
		memset(&aio_recv_data, 0, sizeof(aio_recv_data));
		memset(&peer_accept_cond, 0, sizeof(peer_accept_cond));
		channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
		assert_non_null(channel);

		assert_true(wait_sync_flag(&peer_accept_cond, 10));
		channel_peer = node_peer->priv;

		if(close_aio_inflight(mesh, channel, mesh_peer, channel_peer, &aio_send_data, &aio_recv_data, file_size)) {
			break;
		} else {
			file_size *= 2;
		}

		assert_int_not_equal(attempts, 9);
	}

	assert_true(wait_sync_flag(&recv_fd_cb_cond, 120));
	assert_int_not_equal(aio_recv_data.received_aio_cb_len, file_size);

	// sleep(5);

	assert_int_equal(aio_recv_data.cb_count, 1);
	assert_int_equal(close(aio_recv_data.fd), 0);
	assert_int_equal(find_file_size(AIO_TEST_SEND_FILE_NAME), file_size);
	assert_int_not_equal(find_file_size(AIO_TEST_RECV_FILE_NAME), file_size);
	assert_int_equal(unlink(AIO_TEST_SEND_FILE_NAME), 0);
	assert_int_equal(unlink(AIO_TEST_RECV_FILE_NAME), 0);

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

size_t file_len2 = 1 * MEGA_BYTES;

static void aio_fd_recv_partial_fail_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	if(len == file_len2) {
		assert(raise(SIGKILL) != -1);
	} else {
		abort();
	}
	return;
}

static bool channel_accept2(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;
	assert_int_equal(port, PORT);
	meshlink_set_channel_receive_cb(mesh, channel, channel_receive_fail_cb);
	channel->node->priv = channel;

	int fd_recv = open(AIO_TEST_RECV_FILE_NAME,  O_CREAT | O_RDWR | O_TRUNC, 0644);
	assert(fd_recv != -1);

	assert(meshlink_channel_aio_fd_receive(mesh, channel, fd_recv, file_len2, aio_fd_recv_partial_fail_cb, NULL));

	set_sync_flag(&peer_accept_cond, true);
	return true;
}

/* Test Steps for meshlink AIO Test Case # 7 - Terminating the app node while it's doing AIO transfer
*/
static void test_aio_07(void **state) {
	bool status;
	pid_t pid;
	int pid_status;
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 7);
	create_path(peer_confbase, PEER, 7);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);

	meshlink_close(mesh);
	meshlink_close(mesh_peer);

	int file_size = 1 * MEGA_BYTES;
	aio_data_t aio_send_data = { 0 };
	aio_data_t aio_recv_data = { 0 };
	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);

	for(int attempts = 0; attempts < 10; attempts++) {
		pid = fork();
		assert_int_not_equal(pid, -1);

		if(!pid) {
			mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
			assert(mesh_peer);
			meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
			meshlink_set_channel_accept_cb(mesh_peer, channel_accept2);

			unlink(AIO_TEST_RECV_FILE_NAME);
			set_sync_flag(&nut_reachable_status_cond, false);
			meshlink_start(mesh_peer);
			assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
			assert_true(nut_reachable_status);
			assert_true(wait_sync_flag(&peer_accept_cond, 60));

			usleep(1000);

			raise(SIGINT);
		} else {
			mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
			assert_non_null(mesh);
			meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);

			set_sync_flag(&peer_reachable_status_cond, false);
			meshlink_node_t *node = meshlink_get_node(mesh, PEER);
			assert_true(meshlink_start(mesh));
			assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
			assert_true(peer_reachable_status);

			memset(&aio_send_data, 0, sizeof(aio_send_data));
			file_allocate(AIO_TEST_SEND_FILE_NAME, file_len2);

			int fd_send = open(AIO_TEST_SEND_FILE_NAME, O_RDONLY);
			assert_int_not_equal(fd_send, -1);

			set_sync_flag(&send_fd_cb_cond, false);
			aio_send_data.fd = fd_send;

			meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, NULL, NULL, 0, MESHLINK_CHANNEL_TCP);
			assert_non_null(channel);

			assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd_send, file_len2, aio_fd_send_partial_cb, &aio_send_data));

		}

		// Wait for child exit and verify which signal terminated it

		assert_int_not_equal(waitpid(pid, &pid_status, 0), -1);
		assert_int_equal(WIFSIGNALED(pid_status), true);

		if(WTERMSIG(pid_status) == SIGKILL) {
			assert_int_not_equal(attempts, 9);
			file_len2 *= 2;
			meshlink_close(mesh);
			continue;
		}

		assert_int_equal(WTERMSIG(pid_status), SIGINT);
		break;
	}

	assert_true(wait_sync_flag(&send_fd_cb_cond, 120));
	assert_int_not_equal(aio_send_data.received_aio_cb_len, file_size);

	// sleep(5);

	assert_int_equal(aio_send_data.cb_count, 1);
	assert_int_equal(close(aio_send_data.fd), 0);
	assert_int_equal(find_file_size(AIO_TEST_SEND_FILE_NAME), file_size);
	assert_int_not_equal(find_file_size(AIO_TEST_RECV_FILE_NAME), file_size);
	assert_int_equal(unlink(AIO_TEST_SEND_FILE_NAME), 0);
	assert_int_equal(unlink(AIO_TEST_RECV_FILE_NAME), 0);

	// Cleanup

	meshlink_close(mesh);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return true;
}

static struct sync_flag aio_tx_nut_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag aio_rx_peer_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static void aio_fd_multi_recv_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	assert_int_equal(len, AIO_FILE_SIZE);
	assert_int_equal(close(fd), 0);

	static int aio_recv_no;
	if(TOTAL_CHANNELS == ++aio_recv_no) {
		set_sync_flag(&aio_tx_nut_cond, true);
	}

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	return;
}

static void aio_fd_multi_send_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	assert_int_equal(len, AIO_FILE_SIZE);
	assert_int_equal(close(fd), 0);

	static int aio_send_no;
	if(TOTAL_CHANNELS == ++aio_send_no) {
		set_sync_flag(&aio_rx_peer_cond, true);
	}

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	return;
}

static bool channel_accept_08(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;

	char file_name[1000];
    sprintf(file_name, "%s.%hu", AIO_TEST_RECV_FILE_NAME, port);

    int fd = open(file_name, O_CREAT | O_RDWR | O_TRUNC, 0644);
	assert_int_not_equal(fd, -1);

    assert_true(meshlink_channel_aio_fd_receive(mesh, channel, fd, AIO_FILE_SIZE, aio_fd_multi_recv_cb, NULL));
	meshlink_set_channel_receive_cb(mesh, channel, channel_receive_fail_cb);

	return true;
}

/* Test Steps for meshlink AIO Test Case # 8 - Two nodes opening multiple AIO channels between them and transfer data simultaneously
*/
static void test_aio_08(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 5);
	create_path(peer_confbase, PEER, 5);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_channel_accept_cb(mesh_peer, channel_accept);

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	meshlink_node_t *node_peer = meshlink_get_node(mesh_peer, NUT);

	// Bring nodes online.

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	set_sync_flag(&peer_accept_cond, false);
	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	set_sync_flag(&aio_tx_nut_cond, false);
	set_sync_flag(&aio_rx_peer_cond, false);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));
	assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
	assert_true(peer_reachable_status);
	assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
	assert_true(nut_reachable_status);
	meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
	meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);

	meshlink_channel_t *channel[TOTAL_CHANNELS];
	char file_name[1000];

	for(int i = 0; i < TOTAL_CHANNELS; i++) {
		channel[i] = meshlink_channel_open_ex(mesh, node, i, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
		assert_non_null(channel[i]);
	}
	for(int i = 0; i < TOTAL_CHANNELS; i++) {
		sprintf(file_name, "%s.%d", AIO_TEST_SEND_FILE_NAME, i);
		file_allocate(file_name, AIO_FILE_SIZE);

		int fd = open(file_name, O_RDONLY);
		assert_int_not_equal(fd, -1);
        assert_true(meshlink_channel_aio_fd_send(mesh, channel[i], fd, AIO_FILE_SIZE, aio_fd_multi_send_cb, NULL));
	}

	for(int i = 0; i < TOTAL_CHANNELS; i++) {
		assert_true(wait_sync_flag(&aio_tx_nut_cond, 30));
		assert_true(wait_sync_flag(&aio_rx_peer_cond, 30));
	}

	for(int i = 0; i < TOTAL_CHANNELS; i++) {
		sprintf(file_name, "%s.%d", AIO_TEST_SEND_FILE_NAME, i);
		assert_int_equal(find_file_size(file_name), AIO_FILE_SIZE);
		assert_int_equal(unlink(file_name), 0);
		sprintf(file_name, "%s.%d", AIO_TEST_RECV_FILE_NAME, i);
		assert_int_equal(find_file_size(file_name), AIO_FILE_SIZE);
		assert_int_equal(unlink(file_name), 0);
	}

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

static struct sync_flag one_to_many_aio_tx_nut_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag one_to_many_aio_rx_peer_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static void aio_fd_recv_cb_8(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	assert_int_equal(len, MEGA_BYTES);
	assert_int_equal(close(fd), 0);

    static int aio_recv_no;
	if(PEER_NODES == ++aio_recv_no) {
		meshlink_set_node_status_cb(mesh, NULL);
		set_sync_flag(&one_to_many_aio_rx_peer_cond, true);
	}

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	return;
}

static void aio_fd_send_cb_8(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	assert_int_equal(len, MEGA_BYTES);
	assert_int_equal(close(fd), 0);

    static int aio_send_no;
	if(PEER_NODES == ++aio_send_no) {
		meshlink_set_node_status_cb(mesh, NULL);
		set_sync_flag(&one_to_many_aio_tx_nut_cond, true);
	}

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	return;
}

static bool channel_accept_3(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;

	//assert_int_equal(port, PORT);
	if(!strcasecmp(channel->node->name, NUT)) {
		meshlink_set_channel_receive_cb(mesh, channel, channel_receive_fail_cb);
		channel->node->priv = channel;

		char file_name[1000];
		sprintf(file_name, "aio_recv_%s_file.txt", mesh->name);

		unlink(file_name);
		int fd = open(file_name, O_CREAT | O_RDWR | O_TRUNC, 0644);
		assert_int_not_equal(fd, -1);

		assert_true(meshlink_channel_aio_fd_receive(mesh, channel, fd, MEGA_BYTES, aio_fd_recv_cb_8, NULL));
	}


	set_sync_flag(&peer_accept_cond, true);
	return true;
}

static void meshlink_node_reachable_status_cb_2(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable_status) {
	if(!strcmp(mesh->name, node->name)) {
		return;
	}

	if(!strcasecmp(mesh->name, NUT)) {
		if(reachable_status) {
			meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
			assert_non_null(channel);

			char file_name[1000];
			sprintf(file_name, "aio_send_%s_file.txt", node->name);
			file_allocate(file_name, MEGA_BYTES);

			int fd = open(file_name, O_RDONLY);
			assert_int_not_equal(fd, -1);

			assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd, MEGA_BYTES, aio_fd_send_cb_8, NULL));

		} else {
			fail();
		}
	}

	//meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
}

/* Test Steps for meshlink AIO Test Case # 9 - One node opening AIO channels and sending data to multiple peer nodes and transfer data simultaneously
*/
static void test_aio_09(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PEER_NODES][PATH_MAX];
	meshlink_handle_t *mesh_peer[PEER_NODES];
	create_path(nut_confbase, NUT, 8);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb_2);

	for(int i = 0; i < PEER_NODES; i++) {
		char peer_name[1000];
		sprintf(peer_name, "%s_%d", PEER, i);
		create_path(peer_confbase[i], peer_name, i);
		mesh_peer[i] = meshlink_open(peer_confbase[i], peer_name, TEST_AIO, DEV_CLASS_PORTABLE);
		assert_non_null(mesh_peer[i]);
		link_meshlink_pair(mesh, mesh_peer[i]);
		meshlink_set_node_status_cb(mesh_peer[i], meshlink_node_reachable_status_cb_2);
		meshlink_set_channel_accept_cb(mesh_peer[i], channel_accept_3);
	}

	meshlink_start(mesh);

	for(int i = 0; i < PEER_NODES; i++) {
		meshlink_start(mesh_peer[i]);
	}

	for(int i = 0; i < 5; i++) {
		assert_true(wait_sync_flag(&one_to_many_aio_tx_nut_cond, 120));
		assert_true(wait_sync_flag(&one_to_many_aio_rx_peer_cond, 120));
	}

	int nodes_count = 0;
	meshlink_node_t **nodes = meshlink_get_all_nodes(mesh, NULL, &nodes_count);
	assert_int_equal(PEER_NODES, nodes_count - 1);

	for(int i = 0; i < nodes_count; i++) {
		if(!strcmp(mesh->name, nodes[i]->name)) {
			continue;
		}

		char file_name[1000];
		sprintf(file_name, "aio_send_%s_file.txt", nodes[i]->name);
		assert_int_equal(find_file_size(file_name), MEGA_BYTES);
		assert_int_equal(unlink(file_name), 0);
		sprintf(file_name, "aio_recv_%s_file.txt", nodes[i]->name);
		assert_int_equal(find_file_size(file_name), MEGA_BYTES);
		assert_int_equal(unlink(file_name), 0);
	}

	meshlink_close(mesh);
	assert_true(meshlink_destroy(nut_confbase));

	for(int i = 0; i < 5; i++) {
		meshlink_close(mesh_peer[i]);
		assert_true(meshlink_destroy(peer_confbase));
	}

	return;
}

static struct sync_flag many_to_one_aio_tx_nut_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag many_to_one_aio_rx_peer_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static void aio_fd_recv_cb_9(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	assert_int_equal(len, MEGA_BYTES);
	assert_int_equal(close(fd), 0);

    static int aio_recv_no;
	if(PEER_NODES == ++aio_recv_no) {
		meshlink_set_node_status_cb(mesh, NULL);
		set_sync_flag(&many_to_one_aio_rx_peer_cond, true);
	}

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	return;
}

static void aio_fd_send_cb_9(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	assert_int_equal(len, MEGA_BYTES);
	assert_int_equal(close(fd), 0);

    static int aio_send_no;
	if(PEER_NODES == ++aio_send_no) {
		meshlink_set_node_status_cb(mesh, NULL);
		set_sync_flag(&many_to_one_aio_tx_nut_cond, true);
	}

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	return;
}

static bool channel_accept_4(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;

	//assert_int_equal(port, PORT);
	if(!strcasecmp(channel->node->name, NUT)) {

		char file_name[1000];
		sprintf(file_name, "aio_send_%s_file.txt", mesh->name);
		file_allocate(file_name, MEGA_BYTES);

		int fd = open(file_name, O_RDONLY);
		assert_int_not_equal(fd, -1);

		assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd, MEGA_BYTES, aio_fd_send_cb_9, NULL));
	}


	set_sync_flag(&peer_accept_cond, true);
	return true;
}

static void meshlink_node_reachable_status_cb_3(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable_status) {
	if(!strcmp(mesh->name, node->name)) {
		return;
	}

	if(!strcasecmp(mesh->name, NUT)) {
		if(reachable_status) {
			meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
			assert_non_null(channel);

			char file_name[1000];
			sprintf(file_name, "aio_recv_%s_file.txt", node->name);

			unlink(file_name);
			int fd = open(file_name, O_CREAT | O_RDWR | O_TRUNC, 0644);
			assert_int_not_equal(fd, -1);

			assert_true(meshlink_channel_aio_fd_receive(mesh, channel, fd, MEGA_BYTES, aio_fd_recv_cb_9, NULL));
		} else {
			fail();
		}
	}

	//meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
}

/* Test Steps for meshlink AIO Test Case # 10 - One node receiving data via AIO channels from multiple peer nodes and transfer data simultaneously
*/
static void test_aio_10(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PEER_NODES][PATH_MAX];
	meshlink_handle_t *mesh_peer[PEER_NODES];
	create_path(nut_confbase, NUT, 8);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb_3);

	for(int i = 0; i < PEER_NODES; i++) {
		char peer_name[1000];
		sprintf(peer_name, "%s_%d", PEER, i);
		create_path(peer_confbase[i], peer_name, i);
		mesh_peer[i] = meshlink_open(peer_confbase[i], peer_name, TEST_AIO, DEV_CLASS_PORTABLE);
		assert_non_null(mesh_peer[i]);
		link_meshlink_pair(mesh, mesh_peer[i]);
		meshlink_set_node_status_cb(mesh_peer[i], meshlink_node_reachable_status_cb_3);
		meshlink_set_channel_accept_cb(mesh_peer[i], channel_accept_4);

		/*char file_name[1000];
		sprintf(file_name, "aio_send_%s_file.txt", peer_name);
		file_allocate(file_name, MEGA_BYTES);*/
	}

	meshlink_start(mesh);

	for(int i = 0; i < PEER_NODES; i++) {
		meshlink_start(mesh_peer[i]);
	}

	for(int i = 0; i < 5; i++) {
		assert_true(wait_sync_flag(&many_to_one_aio_rx_peer_cond, 120));
		assert_true(wait_sync_flag(&many_to_one_aio_tx_nut_cond, 120));
	}

	int nodes_count = 0;
	meshlink_node_t **nodes = meshlink_get_all_nodes(mesh, NULL, &nodes_count);
	assert_int_equal(PEER_NODES, nodes_count - 1);

	for(int i = 0; i < nodes_count; i++) {
		if(!strcmp(mesh->name, nodes[i]->name)) {
			continue;
		}

		char file_name[1000];
		sprintf(file_name, "aio_send_%s_file.txt", nodes[i]->name);
		assert_int_equal(find_file_size(file_name), MEGA_BYTES);
		assert_int_equal(unlink(file_name), 0);
		sprintf(file_name, "aio_recv_%s_file.txt", nodes[i]->name);
		assert_int_equal(find_file_size(file_name), MEGA_BYTES);
		assert_int_equal(unlink(file_name), 0);
	}

	meshlink_close(mesh);
	assert_true(meshlink_destroy(nut_confbase));

	for(int i = 0; i < 5; i++) {
		meshlink_close(mesh_peer[i]);
		assert_true(meshlink_destroy(peer_confbase));
	}

	return;
}

static struct sync_flag many_to_many_aio_tx_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag many_to_many_aio_rx_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static void aio_fd_recv_cb_10(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	assert_int_equal(len, MEGA_BYTES);
	assert_int_equal(close(fd), 0);

    static int aio_recv_no;
	if((PEER_NODES - 1) * PEER_NODES == ++aio_recv_no) {
		meshlink_set_node_status_cb(mesh, NULL);
		set_sync_flag(&many_to_many_aio_rx_cond, true);
	}

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	return;
}

static void aio_fd_send_cb_10(meshlink_handle_t *mesh, meshlink_channel_t *channel, int fd, size_t len, void *priv) {
	assert_int_equal(len, MEGA_BYTES);
	assert_int_equal(close(fd), 0);

    static int aio_send_no;
	if((PEER_NODES - 1) * PEER_NODES == ++aio_send_no) {
		meshlink_set_node_status_cb(mesh, NULL);
		set_sync_flag(&many_to_many_aio_tx_cond, true);
	}

	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	return;
}


static bool channel_accept_5(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;

	//assert_int_equal(port, PORT);
	if(!strcasecmp(channel->node->name, NUT) || !strcmp(mesh->name, NUT)) {
		return;
	}

	char file_name[1000];
	sprintf(file_name, "aio_%s_%s_file.txt", mesh->name, channel->node->name);
	//file_allocate(file_name, MEGA_BYTES);

	unlink(file_name);

	int fd = open(file_name, O_CREAT | O_RDWR | O_TRUNC, 0644);
	assert_int_not_equal(fd, -1);

	assert_true(meshlink_channel_aio_fd_receive(mesh, channel, fd, MEGA_BYTES, aio_fd_recv_cb_10, NULL));

	fd = open(AIO_TEST_SEND_FILE_NAME, O_RDONLY, 0644);
	assert_int_not_equal(fd, -1);
	assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd, MEGA_BYTES, aio_fd_send_cb_10, NULL));

	return true;
}

static void meshlink_node_reachable_status_cb_4(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable_status) {
	if(!strcmp(mesh->name, node->name) || !strcmp(node->name, NUT)) {
		return;
	}

	if(reachable_status) {
		meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
		assert_non_null(channel);

		char file_name[1000];
		int fd;
		sprintf(file_name, "aio_%s_%s_file.txt", mesh->name, node->name);

		unlink(file_name);
		fd = open(file_name, O_CREAT | O_RDWR | O_TRUNC, 0644);
		assert_int_not_equal(fd, -1);

		assert_true(meshlink_channel_aio_fd_receive(mesh, channel, fd, MEGA_BYTES, aio_fd_recv_cb_10, NULL));


		fd = open(AIO_TEST_SEND_FILE_NAME, O_RDONLY, 0644);
		assert_int_not_equal(fd, -1);
		assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd, MEGA_BYTES, aio_fd_send_cb_10, NULL));
	} else {
		fail();
	}

	//meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
}

/* Test Steps for meshlink AIO Test Case # 11 - One node receiving data via AIO channels from multiple peer nodes and transfer data simultaneously
*/
static void test_aio_11(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PEER_NODES][PATH_MAX];
	meshlink_handle_t *mesh_peer[PEER_NODES];
	create_path(nut_confbase, NUT, 8);

	file_allocate(AIO_TEST_SEND_FILE_NAME, MEGA_BYTES);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);

	for(int i = 0; i < PEER_NODES; i++) {
		char peer_name[1000];
		sprintf(peer_name, "%s_%d", PEER, i);
		create_path(peer_confbase[i], peer_name, i);
		mesh_peer[i] = meshlink_open(peer_confbase[i], peer_name, TEST_AIO, DEV_CLASS_PORTABLE);
		assert_non_null(mesh_peer[i]);
		link_meshlink_pair(mesh, mesh_peer[i]);
		meshlink_set_node_status_cb(mesh_peer[i], meshlink_node_reachable_status_cb_4);
		meshlink_set_channel_accept_cb(mesh_peer[i], channel_accept_5);
	}

	meshlink_start(mesh);

	for(int i = 0; i < PEER_NODES; i++) {
		meshlink_start(mesh_peer[i]);
	}

	for(int i = 0; i < 5; i++) {
		assert_true(wait_sync_flag(&many_to_many_aio_tx_cond, 120));
		assert_true(wait_sync_flag(&many_to_many_aio_rx_cond, 120));
	}

	for(int i = 0; i < PEER_NODES; i++) {
		for(int j = 0; j < PEER_NODES; j++) {
            if(i == j) {
                continue;
            }
			char file_name[1000];
			sprintf(file_name, "aio_%s_%d_%s_%d_file.txt", PEER, i, PEER, j);

			assert_int_equal(find_file_size(file_name), MEGA_BYTES);
			assert_int_equal(unlink(file_name), 0);
		}
	}

	meshlink_close(mesh);
	assert_true(meshlink_destroy(nut_confbase));

	for(int i = 0; i < 5; i++) {
		meshlink_close(mesh_peer[i]);
		assert_true(meshlink_destroy(peer_confbase));
	}

	return;
}

/* Test Steps for meshlink AIO Test Case # 12 - non-regular file transfer using AIO
*/
static void test_aio_12(void **state) {
	char nut_confbase[PATH_MAX];
	char peer_confbase[PATH_MAX];
	create_path(nut_confbase, NUT, 5);
	create_path(peer_confbase, PEER, 5);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_handle_t *mesh = meshlink_open(nut_confbase, NUT, TEST_AIO, DEV_CLASS_STATIONARY);
	assert_non_null(mesh);
	meshlink_handle_t *mesh_peer = meshlink_open(peer_confbase, PEER, TEST_AIO, DEV_CLASS_PORTABLE);
	assert_non_null(mesh_peer);

	link_meshlink_pair(mesh, mesh_peer);
	meshlink_set_node_status_cb(mesh, meshlink_node_reachable_status_cb);
	meshlink_set_node_status_cb(mesh_peer, meshlink_node_reachable_status_cb);
	meshlink_set_channel_accept_cb(mesh_peer, channel_accept);

	meshlink_node_t *node = meshlink_get_node(mesh, PEER);
	meshlink_node_t *node_peer = meshlink_get_node(mesh_peer, NUT);

	// Bring nodes online.

	set_sync_flag(&peer_reachable_status_cond, false);
	set_sync_flag(&nut_reachable_status_cond, false);
	assert_true(meshlink_start(mesh));
	assert_true(meshlink_start(mesh_peer));
	assert_true(wait_sync_flag(&peer_reachable_status_cond, 60));
	assert_true(peer_reachable_status);
	assert_true(wait_sync_flag(&nut_reachable_status_cond, 60));
	assert_true(nut_reachable_status);
	meshlink_set_node_status_cb(mesh, node_reachable_fail_cb);
	meshlink_set_node_status_cb(mesh_peer, node_reachable_fail_cb);

	meshlink_channel_t *channel = meshlink_channel_open_ex(mesh, node, PORT, channel_receive_fail_cb, NULL, 0, MESHLINK_CHANNEL_TCP);
	assert_non_null(channel);

	assert_true(wait_sync_flag(&peer_accept_cond, 10));
	meshlink_channel_t *channel_peer = node_peer->priv;

    aio_data_t aio_send_data = { 0 };
	aio_data_t aio_recv_data = { 0 };

	int pipe_fd[2];
	size_t file_len = 50;
	char buf[file_len];
	assert_int_not_equal(pipe(pipe_fd), -1);

	int fd_send = pipe_fd[1];

	int fd_recv = open(AIO_TEST_RECV_FILE_NAME,  O_CREAT | O_RDWR | O_TRUNC, 0644);

	set_sync_flag(&send_fd_cb_cond, false);
	set_sync_flag(&recv_fd_cb_cond, false);
	aio_send_data.fd = fd_send;
	aio_recv_data.fd = fd_recv;
	aio_send_data.expected_aio_cb_len = file_len;
	aio_recv_data.expected_aio_cb_len = file_len;

	assert_true(meshlink_channel_aio_fd_receive(mesh_peer, channel_peer, fd_recv, file_len, aio_fd_recv_cb, &aio_recv_data));
	assert_true(meshlink_channel_aio_fd_send(mesh, channel, fd_send, file_len, aio_fd_send_cb, &aio_send_data));

	assert_int_not_equal(write(pipe_fd[0], buf, file_len), -1);

	assert_true(wait_sync_flag(&send_fd_cb_cond, 60));
	assert_true(wait_sync_flag(&recv_fd_cb_cond, 60));

	// sleep(5);

	assert_int_equal(aio_send_data.cb_count, 1);
	assert_int_equal(aio_recv_data.cb_count, 1);
	assert_int_equal(close(pipe_fd[0]), 0);
	assert_int_equal(close(pipe_fd[1]), 0);
	assert_int_equal(close(fd_recv), 0);
	assert_int_equal(unlink(AIO_TEST_RECV_FILE_NAME), 0);

	meshlink_set_node_status_cb(mesh, NULL);
	meshlink_set_node_status_cb(mesh_peer, NULL);
	meshlink_set_channel_receive_cb(mesh, channel, NULL);
	meshlink_set_channel_receive_cb(mesh_peer, channel_peer, NULL);
	meshlink_close(mesh);
	meshlink_close(mesh_peer);
	assert_true(meshlink_destroy(nut_confbase));
	assert_true(meshlink_destroy(peer_confbase));
	return;
}

int test_meshlink_aio(void) {
	const struct CMUnitTest blackbox_aio_tests[] = {
		cmocka_unit_test_prestate_setup_teardown(test_aio_01, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_02, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_03, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_04, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_05, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_06, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_07, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_08, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_09, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_10, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_11, NULL, NULL, NULL),
		cmocka_unit_test_prestate_setup_teardown(test_aio_12, NULL, NULL, NULL),
	};

	total_tests += sizeof(blackbox_aio_tests) / sizeof(blackbox_aio_tests[0]);

	int failed = cmocka_run_group_tests(blackbox_aio_tests, NULL, NULL);

	return failed;
}
