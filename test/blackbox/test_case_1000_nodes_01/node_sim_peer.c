/*
    node_sim_peer.c -- Implementation of Node Simulation for Meshlink Testing
                    for meta connection test case 01 - re-connection of
                    two nodes when relay node goes down
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include "../common/common_handlers.h"
#include "../common/test_step.h"
#include "../common/network_namespace_framework.h"
#include "../../utils.h"

static struct sync_flag close_mesh = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static void log_message(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)level;

    fprintf(stderr, "\x1b[34m [%s]:\x1b[0m %s\n", mesh->name ? mesh->name : "NULL", text);
}

static void sigint_handler(int signal_no) {
    (void)signal_no;

    set_sync_flag(&close_mesh, true);
}

static void channel_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *dat, size_t len) {
	(void)mesh;

	if(len && !channel->node->priv) {
        channel->node->priv = (void *)true;
        assert(meshlink_channel_send(mesh, channel, "reply", 5) > 0);
	}
}

static bool channel_accept(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;

	meshlink_set_channel_receive_cb(mesh, channel, channel_receive_cb);
	assert(meshlink_channel_send(mesh, channel, "reply", 5) > 0);

	return true;
}

int main(int argc, char *argv[]) {
    if(argc < 5) {
        fprintf(stderr, "Invalid number of arguments\n");
        return 1;
    }

    assert(signal(SIGINT, sigint_handler) != SIG_ERR);

	// Run relay node instance
	meshlink_handle_t *mesh;
	mesh = meshlink_open(argv[1], argv[2], argv[3], atoi(argv[4]));
	assert(mesh);

	meshlink_set_log_cb(mesh, MESHLINK_INFO, log_message);
	//meshlink_set_receive_cb(mesh, receive_cb);
	meshlink_set_channel_accept_cb(mesh, channel_accept);
	meshlink_enable_discovery(mesh, false);

	if(argv[5]) {
		int attempts;
		bool join_ret;

		for(attempts = 0; attempts < 10; attempts++) {
			join_ret = meshlink_join(mesh, argv[5]);

			if(join_ret) {
				break;
			}

			srand(getpid());
			int retry_time = random();
			sleep((retry_time % 5) + 1);
		}

		if(attempts == 10) {
            fprintf(stdout, "Node %s failed to join with invitation", mesh->name);
			abort();
		}
	}

	assert(meshlink_start(mesh));

	wait_sync_flag(&close_mesh, 300);

	meshlink_close(mesh);

	return 0;
}
