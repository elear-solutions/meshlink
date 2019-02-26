/*
    node_sim_peer.c -- Implementation of Node Simulation for Meshlink Testing
                    for channel connections with respective to blacklisting their nodes
    Copyright (C) 2019  Guus Sliepen <guus@meshlink.io>

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
#include "../common/common_handlers.h"
#include "../common/test_step.h"
#include "../common/network_namespace_framework.h"
#include "../run_blackbox_tests/test_cases_channel_blacklist.h"
#include "../../utils.h"
#include "node_sim_peer.h"

bool test_case_signal_peer_nut_open_channel_02;
bool test_case_signal_peer_restart_02;
bool test_case_signal_peer_start_02;
bool test_case_signal_peer_stop_02;

static void channel_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *dat, size_t len) {

	if(len == 0) {
		fprintf(stderr, "[%s]Channel closure callback invoked for %s node\n", mesh->name, channel->node->name);
		return;
	}

	if((len == 5) && !strcmp(dat, "ping")) {
		assert(meshlink_channel_send(mesh, channel, "reply", 6) >= 0);
	} else if(!strcmp(dat, "ping_and_close")) {
		assert(meshlink_channel_send(mesh, channel, "close", 6) >= 0);
		return;
	} else if(!strcmp(dat, "close")) {
		meshlink_channel_close(mesh, channel);
	}
}

static bool channel_accept(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;

	meshlink_set_channel_receive_cb(mesh, channel, channel_receive_cb);

	return true;
}

static void peer_poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)len;

	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	assert(meshlink_channel_send(mesh, channel, "ping_and_close", 15) >= 0);
}

static void log_message(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	char name[100];
	bool status;

	if(level == MESHLINK_LOG_LEVEL) {
		fprintf(stderr, "\x1b[35m\x1b[5m\x1b[1m [%s]:\x1b[0m  %s\n", mesh->name, text);
	}

	if(sscanf(text, "Connection with %s activated", name) == 1) {
		status = true;
	} else if(sscanf(text, "Already connected to %s", name) == 1) {
		status = true;
	} else if(sscanf(text, "Connection closed by %s", name) == 1) {
		status = false;
	} else if(sscanf(text, "Closing connection with %s", name) == 1) {
		status = false;
	} else {
		return;
	}

	if(!strcmp(name, "nut")) {
		peer_nut_metaconn = status;
	} else if(!strcmp(name, "relay")) {
		peer_relay_metaconn = status;
	}
}

void *test_channel_blacklist_disconnection_peer_02(void *arg) {
	struct timeval main_loop_wait = { 2, 0 };
	mesh_arg_t *mesh_arg = (mesh_arg_t *)arg;

	// Run relay node instance

	meshlink_handle_t *mesh;
	mesh = meshlink_open(mesh_arg->node_name , mesh_arg->confbase, mesh_arg->app_name, mesh_arg->dev_class);
	assert(mesh);
	meshlink_set_channel_accept_cb(mesh, channel_accept);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, log_message);
	meshlink_enable_discovery(mesh, false);

	// Join relay node and if fails to join then try few more attempts

	if(mesh_arg->join_invitation) {
		assert(meshlink_join(mesh, mesh_arg->join_invitation));
	}

	assert(meshlink_start(mesh));

	// All test steps executed - wait for signals to stop, start, restart or close the it's instance

	while(test_channel_blacklist_disconnection_peer_running) {
		select(1, NULL, NULL, NULL, &main_loop_wait);

		if(test_case_signal_peer_restart_02) {
			meshlink_stop(mesh);
			assert(meshlink_start(mesh));
			test_case_signal_peer_restart_02 = false;
		}

		if(test_case_signal_peer_stop_02) {
			meshlink_stop(mesh);
			test_case_signal_peer_stop_02 = false;
		}

		if(test_case_signal_peer_start_02) {
			meshlink_start(mesh);
			test_case_signal_peer_start_02 = false;
		}

		if(test_case_signal_peer_nut_open_channel_02) {
			meshlink_node_t *nut_node = meshlink_get_node(mesh, "nut");
			assert(nut_node);
			meshlink_channel_t *channel = meshlink_channel_open(mesh, nut_node, 1234, channel_receive_cb, NULL, 0);
			assert(channel);
			meshlink_set_channel_poll_cb(mesh, channel, peer_poll_cb);
			test_case_signal_peer_nut_open_channel_02 = false;
		}
	}

	meshlink_close(mesh);

	return NULL;
}
