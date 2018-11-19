/*
    node_sim_peer.c -- Implementation of Node Simulation for Meshlink Testing
                    for meta connection test case 01 - re-connection of
                    two nodes when relay node goes down
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <signal.h>
#include "../common/common_handlers.h"
#include "../common/test_step.h"
#include "../common/mesh_event_handler.h"

#define CMD_LINE_ARG_NODENAME   1
#define CMD_LINE_ARG_DEVCLASS   2
#define CMD_LINE_ARG_CLIENTID   3
#define CMD_LINE_ARG_IMPORTSTR  4
#define CMD_LINE_ARG_INVITEURL  5

static int client_id = -1;

static void logger_callback(meshlink_handle_t *mesh, meshlink_log_level_t level,
                            const char *text) {
	(void)mesh;
	(void)level;

	fprintf(stderr, "meshlink>> %s\n", text);

	/*int node_num;
	static bool event_sent;
	if(!event_sent && sscanf(text, "Connection with relay activated") == 1) {
	        assert(mesh_event_sock_send(client_id, NODE_JOINED2, NULL, 0));
	        fprintf(stderr, "EVENT_SENT %d\n", node_num);
	        event_sent = true;
	}*/
}

static void node_status_cb(meshlink_handle_t *mesh, meshlink_node_t *source, bool reach) {
	(void)mesh;
	int node_num;
	static bool event_sent;

	if(client_id == 3000 && !event_sent && reach) {
		if(sscanf(source->name, "peer_%d", &node_num)) {
			assert(mesh_event_sock_send(client_id, NODE_JOINED2, &node_num, sizeof(node_num)));
			event_sent = true;
		}
	}
}

int main(int argc, char *argv[]) {
	struct timeval main_loop_wait = { 2, 0 };
	struct timespec timeout = {0};

	// Import mesh event handler

	if((argv[CMD_LINE_ARG_CLIENTID]) && (argv[CMD_LINE_ARG_IMPORTSTR])) {
		client_id = atoi(argv[CMD_LINE_ARG_CLIENTID]);
		mesh_event_sock_connect(argv[CMD_LINE_ARG_IMPORTSTR]);
	}

	// Run peer node instance
	setup_signals();

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, logger_callback);
	meshlink_handle_t *mesh = meshlink_open(argv[CMD_LINE_ARG_NODENAME], argv[CMD_LINE_ARG_NODENAME],
	                                        "test", atoi(argv[CMD_LINE_ARG_DEVCLASS]));
	assert(mesh);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, logger_callback);
	meshlink_set_node_status_cb(mesh, node_status_cb);

	if(argv[5]) {
		int attempts;
		bool joined_status;
		int inv_no;

		for(inv_no = 5; argv[inv_no]; inv_no = inv_no + 1) {
			fprintf(stderr, "INV_NO: %d\n", inv_no);

			for(attempts = 0; attempts < 200; attempts = attempts + 1) {
				joined_status = meshlink_join(mesh, argv[inv_no]);

				if(joined_status) {
					break;
				}
			}

			assert(attempts < 200);
		}
	}

	assert(meshlink_start(mesh));

	// All test steps executed - wait for signals to stop/start or close the mesh
	while(test_running) {
		select(1, NULL, NULL, NULL, &main_loop_wait);
	}

	meshlink_close(mesh);

	return EXIT_SUCCESS;
}
