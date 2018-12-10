/*
    node_sim_gateway.c -- Implementation of Node Simulation for Meshlink Testing
                    for meta connection test case 01 - re-connection of
                    two nodes when relay node goes down
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
#include <stdio.h>
#include <stdlib.h>
#include "../common/common_handlers.h"
#include "../common/test_step.h"
#include "../common/mesh_event_handler.h"

#define CMD_LINE_ARG_NODENAME   1
#define CMD_LINE_ARG_DEVCLASS   2
#define CMD_LINE_ARG_CLIENTID   3
#define CMD_LINE_ARG_IMPORTSTR  4
#define CMD_LINE_ARG_INVITEURL  5

static bool from = false;
static bool sleepy_reachable = false;
static int clientId;
static void meshlink_logger_cb(meshlink_handle_t *mesh, meshlink_log_level_t level,
                                      const char *text) {
    int i;

    fprintf(stderr, "meshlink>> %s\n", text);
    if(strstr(text, "Connection") || strstr(text, "Connected")) {
      if(strstr(text, "Connection from")) {
        from = true;
      }
			if(strstr(text, "Connected to")) {
        from = false;
      }
    }
    return;
}

static void node_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node,
                                        bool reachable) {
    int i;

    fprintf(stderr, "Node %s became %s\n", node->name, (reachable) ? "reachable" : "unreachable");
    if(!strcasecmp(node->name, "sleepy")) {
      if(!reachable) {
        mesh_event_sock_send(clientId, NODE_UNREACHABLE, "sleepy node become unreachable", 30);
      }
      else {
        fprintf(stderr, "SLEEPY is now reachable\n");
        sleepy_reachable = true;
      }
    }

    return;
}

int main(int argc, char *argv[]) {
    struct timeval main_loop_wait = { 5, 0 };
    int i;

    if((argv[CMD_LINE_ARG_CLIENTID]) && (argv[CMD_LINE_ARG_IMPORTSTR] )) {
      clientId = atoi(argv[CMD_LINE_ARG_CLIENTID]);
      mesh_event_sock_connect(argv[CMD_LINE_ARG_IMPORTSTR]);
    }

    setup_signals();

    sleepy_reachable = false;
    from = false;
    execute_open(argv[CMD_LINE_ARG_NODENAME], argv[CMD_LINE_ARG_DEVCLASS]);
    meshlink_set_node_status_cb(mesh_handle, node_status_cb);
    meshlink_set_log_cb(mesh_handle, MESHLINK_DEBUG, meshlink_logger_cb);
    if(argv[CMD_LINE_ARG_INVITEURL]) {
        execute_join(argv[CMD_LINE_ARG_INVITEURL]);
    }

    execute_start();
    fprintf(stderr, "Node started\n");
    while(!sleepy_reachable) {
      sleep(1);
    }
    fprintf(stderr, "sleepy node reachable\n");

    if(from) {
      fprintf(stderr, "Incoming meta connection\n");
      mesh_event_sock_send(clientId, INCOMING_META_CONN, NULL, 30);
    } else {
      fprintf(stderr, "Outgoing meta connection\n");
      mesh_event_sock_send(clientId, OUTGOING_META_CONN, NULL, 30);
    }

    /* All test steps executed - wait for signals to stop/start or close the mesh */
    while(1)
        select(1, NULL, NULL, NULL, &main_loop_wait);
}
