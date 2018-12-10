/*
    node_sim_portable.c -- Implementation of Node Simulation for Meshlink Testing
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

static int clientId;

static void meshlink_logger_cb(meshlink_handle_t *mesh, meshlink_log_level_t level,
                                      const char *text) {
    int i;
    char node_name[50];

    fprintf(stderr, "meshlink>> %s\n", text);
    if(strcasestr(text, "Connection")) {
      if(strstr(text, "Connection with") && strstr(text, "activated")) {
        if(sscanf(text, "%*s %*s %50s %*s", node_name) != 1) {
          fprintf(stderr, "Got bad log text\n");
          return;
        }
        mesh_event_sock_send(clientId, META_CONN, node_name, 50);
      }

      if(strstr(text, "Connection closed by ")) {
        if(sscanf(text, "%*s %*s %*s %50s", node_name) != 1) {
          fprintf(stderr, "Got bad log text\n");
          return;
        }
        mesh_event_sock_send(clientId, META_DISCONN, node_name, 50);
      }
      if(strstr(text, "Closing connection with ")) {
        if(sscanf(text, "%*s %*s %*s %50s", node_name) != 1) {
          fprintf(stderr, "Got bad log text\n");
          return;
        }
        mesh_event_sock_send(clientId, META_DISCONN, node_name, 50);
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
    execute_open(argv[CMD_LINE_ARG_NODENAME], argv[CMD_LINE_ARG_DEVCLASS]);
    if(argv[CMD_LINE_ARG_INVITEURL]) {
        execute_join(argv[CMD_LINE_ARG_INVITEURL]);
    }
    meshlink_set_log_cb(mesh_handle, MESHLINK_DEBUG, meshlink_logger_cb);

    execute_start();
    /* All test steps executed - wait for signals to stop/start or close the mesh */
    while(1)
        select(1, NULL, NULL, NULL, &main_loop_wait);
}
