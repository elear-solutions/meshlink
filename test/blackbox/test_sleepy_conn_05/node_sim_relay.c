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
#include "../../../src/devtools.h"

#define CMD_LINE_ARG_NODENAME   1
#define CMD_LINE_ARG_DEVCLASS   2
#define CMD_LINE_ARG_CLIENTID   3
#define CMD_LINE_ARG_IMPORTSTR  4
#define CMD_LINE_ARG_INVITEURL  5

static int clientId;

static void node_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node,
                                        bool reachable) {
  int i;
  char my_port[10];

  fprintf(stderr, "Now node %s became %s\n", node->name, (reachable) ? "reachable" : "unreachable");
  if(reachable) {
    static devtool_connection_t *conn = NULL;
    static int n = 0;
    mesh_event_sock_send(clientId, NODE_REACHABLE, (char *)node->name, 20);
    conn = devtool_get_all_connections(mesh, conn, (size_t *)&n);
    fprintf(stderr, "return %p\nconnections : %d\n", conn, n);
    for(i = 0; i < n; i++) {
      sprintf(my_port, "%d", conn[i].my_port);
      fprintf(stderr, "my_port: %s\n", my_port);
      mesh_event_sock_send(clientId, PORT_NO, my_port, 10);
    }
  } else {
    mesh_event_sock_send(clientId, NODE_UNREACHABLE, (char *)node->name, 20);
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
    meshlink_set_node_status_cb(mesh_handle, node_status_cb);
    if(argv[CMD_LINE_ARG_INVITEURL]) {
        execute_join(argv[CMD_LINE_ARG_INVITEURL]);
    }
    int listening_port = meshlink_get_port(mesh_handle);
    char port_listen[10];
    sprintf(port_listen, "%d", listening_port);
    mesh_event_sock_send(clientId, PORT_NO, port_listen, 10);

    execute_start();
    /* All test steps executed - wait for signals to stop/start or close the mesh */
    while(1)
        select(1, NULL, NULL, NULL, &main_loop_wait);
}
