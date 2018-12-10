/*
    run_sleepy_tests.c -- Implementation of Black Box Test Execution for meshlink

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
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "execute_tests.h"
#include "test_sleepy_support.h"

#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include "../common/mesh_event_handler.h"
#include "../common/tcpdump.h"

#define CMD_LINE_ARG_MESHLINK_ROOT_PATH 1
#define CMD_LINE_ARG_LXC_PATH 2
#define CMD_LINE_ARG_LXC_BRIDGE_NAME 3
#define CMD_LINE_ARG_ETH_IF_NAME 4
#define CMD_LINE_ARG_CHOOSE_ARCH 5

#define GATEWAY_ID "0"
#define SLEEPY_ID "1"
#define RELAY_ID "2"

static bool test_steps_sleepy_conn_01(void);
static bool mesh_event_cb_01(mesh_event_payload_t payload);
static bool test_steps_sleepy_conn_02(void);
static bool mesh_event_cb_02(mesh_event_payload_t payload);
static bool test_steps_sleepy_conn_03(void);
static bool mesh_event_cb_03(mesh_event_payload_t payload);
static bool test_steps_sleepy_conn_04(void);
static bool mesh_event_cb_04(mesh_event_payload_t payload);
static bool test_steps_sleepy_conn_05(void);
static bool mesh_event_cb_05(mesh_event_payload_t payload);
static bool test_steps_sleepy_conn_06(void);
static bool mesh_event_cb_06(mesh_event_payload_t payload);

/* State structure for sleepy connections Test Case #1 */
static char *test_sleepy_conn_1_nodes[] = { "sleepy", "gateway" };
static black_box_state_t test_sleepy_conn_1_state = {
    /* test_case_name = */ "test_sleepy_conn_01",
    /* node_names = */ test_sleepy_conn_1_nodes,
    /* num_nodes = */ 2,
    /* test_result (defaulted to) = */ false
};

/* State structure for sleepy connections Test Case #2 */
static char *test_sleepy_conn_2_nodes[] = { "sleepy", "nut", "portable1", "portable2", "portable3", "portable4", "portable5" };
static black_box_state_t test_sleepy_conn_2_state = {
    /* test_case_name = */ "test_sleepy_conn_02",
    /* node_names = */ test_sleepy_conn_2_nodes,
    /* num_nodes = */ 7,
    /* test_result (defaulted to) = */ false
};

/* State structure for sleepy connections Test Case #3 */
static char *test_sleepy_conn_3_nodes[] = { "sleepy", "gateway", "relay" };
static black_box_state_t test_sleepy_conn_3_state = {
    /* test_case_name = */ "test_sleepy_conn_03",
    /* node_names = */ test_sleepy_conn_3_nodes,
    /* num_nodes = */ 3,
    /* test_result (defaulted to) = */ false
};

/* State structure for sleepy connections Test Case #4 */
static char *test_sleepy_conn_4_nodes[] = { "sleepy_nut", "gateway", "sleepy_peer", "relay", "portable" };
static black_box_state_t test_sleepy_conn_4_state = {
    /* test_case_name = */ "test_sleepy_conn_04",
    /* node_names = */ test_sleepy_conn_4_nodes,
    /* num_nodes = */ 5,
    /* test_result (defaulted to) = */ false
};

/* State structure for sleepy connections Test Case #5 */
static char *test_sleepy_conn_5_nodes[] = {"gateway", "sleepy", "relay", "relay2"};
static black_box_state_t test_sleepy_conn_5_state = {
    /* test_case_name = */ "test_sleepy_conn_05",
    /* node_names = */ test_sleepy_conn_5_nodes,
    /* num_nodes = */ 4,
    /* test_result (defaulted to) = */ false
};

/* State structure for sleepy connections Test Case #6 */
static char *test_sleepy_conn_6_nodes[] = {"sleepy", "nonsleepy", "relay"};
static black_box_state_t test_sleepy_conn_6_state = {
    /* test_case_name = */ "test_sleepy_conn_06",
    /* node_names = */ test_sleepy_conn_6_nodes,
    /* num_nodes = */ 3,
    /* test_result (defaulted to) = */ false
};

/* Execute sleepy Meta-connections Test Case # 1 - exclusive connection initiation/outgoing done
    by sleepy node */
static void test_case_sleepy_conn_01(void **state) {
    execute_test(test_steps_sleepy_conn_01, state);
    return;
}

static bool sleepy_outgoing_conn = false;
static bool mesh_event_cb_01(mesh_event_payload_t payload) {
  char event_node_name[][10] = {"GATEWAY", "SLEEPY", "RELAY"};
  printf("%s : ", event_node_name[payload.client_id]);

  switch(payload.mesh_event) {
    case META_CONN_SUCCESSFUL   : printf("Meta Connection Successful\n");
                                  break;
    case NODE_STARTED           : printf("Node started\n");
                                  break;
    case NODE_UNREACHABLE       : printf("Peer node become Unreachable\n");
                                  break;
    case INCOMING_META_CONN     : if((unsigned)atoi(GATEWAY_ID) == payload.client_id) {
                                    printf("Sleepy initiated connection\n");
                                    sleepy_outgoing_conn = true;
                                  } else {
                                    printf("Sleepy didn't initiate connection\n");
                                    sleepy_outgoing_conn = false;
                                  }
                                  break;
    case OUTGOING_META_CONN     : if((unsigned)atoi(SLEEPY_ID) == payload.client_id) {
                                    printf("Sleepy initiated connection\n");
                                    sleepy_outgoing_conn = true;
                                  } else {
                                    printf("Sleepy didn't initiate connection\n");
                                    sleepy_outgoing_conn = false;
                                  }
                                  break;
    default                     : printf("Undefined event\n");
  }
  return true;
}

/* Test Steps for sleepy Meta-connections Test Case # 1 -exclusive connection
    initiation/outgoing done by sleepy node.

    Test Steps:
    1. Run sleepy and gateway node with gateway inviting sleepy node.
    2. Make gateway node's instance unreachable and re-start the gateway node,
       do this for more few attempts.
    3. Now make sleepy unreachable and re-start the sleepy node's instance,
        do this for few more attempts.

    Expected Result:
    In each and every attempt only sleepy node should form or initiate the outgoing
     meta-connection with a non-sleepy node.
*/
static bool test_steps_sleepy_conn_01(void) {
  char *invite_sleepy;
  bool result = false;
  int i;
  char *import;

  import = mesh_event_sock_create(eth_if_name);
  invite_sleepy = invite_in_container("gateway", "sleepy");
  node_sim_in_container_event("gateway", "1", NULL, GATEWAY_ID, import);
  node_sim_in_container_event("sleepy", "4", invite_sleepy, SLEEPY_ID, import);

  PRINT_TEST_CASE_MSG("Waiting for sleepy to connect with gateway\n");
  for(i = 0; i < 2; i++) {
    if(!wait_for_event(mesh_event_cb_01, 60)) {
      return false;
    }
  }

  for(i = 0; i < 5; i++) {
    PRINT_TEST_CASE_MSG("ATTEMPT : %d\n", i);
    printf("ATTEMPT : %d\n", i);
    PRINT_TEST_CASE_MSG("Sending SIGTERM to gateway\n");
    node_step_in_container("gateway", "SIGTERM");
    PRINT_TEST_CASE_MSG("Waiting for gateway to become unreachable\n");
    if(!wait_for_event(mesh_event_cb_01, 60)) {
      return false;
    }
    sleep(5);

    PRINT_TEST_CASE_MSG("Launching gateway again into the mesh\n");
    sleepy_outgoing_conn = false;
    node_sim_in_container_event("gateway", "1", NULL, GATEWAY_ID, import);
    wait_for_event(mesh_event_cb_01, 5);
    PRINT_TEST_CASE_MSG("Waiting for sleepy to be re-connected\n");
    wait_for_event(mesh_event_cb_01, 60);
    if(sleepy_outgoing_conn) {
      PRINT_TEST_CASE_MSG("ATTEMPT %d : Sleepy made connection with Gateway\n", i);
    }
    else {
      PRINT_TEST_CASE_MSG("ATTEMPT %d : Gateway made connection with Sleepy\n", i);
      return false;
    }
  }

  for(i = 0; i < 5; i++) {
    PRINT_TEST_CASE_MSG("ATTEMPT : %d\n", i);
    printf("ATTEMPT : %d\n", i);
    sleepy_outgoing_conn = false;
    PRINT_TEST_CASE_MSG("Sending SIGTERM to sleepy\n");
    node_step_in_container("sleepy", "SIGTERM");
    PRINT_TEST_CASE_MSG("Waiting for sleepy to become unreachable\n");
    if(!wait_for_event(mesh_event_cb_01, 60)) {
      return false;
    }
    wait_for_event(mesh_event_cb_01, 5);
    sleep(5);

    PRINT_TEST_CASE_MSG("Launching sleepy again into the mesh\n");
    node_sim_in_container_event("sleepy", "4", NULL, SLEEPY_ID, import);
    PRINT_TEST_CASE_MSG("Waiting for sleepy to be re-connected\n");
    wait_for_event(mesh_event_cb_01, 60);
    if(sleepy_outgoing_conn) {
      PRINT_TEST_CASE_MSG("ATTEMPT %d : Sleepy made connection with Gateway\n", i);
    }
    else {
      PRINT_TEST_CASE_MSG("ATTEMPT %d : Gateway made connection with Sleepy\n", i);
      return false;
    }
  }

  free(invite_sleepy);
  return true;
}


/* Execute sleepy Meta-connections Test Case # 2 -  */
static void test_case_sleepy_conn_02(void **state) {
    execute_test(test_steps_sleepy_conn_02, state);
    return;
}

static bool sleepy_disconn = false;
static bool node_reachable = false;
static uint8_t disconn_count = 0;
static bool mesh_event_cb_02(mesh_event_payload_t payload) {
  char event_node_name[][10] = {"sleepy", "portable1", "portable2", "portable3", "portable4", "portable5", "portable"};
  printf("\x1b[32m%-12s \x1b[0m : ", event_node_name[payload.client_id]);
  PRINT_TEST_CASE_MSG("\x1b[32m%-12s \x1b[0m event found ", event_node_name[payload.client_id]);

  switch(payload.mesh_event) {
    case NODE_REACHABLE         : printf("node reachable\n");
                                  node_reachable = true;
                                  break;
    case NODE_STARTED           : printf("Node started\n");
                                  break;
    case NODE_UNREACHABLE       : printf("node become unreachable\n");
                                  break;
    case AUTO_DISCONN           : printf("Auto-disconnecting from %s\n", (char *)payload.payload);
                                  if(!strcmp((char *)payload.payload, "sleepy")) {
                                    sleepy_disconn = true;
                                  } else {
                                    sleepy_disconn = false;
                                  }
                                  disconn_count += 1;
                                  break;
    default                     : printf("Undefined event\n");
  }
  return true;
}

/* Test Steps for sleepy Meta-connections Test Case # 2 - disconnection of non-sleepy nodes only
    if there are too many connections.

    Test Steps:
    1. Sleepy node and other 5 portable nodes all being invited NUT(Node-Under-Test).
        [All other non-sleepy nodes are of DEV_CLASS_PORTABLE since max. connects are 3]
    2. Individually each node's joined into the mesh by NUT and once joined or being part of mesh
        terminate the node instance.
    3. Re-run all the nodes, wait for 60 seconds and handle the mesh events meanwhile.

    Expected Result:
    NUT disconnects only non-sleepy nodes when all tried to connect with NUT.
*/
static bool test_steps_sleepy_conn_02(void) {
  bool result = false;
  int i;
  char *import;
  char *invitations[7];
  char *node_names[] = {"sleepy", "portable1", "portable2", "portable3", "portable4", "portable5", NULL };
  char *export_ids[] = {"0", "1", "2", "3", "4", "5", "6", NULL};

  import = mesh_event_sock_create(eth_if_name);
  for(i = 0; node_names[i]; i++) {
    invitations[i] = invite_in_container("nut", node_names[i]);
  }

  node_sim_in_container_event("nut", "2", NULL, "6", import);
  if(!wait_for_event(mesh_event_cb_02, 60)) {
    return false;
  }
  for(i = 0; node_names[i]; i++) {
    node_sim_in_container_event(node_names[i], i ? "2" : "4", invitations[i], export_ids[i], import);
    PRINT_TEST_CASE_MSG("Waiting for %s node to connect with NUT\n", node_names[i]);
    if(!wait_for_event(mesh_event_cb_02, 60)) {
      return false;
    }
    PRINT_TEST_CASE_MSG("Sending SIGTERM to %s\n", node_names[i]);
    node_step_in_container(node_names[i], "SIGTERM");
    PRINT_TEST_CASE_MSG("Waiting for %s to become unreachable\n", node_names[i]);
    if(!wait_for_event(mesh_event_cb_02, 60)) {
      PRINT_TEST_CASE_MSG("Timed-out\n");
      return false;
    }
    PRINT_TEST_CASE_MSG("Added %s node into the mesh\n", node_names[i]);
  }

  for(i = 0; invitations[i]; i++) {
    free(invitations[i]);
  }

  sleepy_disconn = false;
  disconn_count = 0;
  for(i = 0; node_names[i]; i++) {
      node_reachable = false;
    node_sim_in_container_event(node_names[i], i ? "2" : "4", NULL, export_ids[i], import);
    PRINT_TEST_CASE_MSG("Waiting for %s node to connect with NUT\n", node_names[i]);
    while(!wait_for_event(mesh_event_cb_02, 60));
    if(!node_reachable) {
      PRINT_TEST_CASE_MSG("Node unreachable\n");
      return false;
    }
  }
  PRINT_TEST_CASE_MSG("Waiting for 60 seconds to allow nodes to make and break connections with its peers");
  for(i = 0; i < 60; i++) {
    (wait_for_event(mesh_event_cb_02, 1));
  }

  if(disconn_count) {
    if(sleepy_disconn) {
      PRINT_TEST_CASE_MSG("sleepy node got disconnected....\n");
      return false;
    } else {
      PRINT_TEST_CASE_MSG("non-sleepy nodes got disconnected....\n");
      return true;
    }
  } else {
    printf("no nodes got disconnected....\n");
    PRINT_TEST_CASE_MSG("no nodes got disconnected....\n");
    return false;
  }
}




/* Execute sleepy Meta-connections Test Case # 3 - discovery of a new non-sleepy node
    by sleepy node if the previously connected non-sleepy node terminates abruptly */
static void test_case_sleepy_conn_03(void **state) {
    execute_test(test_steps_sleepy_conn_03, state);
    return;
}

static bool sleepy_connect = false;
static bool mesh_event_cb_03(mesh_event_payload_t payload) {
  char *event_node_name[] = {"gateway", "sleepy", "relay"};
  printf("\x1b[32m%-8s \x1b[0m : ", event_node_name[payload.client_id]);

  switch(payload.mesh_event) {
    case META_CONN      : printf("Meta-connection successful with %s\n", (char *)payload.payload);
                          sleepy_connect = true;
                          break;

    case META_DISCONN   : printf("Meta-connection disconnected with %s\n", (char *)payload.payload);
                          sleepy_connect = false;
                          break;

    case NODE_REACHABLE : printf("Node %s is now reachable\n", (char *)payload.payload);
                          break;

    case NODE_UNREACHABLE : printf("Node %s is now unreachable\n", (char *)payload.payload);
                          break;

    default             : printf("Undefined event\n");
  }
  return true;
}

/* Test Steps for sleepy Meta-connections Test Case # 3 -

    Test Steps:
    1. Run gateway, sleepy and relay nodes with gateway inviting the other two nodes.
    2. Make gateway unreachable
    3. Re-run gateway and make relay unreachable.

    Expected Result:
    Sleepy node connects with relay node if connected gateway is unreachable and vice-versa
*/
static bool test_steps_sleepy_conn_03(void) {
  char *import = mesh_event_sock_create(eth_if_name);
  char *invite_sleepy = invite_in_container("gateway", "sleepy");
  char *invite_portable = invite_in_container("gateway", "relay");

  node_sim_in_container_event("gateway", "1", NULL, "0", import);
  node_sim_in_container_event("sleepy", "4", invite_sleepy, "1", import);
  node_sim_in_container_event("relay", "0", invite_portable, "2", import);
  while(wait_for_event(mesh_event_cb_03, 10)) {
    PRINT_TEST_CASE_MSG("Got Event\n");
  }
  if(sleepy_connect) {
    PRINT_TEST_CASE_MSG("sleepy discovered and connected with gateway\n");
  }
  assert(sleepy_connect);

  sleepy_connect = false;
  PRINT_TEST_CASE_MSG("Sending SIGTERM to gateway\n");
  node_step_in_container("gateway", "SIGTERM");
  PRINT_TEST_CASE_MSG("Waiting for gateway to become unreachable & sleepy to connect with relay\n");
  while(wait_for_event(mesh_event_cb_03, 10)) {
    PRINT_TEST_CASE_MSG("Got Event\n");
  }
  if(sleepy_connect) {
    PRINT_TEST_CASE_MSG("sleepy discovered and connected\n");
  } else {
    PRINT_TEST_CASE_MSG("sleepy failed to discover and connect with other node if it lost connection\n");
    return false;
  }

  node_sim_in_container_event("gateway", "1", NULL, "0", import);
  PRINT_TEST_CASE_MSG("Waiting gateway to join mesh\n");
  while(wait_for_event(mesh_event_cb_03, 20)) {
    PRINT_TEST_CASE_MSG("Got Event\n");
  }

  sleepy_connect = false;
  PRINT_TEST_CASE_MSG("Sending SIGTERM to relay node\n");
  node_step_in_container("relay", "SIGTERM");
  PRINT_TEST_CASE_MSG("Waiting for relay to become unreachable & sleepy to connect with gateway\n");
  while(wait_for_event(mesh_event_cb_03, 20)) {
    PRINT_TEST_CASE_MSG("Got Event\n");
  }
  if(sleepy_connect) {
    PRINT_TEST_CASE_MSG("sleepy discovered and connected\n");
  } else {
    PRINT_TEST_CASE_MSG("sleepy failed to discover and connect with other node if it lost connection\n");
    return false;
  }

  free(invite_portable);
  free(invite_sleepy);

  return true;
}



/* Execute sleepy Meta-connections Test Case # 4 -  */
static void test_case_sleepy_conn_04(void **state) {
    execute_test(test_steps_sleepy_conn_04, state);
    return;
}

static bool mutual_conn = false;
static bool gateway_nut_conn = false;
static bool gateway_peer_conn = false;
static bool mesh_event_cb_04(mesh_event_payload_t payload) {
  char *event_node_name[] = {"sleepy_nut", "gateway", "sleepy_peer", "relay", "portable"};
  printf("\x1b[32m%-8s \x1b[0m : ", event_node_name[payload.client_id]);

  switch(payload.mesh_event) {
    case META_CONN    : printf("Meta-connection successful with \x1b[32m%s\x1b[0m\n", (char *)payload.payload);
                        /* if sleepy_nut connects sleepy_peer or if sleepy_peer connects sleepy_nut */
                        if((!strcmp(event_node_name[payload.client_id], "sleepy_nut") && !strcmp((char *)payload.payload, "sleepy_peer")) || (!strcmp(event_node_name[payload.client_id], "sleepy_peer") && !strcmp((char *)payload.payload, "sleepy_nut"))) {
                          mutual_conn = true;
                        } else if(!strcmp(event_node_name[payload.client_id], "sleepy_nut") || !strcmp((char *)payload.payload, "sleepy_nut")) {
                          gateway_nut_conn = true;
                        } else {
                          gateway_peer_conn = true;
                        }
                        break;

    case META_DISCONN : printf("Meta-connection disconnected with %s\n", (char *)payload.payload);
                        break;
  }
  return true;
}

/* Test Steps for sleepy Meta-connections Test Case # 4 -

    Test Steps:

    Expected Result:
*/
static bool test_steps_sleepy_conn_04(void) {
  int i;
  char *import = mesh_event_sock_create(eth_if_name);
  char *invite_sleepy_nut = invite_in_container("gateway", "sleepy_nut");
  char *invite_sleepy_peer = invite_in_container("gateway", "sleepy_peer");
  char *invite_relay = invite_in_container("gateway", "relay");
  char *invite_portable = invite_in_container("gateway", "portable");

  mutual_conn = false;
  node_sim_in_container_event("gateway", "1", NULL, "1", import);
  node_sim_in_container_event("sleepy_nut", "4", invite_sleepy_nut, "0", import);
  node_sim_in_container_event("sleepy_peer", "1", invite_sleepy_peer, "2", import);
  node_sim_in_container_event("relay", "1", invite_relay, "3", import);
  node_sim_in_container_event("portable", "1", invite_portable, "4", import);
  PRINT_TEST_CASE_MSG("Wait for nodes to connect\n");
  while(wait_for_event(mesh_event_cb_04, 5));
  assert(gateway_nut_conn && gateway_peer_conn);

  node_step_in_container("gateway", "SIGTERM");

  PRINT_TEST_CASE_MSG("Wait for 60 seconds & check out if there is any connection established between sleepies\n");
  for(i = 0; i < 60; i++) {
    wait_for_event(mesh_event_cb_04, 1);
    if(mutual_conn) {
      PRINT_TEST_CASE_MSG("Found a connection between SLEEPY nodes\n");
      free(invite_sleepy_nut);
      free(invite_sleepy_peer);
      return false;
    }
  }
  PRINT_TEST_CASE_MSG("Found no attempt for a connection between SLEEPY nodes\n");
  free(invite_sleepy_nut);
  free(invite_sleepy_peer);
  return true;
}

/* Execute sleepy Meta-connections Test Case # 5 -  */
static void test_case_sleepy_conn_05(void **state) {
    execute_test(test_steps_sleepy_conn_05, state);
    return;
}

static int ports[4] = {0};
static char *node_portno[4][10];
static bool mesh_event_cb_05(mesh_event_payload_t payload) {
  int i;
  char *event_node_name[] = {"gateway", "sleepy", "relay", "relay2"};
  int client_no = payload.client_id;
  char *my_port = (char *)payload.payload;
  int client_ports = ports[client_no];

  PRINT_TEST_CASE_MSG("\x1b[32m%-8s \x1b[0m : ", event_node_name[client_no]);

  switch(payload.mesh_event) {
    case NODE_REACHABLE   : fprintf(stderr, "%s node is now reachable\n", (char *)payload.payload);
                            break;
    case NODE_UNREACHABLE : fprintf(stderr, "%s node now become unreachable\n", (char *)payload.payload);
                            break;
    case PORT_NO          : fprintf(stderr, "Obtained port : %s from %s\n", my_port, event_node_name[payload.client_id]);
                            for(i = 0; i < client_ports; i++) {
                              if(!strcmp(my_port, node_portno[client_no][i]))
                                break;
                            }
                            if(i == client_ports) {
                              char *port_str;
                              port_str = malloc(strlen(my_port) + 1);
                              assert(port_str);
                              strcpy(port_str, my_port);
                              node_portno[client_no][client_ports] = port_str;
                              ports[client_no] = ports[client_no] + 1;
                              fprintf(stderr, "Saved port: %s, total ports of %s is %d\n", port_str, event_node_name[client_no], ports[client_no]);
                            }

                            break;
    default               : PRINT_TEST_CASE_MSG("Undefined event occurred \n");
  }
  return true;
}

/* Test Steps for sleepy Meta-connections Test Case # 5 -

    Test Steps:

    Expected Result:
*/
static bool test_steps_sleepy_conn_05(void) {
  int i, n;
  pid_t tcpdump_pid;
  char *import = mesh_event_sock_create(eth_if_name);
  char *invite_sleepy = invite_in_container("gateway", "sleepy");
  char *invite_relay = invite_in_container("gateway", "relay");
  char *invite_relay2 = invite_in_container("gateway", "relay2");

  tcpdump_pid = tcpdump_start(lxc_bridge);
  printf("tcp pid : %d\n", tcpdump_pid);

  PRINT_TEST_CASE_MSG("Running nodes in containers\n");
  node_sim_in_container_event("gateway", "1", NULL, "0", import);
  node_sim_in_container_event("sleepy", "4", invite_sleepy, "1", import);
  node_sim_in_container_event("relay", "1", invite_relay, "2", import);
  node_sim_in_container_event("relay2", "1", invite_relay2, "3", import);
  while(wait_for_event(mesh_event_cb_05, 10));
  PRINT_TEST_CASE_MSG("Waiting for 180 seconds to record the traffic between nodes using TCP Dump\n");
  sleep(30);
  tcpdump_stop(tcpdump_pid);

  int node_packets[4] = {0};
  bool ret = false;
  char line[300];
  FILE *log_fp;

  log_fp = fopen(TCPDUMP_LOG_FILE, "r");
  assert(log_fp);
  while(fgets(line, 300, log_fp) != NULL) {
    for(n = 0; n < 4; n++) {
      for(i = 0; i < ports[n]; i++) {
        if(strstr(line, node_portno[n][i])) {
          node_packets[n] = node_packets[n] + 1;
          break;
        }
      }
    }
  }
  assert(fclose(log_fp) != EOF);

  PRINT_TEST_CASE_MSG("SLEEPY PACKETS : %d\n", node_packets[1]);
  PRINT_TEST_CASE_MSG("GATEWAY PACKETS : %d\n", node_packets[0]);
  PRINT_TEST_CASE_MSG("RELAY PACKETS : %d\n", node_packets[2]);
  PRINT_TEST_CASE_MSG("RELAY2 PACKETS : %d\n", node_packets[3]);

  if((node_packets[1] < node_packets[0]) && (node_packets[1] < node_packets[2]) && (node_packets[1] < node_packets[3])) {
    PRINT_TEST_CASE_MSG("Sleepy node packets are less when compared with non-sleepy packets\n");
    return true;
  } else {
    PRINT_TEST_CASE_MSG("Sleepy node packets are more or equal when compared with non-sleepy packets\n");
    return false;
  }
}


/* Execute sleepy Meta-connections Test Case # 6 -  */
static void test_case_sleepy_conn_06(void **state) {
    execute_test(test_steps_sleepy_conn_06, state);
    return;
}

static bool mesh_event_cb_06(mesh_event_payload_t payload) {
  char *event_node_name[] = {"sleepy", "nonsleepy", "relay"};
  printf("\x1b[32m%-8s \x1b[0m : ", event_node_name[payload.client_id]);

  switch(payload.mesh_event) {

    default             : printf("Undefined event\n");
  }
  return true;
}

/* Test Steps for sleepy Meta-connections Test Case # 6 -

    Test Steps:

    Expected Result:
*/
static bool test_steps_sleepy_conn_06(void) {
  char *import = mesh_event_sock_create(eth_if_name);
  char *invite_sleepy = invite_in_container("nonsleepy", "sleepy");
  char *invite_portable = invite_in_container("nonsleepy", "relay");

  node_sim_in_container_event("nonsleepy", "1", NULL, "1", import);
  node_sim_in_container_event("sleepy", "4", invite_sleepy, "0", import);
  node_sim_in_container_event("relay", "0", invite_portable, "2", import);

  return true;
}



int black_box_group1_setup(void **state) {
    const char *nodes[] = { "sleepy", "gateway" };
    int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    printf("Creating Containers\n");
    destroy_containers();
    create_containers(nodes, num_nodes);

    return 0;
}

int black_box_group2_setup(void **state) {
    const char *nodes[] = { "sleepy", "nut", "portable1", "portable2", "portable3", "portable4", "portable5" };
    int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    printf("Creating Containers\n");
    destroy_containers();
    create_containers(nodes, num_nodes);

    return 0;
}

int black_box_group3_setup(void **state) {
    const char *nodes[] = { "sleepy", "gateway", "relay" };
    int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    printf("Creating Containers\n");
    destroy_containers();
    create_containers(nodes, num_nodes);

    return 0;
}

int black_box_group4_setup(void **state) {
    const char *nodes[] = { "sleepy_nut", "gateway", "sleepy_peer", "relay", "portable" };
    int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    printf("Creating Containers\n");
    destroy_containers();
    create_containers(nodes, num_nodes);

    return 0;
}

int black_box_group5_setup(void **state) {
    const char *nodes[] = {"gateway", "sleepy", "relay", "relay2"};
    int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    printf("Creating Containers\n");
    destroy_containers();
    create_containers(nodes, num_nodes);

    return 0;
}

int black_box_group6_setup(void **state) {
    const char *nodes[] = {"sleepy", "nonsleepy", "relay"};
    int num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    printf("Creating Containers\n");
    destroy_containers();
    create_containers(nodes, num_nodes);

    return 0;
}

int black_box_teardown(void **state) {
    printf("Destroying Containers\n");
    destroy_containers();

    return 0;
}


int test_meshlink_sleepy_support(void) {
  const struct CMUnitTest blackbox_group1_tests[] = {
        cmocka_unit_test_prestate_setup_teardown(test_case_sleepy_conn_01, setup_test, teardown_test,
            (void *)&test_sleepy_conn_1_state)
  };
  const struct CMUnitTest blackbox_group2_tests[] = {
        cmocka_unit_test_prestate_setup_teardown(test_case_sleepy_conn_02, setup_test, teardown_test,
            (void *)&test_sleepy_conn_2_state)
  };
  const struct CMUnitTest blackbox_group3_tests[] = {
        cmocka_unit_test_prestate_setup_teardown(test_case_sleepy_conn_03, setup_test, teardown_test,
            (void *)&test_sleepy_conn_3_state)
  };
  const struct CMUnitTest blackbox_group4_tests[] = {
        cmocka_unit_test_prestate_setup_teardown(test_case_sleepy_conn_04, setup_test, teardown_test,
            (void *)&test_sleepy_conn_4_state)
  };

  const struct CMUnitTest blackbox_group5_tests[] = {
        cmocka_unit_test_prestate_setup_teardown(test_case_sleepy_conn_05, setup_test, teardown_test,
            (void *)&test_sleepy_conn_5_state)
  };

  const struct CMUnitTest blackbox_group6_tests[] = {
        cmocka_unit_test_prestate_setup_teardown(test_case_sleepy_conn_06, setup_test, teardown_test,
            (void *)&test_sleepy_conn_6_state)
  };

  int failed_tests = 0;

  total_tests += sizeof(blackbox_group1_tests) / sizeof(blackbox_group1_tests[0]);
  failed_tests += cmocka_run_group_tests(blackbox_group1_tests, black_box_group1_setup, black_box_teardown);
  total_tests += sizeof(blackbox_group1_tests) / sizeof(blackbox_group1_tests[0]);
  failed_tests += cmocka_run_group_tests(blackbox_group2_tests, black_box_group2_setup, black_box_teardown);
  total_tests += sizeof(blackbox_group3_tests) / sizeof(blackbox_group3_tests[0]);
  failed_tests += cmocka_run_group_tests(blackbox_group3_tests, black_box_group3_setup, black_box_teardown);
  total_tests += sizeof(blackbox_group4_tests) / sizeof(blackbox_group4_tests[0]);/*
  failed_tests += cmocka_run_group_tests(blackbox_group4_tests, black_box_group4_setup, black_box_teardown);
  total_tests += sizeof(blackbox_group5_tests) / sizeof(blackbox_group5_tests[0]);
  failed_tests += cmocka_run_group_tests(blackbox_group5_tests, black_box_group5_setup, black_box_teardown);
  total_tests += sizeof(blackbox_group6_tests) / sizeof(blackbox_group6_tests[0]);
  failed_tests += cmocka_run_group_tests(blackbox_group6_tests, black_box_group6_setup, black_box_teardown);*/

  return failed_tests;
}
