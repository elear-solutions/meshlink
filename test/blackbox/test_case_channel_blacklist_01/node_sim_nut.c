/*
    node_sim_nut.c -- Implementation of Node Simulation for Meshlink Testing
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
#include "../common/mesh_event_handler.h"
#include "../common/network_namespace_framework.h"
#include "../run_blackbox_tests/test_cases_channel_blacklist.h"
#include "../../utils.h"
#include "node_sim_nut.h"
#include "node_sim_peer.h"
#include "node_sim_relay.h"

static struct sync_flag reachable = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag relay_reachable_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag channel_active = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag channels_closed = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag channel_ping = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag nut_nut2_metaconn_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag nut_peer_metaconn_cond = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static bool peer_reachable;
static bool relay_reachable;

static void channel_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *dat, size_t len);
static bool channel_accept(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len);

static void node_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node,
                           bool reach) {

	fprintf(stderr, "[%s] Node %s %s\n", mesh->name, node->name, reach ? "reachable" : "unreachable");

	if(!strcmp("peer", node->name)) {
		peer_reachable = reach;
	} else if(!strcmp("relay", node->name)) {
		relay_reachable = reach;
		set_sync_flag(&relay_reachable_cond, true);
	}

	set_sync_flag(&reachable, true);
}

static bool channel_accept(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *dat, size_t len) {
	(void)dat;
	(void)len;
	(void)port;

	meshlink_set_channel_receive_cb(mesh, channel, channel_receive_cb);
	return true;
}

static void poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)len;
	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	assert(meshlink_channel_send(mesh, channel, "ping", 5) >= 0);
}

static void channel_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *dat, size_t len) {
	if(len == 0) {
		meshlink_channel_close(mesh, channel);
		set_sync_flag(&channels_closed, true);
		return;
	}

	if(!strcmp(dat, "reply")) {
		set_sync_flag(&channel_active, true);
		return;
	}

	if(!strcmp(dat, "close")) {
		set_sync_flag(&channel_active, true);
		meshlink_channel_close(mesh, channel);
		return;
	}

	if(!strcmp(dat, "ping_and_close")) {
		set_sync_flag(&channel_ping, true);
		assert(meshlink_channel_send(mesh, channel, "close", 6) >= 0);
	}
}

static void log_message(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	char name[100];
	bool status;

	if(level == MESHLINK_LOG_LEVEL) {
		fprintf(stderr, "\x1b[33m\x1b[1m [%s]:\x1b[0m %s\n", mesh->name, text);
	}

	// Monitor nut node's meta-connection status with peer and relay's nodes.

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

	if(!strcmp(name, "peer")) {
		nut_peer_metaconn = status;
		set_sync_flag(&nut_peer_metaconn_cond, true);
	} else if(!strcmp(name, "relay")) {
		nut_relay_metaconn = status;
	}
}

/*
    A)

      nut <------> relay <------> peer
       |                            |
       ------------------------------

    B)

      ------- relay --------
      |                    |
    [NAT]                [NAT]
      |                    |
     nut                  peer


    Test NUT node blacklist scenarios, in the above topologies (A. and B. for test case 1 and 3 resp.) :
    1. Blacklist API, On blacklisting peer node check for the closure callbacks
        of opened channel with peer and it's node unreachable callback and break
        meta-connections if it had any.
    2. Restarting peer node instance after blacklisting it at NUT node,
        assert on peer node reachable status which should remain silent
        even after the trigger.
    3. Restart NUT node instance after blacklisting it at NUT node,
        assert on peer node reachable status at NUT node which should
        remain silent even after the trigger.
    4. Whitelist peer node when peer node is offline, assert on peer node reachable
        status at NUT node which should remain silent even after the trigger.
    5. Whitelist peer node which is online, assert on peer node reachable status
*/
void *test_channel_blacklist_disconnection_nut_01(void *arg) {
	bool wait_flag;
	bool moniter_meta_close;
	test_channel_discon_case_01 = false;

	mesh_arg_t *mesh_arg = (mesh_arg_t *)arg;

	// Run relay node instance

	meshlink_handle_t *mesh;
	mesh = meshlink_open(mesh_arg->node_name , mesh_arg->confbase, mesh_arg->app_name, mesh_arg->dev_class);
	assert(mesh);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, log_message);
	meshlink_set_node_status_cb(mesh, node_status_cb);
	meshlink_enable_discovery(mesh, false);

	// Join relay node and if fails to join then try few more attempts

	if(mesh_arg->join_invitation) {
		assert(meshlink_join(mesh, mesh_arg->join_invitation));
	}

	set_sync_flag(&reachable, false);
	assert(meshlink_start(mesh));

	// Wait for peer node to join

	assert(wait_sync_flag(&reachable, 10));
	set_sync_flag(&reachable, false);
	wait_sync_flag(&reachable, 10);
	assert(peer_reachable && relay_reachable);

	meshlink_node_t *peer_node = meshlink_get_node(mesh, "peer");
	assert(peer_node);
	meshlink_node_t *self_node = meshlink_get_self(mesh);
	assert(self_node);

	meshlink_channel_t *channel = meshlink_channel_open(mesh, peer_node, 1234,
	                              channel_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = "peer_channel";
	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);

	if(!wait_sync_flag(&channel_active, 15)) {
		PRINT_FAILURE_MSG("Cannot open a channel");
		set_sync_flag(&test_channel_discon_close, true);
		return NULL;
	}

	// Blacklisting peer node, check for the closure callbacks of opened channel with peer,
	// it's node unreachable callback and meta-connection should be closed if it had any

	set_sync_flag(&channels_closed, false);
	set_sync_flag(&reachable, false);

	if(nut_peer_metaconn) {
		set_sync_flag(&nut_peer_metaconn_cond, false);
		moniter_meta_close = true;
	} else {
		moniter_meta_close = false;
	}

	meshlink_blacklist(mesh, peer_node);

	wait_flag = wait_sync_flag(&channels_closed, 10);
	assert(wait_sync_flag(&reachable, 10));

	if(moniter_meta_close) {
		assert(wait_sync_flag(&nut_peer_metaconn_cond, 10));
	}

	if(!read_sync_flag(&channels_closed) || !wait_flag || !relay_reachable || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Blacklist API failed to invoke proper callbacks");
		return NULL;
	}

	if(nut_peer_metaconn || !nut_relay_metaconn || peer_nut_metaconn || !peer_relay_metaconn || !relay_nut_metaconn || !relay_peer_metaconn) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Blacklist API failed to maintain proper meta-connections");
		return NULL;
	}

	// Restarting Peer node instance, assert on peer node reachable status at NUT node which
	// should remain silent even after the trigger

	test_case_signal_peer_restart_02 = true;
	wait_sync_flag(&reachable, 10);

	if(nut_peer_metaconn || !nut_relay_metaconn || peer_nut_metaconn || !peer_relay_metaconn || !relay_nut_metaconn || !relay_peer_metaconn) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Failed to maintain proper meta-connections after restarting peer node instance which is already blacklisted by nut node ");
		return NULL;
	}

	if(!relay_reachable || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Peer status reachable callback invoked");
		return NULL;
	}

	// Restart NUT node instance, assert on peer node reachable status at NUT node which
	// should remain silent even after the trigger

	meshlink_stop(mesh);
	set_sync_flag(&relay_reachable_cond, false);
	assert(meshlink_start(mesh));

	assert(wait_sync_flag(&relay_reachable_cond, 20));

	if(!relay_reachable || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Blacklisted Peer node is reachable on restarting Relay node");
		return NULL;
	}

	// Whitelist peer node after stopping peer node instance, assert on peer node reachable
	// status at NUT node which should remain silent even after the trigger

	set_sync_flag(&reachable, false);
	assert(relay_reachable);
	test_case_signal_peer_stop_02 = true;
	sleep(2);
	meshlink_whitelist(mesh, peer_node);
	fprintf(stderr, "Node whitelisted\n");

	wait_flag = wait_sync_flag(&reachable, 10);

	if(wait_flag && peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Peer node reachable & Node reachable callback invoked for peer node when it's whitelisted and being offline");
		return NULL;
	}

	// Start the peer node instance which is now whitelisted, assert on peer node reachable status
	// callback at NUT node and open a channel with peer node.

	set_sync_flag(&channels_closed, false);
	set_sync_flag(&reachable, false);
	test_case_signal_peer_start_02 = true;

	wait_flag = wait_sync_flag(&reachable, 10);

	if(!wait_flag || !relay_reachable || !peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Node reachable callback's not invoked for peer node when it's whitelisted and being offline");
		return NULL;
	}

	channel = meshlink_channel_open(mesh, peer_node, 1234,
	                                channel_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = "peer_channel";
	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);

	wait_flag = wait_sync_flag(&channel_active, 15);

	if(!wait_flag || !relay_reachable || !peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Couldn't open a channel after whitelisting peer node");
		return NULL;
	}

	// Close NUT node instance and set test case as success while returning.

	meshlink_close(mesh);

	test_channel_discon_case_01 = true;
	set_sync_flag(&test_channel_discon_close, true);
	return NULL;
}

/*
      ------- relay --------
      |                    |
    [NAT]                [NAT]
      |                    |
     nut                  peer


    Test NUT node blacklist scenarios:
    1. Blacklist API, On blacklisting peer node check for the closure callbacks
        of opened channel with peer and it's node unreachable callback.
    2. Restarting peer node instance after blacklisting it at nut node,
        assert on peer node reachable status which should remain silent
        even after the trigger.
    3. Restart nut node instance after blacklisting peer at nut node,
        assert on peer node reachable status at nut node which should
        remain silent even after the trigger.
    4. Whitelist peer node when peer node is offline, assert on peer node reachable
        status at nut node which should remain silent even after the trigger.
    5. Whitelist peer node which is online, assert on peer node reachable status
*/
void *test_channel_blacklist_disconnection_nut_03(void *arg) {
	bool wait_flag;
	test_channel_discon_case_03 = false;

	mesh_arg_t *mesh_arg = (mesh_arg_t *)arg;

	// Run nut node instance

	meshlink_handle_t *mesh;
	mesh = meshlink_open(mesh_arg->node_name , mesh_arg->confbase, mesh_arg->app_name, mesh_arg->dev_class);
	assert(mesh);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, log_message);
	meshlink_set_node_status_cb(mesh, node_status_cb);
	meshlink_enable_discovery(mesh, false);

	// Join nut node and if fails to join then try few more attempts

	if(mesh_arg->join_invitation) {
		assert(meshlink_join(mesh, mesh_arg->join_invitation));
	}

	set_sync_flag(&reachable, false);
	assert(meshlink_start(mesh));

	// Wait for peer node to join

	assert(wait_sync_flag(&reachable, 10));
	set_sync_flag(&reachable, false);
	wait_sync_flag(&reachable, 10);
	assert(peer_reachable && relay_reachable);

	meshlink_node_t *peer_node = meshlink_get_node(mesh, "peer");
	assert(peer_node);

	meshlink_channel_t *channel = meshlink_channel_open(mesh, peer_node, 1234,
	                              channel_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = "peer_channel";
	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);

	if(!wait_sync_flag(&channel_active, 15)) {
		PRINT_FAILURE_MSG("Cannot open a channel");
		set_sync_flag(&test_channel_discon_close, true);
		return NULL;
	}

	// Blacklisting peer node

	set_sync_flag(&channels_closed, false);
	set_sync_flag(&reachable, false);
	meshlink_blacklist(mesh, peer_node);

	wait_flag = wait_sync_flag(&channels_closed, 10);
	assert(wait_sync_flag(&reachable, 10));

	if(!read_sync_flag(&channels_closed) || !wait_flag || !relay_reachable || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Blacklist API failed to invoke proper callbacks");
		return NULL;
	}

	// Restarting Peer node instance

	test_case_signal_peer_restart_02 = true;
	wait_sync_flag(&reachable, 10);

	if(!relay_reachable || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Peer status reachable callback invoked");
		return NULL;
	}

	// Restart nut node

	meshlink_stop(mesh);
	set_sync_flag(&relay_reachable_cond, false);
	assert(meshlink_start(mesh));

	wait_sync_flag(&relay_reachable_cond, 60);

	if(peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Blacklisted Peer node is reachable on restarting Relay node");
		return NULL;
	}

	if(!relay_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Relay node is unreachable after blacklisting peer node");
		return NULL;
	}

	// Whitelist peer node after stopping peer node instance

	set_sync_flag(&reachable, false);
	assert(relay_reachable);
	test_case_signal_peer_stop_02 = true;
	sleep(2);
	meshlink_whitelist(mesh, peer_node);
	fprintf(stderr, "Node whitelisted\n");

	wait_flag = wait_sync_flag(&reachable, 10);

	if(wait_flag || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Node reachable callback invoked for peer node when it's whitelisted and being offline");
		return NULL;
	}

	if(!relay_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Relay node is unreachable after blacklisting peer node");
		return NULL;
	}

	set_sync_flag(&channels_closed, false);
	set_sync_flag(&reachable, false);
	test_case_signal_peer_start_02 = true;

	wait_sync_flag(&reachable, 10);
	wait_flag = wait_sync_flag(&channels_closed, 10);

	if(wait_flag || !relay_reachable || !peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Node reachable callback's not invoked for peer node when it's whitelisted and being offline");
		return NULL;
	}

	channel = meshlink_channel_open(mesh, peer_node, 1234,
	                                channel_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = "peer_channel";
	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);

	wait_flag = wait_sync_flag(&channel_active, 15);

	if(!wait_flag || !relay_reachable || !peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Couldn't open a channel after whitelisting peer node");
		return NULL;
	}

	meshlink_close(mesh);

	test_channel_discon_case_03 = true;
	set_sync_flag(&test_channel_discon_close, true);
	return NULL;
}

/*

   nut2 <-----> relay <-----> peer
     |            |
     ----------> nut


    Run NUT node in the above topology, when relay node blacklists nut node :
    1. peer node sends data to nut node it shouldn't get blocked
    2. nut node sends data to peer node it should get blocked.
*/
void *test_channel_blacklist_disconnection_nut_04(void *arg) {
	bool wait_flag;
	test_channel_discon_case_04 = false;

	mesh_arg_t *mesh_arg = (mesh_arg_t *)arg;

	// Run relay node instance

	meshlink_handle_t *mesh;
	mesh = meshlink_open(mesh_arg->node_name , mesh_arg->confbase, mesh_arg->app_name, mesh_arg->dev_class);
	assert(mesh);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, log_message);
	meshlink_set_channel_accept_cb(mesh, channel_accept);
	meshlink_set_node_status_cb(mesh, node_status_cb);
	meshlink_enable_discovery(mesh, false);

	// Join relay node and if fails to join then try few more attempts

	if(mesh_arg->join_invitation) {
		assert(meshlink_join(mesh, mesh_arg->join_invitation));
	}

	set_sync_flag(&channel_ping, false);
	set_sync_flag(&reachable, false);
	assert(meshlink_start(mesh));

	// Wait for peer node to join and open a channel to it

	assert(wait_sync_flag(&reachable, 10));
	set_sync_flag(&reachable, false);
	wait_sync_flag(&reachable, 10);
	assert(peer_reachable && relay_reachable);
	assert(wait_sync_flag(&nut_nut2_metaconn_cond, 20));

	meshlink_node_t *peer_node = meshlink_get_node(mesh, "peer");
	assert(peer_node);
	meshlink_node_t *self_node = meshlink_get_self(mesh);
	assert(self_node);

	meshlink_channel_t *channel = meshlink_channel_open(mesh, peer_node, 1234,
	                              channel_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = "peer_channel";
	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);

	if(!wait_sync_flag(&channel_active, 15)) {
		PRINT_FAILURE_MSG("Cannot open a channel");
		set_sync_flag(&test_channel_discon_close, true);
		return NULL;
	}

	meshlink_channel_close(mesh, channel);

	// Signal relay node to blacklist NUT node

	set_sync_flag(&relay_blacklist_nut, false);
	test_case_relay_blacklist_nut_04 = true;
	sleep(2);
	assert(wait_sync_flag(&relay_blacklist_nut, 10));

	// Signal peer node to open a channel to NUT node, validate the channel.

	test_case_signal_peer_nut_open_channel_02 = true;

	if(!wait_sync_flag(&channel_ping, 15)) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Peer failed to send data via channel to NUT or relaying failed");
		return NULL;
	}

	assert(wait_sync_flag(&channels_closed, 30));

	// Open a channel from NUT node to peer node, this should be blocked

	set_sync_flag(&channel_active, false);
	channel = meshlink_channel_open(mesh, peer_node, 1234,
	                                channel_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = "peer_channel";
	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);

	if(wait_sync_flag(&channel_active, 10)) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Relay node failed to block the data packets sent to \
                    peer node which gets relayed");
		return NULL;
	}

	// Close NUT node instance and set test case as success while returning

	meshlink_close(mesh);

	test_channel_discon_case_04 = true;
	set_sync_flag(&test_channel_discon_close, true);
	return NULL;
}

static void log_message2(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;

	//if(level == MESHLINK_INFO)
	fprintf(stderr, "\x1b[36m\x1b[1m [%s]:\x1b[0m %s\n", mesh->name, text);

	if(!strcmp(text, "Connection with nut activated")) {
		set_sync_flag(&nut_nut2_metaconn_cond, true);
	}
}

/*
  Run nut2 node instance
*/
void *test_channel_blacklist_disconnection_nut_02(void *arg) {
	struct timeval main_loop_wait = { 2, 0 };
	bool wait_flag;
	mesh_arg_t *mesh_arg = (mesh_arg_t *)arg;

	// Run relay node instance

	meshlink_handle_t *mesh;
	mesh = meshlink_open(mesh_arg->node_name , mesh_arg->confbase, mesh_arg->app_name, mesh_arg->dev_class);
	assert(mesh);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, log_message2);
	meshlink_enable_discovery(mesh, false);

	// Join relay node and if fails to join then try few more attempts

	if(mesh_arg->join_invitation) {
		assert(meshlink_join(mesh, mesh_arg->join_invitation));
	}

	meshlink_start(mesh);

	/* All test steps executed - wait for signals to stop/start or close the mesh */
	while(test_channel_blacklist_disconnection_nut2_running) {
		select(1, NULL, NULL, NULL, &main_loop_wait);
	}

	meshlink_close(mesh);
	return NULL;
}
