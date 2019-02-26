/*
    node_sim_relay.c -- Implementation of Node Simulation for Meshlink Testing
                    for channel connections with respective to blacklisting mesh nodes
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
#include "../common/common_handlers.h"
#include "../common/test_step.h"
#include "../common/network_namespace_framework.h"
#include "../../utils.h"
#include "../run_blackbox_tests/test_cases_channel_blacklist.h"
#include "node_sim_relay.h"
#include "node_sim_peer.h"

#define CHANNEL_PORT 1234

bool test_case_relay_blacklist_nut_04;
struct sync_flag relay_blacklist_nut = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
struct sync_flag relay_drop_nut_packet = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static struct sync_flag reachable = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag channel_active = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static struct sync_flag channels_closed = {.mutex  = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
static bool peer_reachable;
static bool nut_reachable;
static bool peer_meta_conn;
static bool nut_meta_conn;

static void node_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node,
                           bool reach) {

	fprintf(stderr, "[%s]Node %s %s\n", mesh->name, node->name, reach ? "reachable" : "unreachable");

	if(!strcmp("peer", node->name)) {
		peer_reachable = reach;
	} else if(!strcmp("nut", node->name)) {
		nut_reachable = reach;
	} else {
		return;
	}

	set_sync_flag(&reachable, true);
}

static void poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)len;
	meshlink_set_channel_poll_cb(mesh, channel, NULL);

	assert(meshlink_channel_send(mesh, channel, "ping", 5) >= 0);
}

static void channel_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *dat, size_t len) {
	if(!len) {
		meshlink_channel_close(mesh, channel);
		set_sync_flag(&channels_closed, true);
		return;
	}

	if(!strcmp(channel->node->name, "peer")) {
		if(!strcmp(dat, "reply")) {
			fprintf(stderr, "Channel opened with %s\n", (char *)channel->priv);
			set_sync_flag(&channel_active, true);
		}

		if(!strcmp(dat, "close")) {
			fprintf(stderr, "Channel opened with %s\n", (char *)channel->priv);
			set_sync_flag(&channel_active, true);
			meshlink_channel_close(mesh, channel);
		}
	}
}

static void log_message(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	char name[100];
	bool status;

	if(level == MESHLINK_LOG_LEVEL) {
		fprintf(stderr, "\x1b[34m\x1b[1m [%s]:\x1b[0m %s\n", mesh->name, text);
	}

	// Monitor relay's meta-connection status with peer node and nut node

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
		relay_peer_metaconn = status;
	} else if(!strcmp(name, "nut")) {
		relay_nut_metaconn = status;
	}
}

/*
      ------- relay --------
      |                    |
    [NAT]                [NAT]
      |                    |
     nut                  peer


    Test relay node blacklist scenarios:
    1. Blacklist API, On blacklisting peer node check for the closure callbacks
        of opened channel with peer and it's node unreachable callback.
    2. Restarting peer node instance after blacklisting it at relay node,
        assert on peer node reachable status which should remain silent
        even after the trigger.
    3. Restart relay node instance after blacklisting it at relay node,
        assert on peer node reachable status at relay node which should
        remain silent even after the trigger.
    4. Blacklisting peer node twice should not set @meshlink_errno@
    5. Whitelist peer node when peer node is offline, assert on peer node reachable
        status at relay node which should remain silent even after the trigger.
    6. Whitelist peer node which is online, assert on peer node reachable status
        callback at relay node and should be able to open a channel with peer node.
    7. Whitelisting peer node again and assert on @meshlink_errno@ where
        meshlink_whitelist API should be idempotent.
*/
void *test_channel_blacklist_disconnection_relay_02(void *arg) {
	bool wait_flag, wait_flag2;
	bool channels_closed_status;
	test_channel_discon_case_02 = false;

	mesh_arg_t *mesh_arg = (mesh_arg_t *)arg;

	// Run relay node instance

	meshlink_handle_t *mesh;
	mesh = meshlink_open(mesh_arg->node_name , mesh_arg->confbase, mesh_arg->app_name,
	                     mesh_arg->dev_class);
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
	assert(peer_reachable && nut_reachable);

	meshlink_node_t *peer_node = meshlink_get_node(mesh, "peer");
	assert(peer_node);
	meshlink_node_t *nut_node = meshlink_get_node(mesh, "nut");
	assert(nut_node);
	meshlink_node_t *self_node = meshlink_get_self(mesh);
	assert(self_node);

	meshlink_channel_t *channel = meshlink_channel_open(mesh, peer_node, CHANNEL_PORT,
	                              channel_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = "peer_channel";
	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);

	if(!wait_sync_flag(&channel_active, 15)) {
		PRINT_FAILURE_MSG("Cannot open a channel");
		set_sync_flag(&test_channel_discon_close, true);
		return NULL;
	}

	// Blacklisting peer node, check for the closure callbacks of opened channel with peer
	// and it's node unreachable callback

	set_sync_flag(&channels_closed, false);
	set_sync_flag(&reachable, false);
	meshlink_blacklist(mesh, peer_node);

	wait_flag = wait_sync_flag(&channels_closed, 10);
	wait_flag2 = wait_sync_flag(&reachable, 10);
	channels_closed_status = read_sync_flag(&channels_closed);

	if(!channels_closed_status || !wait_flag) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Blacklist API failed to invoke channel closure callback of \
                    peer node's opened channel");
		return NULL;
	}

	if(!wait_flag2 || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Blacklist API failed to invoke peer node unreachable callbacks");
		return NULL;
	}

	// Restarting Peer node instance, assert on peer node reachable status at relay node which
	// should remain silent even after the trigger

	test_case_signal_peer_restart_02 = true;
	wait_sync_flag(&reachable, 10);

	if(!nut_reachable || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Peer status reachable callback invoked");
		return NULL;
	}

	// Restart relay node instance, assert on peer node reachable status at relay node which
	// should remain silent even after the trigger

	meshlink_stop(mesh);
	assert(meshlink_start(mesh));

	sleep(10);

	if(!nut_reachable || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Blacklisted Peer node is reachable on restarting Relay node");
		return NULL;
	}

	// Blacklisting peer node again and assert on @meshlink_errno@

	meshlink_blacklist(mesh, peer_node);

	if(meshlink_errno != MESHLINK_OK) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("meshlink_errno set on blacklisting peer node twice");
		return NULL;
	}

	// Whitelist peer node after stopping peer node instance, assert on peer node reachable
	// status at relay node which should remain silent even after the trigger

	set_sync_flag(&reachable, false);
	assert(nut_reachable);
	test_case_signal_peer_stop_02 = true;
	sleep(2);
	meshlink_whitelist(mesh, peer_node);

	wait_flag = wait_sync_flag(&reachable, 10);

	if(wait_flag || !nut_reachable || peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Node reachable callback invoked for peer node \
                    when it's whitelisted and being offline");
		return NULL;
	}

	// Start the peer node instance which is now whitelisted, assert on peer node reachable status
	// callback at relay node and open a channel with peer node.

	set_sync_flag(&channels_closed, false);
	set_sync_flag(&reachable, false);
	test_case_signal_peer_start_02 = true;

	wait_flag = wait_sync_flag(&reachable, 10);

	if(!wait_flag || !nut_reachable || !peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Node reachable callback's not invoked for peer node \
                    when it's whitelisted and being offline");
		return NULL;
	}

	channel = meshlink_channel_open(mesh, peer_node, CHANNEL_PORT,
	                                channel_receive_cb, NULL, 0);
	assert(channel);
	channel->priv = "peer_channel";
	meshlink_set_channel_poll_cb(mesh, channel, poll_cb);

	wait_flag = wait_sync_flag(&channel_active, 15);

	if(!wait_flag || !nut_reachable || !peer_reachable) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("Couldn't open a channel after whitelisting peer node");
		return NULL;
	}

	// Whitelisting peer node again and assert on @meshlink_errno@ where meshlink_whitelist API
	// should be idempotent

	meshlink_whitelist(mesh, peer_node);

	if(meshlink_errno == MESHLINK_OK) {
		set_sync_flag(&test_channel_discon_close, true);
		PRINT_FAILURE_MSG("meshlink_errno set on whitelisting peer node twice");
		return NULL;
	}

	// Close relay node instance and set test case as success while returning

	meshlink_close(mesh);

	set_sync_flag(&test_channel_discon_close, true);
	test_channel_discon_case_02 = true;
	return NULL;
}

/*
    Run relay node instance on setting test_channel_blacklist_disconnection_relay_running
*/
void *test_channel_blacklist_disconnection_relay_04(void *arg) {
	bool wait_flag;
	mesh_arg_t *mesh_arg = (mesh_arg_t *)arg;

	// Run relay node instance

	meshlink_handle_t *mesh;
	mesh = meshlink_open(mesh_arg->node_name , mesh_arg->confbase, mesh_arg->app_name, mesh_arg->dev_class);
	assert(mesh);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, log_message);

	meshlink_start(mesh);

	// All test steps executed - wait for signal to stop or close the mesh

	while(test_channel_blacklist_disconnection_relay_running) {

		sleep(2);

		// Blacklists NUT node on setting test_case_relay_blacklist_nut_04 and
		// signals by setting @relay_blacklist_nut@ conditional flag

		if(test_case_relay_blacklist_nut_04) {
			meshlink_node_t *nut_node = meshlink_get_node(mesh, "nut");
			assert(nut_node);
			meshlink_blacklist(mesh, nut_node);
			set_sync_flag(&relay_blacklist_nut, true);
			test_case_relay_blacklist_nut_04 = false;
		}
	}

	meshlink_close(mesh);

	return NULL;
}
