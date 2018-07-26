/*
    test_cases_channel_open.c -- Execution of specific meshlink black box test cases
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
#include "execute_tests.h"
#include "test_cases_channel_open.h"
#include "../common/containers.h"
#include "../common/test_step.h"
#include "../common/common_handlers.h"
#include <assert.h>
#include <string.h>

/* Execute meshlink_channel_open Test Case # 1*/
void test_case_mesh_channel_open_01(void **state) {
	 execute_test(test_steps_mesh_channel_open_01, state);
   return;
}

volatile bool barreachable = false;
volatile bool bar_responded = false;


void status_cb2(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	printf("status_cb: %s %sreachable\n", node->name, reachable ? "" : "un");

	if(!strcmp(node->name, "bar")) {
		barreachable = reachable;
	}
}

void foo_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;

	printf("foo_receive_cb %zu: ", len);
	fwrite(data, 1, len, stdout);
	printf("\n");

	if(len == 5 && !memcmp(data, "Hello", 5)) {
		bar_responded = true;
	}
}

void bar_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	printf("bar_receive_cb %zu: ", len);
	fwrite(data, 1, len, stdout);
	printf("\n");
	// Echo the data back.
	meshlink_channel_send(mesh, channel, data, len);
}

bool reject_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)port;
	(void)data;
	(void)len;

	return false;
}

bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	printf("accept_cb: (from %s on port %u) ", channel->node->name, (unsigned int)port);

	if(data) {
		fwrite(data, 1, len, stdout);
	}

	printf("\n");

	if(port != 7) {
		return false;
	}

	meshlink_set_channel_receive_cb(mesh, channel, bar_receive_cb);

	if(data) {
		bar_receive_cb(mesh, channel, data, len);
	}

	return true;
}

void poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)len;

	meshlink_set_channel_poll_cb(mesh, channel, NULL);

	if(meshlink_channel_send(mesh, channel, "Hello", 5) != 5) {
		fprintf(stderr, "Could not send whole message\n");
	}
}


/* Test Steps for meshlink_channel_open Test Case # 1*/
bool test_steps_mesh_channel_open_01(void) {
	bool result = false;
	// Open two new meshlink instance.

	meshlink_handle_t *mesh1 = meshlink_open("channel_open_conf.1", "foo", "channels", DEV_CLASS_BACKBONE);

	if(!mesh1) {
		fprintf(stderr, "Could not initialize configuration for foo\n");
		return false;
	}

	meshlink_handle_t *mesh2 = meshlink_open("channel_open_conf.2", "bar", "channels", DEV_CLASS_BACKBONE);

	if(!mesh2) {
		fprintf(stderr, "Could not initialize configuration for bar\n");
		return false;
	}

	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	// Import and export both side's data

	meshlink_add_address(mesh1, "localhost");

	char *data = meshlink_export(mesh1);

	if(!data) {
		fprintf(stderr, "Foo could not export its configuration\n");
		return 1;
	}

	if(!meshlink_import(mesh2, data)) {
		fprintf(stderr, "Bar could not import foo's configuration\n");
		return 1;
	}

	free(data);

	data = meshlink_export(mesh2);

	if(!data) {
		fprintf(stderr, "Bar could not export its configuration\n");
		return 1;
	}

	if(!meshlink_import(mesh1, data)) {
		fprintf(stderr, "Foo could not import bar's configuration\n");
		return 1;
	}

	free(data);

	// Set the callbacks.

	meshlink_set_channel_accept_cb(mesh1, reject_cb);
	meshlink_set_channel_accept_cb(mesh2, accept_cb);

	meshlink_set_node_status_cb(mesh1, status_cb2);

	// Start both instances

	if(!meshlink_start(mesh1)) {
		fprintf(stderr, "Foo could not start\n");
		return 1;
	}

	if(!meshlink_start(mesh2)) {
		fprintf(stderr, "Bar could not start\n");
		return 1;
	}

	// Wait for the two to connect.

	for(int i = 0; i < 20; i++) {
		sleep(1);

		if(barreachable) {
			break;
		}
	}

	if(!barreachable) {
		fprintf(stderr, "Bar not reachable for foo after 20 seconds\n");
		return false;
	}

	// Open a channel from foo to bar.

	meshlink_node_t *bar = meshlink_get_node(mesh1, "bar");

	if(!bar) {
		fprintf(stderr, "Foo could not find bar\n");
		return false;
	}

	meshlink_channel_t *channel = meshlink_channel_open(mesh1, bar, 7, foo_receive_cb, NULL, 0);
	meshlink_set_channel_poll_cb(mesh1, channel, poll_cb);

	for(int i = 0; i < 20; i++) {
		sleep(1);

		if(bar_responded) {
			break;
		}
	}

	if(!bar_responded) {
		fprintf(stderr, "Bar did not respond to foo's channel message\n");
		return false;
	}

	meshlink_channel_close(mesh1, channel);

	// Clean up.

	meshlink_stop(mesh2);
	meshlink_stop(mesh1);
	meshlink_close(mesh2);
	meshlink_close(mesh1);
	meshlink_destroy("channel_open_conf.1");
	meshlink_destroy("channel_open_conf.1");

	return true;
}
