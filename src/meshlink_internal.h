/*
    meshlink_internal.h -- Internal parts of the public API.
    Copyright (C) 2014 Guus Sliepen <guus@meshlink.io>

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

#ifndef MESHLINK_INTERNAL_H
#define MESHLINK_INTERNAL_H

#include "system.h"

#include "node.h"
#include "meshlink.h"
#include "splay_tree.h"

#define MAXSOCKETS 16

/// A handle for an instance of MeshLink.
struct meshlink_handle {
	char *confbase;
	char *name;

	meshlink_receive_cb_t receive_cb;
	meshlink_node_status_cb_t node_status_cb;
	meshlink_log_cb_t log_cb;
	meshlink_log_level_t log_level;

	pthread_t thread;
	listen_socket_t listen_socket[MAXSOCKETS];

	node_t *myself;

	splay_tree_t *config;
	splay_tree_t *edges;
	splay_tree_t *nodes;

	list_t *outgoing_connections;
};

/// A handle for a MeshLink node.
struct meshlink_node {
	const char *name;
	void *priv;
};

#endif // MESHLINK_INTERNAL_H