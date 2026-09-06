/*
    net_upgrade.c -- upgrade a canonical (relay) meta connection to a direct one
    Copyright (C) 2014-2017 Guus Sliepen <guus@meshlink.io>

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

#include "system.h"

#include "connection.h"
#include "devtools.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "net_upgrade.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "xalloc.h"

/* Only the side that owns the outgoing_t probes; the peer migrates when the
   probe shows up as a second inbound connection. */
bool upgrade_probe_eligible(meshlink_handle_t *mesh, node_t *n) {
	connection_t *c = n->connection;

	if(!c || !c->status.active || !c->status.via_canonical || !c->outgoing) {
		return false;
	}

	if(n->upgrade_probe || n->status.blacklisted) {
		return false;
	}

	if(n->recent[0].sa.sa_family == AF_UNSPEC) {
		return false;
	}

	return mesh->loop.now.tv_sec >= n->upgrade_next_try;
}

/* Pick the next recent[] slot that is not the address we are already connected
   to, rotating through the list so a dead front entry does not starve the rest.
   Like everywhere else, recent[] ends at the first unset slot. Returns false if
   there is nothing to try. */
static bool pick_probe_address(node_t *n, sockaddr_t *out) {
	int count = 0;

	while(count < MAX_RECENT && n->recent[count].sa.sa_family != AF_UNSPEC) {
		count++;
	}

	for(int i = 0; i < count; i++) {
		int idx = (n->upgrade_recent_idx + i) % count;
		const sockaddr_t *sa = &n->recent[idx];

		if(n->connection && !sockaddrcmp(sa, &n->connection->address)) {
			continue;
		}

		*out = *sa;
		n->upgrade_recent_idx = (idx + 1) % count;
		return true;
	}

	return false;
}

static void apply_backoff(meshlink_handle_t *mesh, node_t *n) {
	if(n->upgrade_backoff) {
		n->upgrade_backoff *= 2;

		if(n->upgrade_backoff > UPGRADE_BACKOFF_MAX) {
			n->upgrade_backoff = UPGRADE_BACKOFF_MAX;
		}
	} else {
		n->upgrade_backoff = UPGRADE_BACKOFF_MIN;
	}

	n->upgrade_next_try = mesh->loop.now.tv_sec + n->upgrade_backoff;
}

void start_upgrade_probe(meshlink_handle_t *mesh, node_t *n) {
	sockaddr_t sa;

	if(!pick_probe_address(n, &sa)) {
		logger(mesh, MESHLINK_DEBUG, "No direct address to probe for %s", n->name);
		apply_backoff(mesh, n);
		return;
	}

	connection_t *c = new_connection();
	c->outgoing = NULL;
	c->status.upgrade_probe = true;
	c->name = xstrdup(n->name);
	c->address = sa;

	if(mesh->log_level <= MESHLINK_INFO) {
		char *hostname = sockaddr2hostname(&c->address);
		logger(mesh, MESHLINK_INFO, "Probing direct address %s for %s to replace canonical connection", hostname, n->name);
		free(hostname);
	}

	if(!connect_meta_socket(mesh, c)) {
		free_connection(c);
		apply_backoff(mesh, n);
		devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_FAILED);
		return;
	}

	n->upgrade_probe = c;
	devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_STARTED);
}

void try_upgrade_probe(meshlink_handle_t *mesh, node_t *n) {
	if(upgrade_probe_eligible(mesh, n)) {
		start_upgrade_probe(mesh, n);
	}
}

void upgrade_probe_failed(meshlink_handle_t *mesh, node_t *n) {
	n->upgrade_probe = NULL;
	apply_backoff(mesh, n);
	logger(mesh, MESHLINK_INFO, "Direct probe to %s failed, next try in %d seconds", n->name, n->upgrade_backoff);
	devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_FAILED);
}

void upgrade_probe_succeeded(meshlink_handle_t *mesh, connection_t *c) {
	node_t *n = c->node;

	c->status.upgrade_probe = false;
	n->upgrade_probe = NULL;
	n->upgrade_backoff = 0;
	n->upgrade_next_try = 0;

	if(mesh->log_level <= MESHLINK_INFO) {
		char *hostname = sockaddr2hostname(&c->address);
		logger(mesh, MESHLINK_INFO, "Migrated meta connection to %s from canonical to direct %s", n->name, hostname);
		free(hostname);
	}

	devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_SUCCEEDED);
}

/* The peer probed us to replace its canonical connection. Its old connection stays
   the node's connection until the peer closes it; this one is fully authenticated and
   pinged like any other, with its edge prepared but not yet in the graph. */
void upgrade_hold_spare(meshlink_handle_t *mesh, connection_t *c, node_t *n, const char *hisport, int devclass) {
	c->node = n;
	c->allow_request = ALL;
	c->last_key_renewal = mesh->loop.now.tv_sec;
	c->status.active = true;
	c->status.spare = true;

	c->edge = new_edge();
	c->edge->from = mesh->self;
	c->edge->to = n;
	sockaddrcpy_setport(&c->edge->address, &c->address, atoi(hisport));
	c->edge->weight = mesh->dev_class_traits[devclass].edge_weight;
	c->edge->connection = c;

	node_add_recent_address(mesh, n, &c->address);

	if(mesh->log_level <= MESHLINK_INFO) {
		char *hostname = sockaddr2hostname(&c->address);
		logger(mesh, MESHLINK_INFO, "Holding direct connection from %s at %s as a spare until its current connection closes", n->name, hostname);
		free(hostname);
	}
}

connection_t *upgrade_find_spare(meshlink_handle_t *mesh, const node_t *n) {
	for list_each(connection_t, c, mesh->connections) {
		if(c->status.spare && c->status.active && c->node == n) {
			return c;
		}
	}

	return NULL;
}

/* old is going away: swap the node over to spare in one step, so the graph never
   sees the node without an edge. Caller (terminate_connection) finishes old. */
void upgrade_promote_spare(meshlink_handle_t *mesh, connection_t *old, connection_t *spare) {
	node_t *n = old->node;

	logger(mesh, MESHLINK_INFO, "Promoting spare direct connection with %s, its previous connection is closing", n->name);

	if(mesh->meta_status_cb) {
		mesh->meta_status_cb(mesh, (meshlink_node_t *)n, false);
	}

	if(old->outgoing && !spare->outgoing) {
		spare->outgoing = old->outgoing;
		old->outgoing = NULL;
	}

	if(old->edge) {
		edge_del(mesh, old->edge);
		old->edge = NULL;
	}

	spare->status.spare = false;
	n->connection = spare;
	n->nexthop = n;
	n->last_successfull_connection = mesh->loop.now.tv_sec;

	edge_add(mesh, spare->edge);
	send_add_edge(mesh, mesh->everyone, spare->edge, 0);
	graph(mesh);

	if(mesh->meta_status_cb) {
		mesh->meta_status_cb(mesh, (meshlink_node_t *)n, true);
	}
}

/* At most one probe start per tick, so a burst of eligible nodes does not
   open a burst of sockets. */
void upgrade_probe_sweep(meshlink_handle_t *mesh) {
	for splay_each(node_t, n, mesh->nodes) {
		if(upgrade_probe_eligible(mesh, n)) {
			start_upgrade_probe(mesh, n);
			return;
		}
	}
}
