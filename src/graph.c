/*
    graph.c -- graph algorithms
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

/* We need to generate two trees from the graph:

   1. A minimum spanning tree for broadcasts,
   2. A single-source shortest path tree for unicasts.

   Actually, the first one alone would suffice but would make unicast packets
   take longer routes than necessary.

   For the MST algorithm we can choose from Prim's or Kruskal's. I personally
   favour Kruskal's, because we make an extra AVL tree of edges sorted on
   weights (metric). That tree only has to be updated when an edge is added or
   removed, and during the MST algorithm we just have go linearly through that
   tree, adding safe edges until #edges = #nodes - 1. The implementation here
   however is not so fast, because I tried to avoid having to make a forest and
   merge trees.

   For the SSSP algorithm Dijkstra's seems to be a nice choice. Currently a
   simple breadth-first search is presented here.

   The SSSP algorithm will also be used to determine whether nodes are
   reachable from the source. It will also set the correct destination address
   and port of a node if possible.
*/

#include "system.h"

#include "connection.h"
#include "edge.h"
#include "graph.h"
#include "list.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"
#include "graph.h"

/* Implementation of a simple breadth-first search algorithm.
   Running time: O(E)
*/

static void sssp_bfs(meshlink_handle_t *mesh) {
	logger(mesh, MESHLINK_INFO, "%s.%d list_alloc(NULL)\n", __func__, __LINE__);
	list_t *todo_list = list_alloc(NULL);

	/* Clear visited status on nodes */

	logger(mesh, MESHLINK_INFO, "%s.%d Clear visited status on nodes\n", __func__, __LINE__);
	for splay_each(node_t, n, mesh->nodes) {
	logger(mesh, MESHLINK_INFO, "%s.%d n->status.visited = false\n", __func__, __LINE__);
		n->status.visited = false;
	logger(mesh, MESHLINK_INFO, "%s.%d n->distance = -1\n", __func__, __LINE__);
		n->distance = -1;
	logger(mesh, MESHLINK_INFO, "%s.%d end of splay each loop\n", __func__, __LINE__);
	}

	logger(mesh, MESHLINK_INFO, "%s.%d splay each loop done\n", __func__, __LINE__);
	/* Begin with mesh->self */

	logger(mesh, MESHLINK_INFO, "%s.%d Begin with mesh->self->status.visited\n", __func__, __LINE__);
	mesh->self->status.visited = mesh->threadstarted;
	logger(mesh, MESHLINK_INFO, "%s.%d mesh->self->nexthop = mesh->self\n", __func__, __LINE__);
	mesh->self->nexthop = mesh->self;
	logger(mesh, MESHLINK_INFO, "%s.%d mesh->self->prevedge\n", __func__, __LINE__);
	mesh->self->prevedge = NULL;
	logger(mesh, MESHLINK_INFO, "%s.%d mesh->self->distance\n", __func__, __LINE__);
	mesh->self->distance = 0;
	logger(mesh, MESHLINK_INFO, "%s.%d mesh self list_insert_head\n", __func__, __LINE__);
	list_insert_head(todo_list, mesh->self);

	/* Loop while todo_list is filled */

	logger(mesh, MESHLINK_INFO, "%s.%d Loop while todo_list is filled\n", __func__, __LINE__);
	for list_each(node_t, n, todo_list) {                   /* "n" is the node from which we start */
	logger(mesh, MESHLINK_INFO, "%s.%d Examining edges from %s\n", __func__, __LINE__, n->name);

	logger(mesh, MESHLINK_INFO, "%s.%d En->distance < 0\n", __func__, __LINE__);
		if(n->distance < 0) {
	logger(mesh, MESHLINK_INFO, "%s.%d abort()\n", __func__, __LINE__);
			abort();
		}

	logger(mesh, MESHLINK_INFO, "%s.%d splay each, the edge connected to\n", __func__, __LINE__);
		for splay_each(edge_t, e, n->edge_tree) {       /* "e" is the edge connected to "from" */
	logger(mesh, MESHLINK_INFO, "%s.%d !e->reverse\n", __func__, __LINE__);
			if(!e->reverse) {
	logger(mesh, MESHLINK_INFO, "%s.%d splay edge continue\n", __func__, __LINE__);
				continue;
			}

			/* Situation:

			           /
			          /
			   ----->(n)---e-->(e->to)
			          \
			           \

			   Where e is an edge, (n) and (e->to) are nodes.
			   n->address is set to the e->address of the edge left of n to n.
			   We are currently examining the edge e right of n from n:

			   - If edge e provides for better reachability of e->to, update
			     e->to and (re)add it to the todo_list to (re)examine the reachability
			     of nodes behind it.
			 */

	logger(mesh, MESHLINK_INFO, "%s.%d e->to->status.visited\n", __func__, __LINE__);
			if(e->to->status.visited
			                && (e->to->distance != n->distance + 1 || e->weight >= e->to->prevedge->weight)) {
	logger(mesh, MESHLINK_INFO, "%s.%d splay edge continue\n", __func__, __LINE__);
				continue;
			}

	logger(mesh, MESHLINK_INFO, "%s.%d e->to->status.visited = true\n", __func__, __LINE__);
			e->to->status.visited = true;
	logger(mesh, MESHLINK_INFO, "%s.%d e->to->nexthop\n", __func__, __LINE__);
			e->to->nexthop = (n->nexthop == mesh->self) ? e->to : n->nexthop;
	logger(mesh, MESHLINK_INFO, "%s.%d e->to->prevedge\n", __func__, __LINE__);
			e->to->prevedge = e;
	logger(mesh, MESHLINK_INFO, "%s.%d e->to->distance\n", __func__, __LINE__);
			e->to->distance = n->distance + 1;

	logger(mesh, MESHLINK_INFO, "%s.%d e->to->status.reachable\n", __func__, __LINE__);
			if(!e->to->status.reachable || (e->to->address.sa.sa_family == AF_UNSPEC && e->address.sa.sa_family != AF_UNKNOWN)) {
	logger(mesh, MESHLINK_INFO, "%s.%d update_node_udp\n", __func__, __LINE__);
				update_node_udp(mesh, e->to, &e->address);
	logger(mesh, MESHLINK_INFO, "%s.%d update_node_udp done\n", __func__, __LINE__);
			}

	logger(mesh, MESHLINK_INFO, "%s.%d list_insert_tail\n", __func__, __LINE__);
			list_insert_tail(todo_list, e->to);
	logger(mesh, MESHLINK_INFO, "%s.%d list_insert_tail done\n", __func__, __LINE__);
		}

	logger(mesh, MESHLINK_INFO, "%s.%d next = node->next\n", __func__, __LINE__);
		next = node->next; /* Because the list_insert_tail() above could have added something extra for us! */
	logger(mesh, MESHLINK_INFO, "%s.%d list_delete_node\n", __func__, __LINE__);
		list_delete_node(todo_list, node);
	logger(mesh, MESHLINK_INFO, "%s.%d list_delete_node done\n", __func__, __LINE__);
	}

	logger(mesh, MESHLINK_INFO, "%s.%d list_free\n", __func__, __LINE__);
	list_free(todo_list);
	logger(mesh, MESHLINK_INFO, "%s.%d list_free done, returning\n", __func__, __LINE__);
}

static void check_reachability(meshlink_handle_t *mesh) {
	/* Check reachability status. */

	int reachable = -1; /* Don't count ourself */

	logger(mesh, MESHLINK_INFO, "%s.%d splay_each nodes\n", __func__, __LINE__);
	for splay_each(node_t, n, mesh->nodes) {
	logger(mesh, MESHLINK_INFO, "%s.%d n->status.visited nodes\n", __func__, __LINE__);
		if(n->status.visited) {
	logger(mesh, MESHLINK_INFO, "%s.%d reachable++\n", __func__, __LINE__);
			reachable++;
		}

		/* Check for nodes that have changed session_id */
	logger(mesh, MESHLINK_INFO, "%s.%d n->status.visited\n", __func__, __LINE__);
		if(n->status.visited && n->prevedge && n->prevedge->reverse->session_id != n->session_id) {
	logger(mesh, MESHLINK_INFO, "%s.%d n->session_id\n", __func__, __LINE__);
			n->session_id = n->prevedge->reverse->session_id;

	logger(mesh, MESHLINK_INFO, "%s.%d if n->utcp\n", __func__, __LINE__);
			if(n->utcp) {
	logger(mesh, MESHLINK_INFO, "%s.%d utcp_abort_all_connections\n", __func__, __LINE__);
				utcp_abort_all_connections(n->utcp);
	logger(mesh, MESHLINK_INFO, "%s.%d utcp_abort_all_connections done\n", __func__, __LINE__);
			}

	logger(mesh, MESHLINK_INFO, "%s.%d n->status.visited == n->status.reachable\n", __func__, __LINE__);
			if(n->status.visited == n->status.reachable) {
				/* This session replaces the previous one without changing reachability status.
				 * We still need to reset the UDP SPTPS state.
				 */
	logger(mesh, MESHLINK_INFO, "%s.%d n->status.validkey = false\n", __func__, __LINE__);
				n->status.validkey = false;
	logger(mesh, MESHLINK_INFO, "%s.%d sptps_stop\n", __func__, __LINE__);
				sptps_stop(&n->sptps);
	logger(mesh, MESHLINK_INFO, "%s.%d waitingforkey\n", __func__, __LINE__);
				n->status.waitingforkey = false;
	logger(mesh, MESHLINK_INFO, "%s.%d last_req_key = 0\n", __func__, __LINE__);
				n->last_req_key = 0;

	logger(mesh, MESHLINK_INFO, "%s.%d udp_confirmed\n", __func__, __LINE__);
				n->status.udp_confirmed = false;
	logger(mesh, MESHLINK_INFO, "%s.%d maxmtu = MTU\n", __func__, __LINE__);
				n->maxmtu = MTU;
	logger(mesh, MESHLINK_INFO, "%s.%d minmtu = 0\n", __func__, __LINE__);
				n->minmtu = 0;
	logger(mesh, MESHLINK_INFO, "%s.%d mtuprobes\n", __func__, __LINE__);
				n->mtuprobes = 0;

	logger(mesh, MESHLINK_INFO, "%s.%d timeout_del\n", __func__, __LINE__);
				timeout_del(&mesh->loop, &n->mtutimeout);
	logger(mesh, MESHLINK_INFO, "%s.%d timeout_del done\n", __func__, __LINE__);
			}
	logger(mesh, MESHLINK_INFO, "%s.%d n->status.visited == n->status.reachable DONE\n", __func__, __LINE__);
		}

	logger(mesh, MESHLINK_INFO, "%s.%d check n->status.visited != n->status.reachable\n", __func__, __LINE__);
		if(n->status.visited != n->status.reachable) {
	logger(mesh, MESHLINK_INFO, "%s.%d n->status.reachable = !n->status.reachable\n", __func__, __LINE__);
			n->status.reachable = !n->status.reachable;
	logger(mesh, MESHLINK_INFO, "%s.%d status.dirty = true\n", __func__, __LINE__);
			n->status.dirty = true;

	logger(mesh, MESHLINK_INFO, "%s.%d if n->status.reachable\n", __func__, __LINE__);
			if(n->status.reachable) {
	logger(mesh, MESHLINK_INFO, "%s.%d Node %s became reachable\n", __func__, __LINE__, n->name);
				bool first_time_reachable = !n->last_reachable;
	logger(mesh, MESHLINK_INFO, "%s.%d last_reachable = mesh->loop.now.tv_sec\n", __func__, __LINE__);
				n->last_reachable = mesh->loop.now.tv_sec;

	logger(mesh, MESHLINK_INFO, "%s.%d first_time_reachable\n", __func__, __LINE__);
				if(first_time_reachable) {
	logger(mesh, MESHLINK_INFO, "%s.%d node_write_config\n", __func__, __LINE__);
					node_write_config(mesh, n);
	logger(mesh, MESHLINK_INFO, "%s.%d node_write_config done\n", __func__, __LINE__);
				}
			} else {
	logger(mesh, MESHLINK_INFO, "%s.%d Node %s became unreachable\n", __func__, __LINE__, n->name);
				n->last_unreachable = mesh->loop.now.tv_sec;
	logger(mesh, MESHLINK_INFO, "%s.%d Node %s became unreachable set\n", __func__, __LINE__, n->name);
			}

			/* TODO: only clear status.validkey if node is unreachable? */

	logger(mesh, MESHLINK_INFO, "%s.%d n->status.validkey = false\n", __func__, __LINE__);
			n->status.validkey = false;
	logger(mesh, MESHLINK_INFO, "%s.%d sptps_stop\n", __func__, __LINE__);
			sptps_stop(&n->sptps);
	logger(mesh, MESHLINK_INFO, "%s.%d status.waitingforkey = false\n", __func__, __LINE__);
			n->status.waitingforkey = false;
	logger(mesh, MESHLINK_INFO, "%s.%d last_req_key = 0\n", __func__, __LINE__);
			n->last_req_key = 0;

	logger(mesh, MESHLINK_INFO, "%s.%d set n_->...\n", __func__, __LINE__);
			n->status.udp_confirmed = false;
	logger(mesh, MESHLINK_INFO, "%s.%d set n_->...\n", __func__, __LINE__);
			n->maxmtu = MTU;
	logger(mesh, MESHLINK_INFO, "%s.%d set n_->...\n", __func__, __LINE__);
			n->minmtu = 0;
	logger(mesh, MESHLINK_INFO, "%s.%d set n_->...\n", __func__, __LINE__);
			n->mtuprobes = 0;

	logger(mesh, MESHLINK_INFO, "%s.%d timeout_del\n", __func__, __LINE__);
			timeout_del(&mesh->loop, &n->mtutimeout);
	logger(mesh, MESHLINK_INFO, "%s.%d timeout_del done\n", __func__, __LINE__);

	logger(mesh, MESHLINK_INFO, "%s.%d check blacklisted\n", __func__, __LINE__);
			if(!n->status.blacklisted) {
	logger(mesh, MESHLINK_INFO, "%s.%d update_node_status\n", __func__, __LINE__);
				update_node_status(mesh, n);
	logger(mesh, MESHLINK_INFO, "%s.%d update_node_status done\n", __func__, __LINE__);
			}

	logger(mesh, MESHLINK_INFO, "%s.%d !n->status.reachable\n", __func__, __LINE__);
			if(!n->status.reachable) {
	logger(mesh, MESHLINK_INFO, "%s.%d update_node_status\n", __func__, __LINE__);
				update_node_udp(mesh, n, NULL);
	logger(mesh, MESHLINK_INFO, "%s.%d update_node_status done\n", __func__, __LINE__);
				n->status.broadcast = false;
			} else if(n->connection) {
	logger(mesh, MESHLINK_INFO, "%s.%d n->connection->status.initiator\n", __func__, __LINE__);
				if(n->connection->status.initiator) {
	logger(mesh, MESHLINK_INFO, "%s.%d send req keyn", __func__, __LINE__);
					send_req_key(mesh, n);
	logger(mesh, MESHLINK_INFO, "%s.%d sent req keyn", __func__, __LINE__);
				}
			}

	logger(mesh, MESHLINK_INFO, "%s.%d if n->utcp", __func__, __LINE__);
			if(n->utcp) {
	logger(mesh, MESHLINK_INFO, "%s.%d utcp_offline", __func__, __LINE__);
				utcp_offline(n->utcp, !n->status.reachable);
	logger(mesh, MESHLINK_INFO, "%s.%d utcp_offline done", __func__, __LINE__);
			}
		}
	}

	logger(mesh, MESHLINK_INFO, "%s.%d mesh->reachable != reachable", __func__, __LINE__);
	if(mesh->reachable != reachable) {
	logger(mesh, MESHLINK_INFO, "%s.%d !reachable", __func__, __LINE__);
		if(!reachable) {
	logger(mesh, MESHLINK_INFO, "%s.%d last_unreachable = mesh->loop.now.tv_sec", __func__, __LINE__);
			mesh->last_unreachable = mesh->loop.now.tv_sec;

	logger(mesh, MESHLINK_INFO, "%s.%d check mesh->threadstarted", __func__, __LINE__);
			if(mesh->threadstarted) {
	logger(mesh, MESHLINK_INFO, "%s.%d timeout_set", __func__, __LINE__);
				timeout_set(&mesh->loop, &mesh->periodictimer, &(struct timeval) {
					0, prng(mesh, TIMER_FUDGE)
				});
	logger(mesh, MESHLINK_INFO, "%s.%d timeout_set done", __func__, __LINE__);
			}
		}

	logger(mesh, MESHLINK_INFO, "%s.%d mesh->reachable = reachable", __func__, __LINE__);
		mesh->reachable = reachable;
	}
	logger(mesh, MESHLINK_INFO, "%s.%d check_reachability done", __func__, __LINE__);
}

void graph(meshlink_handle_t *mesh) {
	logger(mesh, MESHLINK_INFO, "%s.%d sssp_bfs(mesh)", __func__, __LINE__);
	sssp_bfs(mesh);
	logger(mesh, MESHLINK_INFO, "%s.%d check_reachability(mesh)", __func__, __LINE__);
	check_reachability(mesh);
	logger(mesh, MESHLINK_INFO, "%s.%d returning from graph()", __func__, __LINE__);
}
