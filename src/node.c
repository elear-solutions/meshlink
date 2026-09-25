/*
    node.c -- node tree management
    Copyright (C) 2014 Guus Sliepen <guus@meshlink.io>,

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

#include "hash.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "connection_policy.h"
#include "path_policy.h"
#include "relay.h"
#include "splay_tree.h"
#include "utils.h"
#include "xalloc.h"

static int node_compare(const node_t *a, const node_t *b) {
	return strcmp(a->name, b->name);
}

void init_nodes(meshlink_handle_t *mesh) {
	mesh->nodes = splay_alloc_tree((splay_compare_t) node_compare, (splay_action_t) free_node);
	mesh->node_udp_cache = hash_alloc(0x100, sizeof(sockaddr_t));
}

void exit_nodes(meshlink_handle_t *mesh) {
	if(mesh->node_udp_cache) {
		hash_free(mesh->node_udp_cache);
	}

	if(mesh->nodes) {
		splay_delete_tree(mesh->nodes);
	}

	mesh->node_udp_cache = NULL;
	mesh->nodes = NULL;
}

node_t *new_node(void) {
	node_t *n = xzalloc(sizeof(*n));

	n->edge_tree = new_edge_tree();
	n->mtu = MTU;
	n->maxmtu = MTU;
	n->devclass = DEV_CLASS_UNKNOWN;
	n->udp_tier = PATH_TIER_NONE;
	n->last_path_tier = PATH_TIER_NONE;
	n->active_route.kind = DATA_ROUTE_NONE;
	n->active_route.relay_carrier = RELAY_CARRIER_NONE;

	return n;
}

static void node_clear_inbound_prev_nexthop(meshlink_handle_t *mesh, node_t *dying) {
	if(!mesh || !mesh->nodes || !dying) {
		return;
	}

	for splay_each(node_t, n, mesh->nodes) {
		if(n->prev_nexthop == dying) {
			n->prev_nexthop = NULL;
		}
	}
}

/* A recorded route names its first hop, a waiting candidate may pin the same
   node, and a send in progress may have queued it for deferred demotion. All
   three outlive the node unless cleared. */
static void node_clear_route_references(meshlink_handle_t *mesh, node_t *dying) {
	if(!mesh || !dying) {
		return;
	}

	if(mesh->nodes) {
		for splay_each(node_t, n, mesh->nodes) {
			if(n->active_route.first_hop == dying) {
				path_suspect_stop(mesh, n);
				memset(&n->active_route, 0, sizeof n->active_route);
			}

			if(n->promotion_candidate.first_hop == dying) {
				timeout_del(&mesh->loop, &n->promotion_timer);
				memset(&n->promotion_candidate, 0, sizeof n->promotion_candidate);
				path_scheduler_cancel_node(mesh, n);
			}
		}
	}

	for(unsigned i = 0; i < mesh->route_guard_deferred_count; i++) {
		if(mesh->route_guard_deferred[i] == dying) {
			mesh->route_guard_deferred[i] = mesh->route_guard_deferred[--mesh->route_guard_deferred_count];
			break;
		}
	}

	dying->demote_deferred = false;
}

void node_set_validkey(meshlink_handle_t *mesh, node_t *n, bool valid) {
	if(!n) {
		return;
	}

	if(n->status.validkey == valid) {
		return;
	}

	n->status.validkey = valid;
	path_note_selected_route(mesh, n, valid ? "key recovered" : "key invalidated");
}

void free_node(node_t *n) {
	n->status.destroyed = true;

	utcp_exit(n->utcp);

	if(n->edge_tree) {
		free_edge_tree(n->edge_tree);
	}

	sockaddrfree(&n->address);

	ecdsa_free(n->ecdsa);
	sptps_stop(&n->sptps);

	if(n->mtutimeout.cb || n->promotion_timer.cb || n->suspect_validation.timer.cb) {
		abort();
	}

	free(n->name);
	free(n->canonical_address);
	free(n->external_ip_address);

	free(n);
}

void node_add(meshlink_handle_t *mesh, node_t *n) {
	n->mesh = mesh;
	splay_insert(mesh->nodes, n);
	connection_policy_on_node_added(mesh, n);
}

static void node_udp_cache_forget(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || !mesh->node_udp_cache) {
		return;
	}

	hash_insert(mesh->node_udp_cache, &n->address, NULL);

	if(n->udp_cache_extra.sa.sa_family) {
		hash_insert(mesh->node_udp_cache, &n->udp_cache_extra, NULL);
		memset(&n->udp_cache_extra, 0, sizeof n->udp_cache_extra);
	}

	if(n->last_udp_from.sa.sa_family) {
		if(hash_search(mesh->node_udp_cache, &n->last_udp_from) == n) {
			hash_insert(mesh->node_udp_cache, &n->last_udp_from, NULL);
		}

		memset(&n->last_udp_from, 0, sizeof n->last_udp_from);
	}
}

void node_udp_cache_alias(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa) {
	if(!mesh || !n || !sa || !mesh->node_udp_cache) {
		return;
	}

	if(n->udp_cache_extra.sa.sa_family) {
		hash_insert(mesh->node_udp_cache, &n->udp_cache_extra, NULL);
	}

	path_copy_sockaddr(&n->udp_cache_extra, sa);

	if(n->udp_cache_extra.sa.sa_family) {
		hash_insert(mesh->node_udp_cache, &n->udp_cache_extra, n);
	}
}

void node_del(meshlink_handle_t *mesh, node_t *n) {
	path_reset_canonical_resolve(n);
	node_udp_cache_forget(mesh, n);
	node_clear_inbound_prev_nexthop(mesh, n);
	node_clear_route_references(mesh, n);
	timeout_del(&mesh->loop, &n->mtutimeout);
	timeout_del(&mesh->loop, &n->promotion_timer);
	path_suspect_stop(mesh, n);
	memset(&n->peer_udp, 0, sizeof n->peer_udp);
	path_scheduler_cancel_node(mesh, n);

	for splay_each(edge_t, e, n->edge_tree) {
		edge_del(mesh, e);
	}

	connection_policy_on_node_deleted(mesh, n);
	splay_delete(mesh->nodes, n);
	connection_policy_validate_topology(mesh);
}

node_t *lookup_node(meshlink_handle_t *mesh, const char *name) {
	const node_t n = {.name = (char *)name};
	node_t *result;

	result = splay_search(mesh->nodes, &n);

	return result;
}

node_t *lookup_node_udp(meshlink_handle_t *mesh, const sockaddr_t *sa) {
	sockaddr_t key;

	/* Same canonical form path_copy_sockaddr() uses for cache keys. */
	path_copy_sockaddr(&key, sa);

	if(!key.sa.sa_family) {
		return NULL;
	}

	return hash_search(mesh->node_udp_cache, &key);
}

bool graph_may_seed_udp(const node_t *n, const sockaddr_t *edge_addr) {
	if(!n || !edge_addr) {
		return false;
	}

	if(n->status.reachable && n->address.sa.sa_family != AF_UNSPEC) {
		return false;
	}

	if(edge_addr->sa.sa_family == AF_UNKNOWN || n->status.udp_confirmed) {
		return false;
	}

	if(path_address_matches_canonical(n, edge_addr) || path_address_shares_canonical_ip(n, edge_addr)) {
		return false;
	}

	return udp_address_usable(edge_addr);
}

void update_node_udp_from(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src) {
	if(n == mesh->self) {
		logger(mesh, MESHLINK_WARNING, "Trying to update UDP address of mesh->self!");
		return;
	}

	node_udp_cache_forget(mesh, n);

	if(sa) {
		bool same = n->address.sa.sa_family && !sockaddrcmp(&n->address, sa);

		path_copy_sockaddr(&n->address, sa);

		/* UNKNOWN must not demote a known source on the same address. */
		if(!same || src != ADDR_SRC_UNKNOWN || n->address_source == ADDR_SRC_UNKNOWN) {
			n->address_source = src;
			n->address_cap = path_default_cap(src);
		}

		n->sock = 0;

		for(int i = 0; i < mesh->listen_sockets; i++) {
			if(mesh->listen_socket[i].sa.sa.sa_family == sa->sa.sa_family) {
				n->sock = i;
				break;
			}
		}

		hash_insert(mesh->node_udp_cache, &n->address, n);

		if(mesh->log_level <= MESHLINK_DEBUG) {
			char *hostname = sockaddr2hostname(&n->address);
			logger(mesh, MESHLINK_DEBUG, "UDP address of %s set to %s", n->name, hostname);
			free(hostname);
		}
	} else {
		n->address_source = ADDR_SRC_UNKNOWN;
		n->address_cap = PATH_CAP_NONE;
	}
}

void update_node_udp(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa) {
	update_node_udp_from(mesh, n, sa, ADDR_SRC_UNKNOWN);
}

bool node_add_recent_address(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src) {
	return path_learn_address(mesh, n, sa, src);
}

bool node_add_recent_address_cap(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	return path_learn_address_cap(mesh, n, sa, src, cap);
}

bool node_add_recent_address_cap_ex(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap, bool *material) {
	return path_learn_address_cap_ex(mesh, n, sa, src, cap, material);
}

bool node_append_recent_address(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src) {
	return path_learn_address_fallback(mesh, n, sa, src);
}

bool node_append_recent_address_cap(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa, address_source_t src, path_cap_t cap) {
	return path_learn_address_fallback_cap(mesh, n, sa, src, cap);
}
