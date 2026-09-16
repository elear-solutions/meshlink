/*
    devtools.c -- Debugging and quality control functions.
    Copyright (C) 2014, 2017 Guus Sliepen <guus@meshlink.io>

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
#include <assert.h>

#include "connection.h"
#include "list.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "node.h"
#include "connection_policy.h"
#include "path_policy.h"
#include "path_policy_devtool.h"
#include "relay.h"
#include "relay_devtool.h"
#include "sptps.h"
#include "submesh.h"
#include "splay_tree.h"
#include "netutl.h"
#include "xalloc.h"

#include "devtools.h"

_Static_assert(DEVTOOL_MAX_RECENT == MAX_RECENT, "devtool_node_status_t.recent[] must mirror node_t.recent[]");
_Static_assert(DEVTOOL_MAX_CANONICAL == MAX_CANONICAL_SA, "devtool_node_status_t.canonical_resolved[] must mirror MAX_CANONICAL_SA");

static void nop_probe(void) {
	return;
}

static void keyrotate_nop_probe(int stage) {
	(void)stage;
	return;
}

static void inviter_commits_first_nop_probe(bool stage) {
	(void)stage;
	return;
}

static void sptps_renewal_nop_probe(meshlink_node_t *node) {
	(void)node;
	return;
}

static void upgrade_nop_probe(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_upgrade_probe_stage_t stage) {
	(void)mesh;
	(void)node;
	(void)stage;
	return;
}

void (*devtool_trybind_probe)(void) = nop_probe;
void (*devtool_keyrotate_probe)(int stage) = keyrotate_nop_probe;
void (*devtool_set_inviter_commits_first)(bool inviter_commited_first) = inviter_commits_first_nop_probe;
void (*devtool_adns_resolve_probe)(void) = nop_probe;
void (*devtool_sptps_renewal_probe)(meshlink_node_t *node) = sptps_renewal_nop_probe;
void (*devtool_upgrade_probe)(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_upgrade_probe_stage_t stage) = upgrade_nop_probe;
bool devtool_repeat_next_ack = false;

/* Return an array of edges in the current network graph.
 * Data captures the current state and will not be updated.
 * Caller must deallocate data when done.
 */
devtool_edge_t *devtool_get_all_edges(meshlink_handle_t *mesh, devtool_edge_t *edges, size_t *nmemb) {
	if(!mesh || !nmemb || (*nmemb && !edges)) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	devtool_edge_t *result = NULL;
	unsigned int result_size = 0;

	result_size = mesh->edges->count / 2;

	// if result is smaller than edges, we have to dealloc all the excess devtool_edge_t
	if((size_t)result_size > *nmemb) {
		result = xrealloc(edges, result_size * sizeof(*result));
	} else {
		result = edges;
	}

	if(result) {
		devtool_edge_t *p = result;
		unsigned int n = 0;

		for splay_each(edge_t, e, mesh->edges) {
			// skip edges that do not represent a two-directional connection
			if(!e->reverse || e->reverse->to != e->from) {
				continue;
			}

			// don't count edges twice
			if(e->to < e->from) {
				continue;
			}

			assert(n < result_size);

			p->from = (meshlink_node_t *)e->from;
			p->to = (meshlink_node_t *)e->to;
			p->address = e->address.storage;
			p->weight = e->weight;

			n++;
			p++;
		}

		// shrink result to the actual amount of memory used
		result = xrealloc(result, n * sizeof(*result));
		*nmemb = n;
	} else {
		*nmemb = 0;
		meshlink_errno = MESHLINK_ENOMEM;
	}

	pthread_mutex_unlock(&mesh->mutex);

	return result;
}

static bool fstrwrite(const char *str, FILE *stream) {
	assert(stream);

	size_t len = strlen(str);

	if(fwrite((void *)str, 1, len, stream) != len) {
		return false;
	}

	return true;
}

bool devtool_export_json_all_edges_state(meshlink_handle_t *mesh, FILE *stream) {
	assert(stream);

	bool result = true;

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	// export edges and nodes
	size_t node_count = 0;
	size_t edge_count = 0;

	meshlink_node_t **nodes = meshlink_get_all_nodes(mesh, NULL, &node_count);
	devtool_edge_t *edges = devtool_get_all_edges(mesh, NULL, &edge_count);

	if((!nodes && node_count != 0) || (!edges && edge_count != 0)) {
		goto fail;
	}

	// export begin
	if(!fstrwrite("{\n", stream)) {
		goto fail;
	}

	if(!fstrwrite("\t\"backbone\": ", stream)) {
		goto fail;
	}

	if(mesh->backbone.name) {
		if(!fstrwrite("\"", stream) || !fstrwrite(mesh->backbone.name, stream) || !fstrwrite("\",\n", stream)) {
			goto fail;
		}
	} else if(!fstrwrite("null,\n", stream)) {
		goto fail;
	}

	// export nodes
	if(!fstrwrite("\t\"nodes\": {\n", stream)) {
		goto fail;
	}

	char buf[16];

	for(size_t i = 0; i < node_count; ++i) {
		if(!fstrwrite("\t\t\"", stream) || !fstrwrite(((node_t *)nodes[i])->name, stream) || !fstrwrite("\": {\n", stream)) {
			goto fail;
		}

		if(!fstrwrite("\t\t\t\"name\": \"", stream) || !fstrwrite(((node_t *)nodes[i])->name, stream) || !fstrwrite("\",\n", stream)) {
			goto fail;
		}

		snprintf(buf, sizeof(buf), "%d", ((node_t *)nodes[i])->devclass);

		if(!fstrwrite("\t\t\t\"devclass\": ", stream) || !fstrwrite(buf, stream) || !fstrwrite("\n", stream)) {
			goto fail;
		}

		if(!fstrwrite((i + 1) != node_count ? "\t\t},\n" : "\t\t}\n", stream)) {
			goto fail;
		}
	}

	if(!fstrwrite("\t},\n", stream)) {
		goto fail;
	}

	// export edges

	if(!fstrwrite("\t\"edges\": {\n", stream)) {
		goto fail;
	}

	for(size_t i = 0; i < edge_count; ++i) {
		if(!fstrwrite("\t\t\"", stream) || !fstrwrite(edges[i].from->name, stream) || !fstrwrite("_to_", stream) || !fstrwrite(edges[i].to->name, stream) || !fstrwrite("\": {\n", stream)) {
			goto fail;
		}

		if(!fstrwrite("\t\t\t\"from\": \"", stream) || !fstrwrite(edges[i].from->name, stream) || !fstrwrite("\",\n", stream)) {
			goto fail;
		}

		if(!fstrwrite("\t\t\t\"to\": \"", stream) || !fstrwrite(edges[i].to->name, stream) || !fstrwrite("\",\n", stream)) {
			goto fail;
		}

		char *host = NULL, *port = NULL, *address = NULL;
		sockaddr2str((const sockaddr_t *)&edges[i].address, &host, &port);

		if(host && port) {
			xasprintf(&address, "{ \"host\": \"%s\", \"port\": %s }", host, port);
		}

		free(host);
		free(port);

		if(!fstrwrite("\t\t\t\"address\": ", stream) || !fstrwrite(address ? address : "null", stream) || !fstrwrite(",\n", stream)) {
			free(address);
			goto fail;
		}

		free(address);

		snprintf(buf, sizeof(buf), "%d", edges[i].weight);

		if(!fstrwrite("\t\t\t\"weight\": ", stream) || !fstrwrite(buf, stream) || !fstrwrite("\n", stream)) {
			goto fail;
		}

		if(!fstrwrite((i + 1) != edge_count ? "\t\t},\n" : "\t\t}\n", stream)) {
			goto fail;
		}
	}

	if(!fstrwrite("\t}\n", stream)) {
		goto fail;
	}

	// DONE!

	if(!fstrwrite("}", stream)) {
		goto fail;
	}

	goto done;

fail:
	result = false;

done:
	free(nodes);
	free(edges);

	pthread_mutex_unlock(&mesh->mutex);

	return result;
}

static void devtool_get_reset_node_status(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_node_status_t *status, bool reset) {
	node_t *internal = (node_t *)node;

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	if(status) {
		memcpy(&status->status, &internal->status, sizeof status->status);
		memcpy(&status->address, &internal->address, sizeof status->address);
		status->mtu = internal->mtu;
		status->minmtu = internal->minmtu;
		status->maxmtu = internal->maxmtu;
		status->mtuprobes = internal->mtuprobes;
		status->in_data = internal->in_data;
		status->out_data = internal->out_data;
		status->in_forward = internal->in_forward;
		status->out_forward = internal->out_forward;
		status->in_meta = internal->in_meta;
		status->out_meta = internal->out_meta;

		// External address information (from REQ_EXTERNAL messages)
		status->external_ip_address = internal->external_ip_address ? xstrdup(internal->external_ip_address) : NULL;
		status->canonical_address = internal->canonical_address ? xstrdup(internal->canonical_address) : NULL;

		// Meta connection information
		connection_t *c = internal->connection;
		memset(&status->meta_address, 0, sizeof status->meta_address);
		status->meta_connected = c && c->status.active;
		status->meta_via_canonical = c && c->status.via_canonical;
		status->meta_is_outgoing = c && c->outgoing;

		if(c) {
			memcpy(&status->meta_address, &c->address, sizeof status->meta_address);
		}

		status->upgrade_probe_active = internal->upgrade_probe != NULL;
		status->upgrade_backoff = internal->upgrade_backoff;

		// Recent direct addresses
		status->recent_count = 0;
		memset(status->recent, 0, sizeof status->recent);

		status->udp_tier = (int)internal->udp_tier;
		status->dest_path_tier = path_select_destination_tier(internal, false);
		status->meta_dial_tier = c ? (int)c->status.meta_dial_tier : (int)META_DIAL_DIRECT;
		status->would_probe_local_udp = path_udp_should_probe_local(mesh, internal, NULL);
		memset(status->recent_source, 0, sizeof status->recent_source);
		memset(status->recent_cap, 0, sizeof status->recent_cap);
		memset(status->canonical_resolved, 0, sizeof status->canonical_resolved);
		status->canonical_resolved_count = 0;
		memset(&status->upgrade_target, 0, sizeof status->upgrade_target);
		memset(&status->startup_skip, 0, sizeof status->startup_skip);

		status->active_route_kind = (int)internal->active_route.kind;
		status->active_route_carrier = (int)internal->active_route.relay_carrier;
		status->active_route_suspect = internal->active_route.suspect;
		status->active_route_local = internal->active_route.local;
		status->candidate_active = internal->promotion_candidate.active;
		status->candidate_rounds = internal->promotion_candidate.successful_rounds;
		status->candidate_failures = internal->promotion_candidate.failures;
		status->candidate_nonce = internal->promotion_candidate.active ? internal->promotion_candidate.nonce : 0;
		status->channel_mtu = internal->utcp ? utcp_get_mtu(internal->utcp) : 0;
		memset(&status->candidate_endpoint, 0, sizeof status->candidate_endpoint);

		if(internal->promotion_candidate.active) {
			memcpy(&status->candidate_endpoint, &internal->promotion_candidate.endpoint, sizeof status->candidate_endpoint);
		}

		status->candidate_cooldown_remaining = 0;

		if(internal->promotion_candidate.cooldown_until.tv_sec > mesh->loop.now.tv_sec) {
			status->candidate_cooldown_remaining = (int)(internal->promotion_candidate.cooldown_until.tv_sec - mesh->loop.now.tv_sec);
		}

		if(internal->startup_skip_sa.sa.sa_family) {
			memcpy(&status->startup_skip, &internal->startup_skip_sa, sizeof status->startup_skip);
		}

		for(int i = 0; i < MAX_RECENT && internal->recent[i].sa.sa_family; i++) {
			memcpy(&status->recent[i], &internal->recent[i], sizeof status->recent[i]);
			status->recent_source[i] = (uint8_t)internal->recent_source[i];
			status->recent_cap[i] = internal->recent_cap[i];
			status->recent_count++;
		}

		if(internal->canonical_sa_count > 0 && internal->canonical_sa.sa.sa_family) {
			memcpy(&status->canonical_resolved[status->canonical_resolved_count++], &internal->canonical_sa, sizeof status->canonical_resolved[0]);
		}

		for(int i = 1; i < internal->canonical_sa_count && status->canonical_resolved_count < DEVTOOL_MAX_CANONICAL; i++) {
			memcpy(&status->canonical_resolved[status->canonical_resolved_count++], &internal->canonical_extra[i - 1], sizeof status->canonical_resolved[0]);
		}

		path_tier_t hop_tier = path_select_hop_tier(internal, true);
		status->active_meta_tier = (int)hop_tier;
		status->upgrade_ineligible_reason = path_upgrade_ineligible_reason(mesh, internal);
		status->validkey = internal->status.validkey;
		status->waitingforkey = internal->status.waitingforkey;
		status->sptps_state = internal->sptps.state;
		status->sptps_outseqno = internal->sptps.outseqno;
		status->sptps_restart_count = internal->sptps_restart_count;
		status->connection_generation = c && c->outgoing ? c->outgoing->generation : 0;
		status->meta_drain_active = false;

		for list_each(connection_t, other, mesh->connections) {
			if(other->status.drain_only && other->name && !strcmp(other->name, internal->name)) {
				status->meta_drain_active = true;
				break;
			}
		}

		sockaddr_t target;
		memset(&target, 0, sizeof target);

		if(path_best_direct_meta(internal, c ? &c->address : NULL, &target, NULL)) {
			memcpy(&status->upgrade_target, &target, sizeof status->upgrade_target);
		}

		// Derive UDP connection status
		if(internal == mesh->self) {
			status->udp_status = DEVTOOL_UDP_WORKING;
		} else if(!internal->status.reachable) {
			status->udp_status = DEVTOOL_UDP_IMPOSSIBLE;
		} else if(!internal->status.validkey) {
			status->udp_status = DEVTOOL_UDP_UNKNOWN;
		} else if(internal->status.udp_confirmed) {
			status->udp_status = DEVTOOL_UDP_WORKING;
		} else if(internal->mtuprobes > 30) {
			status->udp_status = DEVTOOL_UDP_FAILED;
		} else if(internal->mtuprobes > 0) {
			status->udp_status = DEVTOOL_UDP_TRYING;
		} else {
			status->udp_status = DEVTOOL_UDP_UNKNOWN;
		}
	}

	if(reset) {
		internal->in_data = 0;
		internal->out_data = 0;
		internal->in_forward = 0;
		internal->out_forward = 0;
		internal->in_meta = 0;
		internal->out_meta = 0;
	}

	pthread_mutex_unlock(&mesh->mutex);
}

void devtool_get_node_status(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_node_status_t *status) {
	if(!mesh || !node || !status) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	devtool_get_reset_node_status(mesh, node, status, false);
}

void devtool_reset_node_counters(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_node_status_t *status) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	devtool_get_reset_node_status(mesh, node, status, true);
}

meshlink_submesh_t **devtool_get_all_submeshes(meshlink_handle_t *mesh, meshlink_submesh_t **submeshes, size_t *nmemb) {
	if(!mesh || !nmemb || (*nmemb && !submeshes)) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	meshlink_submesh_t **result;

	//lock mesh->nodes
	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	*nmemb = mesh->submeshes->count;
	result = realloc(submeshes, *nmemb * sizeof(*submeshes));

	if(result) {
		meshlink_submesh_t **p = result;

		for list_each(submesh_t, s, mesh->submeshes) {
			*p++ = (meshlink_submesh_t *)s;
		}
	} else {
		*nmemb = 0;
		free(submeshes);
		meshlink_errno = MESHLINK_ENOMEM;
	}

	pthread_mutex_unlock(&mesh->mutex);

	return result;
}

meshlink_handle_t *devtool_open_in_netns(const char *confbase, const char *name, const char *appname, dev_class_t devclass, int netns) {
	meshlink_open_params_t *params = meshlink_open_params_init(confbase, name, appname, devclass);
	params->netns = dup(netns);
	meshlink_handle_t *handle;

	if(params->netns == -1) {
		handle = NULL;
		meshlink_errno = MESHLINK_EINVAL;
	} else {
		handle = meshlink_open_ex(params);
	}

	meshlink_open_params_free(params);

	return handle;
}

void devtool_force_sptps_renewal(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	node_t *n = (node_t *)node;
	connection_t *c = n->connection;

	n->last_req_key = -3600;

	if(c) {
		c->last_key_renewal = -3600;
	}
}

const char *devtool_get_backbone_name(meshlink_handle_t *mesh) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	const char *name = connection_policy_backbone_name(mesh);
	pthread_mutex_unlock(&mesh->mutex);
	return name;
}

meshlink_node_t *devtool_get_backbone(meshlink_handle_t *mesh) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	meshlink_node_t *node = (meshlink_node_t *)connection_policy_backbone(mesh);
	pthread_mutex_unlock(&mesh->mutex);
	return node;
}

void devtool_set_allow_peer_bootstrap(meshlink_handle_t *mesh, bool allow) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->allow_peer_bootstrap = allow;
	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_node_has_conflict_backbone(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool conflict = ((node_t *)node)->status.conflict_backbone;
	pthread_mutex_unlock(&mesh->mutex);
	return conflict;
}

void devtool_free_node_status(devtool_node_status_t *status) {
	if(!status) {
		return;
	}

	// Free the dynamically allocated strings
	free(status->external_ip_address);
	free(status->canonical_address);
	
	// Clear the pointers to prevent double-free
	status->external_ip_address = NULL;
	status->canonical_address = NULL;
}

void devtool_set_meta_status_cb(meshlink_handle_t *mesh, meshlink_node_status_cb_t cb) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->meta_status_cb = cb;
	pthread_mutex_unlock(&mesh->mutex);
}

void devtool_set_external_ip_address(meshlink_handle_t *mesh, meshlink_node_t *node, const char *external_ip_address) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	free(n->external_ip_address);
	n->external_ip_address = external_ip_address ? xstrdup(external_ip_address) : NULL;
	pthread_mutex_unlock(&mesh->mutex);
}

void devtool_update_node_udp(meshlink_handle_t *mesh, meshlink_node_t *node, const struct sockaddr *addr) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	const sockaddr_t *sa = (const sockaddr_t *)addr;

	if(n != mesh->self && sa && sa->sa.sa_family == AF_UNSPEC) {
		/* Forget every learned dest: cache entry, n->address and recent[].
		   update_node_udp() must not take the address itself: it would install
		   AF_UNSPEC as a real dest and log it as an unknown address.
		   n->address may own AF_UNKNOWN strings; recent[] only holds shallow
		   copies of them, so free once and zero both. recent[] is persisted,
		   so mark the node dirty like node_add_recent_address() does. Self is
		   left to update_node_udp(), which refuses it with a warning. */
		update_node_udp(mesh, n, NULL);
		sockaddrfree(&n->address);
		memset(&n->address, 0, sizeof n->address);
		path_clear_recent(n);
		n->udp_tier = PATH_TIER_NONE;
		n->last_path_tier = PATH_TIER_NONE;
	} else {
		update_node_udp(mesh, n, sa);
	}

	pthread_mutex_unlock(&mesh->mutex);
}

static bool devtool_pick_udp_address(meshlink_handle_t *mesh, meshlink_node_t *node, struct sockaddr_storage *addr, int *sock, bool advance) {
	if(!mesh || !node || !addr || !sock) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	int saved_choice = n->udp_choice;
	uint64_t saved_prng[4];
	memcpy(saved_prng, mesh->prng_state, sizeof saved_prng);

	sockaddr_t sa_buf;
	const sockaddr_t *sa = NULL;
	choose_udp_address(mesh, n, &sa, sock, &sa_buf);

	if(!advance) {
		n->udp_choice = saved_choice;
		memcpy(mesh->prng_state, saved_prng, sizeof saved_prng);
	}

	if(!sa || sa->sa.sa_family == AF_UNSPEC || sa->sa.sa_family == AF_UNKNOWN) {
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	memset(addr, 0, sizeof(*addr));
	memcpy(addr, &sa->storage, sizeof(*addr));
	pthread_mutex_unlock(&mesh->mutex);
	return true;
}

bool devtool_choose_udp_address(meshlink_handle_t *mesh, meshlink_node_t *node, struct sockaddr_storage *addr, int *sock) {
	return devtool_pick_udp_address(mesh, node, addr, sock, false);
}

bool devtool_choose_udp_address_advance(meshlink_handle_t *mesh, meshlink_node_t *node, struct sockaddr_storage *addr, int *sock) {
	return devtool_pick_udp_address(mesh, node, addr, sock, true);
}

bool devtool_graph_may_seed_udp(meshlink_handle_t *mesh, meshlink_node_t *node, const struct sockaddr *addr) {
	if(!mesh || !node || !addr) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool ok = graph_may_seed_udp((node_t *)node, (const sockaddr_t *)addr);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

bool devtool_force_relay_path(meshlink_handle_t *mesh, meshlink_node_t *dest, meshlink_node_t *nexthop) {
	if(!mesh || !dest || !nexthop) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *d = (node_t *)dest;
	node_t *h = (node_t *)nexthop;

	if(d == h || !h->status.validkey) {
		pthread_mutex_unlock(&mesh->mutex);
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	d->nexthop = h;
	d->prev_nexthop = h;
	d->status.forced_relay = true;
	d->status.udp_confirmed = false;
	h->status.udp_confirmed = true;
	timeout_del(&mesh->loop, &d->mtutimeout);
	d->mtuprobes = 0;
	d->relay_budget = 0;
	pthread_mutex_unlock(&mesh->mutex);
	return true;
}

void devtool_set_udp_confirmed(meshlink_handle_t *mesh, meshlink_node_t *node, bool confirmed) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	n->status.udp_confirmed = confirmed;

	if(!confirmed && !n->devtool_force_meta && n->status.validkey && n->status.reachable && !n->mtutimeout.cb) {
		send_mtu_probe(mesh, n);
	}

	pthread_mutex_unlock(&mesh->mutex);
}

void devtool_force_meta(meshlink_handle_t *mesh, meshlink_node_t *node, bool enabled) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;

	n->devtool_force_meta = enabled;

	if(enabled) {
		timeout_del(&mesh->loop, &n->mtutimeout);
		timeout_del(&mesh->loop, &n->promotion_timer);
		n->mtuprobes = 31;
		n->status.udp_confirmed = false;
		n->status.want_udp = false;
		n->udp_tier = PATH_TIER_NONE;
		n->probe_dest_override_active = false;
		memset(&n->promotion_candidate, 0, sizeof n->promotion_candidate);
	} else if(n->status.validkey && n->status.reachable && !n->mtutimeout.cb) {
		n->mtuprobes = 0;
		send_mtu_probe(mesh, n);
	}

	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_plant_recent_address(meshlink_handle_t *mesh, meshlink_node_t *node, const struct sockaddr *addr) {
	if(!mesh || !node || !addr) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	sockaddr_t sa;

	path_copy_sockaddr(&sa, (const sockaddr_t *)addr);

	if(sa.sa.sa_family == AF_UNSPEC) {
		meshlink_errno = MESHLINK_EINVAL;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	path_plant_recent(n, &sa);

	if(!node_write_config(mesh, n, false)) {
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	pthread_mutex_unlock(&mesh->mutex);
	return true;
}

bool devtool_confirm_udp_from(meshlink_handle_t *mesh, meshlink_node_t *node, const struct sockaddr *addr, int tier) {
	if(!mesh || !node || !addr) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	sockaddr_t sa;

	if(tier < PATH_TIER_DIRECT_LOCAL_UDP || tier > PATH_TIER_NONE) {
		meshlink_errno = MESHLINK_EINVAL;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	path_copy_sockaddr(&sa, (const sockaddr_t *)addr);

	if(sa.sa.sa_family == AF_UNSPEC) {
		meshlink_errno = MESHLINK_EINVAL;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	update_node_udp(mesh, n, &sa);
	n->status.udp_confirmed = true;
	n->udp_tier = (path_tier_t)tier;
	n->udp_local_probe_next = 0;
	pthread_mutex_unlock(&mesh->mutex);
	return true;
}

bool devtool_promote_udp_if_better(meshlink_handle_t *mesh, meshlink_node_t *node, const struct sockaddr *addr) {
	sockaddr_t sa;
	node_t *n;
	bool ok;

	if(!mesh || !node || !addr) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	n = (node_t *)node;
	path_copy_sockaddr(&sa, (const sockaddr_t *)addr);

	if(sa.sa.sa_family == AF_UNSPEC) {
		meshlink_errno = MESHLINK_EINVAL;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	ok = path_promote_udp_if_better(mesh, n, &sa);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

bool devtool_send_raw_record(meshlink_handle_t *mesh, meshlink_node_t *to, uint8_t type, const void *data, size_t len) {
	if(!mesh || !to) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)to;
	bool ok = false;

	if(data && len) {
		ok = sptps_send_record(&n->sptps, type, data, (uint16_t)len);
	} else {
		ok = relay_inject_inner(mesh, n, type);
	}

	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

bool devtool_set_minmtu(meshlink_handle_t *mesh, meshlink_node_t *node, uint16_t mtu) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	n->minmtu = mtu;
	update_node_pmtu(mesh, n);
	pthread_mutex_unlock(&mesh->mutex);
	return true;
}

void devtool_clear_relay_reports(meshlink_handle_t *mesh) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	relay_devtool_clear_reports(mesh);
	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_seed_relay_report(meshlink_handle_t *mesh, const char *origin, const char *destination, unsigned age_sec, bool have_reported) {
	if(!mesh || !origin || !destination) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool ok = relay_devtool_seed_report(mesh, origin, destination, age_sec, have_reported);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

bool devtool_has_relay_report(meshlink_handle_t *mesh, const char *origin, const char *destination) {
	if(!mesh || !origin || !destination) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool found = relay_devtool_has_report(mesh, origin, destination);
	pthread_mutex_unlock(&mesh->mutex);
	return found;
}

bool devtool_relay_report_have_reported(meshlink_handle_t *mesh, const char *origin, const char *destination) {
	if(!mesh || !origin || !destination) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool stamped = relay_devtool_have_reported(mesh, origin, destination);
	pthread_mutex_unlock(&mesh->mutex);
	return stamped;
}

size_t devtool_relay_report_count(meshlink_handle_t *mesh) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return 0;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	size_t n = relay_devtool_report_count(mesh);
	pthread_mutex_unlock(&mesh->mutex);
	return n;
}

bool devtool_fill_relay_reports(meshlink_handle_t *mesh, size_t count, unsigned age_sec, bool have_reported) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool ok = relay_devtool_fill_reports(mesh, count, age_sec, have_reported);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

void devtool_fail_relay_reports(meshlink_handle_t *mesh, bool fail) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	relay_devtool_force_report_null_connection(mesh, fail);
	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_handle_relay_aliased(meshlink_handle_t *mesh, meshlink_node_t *from, const void *data, size_t len) {
	if(!mesh || !from || !data || !len || len > UINT16_MAX) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool ok = relay_devtool_handle_aliased(mesh, (node_t *)from, data, (uint16_t)len);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

bool devtool_send_meta_sptps(meshlink_handle_t *mesh, meshlink_node_t *dest, uint8_t type, const void *data, size_t len) {
	if(!mesh || !dest) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool ok = relay_devtool_send_meta_sptps(mesh, (node_t *)dest, type, data, len);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

void devtool_fail_relay_realloc(meshlink_handle_t *mesh, bool fail) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	relay_devtool_fail_realloc(mesh, fail);
	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_handle_req_relay_mtu(meshlink_handle_t *mesh, meshlink_node_t *from, const char *request) {
	if(!mesh || !from || !request) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool ok = relay_devtool_handle_req_relay_mtu(mesh, (node_t *)from, request);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

bool devtool_path_policy_cover_unit(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool ok = path_policy_cover_unit(mesh, (node_t *)node);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

int devtool_select_destination_tier(meshlink_handle_t *mesh, meshlink_node_t *node, bool meta_in) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return (int)PATH_TIER_NONE;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	path_tier_t selected = path_select_destination_tier((node_t *)node, meta_in);
	pthread_mutex_unlock(&mesh->mutex);
	return (int)selected;
}

int devtool_select_hop_tier(meshlink_handle_t *mesh, meshlink_node_t *node, bool meta_in) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return (int)PATH_TIER_NONE;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	path_tier_t selected = path_select_hop_tier((node_t *)node, meta_in);
	pthread_mutex_unlock(&mesh->mutex);
	return (int)selected;
}

int devtool_select_dest_with_udp(meshlink_handle_t *mesh, meshlink_node_t *dest, bool dest_udp, meshlink_node_t *hop, bool hop_udp, bool meta_in) {
	if(!mesh || !dest) {
		meshlink_errno = MESHLINK_EINVAL;
		return (int)PATH_TIER_NONE;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *d = (node_t *)dest;
	node_t *h = (node_t *)hop;

	d->status.udp_confirmed = dest_udp;

	if(!dest_udp) {
		timeout_del(&mesh->loop, &d->mtutimeout);
	}

	if(h && h != d) {
		d->nexthop = h;
		d->status.forced_relay = true;
		h->status.udp_confirmed = hop_udp;

		if(!hop_udp) {
			timeout_del(&mesh->loop, &h->mtutimeout);
		}

		if(hop_udp && h->status.validkey) {
			h->status.temp_udp_confirmed = false;
		}
	}

	path_tier_t selected = path_select_destination_tier(d, meta_in);
	pthread_mutex_unlock(&mesh->mutex);
	return (int)selected;
}

void devtool_path_route_tick(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	path_route_tick(mesh, (node_t *)node);
	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_apply_send_target(meshlink_handle_t *mesh, meshlink_node_t *node, int *chosen_kind) {
	if(!mesh || !node || !chosen_kind) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	path_target_t target;
	bool ok = path_active_send_target(mesh, (node_t *)node, &target);

	if(ok) {
		*chosen_kind = (int)target.kind;
		path_record_active_route(mesh, (node_t *)node, &target);
	}

	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

bool devtool_candidate_probe_target(meshlink_handle_t *mesh, meshlink_node_t *node, struct sockaddr_storage *addr, uint64_t *nonce) {
	if(!mesh || !node || !addr || !nonce) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	sockaddr_t sa;
	memset(&sa, 0, sizeof sa);
	bool ok = path_candidate_probe_target(mesh, (node_t *)node, &sa, nonce);

	memset(addr, 0, sizeof *addr);

	if(ok) {
		memcpy(addr, &sa, sizeof sa < sizeof *addr ? sizeof sa : sizeof *addr);
	}

	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

void devtool_observe_probe_reply(meshlink_handle_t *mesh, meshlink_node_t *node, const struct sockaddr *addr, uint64_t nonce) {
	if(!mesh || !node || !addr) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	path_observe_probe_reply(mesh, (node_t *)node, (const sockaddr_t *)addr, nonce);
	pthread_mutex_unlock(&mesh->mutex);
}

void devtool_note_route_suspect(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	path_note_route_suspect(mesh, (node_t *)node, "reliable retransmit");
	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_has_live_fallback(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool live = path_has_live_fallback(mesh, (node_t *)node);
	pthread_mutex_unlock(&mesh->mutex);
	return live;
}

void devtool_age_route(meshlink_handle_t *mesh, meshlink_node_t *node, int seconds) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;

	if(n->active_route.selected_at.tv_sec) {
		n->active_route.selected_at.tv_sec -= seconds;
	}

	if(n->active_route.suspect_at.tv_sec) {
		n->active_route.suspect_at.tv_sec -= seconds;
	}

	pthread_mutex_unlock(&mesh->mutex);
}

void devtool_age_candidate(meshlink_handle_t *mesh, meshlink_node_t *node, int seconds) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;

	if(n->promotion_candidate.first_success.tv_sec) {
		n->promotion_candidate.first_success.tv_sec -= seconds;
	}

	if(n->promotion_candidate.deadline.tv_sec) {
		n->promotion_candidate.deadline.tv_sec -= seconds;
	}

	if(n->promotion_candidate.cooldown_until.tv_sec) {
		n->promotion_candidate.cooldown_until.tv_sec -= seconds;
	}

	pthread_mutex_unlock(&mesh->mutex);
}

void devtool_candidate_clear_cooldown(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	path_candidate_clear_cooldown(mesh, (node_t *)node);
	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_liveness_probe_warranted(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool warranted = path_liveness_probe_warranted(mesh, (node_t *)node);
	pthread_mutex_unlock(&mesh->mutex);
	return warranted;
}

bool devtool_relay_cover_unit(meshlink_handle_t *mesh, meshlink_node_t *from, meshlink_node_t *dest, meshlink_node_t *hop) {
	if(!mesh || !from || !dest || !hop) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool ok = relay_devtool_cover_unit(mesh, (node_t *)from, (node_t *)dest, (node_t *)hop);
	pthread_mutex_unlock(&mesh->mutex);
	return ok;
}

void devtool_relay_hard_send_error(meshlink_handle_t *mesh, meshlink_node_t *hop) {
	if(!mesh || !hop) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)hop;
	relay_on_hard_send_error(mesh, n, &n->address, n->sock);
	pthread_mutex_unlock(&mesh->mutex);
}

void devtool_relay_hard_send_error_at(meshlink_handle_t *mesh, meshlink_node_t *hop, const struct sockaddr *addr, int sock) {
	if(!mesh || !hop || !addr) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	relay_on_hard_send_error(mesh, (node_t *)hop, (const sockaddr_t *)addr, sock);
	pthread_mutex_unlock(&mesh->mutex);
}

bool devtool_inject_broadcast_hard_send(meshlink_handle_t *mesh, meshlink_node_t *hop) {
	if(!mesh || !hop) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)hop;

	if(!n->prevedge || !n->status.validkey) {
		pthread_mutex_unlock(&mesh->mutex);
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	bool saved = n->status.broadcast;
	uint8_t probe[64];
	memset(probe, 0, sizeof probe);
	n->status.broadcast = true;
	relay_devtool_get(mesh)->inject_hard_send_error = true;
	(void)sptps_send_record(&n->sptps, PKT_PROBE, probe, sizeof probe);
	n->status.broadcast = saved;

	bool injected = !relay_devtool_get(mesh)->inject_hard_send_error;
	relay_devtool_get(mesh)->inject_hard_send_error = false;
	pthread_mutex_unlock(&mesh->mutex);
	return injected;
}

void devtool_fill_port_mismatch(const struct sockaddr_storage *src, struct sockaddr_storage *dst) {
	sockaddr_t in = {0};
	sockaddr_t out = {0};

	if(!src || !dst) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	in.storage = *src;
	relay_fill_port_mismatch(&in, &out);
	*dst = out.storage;
}

void devtool_fill_host_mismatch(const struct sockaddr_storage *src, struct sockaddr_storage *dst) {
	sockaddr_t in = {0};
	sockaddr_t out = {0};

	if(!src || !dst) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	in.storage = *src;
	relay_fill_host_mismatch(&in, &out);
	*dst = out.storage;
}

void devtool_fill_mcast_ff02_1(struct sockaddr_storage *dst) {
	sockaddr_t out = {0};

	if(!dst) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	relay_fill_mcast_ff02_1(&out);
	*dst = out.storage;
}

void devtool_fill_bcast_ipv4(struct sockaddr_storage *dst) {
	sockaddr_t out = {0};

	if(!dst) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	relay_fill_bcast_ipv4(&out);
	*dst = out.storage;
}

void devtool_set_outgoing_startup_ms(int ms) {
	outgoing_set_startup_ms(ms);
}
