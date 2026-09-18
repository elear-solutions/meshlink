/*
    connection_policy.c -- unique backbone identity and META connection pools
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "conf.h"
#include "connection.h"
#include "connection_policy.h"
#include "event.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "node.h"
#include "packmsg.h"
#include "protocol.h"
#include "splay_tree.h"
#include "xalloc.h"

void connection_policy_init(meshlink_handle_t *mesh) {
	if(!mesh) {
		return;
	}

	mesh->backbone.name = NULL;
	mesh->backbone.node = NULL;
	mesh->allow_peer_bootstrap = false;
	mesh->lan_network_epoch = 1;
}

void connection_policy_exit(meshlink_handle_t *mesh) {
	if(!mesh) {
		return;
	}

	free(mesh->backbone.name);
	mesh->backbone.name = NULL;
	mesh->backbone.node = NULL;
}

bool connection_policy_persist(meshlink_handle_t *mesh) {
	if(!mesh) {
		return false;
	}

	if(!mesh->confbase || mesh->storage_policy == MESHLINK_STORAGE_DISABLED) {
		return true;
	}

	if(!mesh->backbone.name) {
		return true;
	}

	uint8_t buf[512];
	packmsg_output_t out = {buf, sizeof buf};

	packmsg_add_uint32(&out, MESHLINK_BACKBONE_FILE_VERSION);
	packmsg_add_str(&out, mesh->backbone.name);

	if(!packmsg_output_ok(&out)) {
		meshlink_errno = MESHLINK_EINTERNAL;
		return false;
	}

	config_t config = {buf, packmsg_output_size(&out, buf)};

	const char *subdir = mesh_conf_write_subdir(mesh);

	if(!backbone_config_write(mesh, subdir, &config, mesh->config_key)) {
		return false;
	}

	return config_sync(mesh, subdir);
}

bool connection_policy_load(meshlink_handle_t *mesh) {
	if(!mesh) {
		return false;
	}

	if(!mesh->confbase) {
		return true;
	}

	if(!backbone_config_exists(mesh, "current")) {
		return true;
	}

	config_t config;

	if(!backbone_config_read(mesh, "current", &config, mesh->config_key)) {
		return false;
	}

	packmsg_input_t in = {config.buf, config.len};
	uint32_t version = packmsg_get_uint32(&in);
	char *name = packmsg_get_str_dup(&in);

	if(!packmsg_done(&in) || version != MESHLINK_BACKBONE_FILE_VERSION || !check_id(name)) {
		logger(mesh, MESHLINK_ERROR, "Invalid backbone identity file");
		free(name);
		config_free(&config);
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	free(mesh->backbone.name);
	mesh->backbone.name = name;
	mesh->backbone.node = NULL;
	config_free(&config);
	return true;
}

void connection_policy_resolve(meshlink_handle_t *mesh) {
	if(!mesh) {
		return;
	}

	mesh->backbone.node = NULL;

	if(!mesh->backbone.name || !mesh->nodes) {
		return;
	}

	mesh->backbone.node = lookup_node(mesh, mesh->backbone.name);
}

bool connection_policy_validate_topology(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->nodes) {
		return true;
	}

	unsigned backbone_class_count = 0;

	if(!mesh->backbone.name) {
		for splay_each(node_t, n, mesh->nodes) {
			if(n->devclass == DEV_CLASS_BACKBONE) {
				backbone_class_count++;
			}
		}
	}

	bool ok = true;

	for splay_each(node_t, n, mesh->nodes) {
		bool named = mesh->backbone.name && n->name && !strcmp(n->name, mesh->backbone.name);
		bool extra = n->devclass == DEV_CLASS_BACKBONE && !named
		             && (mesh->backbone.name || backbone_class_count >= 2);
		bool wrong_class = named && n->devclass != DEV_CLASS_BACKBONE;
		bool conflict = extra || wrong_class;
		bool was = n->status.conflict_backbone;

		n->status.conflict_backbone = conflict;

		if(conflict) {
			ok = false;

			if(!was) {
				if(wrong_class) {
					logger(mesh, MESHLINK_WARNING, "Stored backbone %s has device class %d, not BACKBONE", n->name, n->devclass);
				} else {
					logger(mesh, MESHLINK_WARNING, "Node %s is DEV_CLASS_BACKBONE but is not the stored backbone identity", n->name);
				}
			}
		}
	}

	return ok;
}

bool connection_policy_set_backbone(meshlink_handle_t *mesh, const char *name) {
	if(!mesh || !check_id(name)) {
		return false;
	}

	if(mesh->backbone.name) {
		if(!strcmp(mesh->backbone.name, name)) {
			connection_policy_resolve(mesh);
			(void)connection_policy_validate_topology(mesh);
			return connection_policy_persist(mesh);
		}

		logger(mesh, MESHLINK_ERROR, "Backbone identity already set to %s, refusing %s", mesh->backbone.name, name);
		return false;
	}

	mesh->backbone.name = xstrdup(name);
	connection_policy_resolve(mesh);

	if(!connection_policy_persist(mesh)) {
		free(mesh->backbone.name);
		mesh->backbone.name = NULL;
		mesh->backbone.node = NULL;
		return false;
	}

	(void)connection_policy_validate_topology(mesh);
	return true;
}

void connection_policy_migrate(meshlink_handle_t *mesh) {
	if(!mesh || mesh->backbone.name || !mesh->nodes) {
		return;
	}

	node_t *self_backbone = NULL;
	node_t *other_backbone = NULL;
	unsigned others = 0;
	unsigned total = 0;

	for splay_each(node_t, n, mesh->nodes) {
		if(n->devclass != DEV_CLASS_BACKBONE) {
			continue;
		}

		total++;

		if(n == mesh->self) {
			self_backbone = n;
		} else {
			others++;
			other_backbone = n;
		}
	}

	if(self_backbone && others == 0) {
		(void)connection_policy_set_backbone(mesh, self_backbone->name);
		return;
	}

	if(!self_backbone && others == 1 && other_backbone) {
		(void)connection_policy_set_backbone(mesh, other_backbone->name);
		return;
	}

	if(total >= 2) {
		logger(mesh, MESHLINK_WARNING, "Refusing to guess backbone identity among %u backbone-class nodes", total);
		(void)connection_policy_validate_topology(mesh);
	}
}

void connection_policy_on_node_added(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	if(mesh->backbone.name && n->name && !strcmp(n->name, mesh->backbone.name)) {
		mesh->backbone.node = n;
	}

	(void)connection_policy_validate_topology(mesh);
	connection_policy_tick(mesh);
}

void connection_policy_on_node_deleted(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	if(mesh->backbone.node == n) {
		mesh->backbone.node = NULL;
	}

	connection_policy_tick(mesh);
}

void connection_policy_on_devclass(meshlink_handle_t *mesh, node_t *n) {
	(void)n;
	(void)connection_policy_validate_topology(mesh);
	connection_policy_tick(mesh);
}

const char *connection_policy_backbone_name(const meshlink_handle_t *mesh) {
	return mesh ? mesh->backbone.name : NULL;
}

node_t *connection_policy_backbone(meshlink_handle_t *mesh) {
	return mesh ? mesh->backbone.node : NULL;
}

bool connection_policy_is_backbone(const meshlink_handle_t *mesh, const node_t *n) {
	if(!mesh || !n || !mesh->backbone.name || !n->name) {
		return false;
	}

	return !strcmp(mesh->backbone.name, n->name);
}

static unsigned connection_policy_backbone_class_count(const meshlink_handle_t *mesh) {
	unsigned count = 0;

	if(!mesh || !mesh->nodes) {
		return 0;
	}

	for splay_each(node_t, n, mesh->nodes) {
		if(n->devclass == DEV_CLASS_BACKBONE) {
			count++;
		}
	}

	return count;
}

static bool connection_policy_unambiguous_creator(const meshlink_handle_t *mesh) {
	return mesh->self->devclass == DEV_CLASS_BACKBONE
	       && !mesh->self->status.conflict_backbone
	       && connection_policy_backbone_class_count(mesh) == 1;
}

bool connection_policy_can_invite(const meshlink_handle_t *mesh) {
	if(!mesh || !mesh->self) {
		return false;
	}

	if(mesh->allow_peer_bootstrap) {
		return true;
	}

	if(mesh->self->devclass != DEV_CLASS_BACKBONE) {
		return false;
	}

	if(!mesh->backbone.name) {
		return connection_policy_unambiguous_creator(mesh);
	}

	return connection_policy_is_backbone(mesh, mesh->self);
}

bool connection_policy_commit_self_if_creator(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->self) {
		return false;
	}

	if(mesh->backbone.name) {
		return true;
	}

	if(mesh->self->devclass != DEV_CLASS_BACKBONE) {
		return true;
	}

	if(!connection_policy_unambiguous_creator(mesh)) {
		return true;
	}

	return connection_policy_set_backbone(mesh, mesh->self->name);
}

static bool connection_still_listed(meshlink_handle_t *mesh, const connection_t *c) {
	if(!mesh || !mesh->connections || !c) {
		return false;
	}

	for list_each(connection_t, cand, mesh->connections) {
		if(cand == c) {
			return true;
		}
	}

	return false;
}

static void close_retired_socket(meshlink_handle_t *mesh, connection_t *c) {
	if(!c || !connection_still_listed(mesh, c)) {
		return;
	}

	/* The IO handler still owns this object. SHUT_RDWR makes it unusable;
	   handle_meta_io frees it when receive_meta fails. */
	if(c == mesh->protocol_connection) {
		shutdown(c->socket, SHUT_RDWR);
		return;
	}

	terminate_connection(mesh, c, c->status.active);
}

static void drop_outgoing(meshlink_handle_t *mesh, outgoing_t *outgoing) {
	connection_t **victims = NULL;
	unsigned nv = 0;
	unsigned i;
	connection_t *pending;

	if(!mesh || !outgoing) {
		return;
	}

	mesh->retiring_outgoing = true;

	pending = outgoing->pending;
	outgoing_detach_startup(mesh, outgoing);

	if(pending) {
		close_retired_socket(mesh, pending);
	}

	if(mesh->connections && mesh->connections->count) {
		victims = xzalloc(mesh->connections->count * sizeof(*victims));

		for list_each(connection_t, c, mesh->connections) {
			if(c->outgoing == outgoing && c != pending) {
				victims[nv++] = c;
			}
		}
	}

	for(i = 0; i < nv; i++) {
		victims[i]->outgoing = NULL;
	}

	if(mesh->outgoings) {
		list_delete(mesh->outgoings, outgoing);
	}

	for(i = 0; i < nv; i++) {
		close_retired_socket(mesh, victims[i]);
	}

	free(victims);
	mesh->retiring_outgoing = false;
}

static outgoing_t *find_outgoing_for_purpose(meshlink_handle_t *mesh, meta_connection_purpose_t purpose) {
	if(!mesh->outgoings) {
		return NULL;
	}

	for list_each(outgoing_t, outgoing, mesh->outgoings) {
		if(outgoing->purpose == purpose) {
			return outgoing;
		}
	}

	return NULL;
}

static outgoing_t *find_outgoing_for_node(meshlink_handle_t *mesh, const node_t *n) {
	if(!mesh->outgoings || !n) {
		return NULL;
	}

	for list_each(outgoing_t, outgoing, mesh->outgoings) {
		if(outgoing->node == n) {
			return outgoing;
		}
	}

	return NULL;
}

static bool backbone_target_ok(const node_t *bb) {
	return bb
	       && !bb->status.conflict_backbone
	       && !bb->status.blacklisted
	       && bb->devclass == DEV_CLASS_BACKBONE;
}

bool connection_policy_lan_device_class(int devclass) {
	return devclass == DEV_CLASS_STATIONARY || devclass == DEV_CLASS_PORTABLE;
}

static bool local_candidate_with_class(const node_t *node,
                                       const sockaddr_t *address,
                                       address_source_t source,
                                       path_cap_t capability,
                                       int devclass) {
	if(!node || !address) {
		return false;
	}

	if(node->status.blacklisted || node->status.conflict_backbone) {
		return false;
	}

	if(!connection_policy_lan_device_class(devclass)) {
		return false;
	}

	return path_address_is_local(address)
	       && (capability & PATH_CAP_META)
	       && (source == ADDR_SRC_DISCOVERY || source == ADDR_SRC_AUTH_DIRECT);
}

bool connection_policy_local_candidate(const node_t *node,
                                       const sockaddr_t *address,
                                       address_source_t source,
                                       path_cap_t capability) {
	if(!node) {
		return false;
	}

	return local_candidate_with_class(node, address, source, capability, node->devclass);
}

static bool connection_looks_like_lan_meta(const meshlink_handle_t *mesh, const connection_t *c) {
	if(!mesh || !c || !c->status.active || c->status.drain_only || c->status.upgrade_probe) {
		return false;
	}

	if(!c->node || c->node == mesh->self) {
		return false;
	}

	if(connection_policy_is_backbone(mesh, c->node)
	                || !connection_policy_lan_device_class(c->node->devclass)) {
		return false;
	}

	return path_address_is_local(&c->address);
}

static bool connection_is_local_adjacency(const meshlink_handle_t *mesh, const connection_t *c) {
	if(!connection_looks_like_lan_meta(mesh, c)) {
		return false;
	}

	return c->node->lan_admitted_epoch == mesh->lan_network_epoch;
}

bool connection_policy_is_local_adjacency(const meshlink_handle_t *mesh, const node_t *n) {
	if(!mesh || !n || !n->connection) {
		return false;
	}

	return connection_is_local_adjacency(mesh, n->connection);
}

static bool node_has_local_source(const node_t *n, address_source_t want) {
	int i;

	if(!n) {
		return false;
	}

	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(n->recent_source[i] != want) {
			continue;
		}

		if(connection_policy_local_candidate(n, &n->recent[i], n->recent_source[i], n->recent_cap[i])) {
			return true;
		}
	}

	return false;
}

static bool node_has_current_discovery(const meshlink_handle_t *mesh, const node_t *n) {
	if(!mesh || !n || !n->lan_presence.last_discovered_at) {
		return false;
	}

	return n->lan_presence.network_epoch == mesh->lan_network_epoch;
}

static bool node_has_auth_direct_grace(const meshlink_handle_t *mesh, const node_t *n) {
	if(!mesh || !n || !n->lan_auth_direct_until) {
		return false;
	}

	if(mesh->loop.now.tv_sec >= n->lan_auth_direct_until) {
		return false;
	}

	return node_has_local_source(n, ADDR_SRC_AUTH_DIRECT);
}

static bool node_is_lan_eligible(const meshlink_handle_t *mesh, const node_t *n, const sockaddr_t *extra_addr, int extra_devclass) {
	int devclass;

	if(!mesh || !n || !n->name) {
		return false;
	}

	if(n->status.blacklisted || n->status.conflict_backbone) {
		return false;
	}

	if(connection_policy_is_backbone(mesh, n)) {
		return false;
	}

	if(n == mesh->self) {
		return connection_policy_lan_device_class(n->devclass);
	}

	devclass = extra_devclass >= 0 ? extra_devclass : (int)n->devclass;

	if(!connection_policy_lan_device_class(devclass)) {
		return false;
	}

	if(connection_policy_is_local_adjacency(mesh, n)) {
		return true;
	}

	(void)extra_addr;

	if(node_has_current_discovery(mesh, n)) {
		return true;
	}

	return node_has_auth_direct_grace(mesh, n);
}

static int cmp_node_name(const void *a, const void *b) {
	const node_t *na = *(const node_t *const *)a;
	const node_t *nb = *(const node_t *const *)b;

	return strcmp(na->name, nb->name);
}

static unsigned lan_pick_desired(node_t *self, node_t **names, unsigned n, node_t **desired) {
	unsigned nd = 0;
	unsigned i, pred, succ, j;

	if(!self || !names || !desired || n < 2) {
		return 0;
	}

	for(i = 0; i < n; i++) {
		if(names[i] == self) {
			break;
		}
	}

	if(i >= n) {
		return 0;
	}

	succ = (i + 1) % n;
	desired[nd++] = names[succ];

	pred = succ;

	if(n >= 3) {
		pred = (i + n - 1) % n;

		if(names[pred] != names[succ]) {
			desired[nd++] = names[pred];
		}
	}

	if(n >= 4 && nd < META_LAN_RESILIENCE_MAX) {
		if(n % 2 == 0) {
			j = (i + n / 2) % n;
		} else if(i < n - 1) {
			j = (i + (n - 1) / 2) % (n - 1);
		} else {
			j = i;
		}

		if(j != i && j != succ && j != pred) {
			desired[nd++] = names[j];
		}
	}

	return nd;
}

static bool node_in_desired(node_t **desired, unsigned nd, const node_t *n) {
	unsigned i;

	for(i = 0; i < nd; i++) {
		if(desired[i] == n) {
			return true;
		}
	}

	return false;
}

static unsigned lan_desired_peers(meshlink_handle_t *mesh, node_t *extra, const sockaddr_t *extra_addr, int extra_devclass, node_t **desired) {
	node_t **cand;
	unsigned nc = 0;
	unsigned nd = 0;
	unsigned max;

	if(!mesh || !mesh->self || !mesh->nodes || !desired) {
		return 0;
	}

	max = mesh->nodes->count;

	if(!max) {
		return 0;
	}

	cand = xzalloc(max * sizeof(*cand));

	for splay_each(node_t, n, mesh->nodes) {
		const sockaddr_t *ea = extra == n ? extra_addr : NULL;
		int dc = extra == n ? extra_devclass : -1;

		if(node_is_lan_eligible(mesh, n, ea, dc)) {
			cand[nc++] = n;
		}
	}

	if(nc >= 2) {
		qsort(cand, nc, sizeof(*cand), cmp_node_name);
		nd = lan_pick_desired(mesh->self, cand, nc, desired);
	}

	free(cand);
	return nd;
}

static unsigned local_adjacency_count(const meshlink_handle_t *mesh) {
	unsigned count = 0;

	if(!mesh || !mesh->nodes) {
		return 0;
	}

	for splay_each(node_t, n, mesh->nodes) {
		if(n != mesh->self && connection_policy_is_local_adjacency(mesh, n)) {
			count++;
		}
	}

	return count;
}

static node_t *least_preferred_extra(meshlink_handle_t *mesh, node_t **desired, unsigned nd) {
	node_t *worst = NULL;

	if(!mesh || !mesh->nodes) {
		return NULL;
	}

	for splay_each(node_t, n, mesh->nodes) {
		if(n == mesh->self || !connection_policy_is_local_adjacency(mesh, n)) {
			continue;
		}

		if(node_in_desired(desired, nd, n)) {
			continue;
		}

		if(!worst || strcmp(n->name, worst->name) > 0) {
			worst = n;
		}
	}

	return worst;
}

static bool node_has_meta_socket(const meshlink_handle_t *mesh, const node_t *n) {
	if(!n) {
		return false;
	}

	if(n->connection) {
		return true;
	}

	if(!mesh || !mesh->connections || !n->name) {
		return false;
	}

	for list_each(connection_t, c, mesh->connections) {
		if(c->status.drain_only) {
			continue;
		}

		if(c->node == n) {
			return true;
		}

		if(c->name && !strcmp(c->name, n->name)) {
			return true;
		}
	}

	return false;
}

static void retire_local_adjacency(meshlink_handle_t *mesh, node_t *n) {
	outgoing_t *o;
	connection_t *c;

	if(!mesh || !n) {
		return;
	}

	o = find_outgoing_for_node(mesh, n);

	if(o && o->purpose != META_PURPOSE_BACKBONE_REQUIRED) {
		drop_outgoing(mesh, o);
		return;
	}

	c = n->connection;

	if(!c) {
		return;
	}

	mesh->retiring_outgoing = true;
	close_retired_socket(mesh, c);
	mesh->retiring_outgoing = false;
}

static void retire_lan_overlay(meshlink_handle_t *mesh) {
	outgoing_t **intents = NULL;
	unsigned ni = 0;
	unsigned i;
	node_t **nodes = NULL;
	unsigned nn = 0;

	if(!mesh) {
		return;
	}

	if(mesh->outgoings && mesh->outgoings->count) {
		intents = xzalloc(mesh->outgoings->count * sizeof(*intents));

		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			if(outgoing->purpose == META_PURPOSE_LAN_RESILIENCE) {
				intents[ni++] = outgoing;
			}
		}

		for(i = 0; i < ni; i++) {
			drop_outgoing(mesh, intents[i]);
		}

		free(intents);
	}

	if(!mesh->nodes || !mesh->nodes->count) {
		return;
	}

	nodes = xzalloc(mesh->nodes->count * sizeof(*nodes));

	for splay_each(node_t, n, mesh->nodes) {
		if(n == mesh->self || !n->connection) {
			continue;
		}

		if(connection_looks_like_lan_meta(mesh, n->connection)) {
			nodes[nn++] = n;
		}
	}

	for(i = 0; i < nn; i++) {
		nodes[i]->lan_admitted_epoch = 0;
		retire_local_adjacency(mesh, nodes[i]);
	}

	free(nodes);
}

static const unsigned backbone_retry_seconds[] = {
	1, 2, 5, 10, 30, 60, 300, 900
};

void connection_policy_reset_backbone_retry(outgoing_t *outgoing) {
	if(!outgoing) {
		return;
	}

	outgoing->retry_step = 0;
	outgoing->timeout = 0;
}

static int backbone_retry_delay(meshlink_handle_t *mesh, unsigned step) {
	size_t n = sizeof backbone_retry_seconds / sizeof backbone_retry_seconds[0];
	int base = (int)backbone_retry_seconds[step >= n ? n - 1 : step];
	int span = base / 5;
	int delay;

	if(span < 1) {
		span = 1;
	}

	delay = base - span + (int)prng(mesh, (uint64_t)(2 * span + 1));

	if(delay < 1) {
		delay = 1;
	}

	return delay;
}

void connection_policy_schedule_backbone_retry(meshlink_handle_t *mesh, outgoing_t *outgoing) {
	size_t n = sizeof backbone_retry_seconds / sizeof backbone_retry_seconds[0];
	int delay;

	if(!mesh || !outgoing) {
		return;
	}

	delay = backbone_retry_delay(mesh, outgoing->retry_step);

	if(outgoing->retry_step + 1 < n) {
		outgoing->retry_step++;
	}

	outgoing_arm_retry(mesh, outgoing, delay);
	logger(mesh, MESHLINK_INFO, "Trying to re-establish outgoing connection in %d seconds", delay);
}

void connection_policy_bind_connection(meshlink_handle_t *mesh, connection_t *c) {
	outgoing_t *intent;

	if(!mesh || !c || !c->node) {
		return;
	}

	if(connection_policy_is_backbone(mesh, c->node)) {
		intent = find_outgoing_for_purpose(mesh, META_PURPOSE_BACKBONE_REQUIRED);

		if(!intent || intent->node != c->node) {
			return;
		}

		if(c->outgoing && c->outgoing != intent) {
			return;
		}

		c->outgoing = intent;
		return;
	}

	intent = find_outgoing_for_node(mesh, c->node);

	if(!intent || intent->purpose != META_PURPOSE_LAN_RESILIENCE) {
		return;
	}

	if(c->outgoing && c->outgoing != intent) {
		return;
	}

	c->outgoing = intent;
}

static bool backbone_outgoing_in_flight(const outgoing_t *outgoing) {
	return outgoing->pending
	       || outgoing->ev.cb
	       || (outgoing->node && outgoing->node->connection && outgoing->node->connection->status.active);
}

static void ensure_backbone_outgoing(meshlink_handle_t *mesh, node_t *bb, bool may_dial) {
	outgoing_t *existing = find_outgoing_for_node(mesh, bb);

	if(existing) {
		existing->purpose = META_PURPOSE_BACKBONE_REQUIRED;

		if(may_dial && !backbone_outgoing_in_flight(existing)) {
			setup_outgoing_connection(mesh, existing);
		}

		return;
	}

	outgoing_t *outgoing = xzalloc(sizeof(outgoing_t));
	outgoing->node = bb;
	outgoing->purpose = META_PURPOSE_BACKBONE_REQUIRED;
	list_insert_tail(mesh->outgoings, outgoing);

	if(may_dial) {
		setup_outgoing_connection(mesh, outgoing);
	}
}

static bool lan_outgoing_in_flight(meshlink_handle_t *mesh, const outgoing_t *outgoing) {
	return outgoing->pending
	       || outgoing->ev.cb
	       || node_has_meta_socket(mesh, outgoing->node);
}

static void ensure_lan_outgoing(meshlink_handle_t *mesh, node_t *peer, bool may_dial) {
	outgoing_t *existing = find_outgoing_for_node(mesh, peer);

	if(existing) {
		if(existing->purpose == META_PURPOSE_BACKBONE_REQUIRED) {
			return;
		}

		existing->purpose = META_PURPOSE_LAN_RESILIENCE;

		/* Never setup() an existing LAN intent from tick: abort_startup
		   nulls pending and c->outgoing before terminate, nested tick then
		   sees !in_flight and SYN-floods. Redial only via the retry timer. */
		if(may_dial && !lan_outgoing_in_flight(mesh, existing)) {
			int delay = existing->timeout > 0 ? existing->timeout : 1;

			outgoing_arm_retry(mesh, existing, delay);
		}

		return;
	}

	outgoing_t *outgoing = xzalloc(sizeof(outgoing_t));
	outgoing->node = peer;
	outgoing->purpose = META_PURPOSE_LAN_RESILIENCE;
	list_insert_tail(mesh->outgoings, outgoing);

	if(may_dial && !node_has_meta_socket(mesh, peer)) {
		setup_outgoing_connection(mesh, outgoing);
	}
}

static void fill_lan_overlay(meshlink_handle_t *mesh) {
	node_t *desired[META_LAN_RESILIENCE_MAX];
	unsigned nd;
	unsigned i;

	if(!mesh->nodes) {
		return;
	}

	for list_each(outgoing_t, outgoing, mesh->outgoings) {
		if(outgoing->purpose != META_PURPOSE_BACKBONE_REQUIRED
		                && outgoing->purpose != META_PURPOSE_LAN_RESILIENCE) {
			drop_outgoing(mesh, outgoing);
		}
	}

	nd = lan_desired_peers(mesh, NULL, NULL, -1, desired);

	for list_each(outgoing_t, outgoing, mesh->outgoings) {
		if(outgoing->purpose != META_PURPOSE_LAN_RESILIENCE) {
			continue;
		}

		if(!node_in_desired(desired, nd, outgoing->node)) {
			drop_outgoing(mesh, outgoing);
		}
	}

	while(local_adjacency_count(mesh) > META_LAN_RESILIENCE_MAX) {
		node_t *extra = least_preferred_extra(mesh, desired, nd);

		if(!extra) {
			break;
		}

		retire_local_adjacency(mesh, extra);
	}

	for(i = 0; i < nd; i++) {
		node_t *peer = desired[i];
		sockaddr_t sa;
		bool may_dial;

		if(strcmp(mesh->self->name, peer->name) >= 0) {
			continue;
		}

		if(!node_read_public_key(mesh, peer)) {
			if(peer->status.reachable) {
				send_req_key(mesh, peer);
			}

			ensure_lan_outgoing(mesh, peer, false);
			continue;
		}

		may_dial = path_best_local_meta(peer, NULL, &sa, NULL)
		           || connection_policy_is_local_adjacency(mesh, peer)
		           || node_has_meta_socket(mesh, peer);
		ensure_lan_outgoing(mesh, peer, may_dial);
	}
}

static bool node_would_conflict_backbone(const meshlink_handle_t *mesh, const node_t *n, int announced) {
	bool named;
	bool extra;
	bool wrong_class;

	if(!mesh || !n) {
		return false;
	}

	named = mesh->backbone.name && n->name && !strcmp(n->name, mesh->backbone.name);
	extra = announced == DEV_CLASS_BACKBONE && !named
	        && (mesh->backbone.name || connection_policy_backbone_class_count(mesh) >= 2);
	wrong_class = named && announced != DEV_CLASS_BACKBONE;
	return extra || wrong_class;
}

static bool admit_incoming_eval(meshlink_handle_t *mesh, connection_t *c, node_t *n, int announced_devclass, bool apply_side_effects) {
	node_t *desired[META_LAN_RESILIENCE_MAX];
	unsigned nd;
	bool desired_peer;
	unsigned degree;

	if(mesh->self->devclass == DEV_CLASS_BACKBONE || connection_policy_is_backbone(mesh, mesh->self)) {
		return true;
	}

	if(connection_policy_is_backbone(mesh, n)) {
		return true;
	}

	if(c->status.upgrade_probe) {
		return true;
	}

	if(!connection_policy_lan_device_class(mesh->self->devclass)) {
		return false;
	}

	if(!local_candidate_with_class(n, &c->address, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH, announced_devclass)) {
		return false;
	}

	if(!node_is_lan_eligible(mesh, n, NULL, announced_devclass)) {
		return false;
	}

	nd = lan_desired_peers(mesh, n, &c->address, announced_devclass, desired);
	desired_peer = node_in_desired(desired, nd, n);
	degree = local_adjacency_count(mesh);

	if(connection_policy_is_local_adjacency(mesh, n)) {
		if(apply_side_effects) {
			n->lan_admitted_epoch = mesh->lan_network_epoch;
		}

		return true;
	}

	if(desired_peer || degree < META_LAN_RESILIENCE_MAX) {
		if(desired_peer && degree >= META_LAN_RESILIENCE_MAX) {
			node_t *extra;

			if(!apply_side_effects) {
				return true;
			}

			extra = least_preferred_extra(mesh, desired, nd);

			if(!extra) {
				return false;
			}

			retire_local_adjacency(mesh, extra);
		}

		if(apply_side_effects) {
			n->lan_admitted_epoch = mesh->lan_network_epoch;
		}

		return true;
	}

	return false;
}

bool connection_policy_may_accept_incoming(meshlink_handle_t *mesh, connection_t *c, int announced_devclass) {
	node_t *n;

	if(!mesh || !c || !mesh->self) {
		return false;
	}

	n = c->node ? c->node : (c->name ? lookup_node(mesh, c->name) : NULL);

	if(!n) {
		return false;
	}

	if(node_would_conflict_backbone(mesh, n, announced_devclass)) {
		return false;
	}

	return admit_incoming_eval(mesh, c, n, announced_devclass, false);
}

bool connection_policy_admit_incoming(meshlink_handle_t *mesh, connection_t *c, int announced_devclass) {
	node_t *n;

	if(!mesh || !c || !mesh->self) {
		return false;
	}

	n = c->node ? c->node : (c->name ? lookup_node(mesh, c->name) : NULL);

	if(!n) {
		return false;
	}

	if(node_would_conflict_backbone(mesh, n, announced_devclass)) {
		return false;
	}

	return admit_incoming_eval(mesh, c, n, announced_devclass, true);
}

void connection_policy_tick(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->self || !mesh->outgoings || mesh->retiring_outgoing || mesh->connection_policy_busy || mesh->lan_epoch_retiring) {
		return;
	}

	mesh->connection_policy_busy = true;

	/* Any BACKBONE-class node, including a conflicted extra, initiates nothing. */
	if(mesh->self->devclass == DEV_CLASS_BACKBONE || connection_policy_is_backbone(mesh, mesh->self)) {
		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			drop_outgoing(mesh, outgoing);
		}

		goto done;
	}

	node_t *bb = connection_policy_backbone(mesh);

	if(!backbone_target_ok(bb)) {
		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			if(outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED) {
				drop_outgoing(mesh, outgoing);
			}
		}
	} else {
		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			if(outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED && outgoing->node != bb) {
				drop_outgoing(mesh, outgoing);
			}
		}

		if(!node_read_public_key(mesh, bb)) {
			if(bb->status.reachable) {
				send_req_key(mesh, bb);
			}

			ensure_backbone_outgoing(mesh, bb, false);
		} else {
			ensure_backbone_outgoing(mesh, bb, true);
		}
	}

	if(connection_policy_lan_device_class(mesh->self->devclass)) {
		fill_lan_overlay(mesh);
	} else {
		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			if(outgoing->purpose == META_PURPOSE_LAN_RESILIENCE) {
				drop_outgoing(mesh, outgoing);
			}
		}
	}

done:
	mesh->connection_policy_busy = false;
}

void connection_policy_on_discovery(meshlink_handle_t *mesh, node_t *node,
                                    const sockaddr_t *address, address_source_t source) {
	if(!mesh || !node) {
		return;
	}

	if(source == ADDR_SRC_DISCOVERY && address && path_address_is_local(address)) {
		time_t now = mesh->loop.now.tv_sec;

		if(now <= 0) {
			event_loop_stamp_now(&mesh->loop);
			now = mesh->loop.now.tv_sec;
		}

		if(now <= 0) {
			now = 1;
		}

		node->lan_presence.network_epoch = mesh->lan_network_epoch;
		node->lan_presence.last_discovered_at = now;
	}

	node->last_connect_try = 0;

	if(connection_policy_is_backbone(mesh, node)
	                && node->connection && node->connection->status.active) {
		return;
	}

	if(mesh->outgoings) {
		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			if(outgoing->node != node) {
				continue;
			}

			if(outgoing->purpose == META_PURPOSE_LAN_RESILIENCE) {
				continue;
			}

			if(outgoing->purpose != META_PURPOSE_BACKBONE_REQUIRED) {
				outgoing->timeout = 0;
			}

			/* Wake a scheduled retry. Keep retry_step. Do not abort a
			   pending connect or invent a second dial. LAN keeps its backoff. */
			if(outgoing->ev.cb && !outgoing->pending) {
				timeout_set(&mesh->loop, &outgoing->ev, &(struct timespec) {
					0, 0
				});
			}
		}
	}

	connection_policy_tick(mesh);
}

void connection_policy_advance_network_epoch(meshlink_handle_t *mesh) {
	if(!mesh) {
		return;
	}

	mesh->lan_epoch_retiring = true;
	mesh->lan_network_epoch++;

	if(!mesh->lan_network_epoch) {
		mesh->lan_network_epoch = 1;
	}

	if(mesh->nodes) {
		for splay_each(node_t, n, mesh->nodes) {
			n->lan_auth_direct_until = 0;
			n->lan_admitted_epoch = 0;
		}
	}

	retire_lan_overlay(mesh);
	mesh->lan_epoch_retiring = false;
	connection_policy_tick(mesh);
}

void connection_policy_note_lan_drop(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || mesh->lan_epoch_retiring) {
		return;
	}

	n->lan_auth_direct_until = mesh->loop.now.tv_sec + LAN_AUTH_DIRECT_GRACE_SEC;
}

void connection_policy_on_connection_closed(meshlink_handle_t *mesh, node_t *node,
                meta_connection_purpose_t purpose) {
	(void)node;
	(void)purpose;

	if(!mesh || mesh->retiring_outgoing || mesh->lan_epoch_retiring) {
		return;
	}

	connection_policy_tick(mesh);
}
