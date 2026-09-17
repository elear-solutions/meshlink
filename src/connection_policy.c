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

	if(!mesh || !c || !c->node || !connection_policy_is_backbone(mesh, c->node)) {
		return;
	}

	intent = find_outgoing_for_purpose(mesh, META_PURPOSE_BACKBONE_REQUIRED);

	if(!intent || intent->node != c->node) {
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

void connection_policy_tick(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->self || !mesh->outgoings || mesh->retiring_outgoing) {
		return;
	}

	/* Any BACKBONE-class node, including a conflicted extra, initiates nothing. */
	if(mesh->self->devclass == DEV_CLASS_BACKBONE || connection_policy_is_backbone(mesh, mesh->self)) {
		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			drop_outgoing(mesh, outgoing);
		}

		return;
	}

	/* Finding 7 fills LAN. Finding 5 keeps only BACKBONE_REQUIRED. */
	for list_each(outgoing_t, outgoing, mesh->outgoings) {
		if(outgoing->purpose != META_PURPOSE_BACKBONE_REQUIRED) {
			drop_outgoing(mesh, outgoing);
		}
	}

	node_t *bb = connection_policy_backbone(mesh);

	if(!backbone_target_ok(bb)) {
		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			if(outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED) {
				drop_outgoing(mesh, outgoing);
			}
		}

		return;
	}

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
		return;
	}

	ensure_backbone_outgoing(mesh, bb, true);
}

void connection_policy_on_discovery(meshlink_handle_t *mesh, node_t *node,
                                    const sockaddr_t *address, address_source_t source) {
	(void)address;
	(void)source;

	if(!mesh || !node) {
		return;
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

			if(outgoing->purpose != META_PURPOSE_BACKBONE_REQUIRED) {
				outgoing->timeout = 0;
			}

			/* Wake a scheduled retry. Keep retry_step. Do not abort a
			   pending connect or invent a second dial. */
			if(outgoing->ev.cb && !outgoing->pending) {
				timeout_set(&mesh->loop, &outgoing->ev, &(struct timespec) {
					0, 0
				});
			}
		}
	}

	connection_policy_tick(mesh);
}

void connection_policy_on_connection_closed(meshlink_handle_t *mesh, node_t *node,
                meta_connection_purpose_t purpose) {
	(void)node;
	(void)purpose;

	if(!mesh || mesh->retiring_outgoing) {
		return;
	}

	connection_policy_tick(mesh);
}
