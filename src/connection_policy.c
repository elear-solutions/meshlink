/*
    connection_policy.c -- unique backbone identity
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "conf.h"
#include "connection_policy.h"
#include "logger.h"
#include "meshlink_internal.h"
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
}

void connection_policy_on_node_deleted(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n) {
		return;
	}

	if(mesh->backbone.node == n) {
		mesh->backbone.node = NULL;
	}
}

void connection_policy_on_devclass(meshlink_handle_t *mesh, node_t *n) {
	(void)n;
	(void)connection_policy_validate_topology(mesh);
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
