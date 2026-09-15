#ifndef MESHLINK_CONNECTION_POLICY_H
#define MESHLINK_CONNECTION_POLICY_H

/*
    connection_policy.h -- unique backbone identity
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdbool.h>

struct meshlink_handle;
struct node_t;

void connection_policy_init(struct meshlink_handle *mesh);
void connection_policy_exit(struct meshlink_handle *mesh);
bool connection_policy_load(struct meshlink_handle *mesh);
bool connection_policy_persist(struct meshlink_handle *mesh);
bool connection_policy_set_backbone(struct meshlink_handle *mesh, const char *name);
void connection_policy_resolve(struct meshlink_handle *mesh);
void connection_policy_migrate(struct meshlink_handle *mesh);
void connection_policy_on_node_added(struct meshlink_handle *mesh, struct node_t *n);
void connection_policy_on_node_deleted(struct meshlink_handle *mesh, struct node_t *n);
void connection_policy_on_devclass(struct meshlink_handle *mesh, struct node_t *n);
const char *connection_policy_backbone_name(const struct meshlink_handle *mesh);
struct node_t *connection_policy_backbone(struct meshlink_handle *mesh);
bool connection_policy_is_backbone(const struct meshlink_handle *mesh, const struct node_t *n);
bool connection_policy_validate_topology(struct meshlink_handle *mesh);

#endif
