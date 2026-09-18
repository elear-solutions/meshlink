#ifndef MESHLINK_CONNECTION_POLICY_H
#define MESHLINK_CONNECTION_POLICY_H

/*
    connection_policy.h -- unique backbone identity and META connection pools
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdbool.h>

#include "path_policy.h"

struct meshlink_handle;
struct node_t;
struct connection_t;
struct outgoing_t;

typedef enum meta_connection_purpose_t {
	META_PURPOSE_NONE = 0,
	META_PURPOSE_BACKBONE_REQUIRED,
	META_PURPOSE_LAN_RESILIENCE,
	META_PURPOSE_HANDOVER_SPARE,
} meta_connection_purpose_t;

#define META_LAN_RESILIENCE_MAX 3

/* Authenticated backbone META must live this long before a drop resets retry_step. */
#define BACKBONE_STABLE_RESET_SEC 5

/* After a local META drop on the same network, AUTH_DIRECT recent[] may redial only this long. */
#define LAN_AUTH_DIRECT_GRACE_SEC 15

static inline bool meta_purpose_is_persistent(meta_connection_purpose_t purpose) {
	return purpose == META_PURPOSE_BACKBONE_REQUIRED
	       || purpose == META_PURPOSE_LAN_RESILIENCE;
}

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
void connection_policy_tick(struct meshlink_handle *mesh);
void connection_policy_on_discovery(struct meshlink_handle *mesh, struct node_t *node,
                                    const sockaddr_t *address, address_source_t source);
void connection_policy_on_connection_closed(struct meshlink_handle *mesh, struct node_t *node,
                meta_connection_purpose_t purpose);
void connection_policy_schedule_backbone_retry(struct meshlink_handle *mesh, struct outgoing_t *outgoing);
void connection_policy_reset_backbone_retry(struct outgoing_t *outgoing);
void connection_policy_bind_connection(struct meshlink_handle *mesh, struct connection_t *c);
bool connection_policy_lan_device_class(int devclass);
bool connection_policy_local_candidate(const struct node_t *node,
                                       const sockaddr_t *address,
                                       address_source_t source,
                                       path_cap_t capability);
bool connection_policy_may_accept_incoming(struct meshlink_handle *mesh, struct connection_t *c, int announced_devclass);
bool connection_policy_admit_incoming(struct meshlink_handle *mesh, struct connection_t *c, int announced_devclass);
void connection_policy_advance_network_epoch(struct meshlink_handle *mesh);
void connection_policy_note_lan_drop(struct meshlink_handle *mesh, struct node_t *n);
bool connection_policy_is_local_adjacency(const struct meshlink_handle *mesh, const struct node_t *n);
const char *connection_policy_backbone_name(const struct meshlink_handle *mesh);
struct node_t *connection_policy_backbone(struct meshlink_handle *mesh);
bool connection_policy_is_backbone(const struct meshlink_handle *mesh, const struct node_t *n);
bool connection_policy_backbone_udp_required(const struct meshlink_handle *mesh, const struct node_t *n);
bool connection_policy_validate_topology(struct meshlink_handle *mesh);
bool connection_policy_can_invite(const struct meshlink_handle *mesh);
bool connection_policy_commit_self_if_creator(struct meshlink_handle *mesh);

#endif
