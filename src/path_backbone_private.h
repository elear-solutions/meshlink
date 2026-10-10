#ifndef MESHLINK_PATH_BACKBONE_PRIVATE_H
#define MESHLINK_PATH_BACKBONE_PRIVATE_H

/*
    path_backbone_private.h -- authenticated backbone private endpoints
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "path_types.h"
#include "sockaddr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct meshlink_handle;
struct node_t;
struct connection_t;

#define BB_PRIVATE_MAX 8
#define BB_PRIVATE_LIFETIME_SEC 300
#define BB_PRIVATE_REPLY_MIN_SEC 2
#define BB_PRIVATE_COOLDOWN_MIN 30
#define BB_PRIVATE_COOLDOWN_MAX 600

enum {
	BB_EP_IDLE = 0,
	BB_EP_VALIDATING,
	BB_EP_PROVEN,
	BB_EP_FAILED
};

typedef struct bb_private_endpoint {
	sockaddr_t sa;
	path_cap_t cap;
	uint8_t meta_state;
	uint8_t udp_state;
	uint8_t meta_failures;
	uint8_t udp_failures;
	struct timespec meta_retry_at;
	struct timespec udp_retry_at;
} bb_private_endpoint_t;

typedef struct backbone_private_t {
	uint64_t query_id;
	uint8_t ladder_step;
	struct timespec next_query_at;
	uint32_t session_id;
	uint32_t revision;
	uint32_t network_epoch;
	struct timespec expires_at;
	bool empty;
	bool ever_proven;
	bool changed_pending;
	bb_private_endpoint_t endpoints[BB_PRIVATE_MAX];
	size_t count;
	uint32_t publish_revision;
	uint64_t publish_hash;
} backbone_private_t;

void path_backbone_private_tick(struct meshlink_handle *mesh, struct node_t *n);
/* Backbone side: recompute the published set and push CHANGED to queried members. */
void path_backbone_private_publish_refresh(struct meshlink_handle *mesh);
/* The live private META carrier's address left the vouched set. */
bool path_backbone_private_meta_superseded(const struct meshlink_handle *mesh, const struct node_t *n);
bool path_backbone_private_vouches(const struct meshlink_handle *mesh, const struct node_t *n, const sockaddr_t *sa);
bool path_backbone_private_knows(const struct meshlink_handle *mesh, const sockaddr_t *sa);
bool path_backbone_private_has_unproven_meta(const struct meshlink_handle *mesh, const struct node_t *n);
bool path_backbone_private_pick_meta(struct meshlink_handle *mesh, struct node_t *n, sockaddr_t *out);
void path_backbone_private_note_meta_failure(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa);
void path_backbone_private_note_meta_proven(struct meshlink_handle *mesh, struct node_t *n, const sockaddr_t *sa);
void path_backbone_private_on_session_change(struct meshlink_handle *mesh, struct node_t *n);
bool path_backbone_private_public_data_allowed(const struct meshlink_handle *mesh, const struct node_t *n);
bool path_backbone_private_fill_udp(const struct meshlink_handle *mesh, const struct node_t *n, sockaddr_t *out);
bool path_backbone_private_fill_meta(const struct meshlink_handle *mesh, const struct node_t *n);

bool path_backbone_private_handle_request(struct meshlink_handle *mesh, struct connection_t *c, struct node_t *from, const char *request);
bool path_backbone_private_handle_answer(struct meshlink_handle *mesh, struct connection_t *c, struct node_t *from, const char *request);
bool path_backbone_private_handle_changed(struct meshlink_handle *mesh, struct connection_t *c, struct node_t *from, const char *request);

/* Inject a reply the way a forged or stale frame would arrive. Tests only. */
bool path_backbone_private_test_offer(struct meshlink_handle *mesh, struct connection_t *c, struct node_t *from, uint64_t query_id, uint32_t session_id, uint32_t revision, int lifetime, const sockaddr_t *sa, path_cap_t cap);

#endif
