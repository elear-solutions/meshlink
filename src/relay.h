#ifndef MESHLINK_RELAY_H
#define MESHLINK_RELAY_H

/*
    relay.h -- UDP type-8 relay
    Copyright (C) 2026 Elear Solutions / MeshLink contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct meshlink_handle;
struct node_t;

#define RELAY_REPORT_MAX 4096
#define RELAY_REPORT_IDLE_SEC 30
#define RELAY_NAME_MAX 255
#define RELAY_INNER_MIN 21

void relay_init(struct meshlink_handle *mesh);
void relay_exit(struct meshlink_handle *mesh);

bool hop_udp_ready(const struct node_t *hop);
bool relay_names_unusable(const char *origin, const char *destination);
size_t relay_prefix_len(const char *origin, const char *destination);
bool relay_sub_u32(uint32_t a, uint32_t b, uint32_t *out);

void update_destination_transport(struct meshlink_handle *mesh, struct node_t *dest);
void recompute_relay_dependents(struct meshlink_handle *mesh, struct node_t *hop);
void node_set_validkey(struct meshlink_handle *mesh, struct node_t *n, bool valid);
void relay_on_hard_send_error(struct meshlink_handle *mesh, struct node_t *hop);
void relay_wake_probes(struct meshlink_handle *mesh, struct node_t *hop);
void relay_clear_budget_if_nexthop_changed(struct meshlink_handle *mesh, struct node_t *dest);

bool relay_encode(const char *origin, const char *destination, const void *inner, size_t inner_len, void *out, size_t *out_len);
bool relay_decode(const void *data, size_t len, char *origin, size_t origin_size, char *destination, size_t destination_size, const uint8_t **inner, size_t *inner_len);

bool handle_relay_record(struct meshlink_handle *mesh, struct node_t *from, const void *data, uint16_t len);
bool send_meta_req_sptps(struct meshlink_handle *mesh, const char *origin, struct node_t *dest, const void *inner, size_t inner_len);
void relay_maybe_report(struct meshlink_handle *mesh, const char *origin, struct node_t *dest, bool oversize);
void relay_notify_minmtu_change(struct meshlink_handle *mesh, struct node_t *dest);
void relay_touch_traffic(struct meshlink_handle *mesh, const char *origin, const char *destination);

bool relay_inject_inner(struct meshlink_handle *mesh, struct node_t *dest, uint8_t type);
bool relay_handle_req_relay_mtu(struct meshlink_handle *mesh, struct connection_t *c, const char *request, struct node_t *from);

void relay_devtool_clear_reports(struct meshlink_handle *mesh);
bool relay_devtool_seed_report(struct meshlink_handle *mesh, const char *origin, const char *destination, unsigned age_sec, bool have_reported);
bool relay_devtool_has_report(struct meshlink_handle *mesh, const char *origin, const char *destination);
bool relay_devtool_have_reported(struct meshlink_handle *mesh, const char *origin, const char *destination);
size_t relay_devtool_report_count(struct meshlink_handle *mesh);
bool relay_devtool_fill_reports(struct meshlink_handle *mesh, size_t count, unsigned age_sec, bool have_reported);
void relay_devtool_fail_reports(struct meshlink_handle *mesh, bool fail);

#endif
