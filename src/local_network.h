#ifndef MESHLINK_LOCAL_NETWORK_H
#define MESHLINK_LOCAL_NETWORK_H

/*
    local_network.h -- cached local interface address/prefix snapshot
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "sockaddr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct meshlink_handle;
struct ifaddrs;

/* A failed scan keeps the previous snapshot for this long, then on-link
   queries fail closed for speculative addresses. */
#define LOCAL_NETWORK_STALE_SEC 60

typedef struct local_iface_addr {
	int ifindex;
	uint32_t flags;      /* IFF_UP, IFF_LOOPBACK, IFF_POINTOPOINT, IFF_MULTICAST */
	sockaddr_t address;  /* port 0; sin6_scope_id preserved */
	uint8_t prefix_len;
} local_iface_addr_t;

typedef struct local_network {
	local_iface_addr_t *addrs;
	size_t count;
	uint64_t fingerprint;
	uint32_t epoch;
	struct timespec scanned_at;  /* last successful scan; failures never restamp it */
	bool valid;
	bool failed;         /* last scan failed; snapshot may still be fresh */
	bool override;       /* devtool snapshot; refresh does not replace it */
	bool test_fail_scans;
} local_network_t;

uint8_t local_network_prefix_from_mask(const struct sockaddr *mask, int family);

bool local_network_refresh(struct meshlink_handle *mesh);
/* Record a snapshot from a list the caller already fetched. Does not free it. */
bool local_network_ingest(struct meshlink_handle *mesh, struct ifaddrs *ifa);
void local_network_teardown(struct meshlink_handle *mesh);
bool local_network_on_link(const struct meshlink_handle *mesh, const sockaddr_t *sa);
bool local_network_is_own_address(const struct meshlink_handle *mesh, const sockaddr_t *sa);
size_t local_network_private_publishable(const struct meshlink_handle *mesh, int family, sockaddr_t *out, size_t max);
int local_network_getifaddrs(struct meshlink_handle *mesh, struct ifaddrs **ifa);

/* Test override. NULL clears it and scans again. */
bool local_network_set_snapshot(struct meshlink_handle *mesh, const local_iface_addr_t *addrs, size_t count);
uint32_t local_network_epoch(const struct meshlink_handle *mesh);
void local_network_force_stale(struct meshlink_handle *mesh);
/* Tests only: make later scans fail, and age the current snapshot. Both drop
   any override so local_network_refresh() runs its real failure path. */
void local_network_test_fail_scans(struct meshlink_handle *mesh, bool fail);
void local_network_test_age(struct meshlink_handle *mesh, int seconds);

#endif
