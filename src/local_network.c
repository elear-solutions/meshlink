/*
    local_network.c -- cached local interface address/prefix snapshot
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "connection_policy.h"
#include "local_network.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "netutl.h"
#include "xalloc.h"

#include <net/if.h>
#include <string.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

#define LOCAL_NETWORK_MAX 64

static void fnv1a(uint64_t *h, const void *p, size_t n) {
	const uint8_t *b = p;

	while(n--) {
		*h ^= *b++;
		*h *= 1099511628211ULL;
	}
}

uint8_t local_network_prefix_from_mask(const struct sockaddr *mask, int family) {
	const uint8_t *bytes;
	size_t len;
	uint8_t bits = 0;
	size_t i;

	if(!mask) {
		return 0;
	}

	if(family == AF_INET) {
		bytes = (const uint8_t *)&((const struct sockaddr_in *)mask)->sin_addr;
		len = 4;
	} else if(family == AF_INET6) {
		bytes = (const uint8_t *)&((const struct sockaddr_in6 *)mask)->sin6_addr;
		len = 16;
	} else {
		return 0;
	}

	for(i = 0; i < len; i++) {
		uint8_t b = bytes[i];

		if(b == 0xff) {
			bits += 8;
			continue;
		}

		while(b & 0x80) {
			bits++;
			b <<= 1;
		}

		break;
	}

	return bits;
}

static bool prefix_match(const sockaddr_t *addr, uint8_t prefix, const sockaddr_t *dest) {
	size_t len;
	size_t full;
	uint8_t rem;
	size_t i;
	const uint8_t *a;
	const uint8_t *b;

	if(!addr || !dest || addr->sa.sa_family != dest->sa.sa_family) {
		return false;
	}

	if(addr->sa.sa_family == AF_INET) {
		a = (const uint8_t *)&addr->in.sin_addr;
		b = (const uint8_t *)&dest->in.sin_addr;
		len = 4;
	} else if(addr->sa.sa_family == AF_INET6) {
		a = (const uint8_t *)&addr->in6.sin6_addr;
		b = (const uint8_t *)&dest->in6.sin6_addr;
		len = 16;
	} else {
		return false;
	}

	if(prefix > len * 8) {
		prefix = (uint8_t)(len * 8);
	}

	full = prefix / 8;
	rem = prefix % 8;

	for(i = 0; i < full; i++) {
		if(a[i] != b[i]) {
			return false;
		}
	}

	if(!rem) {
		return true;
	}

	uint8_t mask = (uint8_t)(0xff << (8 - rem));
	return (a[full] & mask) == (b[full] & mask);
}

static bool ipv6_link_local(const sockaddr_t *sa) {
	return sa && sa->sa.sa_family == AF_INET6
	       && sa->in6.sin6_addr.s6_addr[0] == 0xfe
	       && (sa->in6.sin6_addr.s6_addr[1] & 0xc0) == 0x80;
}

static bool ipv4_loopback(const sockaddr_t *sa) {
	return sa && sa->sa.sa_family == AF_INET
	       && (ntohl(sa->in.sin_addr.s_addr) & 0xff000000) == 0x7f000000;
}

static bool address_is_loopback(const sockaddr_t *sa) {
	if(!sa) {
		return false;
	}

	if(ipv4_loopback(sa)) {
		return true;
	}

	return sa->sa.sa_family == AF_INET6 && IN6_IS_ADDR_LOOPBACK(&sa->in6.sin6_addr);
}

static bool rfc1918_or_ula(const sockaddr_t *sa) {
	uint32_t a;

	if(!sa || address_is_loopback(sa) || ipv6_link_local(sa)) {
		return false;
	}

	if(sa->sa.sa_family == AF_INET) {
		a = ntohl(sa->in.sin_addr.s_addr);

		if(a == 0 || a == 0xffffffff) {
			return false;
		}

		if((a & 0xf0000000) == 0xe0000000) {
			return false; /* multicast */
		}

		if((a & 0xff000000) == 0x0a000000) {
			return true;
		}

		if((a & 0xfff00000) == 0xac100000) {
			return true;
		}

		if((a & 0xffff0000) == 0xc0a80000) {
			return true;
		}

		return false;
	}

	if(sa->sa.sa_family == AF_INET6) {
		if(IN6_IS_ADDR_UNSPECIFIED(&sa->in6.sin6_addr) || IN6_IS_ADDR_MULTICAST(&sa->in6.sin6_addr)) {
			return false;
		}

		return (sa->in6.sin6_addr.s6_addr[0] & 0xfe) == 0xfc;
	}

	return false;
}

static bool snapshot_usable(const struct meshlink_handle *mesh) {
	const local_network_t *ln;
	struct timespec now;

	if(!mesh) {
		return false;
	}

	ln = &mesh->local_network;

	if(!ln->valid) {
		return false;
	}

	if(ln->override || !ln->failed) {
		return true;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);

	return now.tv_sec - ln->scanned_at.tv_sec < LOCAL_NETWORK_STALE_SEC;
}

static uint64_t fingerprint_of(const local_iface_addr_t *addrs, size_t count) {
	uint64_t h = 1469598103934665603ULL;
	size_t i;

	fnv1a(&h, &count, sizeof count);

	for(i = 0; i < count; i++) {
		fnv1a(&h, &addrs[i].ifindex, sizeof addrs[i].ifindex);
		fnv1a(&h, &addrs[i].flags, sizeof addrs[i].flags);
		fnv1a(&h, &addrs[i].prefix_len, sizeof addrs[i].prefix_len);
		fnv1a(&h, &addrs[i].address, sizeof addrs[i].address);
	}

	return h;
}

static void commit_snapshot(struct meshlink_handle *mesh, local_iface_addr_t *addrs, size_t count, bool advance) {
	local_network_t *ln = &mesh->local_network;
	uint64_t fp = fingerprint_of(addrs, count);
	bool changed = !ln->valid || fp != ln->fingerprint;

	free(ln->addrs);
	ln->addrs = addrs;
	ln->count = count;
	ln->fingerprint = fp;
	ln->valid = true;
	ln->failed = false;
	clock_gettime(CLOCK_MONOTONIC, &ln->scanned_at);

	if(!changed) {
		return;
	}

	ln->epoch++;

	if(!ln->epoch) {
		ln->epoch = 1;
	}

	if(advance && ln->epoch > 1) {
		connection_policy_advance_network_epoch(mesh);
	}

	/* A backbone whose private listeners changed tells queried members now,
	   not when one of them happens to query again. */
	path_backbone_private_publish_refresh(mesh);
}

#ifdef HAVE_GETIFADDRS
static size_t ifaddrs_length(const struct ifaddrs *ifa) {
	size_t n = 0;

	for(; ifa; ifa = ifa->ifa_next) {
		n++;
	}

	return n;
}

struct local_index_params {
	const struct ifaddrs *ifa;
	int *out;
	size_t max;
	int netns;
};

static void *local_index_fill(void *arg) {
	struct local_index_params *params = arg;
	const struct ifaddrs *ifap;
	size_t i = 0;

#ifdef HAVE_SETNS

	if(params->netns != -1 && setns(params->netns, CLONE_NEWNET) == -1) {
		return NULL;
	}

#endif

	for(ifap = params->ifa; ifap && i < params->max; ifap = ifap->ifa_next, i++) {
		params->out[i] = ifap->ifa_name ? (int)if_nametoindex(ifap->ifa_name) : 0;
	}

	return NULL;
}

/* if_nametoindex() resolves in the calling thread's namespace, and an app
   thread is not in the mesh netns. Resolve every entry where getifaddrs ran. */
static void local_resolve_indices(struct meshlink_handle *mesh, const struct ifaddrs *ifa, int *out, size_t max) {
	struct local_index_params params = {ifa, out, max, mesh->netns};

	if(mesh->netns == -1) {
		local_index_fill(&params);
		return;
	}

#ifdef HAVE_SETNS
	{
		pthread_t thr;

		if(pthread_create(&thr, NULL, local_index_fill, &params) == 0) {
			if(pthread_join(thr, NULL) != 0) {
				abort();
			}
		}
	}
#endif
}

#ifdef HAVE_SETNS
struct local_getifaddrs_params {
	struct ifaddrs **ifa;
	int netns;
};

static void *local_getifaddrs_thread(void *arg) {
	struct local_getifaddrs_params *params = arg;

	if(setns(params->netns, CLONE_NEWNET) == -1) {
		return NULL;
	}

	if(getifaddrs(params->ifa) != 0) {
		*params->ifa = NULL;
	}

	return NULL;
}
#endif
#endif

int local_network_getifaddrs(struct meshlink_handle *mesh, struct ifaddrs **ifa) {
#ifdef HAVE_GETIFADDRS
	int netns;

	if(!ifa) {
		return -1;
	}

	*ifa = NULL;
	netns = mesh ? mesh->netns : -1;

	if(netns == -1) {
		return getifaddrs(ifa);
	}

#ifdef HAVE_SETNS
	{
		struct local_getifaddrs_params params = {ifa, netns};
		pthread_t thr;

		if(pthread_create(&thr, NULL, local_getifaddrs_thread, &params) == 0) {
			if(pthread_join(thr, NULL) != 0) {
				abort();
			}
		}

		return *ifa ? 0 : -1;
	}
#else
	(void)netns;
	return -1;
#endif
#else
	(void)mesh;
	(void)ifa;
	return -1;
#endif
}

bool local_network_ingest(struct meshlink_handle *mesh, struct ifaddrs *ifa) {
	local_iface_addr_t *built;
	size_t count = 0;
#ifdef HAVE_GETIFADDRS
	struct ifaddrs *ifap;
#endif

	if(!mesh) {
		return false;
	}

	if(mesh->local_network.override) {
		return mesh->local_network.valid;
	}

#ifdef HAVE_GETIFADDRS
	size_t entries = ifaddrs_length(ifa);
	int *indices = xzalloc((entries ? entries : 1) * sizeof *indices);
	size_t k = 0;

	local_resolve_indices(mesh, ifa, indices, entries);
	built = xzalloc(LOCAL_NETWORK_MAX * sizeof *built);

	for(ifap = ifa; ifap && count < LOCAL_NETWORK_MAX; ifap = ifap->ifa_next, k++) {
		sockaddr_t *sa;
		local_iface_addr_t *slot;

		if(!ifap->ifa_name || !ifap->ifa_addr) {
			continue;
		}

		sa = (sockaddr_t *)ifap->ifa_addr;

		if(sa->sa.sa_family != AF_INET && sa->sa.sa_family != AF_INET6) {
			continue;
		}

		slot = &built[count];
		slot->ifindex = indices[k];
		slot->flags = ifap->ifa_flags;
		slot->prefix_len = local_network_prefix_from_mask(ifap->ifa_netmask, sa->sa.sa_family);

		if(sa->sa.sa_family == AF_INET) {
			memcpy(&slot->address.in, &sa->in, sizeof sa->in);
			slot->address.in.sin_port = 0;
		} else {
			memcpy(&slot->address.in6, &sa->in6, sizeof sa->in6);
			slot->address.in6.sin6_port = 0;

			if(!slot->address.in6.sin6_scope_id) {
				slot->address.in6.sin6_scope_id = slot->ifindex;
			}
		}

		count++;
	}

	free(indices);
	commit_snapshot(mesh, built, count, true);
	return true;
#else
	(void)built;
	(void)count;
	(void)ifa;
	mesh->local_network.failed = true;
	return false;
#endif
}

bool local_network_refresh(struct meshlink_handle *mesh) {
#ifdef HAVE_GETIFADDRS
	struct ifaddrs *ifa = NULL;
	bool ok;
#endif

	if(!mesh) {
		return false;
	}

	if(mesh->local_network.override) {
		return mesh->local_network.valid;
	}

#ifdef HAVE_GETIFADDRS

	if(mesh->local_network.test_fail_scans || local_network_getifaddrs(mesh, &ifa) != 0) {
		logger(mesh, MESHLINK_ERROR, "Could not scan local interfaces: %s",
		       mesh->local_network.test_fail_scans ? "test failure" : strerror(errno));
		/* Keep scanned_at at the last success so repeated failures age the
		   snapshot out instead of renewing it. */
		mesh->local_network.failed = true;
		return false;
	}

	ok = local_network_ingest(mesh, ifa);
	freeifaddrs(ifa);
	return ok;
#else
	mesh->local_network.failed = true;
	return false;
#endif
}

void local_network_teardown(struct meshlink_handle *mesh) {
	if(!mesh) {
		return;
	}

	free(mesh->local_network.addrs);
	memset(&mesh->local_network, 0, sizeof mesh->local_network);
}

bool local_network_on_link(const struct meshlink_handle *mesh, const sockaddr_t *sa) {
	size_t i;

	if(!snapshot_usable(mesh) || !sa) {
		return false;
	}

	if(address_is_loopback(sa)) {
		for(i = 0; i < mesh->local_network.count; i++) {
			const local_iface_addr_t *a = &mesh->local_network.addrs[i];

			if(!(a->flags & IFF_UP) || !(a->flags & IFF_LOOPBACK)) {
				continue;
			}

			if(a->address.sa.sa_family == sa->sa.sa_family) {
				return true;
			}
		}

		return false;
	}

	for(i = 0; i < mesh->local_network.count; i++) {
		const local_iface_addr_t *a = &mesh->local_network.addrs[i];

		if(!(a->flags & IFF_UP) || (a->flags & IFF_LOOPBACK)) {
			continue;
		}

		if(a->address.sa.sa_family != sa->sa.sa_family) {
			continue;
		}

		if(ipv6_link_local(sa) || ipv6_link_local(&a->address)) {
			if(!ipv6_link_local(sa) || !ipv6_link_local(&a->address)) {
				continue;
			}

			if(!sa->in6.sin6_scope_id || sa->in6.sin6_scope_id != (uint32_t)a->ifindex) {
				continue;
			}

			return true;
		}

		if(prefix_match(&a->address, a->prefix_len, sa)) {
			return true;
		}
	}

	return false;
}

bool local_network_is_own_address(const struct meshlink_handle *mesh, const sockaddr_t *sa) {
	size_t i;

	if(!snapshot_usable(mesh) || !sa) {
		return false;
	}

	for(i = 0; i < mesh->local_network.count; i++) {
		const local_iface_addr_t *a = &mesh->local_network.addrs[i];

		if(!(a->flags & IFF_UP)) {
			continue;
		}

		if(!sockaddrcmp_noport(&a->address, sa)) {
			return true;
		}
	}

	return false;
}

size_t local_network_private_publishable(const struct meshlink_handle *mesh, int family, sockaddr_t *out, size_t max) {
	size_t n = 0;
	size_t i;

	if(!snapshot_usable(mesh) || !out || !max) {
		return 0;
	}

	for(i = 0; i < mesh->local_network.count && n < max; i++) {
		const local_iface_addr_t *a = &mesh->local_network.addrs[i];

		if(!(a->flags & IFF_UP) || (a->flags & IFF_LOOPBACK)) {
			continue;
		}

		if(a->address.sa.sa_family != family) {
			continue;
		}

		if(!rfc1918_or_ula(&a->address)) {
			continue;
		}

		out[n] = a->address;

		if(family == AF_INET) {
			out[n].in.sin_port = 0;
		} else {
			out[n].in6.sin6_port = 0;
		}

		n++;
	}

	return n;
}

bool local_network_set_snapshot(struct meshlink_handle *mesh, const local_iface_addr_t *addrs, size_t count) {
	local_iface_addr_t *copy;

	if(!mesh) {
		return false;
	}

	if(!addrs) {
		mesh->local_network.override = false;
		return local_network_refresh(mesh);
	}

	if(count > LOCAL_NETWORK_MAX) {
		count = LOCAL_NETWORK_MAX;
	}

	copy = xzalloc((count ? count : 1) * sizeof *copy);

	if(count) {
		memcpy(copy, addrs, count * sizeof *copy);
	}

	mesh->local_network.override = true;
	/* A test override changes eligibility only. It is not a host network change,
	   so it must not retire live META. */
	commit_snapshot(mesh, copy, count, false);
	return true;
}

uint32_t local_network_epoch(const struct meshlink_handle *mesh) {
	return mesh ? mesh->local_network.epoch : 0;
}

void local_network_force_stale(struct meshlink_handle *mesh) {
	if(!mesh) {
		return;
	}

	mesh->local_network.failed = true;
	mesh->local_network.override = false;
	mesh->local_network.scanned_at.tv_sec = 0;
	mesh->local_network.scanned_at.tv_nsec = 0;
}

void local_network_test_fail_scans(struct meshlink_handle *mesh, bool fail) {
	if(!mesh) {
		return;
	}

	mesh->local_network.test_fail_scans = fail;
	mesh->local_network.override = false;
}

void local_network_test_age(struct meshlink_handle *mesh, int seconds) {
	if(!mesh) {
		return;
	}

	mesh->local_network.override = false;
	mesh->local_network.scanned_at.tv_sec -= seconds;
}
