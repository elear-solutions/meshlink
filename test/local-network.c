#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"

#include <net/if.h>
#include <string.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

#include "meshlink_internal.h"
#include "local_network.h"

static local_iface_addr_t v4(const char *ip, uint8_t prefix, int index, uint32_t flags) {
	local_iface_addr_t a;

	memset(&a, 0, sizeof a);
	a.ifindex = index;
	a.flags = flags;
	a.prefix_len = prefix;
	a.address.sa.sa_family = AF_INET;
	assert(inet_pton(AF_INET, ip, &a.address.in.sin_addr) == 1);
	return a;
}

static local_iface_addr_t v6(const char *ip, uint8_t prefix, int index, uint32_t scope, uint32_t flags) {
	local_iface_addr_t a;

	memset(&a, 0, sizeof a);
	a.ifindex = index;
	a.flags = flags;
	a.prefix_len = prefix;
	a.address.sa.sa_family = AF_INET6;
	assert(inet_pton(AF_INET6, ip, &a.address.in6.sin6_addr) == 1);
	a.address.in6.sin6_scope_id = scope;
	return a;
}

static sockaddr_t dest4(const char *ip) {
	sockaddr_t sa;

	memset(&sa, 0, sizeof sa);
	sa.sa.sa_family = AF_INET;
	assert(inet_pton(AF_INET, ip, &sa.in.sin_addr) == 1);
	sa.in.sin_port = htons(9);
	return sa;
}

static sockaddr_t dest6(const char *ip, uint32_t scope) {
	sockaddr_t sa;

	memset(&sa, 0, sizeof sa);
	sa.sa.sa_family = AF_INET6;
	assert(inet_pton(AF_INET6, ip, &sa.in6.sin6_addr) == 1);
	sa.in6.sin6_scope_id = scope;
	sa.in6.sin6_port = htons(9);
	return sa;
}

int main(void) {
	meshlink_handle_t *mesh = meshlink_open_ephemeral("local", "local-network", DEV_CLASS_STATIONARY);
	local_iface_addr_t addrs[4];
	sockaddr_t sa;
	sockaddr_t pub[4];
	uint32_t epoch;
	size_t n;

	assert(mesh);
	meshlink_enable_discovery(mesh, false);

	addrs[0] = v4("10.20.0.1", 20, 2, IFF_UP);
	addrs[1] = v4("192.168.9.1", 26, 3, IFF_UP);
	addrs[2] = v4("172.16.5.1", 24, 4, IFF_UP | IFF_POINTOPOINT);
	addrs[3] = v6("fd00:20::1", 64, 5, 0, IFF_UP);
	assert(local_network_set_snapshot(mesh, addrs, 4));
	epoch = local_network_epoch(mesh);
	assert(epoch);

	sa = dest4("10.20.1.181");
	assert(local_network_on_link(mesh, &sa));
	sa = dest4("10.20.16.1");
	assert(!local_network_on_link(mesh, &sa));
	sa = dest4("192.168.9.62");
	assert(local_network_on_link(mesh, &sa));
	sa = dest4("192.168.9.64");
	assert(!local_network_on_link(mesh, &sa));
	sa = dest4("172.16.5.9");
	assert(local_network_on_link(mesh, &sa));
	sa = dest6("fd00:20::181", 0);
	assert(local_network_on_link(mesh, &sa));
	sa = dest6("fd00:21::1", 0);
	assert(!local_network_on_link(mesh, &sa));

	addrs[3] = v6("fe80::1", 10, 6, 6, IFF_UP);
	assert(local_network_set_snapshot(mesh, addrs, 4));
	assert(local_network_epoch(mesh) != epoch);
	sa = dest6("fe80::abcd", 6);
	assert(local_network_on_link(mesh, &sa));
	sa = dest6("fe80::abcd", 0);
	assert(!local_network_on_link(mesh, &sa));
	sa = dest6("fe80::abcd", 7);
	assert(!local_network_on_link(mesh, &sa));

	addrs[0] = v4("127.0.0.1", 8, 1, IFF_UP | IFF_LOOPBACK);
	assert(local_network_set_snapshot(mesh, addrs, 1));
	sa = dest4("127.0.0.2");
	assert(local_network_on_link(mesh, &sa));
	sa = dest4("10.1.1.1");
	assert(!local_network_on_link(mesh, &sa));

	addrs[0] = v4("10.1.1.1", 24, 8, IFF_UP);
	addrs[1] = v4("10.2.2.2", 24, 9, 0);
	assert(local_network_set_snapshot(mesh, addrs, 2));
	sa = dest4("10.1.1.9");
	assert(local_network_on_link(mesh, &sa));
	assert(local_network_is_own_address(mesh, &sa) == false);
	sa = dest4("10.1.1.1");
	assert(local_network_is_own_address(mesh, &sa));
	sa = dest4("10.2.2.9");
	assert(!local_network_on_link(mesh, &sa));

	addrs[0] = v4("10.9.0.1", 16, 2, IFF_UP);
	assert(local_network_set_snapshot(mesh, addrs, 1));
	n = local_network_private_publishable(mesh, AF_INET, pub, 4);
	assert(n == 1);
	addrs[0].flags = 0;
	assert(local_network_set_snapshot(mesh, addrs, 1));
	assert(local_network_private_publishable(mesh, AF_INET, pub, 4) == 0);

	epoch = local_network_epoch(mesh);
	addrs[0] = v4("10.9.0.1", 24, 2, IFF_UP);
	assert(local_network_set_snapshot(mesh, addrs, 1));
	assert(local_network_epoch(mesh) != epoch);
	sa = dest4("10.9.1.1");
	assert(!local_network_on_link(mesh, &sa));

	local_network_force_stale(mesh);
	sa = dest4("10.9.0.2");
	assert(!local_network_on_link(mesh, &sa));

	/* Failed scans keep the last good snapshot only until it ages out. A
	   failure must not restamp the freshness clock. */
	assert(local_network_set_snapshot(mesh, addrs, 1));
	local_network_test_fail_scans(mesh, true);
	local_network_test_age(mesh, LOCAL_NETWORK_STALE_SEC - 5);
	assert(!local_network_refresh(mesh));
	assert(local_network_on_link(mesh, &sa));
	local_network_test_age(mesh, 10);
	assert(!local_network_refresh(mesh));
	assert(!local_network_on_link(mesh, &sa));
	assert(!local_network_refresh(mesh));
	assert(!local_network_on_link(mesh, &sa));
	local_network_test_fail_scans(mesh, false);

	addrs[0] = v6("fd12:3456::1", 64, 4, 0, IFF_UP | IFF_MULTICAST);
	addrs[1] = v6("fe80::1", 64, 4, 4, IFF_UP | IFF_MULTICAST);
	assert(local_network_set_snapshot(mesh, addrs, 2));
	sa = dest6("fd12:3456::20", 0);
	{
		sockaddr_t out;

		assert(local_network_broadcast_target(mesh, &sa, htons(7000), &out));
		assert(out.in6.sin6_family == AF_INET6);
		assert(out.in6.sin6_addr.s6_addr[0] == 0xff);
		assert(out.in6.sin6_addr.s6_addr[1] == 0x02);
		assert(out.in6.sin6_addr.s6_addr[15] == 0x01);
		assert(out.in6.sin6_scope_id == 4);
	}

	assert(local_network_set_snapshot(mesh, NULL, 0));

#ifdef HAVE_GETIFADDRS
	/* Same ULA plus link-local, but the interface is gone before the index
	   lookup, so both entries are cached with ifindex 0. The prefix is still
	   on-link; the multicast query must not return unscoped ff02::1. */
	{
		struct ifaddrs entries[2];
		struct sockaddr_in6 ula;
		struct sockaddr_in6 link_local;
		struct sockaddr_in6 mask;
		sockaddr_t near;
		sockaddr_t out;
		sockaddr_t poisoned;
		char gone[] = "ml-vanished0";

		assert(if_nametoindex(gone) == 0);
		memset(entries, 0, sizeof entries);
		memset(&ula, 0, sizeof ula);
		memset(&link_local, 0, sizeof link_local);
		memset(&mask, 0, sizeof mask);
		ula.sin6_family = AF_INET6;
		assert(inet_pton(AF_INET6, "fd12:3456::1", &ula.sin6_addr) == 1);
		link_local.sin6_family = AF_INET6;
		assert(inet_pton(AF_INET6, "fe80::1", &link_local.sin6_addr) == 1);
		mask.sin6_family = AF_INET6;
		memset(mask.sin6_addr.s6_addr, 0xff, 8);

		entries[0].ifa_next = &entries[1];
		entries[0].ifa_name = gone;
		entries[0].ifa_flags = IFF_UP | IFF_MULTICAST;
		entries[0].ifa_addr = (struct sockaddr *)&ula;
		entries[0].ifa_netmask = (struct sockaddr *)&mask;
		entries[1].ifa_name = gone;
		entries[1].ifa_flags = IFF_UP | IFF_MULTICAST;
		entries[1].ifa_addr = (struct sockaddr *)&link_local;
		entries[1].ifa_netmask = (struct sockaddr *)&mask;

		assert(!mesh->local_network.override);
		assert(local_network_ingest(mesh, entries));
		assert(mesh->local_network.count == 2);
		assert(mesh->local_network.addrs[0].ifindex == 0);
		assert(mesh->local_network.addrs[1].ifindex == 0);
		near = dest6("fd12:3456::20", 0);
		assert(local_network_on_link(mesh, &near));
		memset(&poisoned, 0xa5, sizeof poisoned);
		out = poisoned;
		assert(!local_network_broadcast_target(mesh, &near, htons(7000), &out));
		assert(!memcmp(&out, &poisoned, sizeof out));
	}
#endif

	/* A prefix of 0 is a missing netmask, not "every address of this family". */
	addrs[0] = v4("10.20.0.1", 0, 2, IFF_UP);
	assert(local_network_set_snapshot(mesh, addrs, 1));
	sa = dest4("10.20.0.2");
	assert(!local_network_on_link(mesh, &sa));
	sa = dest4("192.0.2.1");
	assert(!local_network_on_link(mesh, &sa));
	addrs[0] = v6("fd00:20::1", 0, 5, 0, IFF_UP);
	assert(local_network_set_snapshot(mesh, addrs, 1));
	sa = dest6("fd00:20::2", 0);
	assert(!local_network_on_link(mesh, &sa));

	meshlink_close(mesh);
	return 0;
}
