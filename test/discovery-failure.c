/* Exercise discovery's real fallback paths with test-only syscall wrapping. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include "meshlink_internal.h"
#include "discovery.h"
#include <assert.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/netlink.h>

int __real_bind(int fd, const struct sockaddr *addr, socklen_t len);
int __real_setsockopt(int fd, int level, int option, const void *value, socklen_t len);
int __real_getifaddrs(struct ifaddrs **addresses);
void __real_freeifaddrs(struct ifaddrs *addresses);
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len);
int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t len);
int __wrap_getifaddrs(struct ifaddrs **addresses);
void __wrap_freeifaddrs(struct ifaddrs *addresses);

static bool inject_failures;
static int failed_netlink_fd;
static unsigned netlink_failures;
static unsigned address_scans;
static unsigned ipv4_errors;
static unsigned ipv6_errors;
static struct ifaddrs interfaces[2];
static struct sockaddr_in ipv4;
static struct sockaddr_in6 ipv6;
static char interface_name[] = "lo";
static char interface_context[80];

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
	if(inject_failures && addr->sa_family == AF_NETLINK) {
		failed_netlink_fd = fd;
		netlink_failures++;
		errno = EACCES;
		return -1;
	}

	return __real_bind(fd, addr, len);
}

int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t len) {
	if(inject_failures && ((level == IPPROTO_IP && option == IP_MULTICAST_IF)
	                      || (level == IPPROTO_IPV6 && option == IPV6_MULTICAST_IF))) {
		errno = ENODEV;
		return -1;
	}

	return __real_setsockopt(fd, level, option, value, len);
}

int __wrap_getifaddrs(struct ifaddrs **addresses) {
	if(!inject_failures) {
		return __real_getifaddrs(addresses);
	}

	address_scans++;
	*addresses = interfaces;
	return 0;
}

void __wrap_freeifaddrs(struct ifaddrs *addresses) {
	if(addresses != interfaces) {
		__real_freeifaddrs(addresses);
	}
}

static void discovery_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	(void)level;

	if(strstr(text, "Could not set outgoing multicast interface")) {
		assert(strstr(text, interface_context));
		assert(strstr(text, strerror(ENODEV)));
		if(strstr(text, "IPv4")) {
			ipv4_errors++;
		} else {
			assert(strstr(text, "IPv6"));
			ipv6_errors++;
		}
	}
}

static unsigned open_descriptors(void) {
	DIR *dir = opendir("/proc/self/fd");
	assert(dir);
	unsigned count = 0;
	struct dirent *entry;

	while((entry = readdir(dir))) {
		if(entry->d_name[0] != '.') {
			count++;
		}
	}

	closedir(dir);
	return count;
}

static void verify_unicast_udp(void) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd >= 0);
	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	assert(bind(fd, (struct sockaddr *)&addr, sizeof addr) == 0);
	socklen_t len = sizeof addr;
	assert(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
	struct timeval wait = {.tv_sec = 1};
	assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait) == 0);
	assert(sendto(fd, "hello", 5, 0, (struct sockaddr *)&addr, sizeof addr) == 5);
	char buf[5];
	assert(recv(fd, buf, sizeof buf, 0) == 5);
	assert(!memcmp(buf, "hello", 5));
	close(fd);
}

int main(void) {
	meshlink_handle_t *mesh = meshlink_open_ephemeral("discovery-peer", "discovery-failure", DEV_CLASS_STATIONARY);
	assert(mesh);
	meshlink_set_log_cb(mesh, MESHLINK_DEBUG, discovery_log);

	unsigned index = if_nametoindex(interface_name);
	assert(index);
	snprintf(interface_context, sizeof interface_context, "interface index %u", index);
	ipv4.sin_family = AF_INET;
	ipv4.sin_addr.s_addr = htonl(0xc000020a); /* 192.0.2.10 */
	ipv6.sin6_family = AF_INET6;
	assert(inet_pton(AF_INET6, "2001:db8::10", &ipv6.sin6_addr) == 1);
	interfaces[0].ifa_next = &interfaces[1];
	interfaces[0].ifa_name = interfaces[1].ifa_name = interface_name;
	interfaces[0].ifa_flags = interfaces[1].ifa_flags = IFF_UP | IFF_MULTICAST;
	interfaces[0].ifa_addr = (struct sockaddr *)&ipv4;
	interfaces[1].ifa_addr = (struct sockaddr *)&ipv6;
	inject_failures = true;
	unsigned baseline = open_descriptors();

	for(unsigned cycle = 0; cycle < 16; cycle++) {
		unsigned scans = address_scans;
		assert(discovery_start(mesh));
		assert(address_scans == scans + 1);
		assert(!mesh->discovery.pfroute_io.cb);
		errno = 0;
		assert(fcntl(failed_netlink_fd, F_GETFD) == -1 && errno == EBADF);
		assert(mesh->discovery.sockets[0].cb && mesh->discovery.sockets[1].cb);
		assert(mesh->discovery.address_count == 2);

		/* Without netlink notifications, an application hint must rescan
		   changed addresses and advance the network epoch. */
		uint64_t fingerprint = mesh->discovery.addr_set_fingerprint;
		uint64_t epoch = mesh->lan_network_epoch;
		ipv4.sin_addr.s_addr = htonl(0xc000020b + cycle);
		scans = address_scans;
		meshlink_hint_network_change(mesh);
		assert(address_scans == scans + 1);
		assert(mesh->discovery.addr_set_fingerprint != fingerprint);
		assert(mesh->lan_network_epoch > epoch);
		assert(mesh->discovery.address_count == 2);
		assert(ipv4_errors && ipv6_errors);
		verify_unicast_udp();

		discovery_stop(mesh);
		assert(open_descriptors() == baseline);
	}

	assert(netlink_failures == 16);
	inject_failures = false;
	meshlink_close(mesh);
	return 0;
}
