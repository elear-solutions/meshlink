#define _GNU_SOURCE 1

#ifndef NDEBUG
#undef NDEBUG
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "../src/meshlink.h"
#include "netns_utils.h"

#include <string.h>
#include "utils.h"

static int ip = 1;

bool netns_available(void) {
	char *add_cmd = NULL;
	char *del_cmd = NULL;
	int rc;

	if(getuid() != 0 || access("/bin/ip", X_OK) != 0) {
		return false;
	}

	/* PID-unique name + delete-first so a leftover or parallel probe cannot false-negative. */
	if(asprintf(&add_cmd, "/bin/ip netns add meshlink-netns-probe-%d >/dev/null 2>&1", getpid()) <= 0
	                || asprintf(&del_cmd, "/bin/ip netns delete meshlink-netns-probe-%d >/dev/null 2>&1", getpid()) <= 0) {
		free(add_cmd);
		free(del_cmd);
		return false;
	}

	(void)system(del_cmd);
	rc = system(add_cmd);
	(void)system(del_cmd);
	free(add_cmd);
	free(del_cmd);
	return rc == 0;
}

/// SKIP (exit 77) when this environment cannot create netns.
static void require_netns(void) {
	if(netns_available()) {
		return;
	}

	if(getuid() != 0) {
		fprintf(stderr, "SKIP: netns tests require root\n");
	} else if(access("/bin/ip", X_OK) != 0) {
		fprintf(stderr, "SKIP: /bin/ip not found (need iproute2)\n");
	} else {
		fprintf(stderr, "SKIP: cannot create netns (need CAP_SYS_ADMIN and shared /run/netns)\n");
	}

	exit(77);
}

/// Create meshlink instances and network namespaces for a list of peers
static void create_peers(peer_config_t *peers, int npeers, const char *prefix) {
	require_netns();

	for(int i = 0; i < npeers; i++) {
		assert(asprintf(&peers[i].netns_name, "%s%d", prefix, i) > 0);
		char *command = NULL;
		assert(asprintf(&command,
		                "/bin/ip netns delete %s 2>/dev/null || true;"
		                "/bin/ip netns add %s;"
		                "/bin/ip netns exec %s ip link set dev lo up;",
		                peers[i].netns_name, peers[i].netns_name, peers[i].netns_name));
		assert(command);
		assert(system(command) == 0);
		free(command);

		char *netns_path = NULL;
		assert(asprintf(&netns_path, "/run/netns/%s", peers[i].netns_name));
		assert(netns_path);
		peers[i].netns = open(netns_path, O_RDONLY);
		assert(peers[i].netns != -1);
		free(netns_path);

		char *conf_path = NULL;
		assert(asprintf(&conf_path, "%s_conf.%d", prefix, i + 1) > 0);
		assert(conf_path);
		assert(meshlink_destroy(conf_path));

		meshlink_open_params_t *params = meshlink_open_params_init(conf_path, peers[i].name, prefix, peers[i].devclass);
		assert(params);
		assert(meshlink_open_params_set_netns(params, peers[i].netns));

		peers[i].mesh = meshlink_open_ex(params);
		assert(peers[i].mesh);
		free(params);
		free(conf_path);

		meshlink_enable_discovery(peers[i].mesh, false);
	}
}

/// Set up a LAN topology where all peers can see each other directly
static void setup_lan_topology(peer_config_t *peers, int npeers) {
	// Set up the LAN bridge
	{
		char *command = NULL;
		assert(asprintf(&command,
		                "/bin/ip netns exec %s /bin/ip link add eth0 type bridge;"
		                "/bin/ip netns exec %s /bin/ip link set eth0 up;",
		                peers[0].netns_name, peers[0].netns_name));
		assert(command);
		assert(system(command) == 0);
	}

	// Add an interface to each peer that is connected to the bridge
	for(int i = 1; i < npeers; i++) {
		char *command = NULL;
		assert(asprintf(&command,
		                "/bin/ip netns exec %s /bin/ip link add eth0 type veth peer eth%d netns %s;"
		                "/bin/ip netns exec %s /bin/ip link set dev eth0 up;"
		                "/bin/ip netns exec %s /bin/ip link set dev eth%d master eth0 up;",
		                peers[i].netns_name, i, peers[0].netns_name,
		                peers[i].netns_name,
		                peers[0].netns_name, i));
		assert(command);
		assert(system(command) == 0);
		free(command);
	}

	// Configure addresses
	for(int i = 0; i < npeers; i++) {
		change_peer_ip(&peers[i]);
	}
}

/// Set up an indirect topology where all peers can only access the relay
static void setup_indirect_topology(peer_config_t *peers, int npeers) {
	// Add an interface to each peer that is connected to the relay
	for(int i = 1; i < npeers; i++) {
		char *command = NULL;
		assert(asprintf(&command,
		                "/bin/ip netns exec %s /bin/ip link add eth0 type veth peer eth%d netns %s;"
		                "/bin/ip netns exec %s ip addr flush dev eth0;"
		                "/bin/ip netns exec %s ip addr add 192.168.%d.2/24 dev eth0;"
		                "/bin/ip netns exec %s /bin/ip link set dev eth0 up;"
		                "/bin/ip netns exec %s ip addr flush dev eth%d;"
		                "/bin/ip netns exec %s ip addr add 192.168.%d.1/24 dev eth%d;"
		                "/bin/ip netns exec %s /bin/ip link set dev eth%d up;",
		                peers[i].netns_name, i, peers[0].netns_name,
		                peers[i].netns_name,
		                peers[i].netns_name, i,
		                peers[i].netns_name,
		                peers[0].netns_name, i,
		                peers[0].netns_name, i, i,
		                peers[0].netns_name, i));
		assert(command);
		assert(system(command) == 0);
		free(command);
	}
}

/// Give a peer a unique IP address
void change_peer_ip(peer_config_t *peer) {
	char *command = NULL;

	snprintf(peer->ip, sizeof peer->ip, "10.0.113.%d", ip);
	ip++;
	assert(asprintf(&command,
	                "/bin/ip netns exec %s ip addr flush dev eth0;"
	                "/bin/ip netns exec %s ip addr add %s/24 dev eth0;",
	                peer->netns_name, peer->netns_name, peer->ip));
	assert(command);
	assert(system(command) == 0);
	free(command);
}

void change_peer_ip_to(peer_config_t *peer, const char *ipv4) {
	char *command = NULL;

	assert(ipv4);
	snprintf(peer->ip, sizeof peer->ip, "%s", ipv4);
	assert(asprintf(&command,
	                "/bin/ip netns exec %s ip addr flush dev eth0;"
	                "/bin/ip netns exec %s ip addr add %s/24 dev eth0;",
	                peer->netns_name, peer->netns_name, peer->ip));
	assert(command);
	assert(system(command) == 0);
	free(command);
}

/// Let the first peer in a list invite all the subsequent peers
static void invite_peers(peer_config_t *peers, int npeers) {
	assert(meshlink_start(peers[0].mesh));

	for(int i = 1; i < npeers; i++) {
		char *invitation = meshlink_invite_ex(peers[0].mesh, NULL, peers[i].name, MESHLINK_INVITE_LOCAL | MESHLINK_INVITE_NUMERIC);
		assert(invitation);
		printf("%s\n", invitation);
		assert(meshlink_join(peers[i].mesh, invitation));
		free(invitation);
	}

	meshlink_stop(peers[0].mesh);
}

/// Close meshlink instances and clean up
static void close_peers(peer_config_t *peers, int npeers) {
	for(int i = 0; i < npeers; i++) {
		meshlink_close(peers[i].mesh);
		close(peers[i].netns);
		free(peers[i].netns_name);
	}
}

/// Set up relay, peer and NUT that are directly connected
peer_config_t *setup_relay_peer_nut(const char *prefix) {
	static peer_config_t peers[] = {
		{"relay", DEV_CLASS_BACKBONE, NULL, 0, NULL},
		{"peer", DEV_CLASS_STATIONARY, NULL, 0, NULL},
		{"nut", DEV_CLASS_STATIONARY, NULL, 0, NULL},
	};

	create_peers(peers, 3, prefix);
	setup_lan_topology(peers, 3);
	invite_peers(peers, 3);

	return peers;
}

/// Same LAN bridge, but 203.0.113/24 so path_address_is_local is false (WAN UDP).
peer_config_t *setup_relay_peer_nut_wan(const char *prefix) {
	static peer_config_t peers[] = {
		{"relay", DEV_CLASS_BACKBONE, NULL, 0, NULL},
		{"peer", DEV_CLASS_STATIONARY, NULL, 0, NULL},
		{"nut", DEV_CLASS_STATIONARY, NULL, 0, NULL},
	};

	create_peers(peers, 3, prefix);
	setup_lan_topology(peers, 3);
	change_peer_ip_to(&peers[0], "203.0.113.1");
	change_peer_ip_to(&peers[1], "203.0.113.2");
	change_peer_ip_to(&peers[2], "203.0.113.3");
	invite_peers(peers, 3);

	return peers;
}

/// Set up relay, peer and NUT that are directly connected
peer_config_t *setup_relay_peer_nut_indirect(const char *prefix) {
	static peer_config_t peers[] = {
		{"relay", DEV_CLASS_BACKBONE, NULL, 0, NULL},
		{"peer", DEV_CLASS_STATIONARY, NULL, 0, NULL},
		{"nut", DEV_CLASS_STATIONARY, NULL, 0, NULL},
	};

	create_peers(peers, 3, prefix);
	setup_indirect_topology(peers, 3);
	assert(meshlink_add_invitation_address(peers[0].mesh, "192.168.1.1", NULL));
	assert(meshlink_add_invitation_address(peers[0].mesh, "192.168.2.1", NULL));
	invite_peers(peers, 3);

	return peers;
}

/// Make all nodes only be able to communicate via TCP. False leaves the caller
/// to skip only the case that needed the drop.
bool set_peers_tcponly(peer_config_t *peers, int npeers) {
	const char *ipt = (access("/usr/sbin/iptables-legacy", X_OK) == 0) ? "/usr/sbin/iptables-legacy" : "iptables";

	for(int i = 0; i < npeers; i++) {
		char *command = NULL;
		int rc;

		assert(asprintf(&command,
		                "/bin/ip netns exec %s %s -A INPUT -p udp -j DROP;"
		                "/bin/ip netns exec %s %s -A OUTPUT -p udp -j DROP;",
		                peers[i].netns_name, ipt,
		                peers[i].netns_name, ipt));
		assert(command);
		rc = system(command);
		free(command);

		if(rc != 0) {
			fprintf(stderr, "SKIP: iptables UDP drop not supported in this environment\n");
			return false;
		}
	}

	return true;
}

void close_relay_peer_nut(peer_config_t *peers) {
	close_peers(peers, 3);
}

static char *nat_netns_name[2];

static void forget_nat_netns(void) {
	for(int i = 0; i < 2; i++) {
		char *command = NULL;

		if(!nat_netns_name[i]) {
			continue;
		}

		assert(asprintf(&command, "/bin/ip netns delete %s >/dev/null 2>&1", nat_netns_name[i]) > 0);
		(void)system(command);
		free(command);
		free(nat_netns_name[i]);
		nat_netns_name[i] = NULL;
	}
}

static int nat_run(const char *command) {
	int rc = system(command);

	if(rc != 0) {
		fprintf(stderr, "nat setup failed (%d): %s\n", rc, command);
	}

	return rc;
}

peer_config_t *setup_nat_hole_punch(const char *prefix, bool symmetric) {
	return setup_nat_hole_punch_asymm(prefix, symmetric, symmetric);
}

peer_config_t *setup_nat_hole_punch_asymm(const char *prefix, bool app_symmetric, bool cam_symmetric) {
	static peer_config_t peers[] = {
		{"relay", DEV_CLASS_BACKBONE, NULL, 0, NULL, {0}},
		{"app", DEV_CLASS_PORTABLE, NULL, 0, NULL, {0}},
		{"cam", DEV_CLASS_STATIONARY, NULL, 0, NULL, {0}},
	};
	const char *ipt = (access("/usr/sbin/iptables-legacy", X_OK) == 0) ? "/usr/sbin/iptables-legacy" : "iptables";
	const char *random_app = app_symmetric ? " --random" : "";
	const char *random_cam = cam_symmetric ? " --random" : "";
	char *command = NULL;

	forget_nat_netns();
	create_peers(peers, 3, prefix);

	assert(asprintf(&nat_netns_name[0], "%sna", prefix) > 0);
	assert(asprintf(&nat_netns_name[1], "%snb", prefix) > 0);

	assert(asprintf(&command,
	                "/bin/ip netns delete %s >/dev/null 2>&1 || true;"
	                "/bin/ip netns delete %s >/dev/null 2>&1 || true;"
	                "/bin/ip netns add %s;"
	                "/bin/ip netns add %s;"
	                "/bin/ip netns exec %s ip link set dev lo up;"
	                "/bin/ip netns exec %s ip link set dev lo up;"
	                "/bin/ip netns exec %s ip link add br0 type bridge;"
	                "/bin/ip netns exec %s ip addr add 203.0.113.1/24 dev br0;"
	                "/bin/ip netns exec %s ip link set br0 up;"
	                "/bin/ip netns exec %s ip link add eth0 type veth peer name nata netns %s;"
	                "/bin/ip netns exec %s ip link set nata master br0 up;"
	                "/bin/ip netns exec %s ip addr add 203.0.113.2/24 dev eth0;"
	                "/bin/ip netns exec %s ip link set eth0 up;"
	                "/bin/ip netns exec %s ip link add eth0 type veth peer name natb netns %s;"
	                "/bin/ip netns exec %s ip link set natb master br0 up;"
	                "/bin/ip netns exec %s ip addr add 203.0.113.3/24 dev eth0;"
	                "/bin/ip netns exec %s ip link set eth0 up;"
	                "/bin/ip netns exec %s ip link add eth0 type veth peer name lan netns %s;"
	                "/bin/ip netns exec %s ip addr add 10.1.0.1/24 dev lan;"
	                "/bin/ip netns exec %s ip link set lan up;"
	                "/bin/ip netns exec %s ip addr add 10.1.0.2/24 dev eth0;"
	                "/bin/ip netns exec %s ip link set eth0 up;"
	                "/bin/ip netns exec %s ip route add default via 10.1.0.1;"
	                "/bin/ip netns exec %s ip link add eth0 type veth peer name lan netns %s;"
	                "/bin/ip netns exec %s ip addr add 10.2.0.1/24 dev lan;"
	                "/bin/ip netns exec %s ip link set lan up;"
	                "/bin/ip netns exec %s ip addr add 10.2.0.2/24 dev eth0;"
	                "/bin/ip netns exec %s ip link set eth0 up;"
	                "/bin/ip netns exec %s ip route add default via 10.2.0.1;",
	                nat_netns_name[0], nat_netns_name[1],
	                nat_netns_name[0], nat_netns_name[1],
	                nat_netns_name[0], nat_netns_name[1],
	                peers[0].netns_name,
	                peers[0].netns_name,
	                peers[0].netns_name,
	                nat_netns_name[0], peers[0].netns_name,
	                peers[0].netns_name,
	                nat_netns_name[0],
	                nat_netns_name[0],
	                nat_netns_name[1], peers[0].netns_name,
	                peers[0].netns_name,
	                nat_netns_name[1],
	                nat_netns_name[1],
	                peers[1].netns_name, nat_netns_name[0],
	                nat_netns_name[0],
	                nat_netns_name[0],
	                peers[1].netns_name,
	                peers[1].netns_name,
	                peers[1].netns_name,
	                peers[2].netns_name, nat_netns_name[1],
	                nat_netns_name[1],
	                nat_netns_name[1],
	                peers[2].netns_name,
	                peers[2].netns_name,
	                peers[2].netns_name) > 0);

	if(nat_run(command) != 0) {
		free(command);
		close_peers(peers, 3);
		forget_nat_netns();
		return NULL;
	}

	free(command);
	command = NULL;

	/* Cone: DNAT only the preserved mapped port (the listen port MASQUERADE
	   keeps) back to that socket. A probe to any other port, including a
	   planted :9, must not reach the host. Plain MASQUERADE otherwise files
	   that packet as a new flow and moves the outbound source port.
	   Endpoint-dependent (--random) must not DNAT: the observed port is not
	   the socket. Each side is independent, so a cone can face an
	   endpoint-dependent peer. */
	char dnat[1280] = "";
	size_t dnat_used = 0;

	if(!app_symmetric) {
		int port1 = meshlink_get_port(peers[1].mesh);
		int wrote;

		assert(port1 > 0);
		wrote = snprintf(dnat + dnat_used, sizeof dnat - dnat_used,
		                 "/bin/ip netns exec %s %s -t nat -A PREROUTING -i eth0 -p udp --dport %d -j DNAT --to-destination 10.1.0.2:%d;",
		                 nat_netns_name[0], ipt, port1, port1);
		assert(wrote > 0 && (size_t)wrote < sizeof dnat - dnat_used);
		dnat_used += (size_t)wrote;
	}

	if(!cam_symmetric) {
		int port2 = meshlink_get_port(peers[2].mesh);
		int wrote;

		assert(port2 > 0);
		wrote = snprintf(dnat + dnat_used, sizeof dnat - dnat_used,
		                 "/bin/ip netns exec %s %s -t nat -A PREROUTING -i eth0 -p udp --dport %d -j DNAT --to-destination 10.2.0.2:%d;",
		                 nat_netns_name[1], ipt, port2, port2);
		assert(wrote > 0 && (size_t)wrote < sizeof dnat - dnat_used);
		dnat_used += (size_t)wrote;
	}

	assert(asprintf(&command,
	                "/bin/ip netns exec %s sysctl -w net.ipv4.ip_forward=1 >/dev/null;"
	                "/bin/ip netns exec %s sysctl -w net.ipv4.ip_forward=1 >/dev/null;"
	                "/bin/ip netns exec %s %s -P FORWARD ACCEPT;"
	                "/bin/ip netns exec %s %s -P FORWARD ACCEPT;"
	                "%s"
	                "/bin/ip netns exec %s %s -t nat -A POSTROUTING -s 10.1.0.0/24 -o eth0 -j MASQUERADE%s;"
	                "/bin/ip netns exec %s %s -t nat -A POSTROUTING -s 10.2.0.0/24 -o eth0 -j MASQUERADE%s;",
	                nat_netns_name[0], nat_netns_name[1],
	                nat_netns_name[0], ipt,
	                nat_netns_name[1], ipt,
	                dnat,
	                nat_netns_name[0], ipt, random_app,
	                nat_netns_name[1], ipt, random_cam) > 0);

	if(nat_run(command) != 0) {
		free(command);
		close_peers(peers, 3);
		forget_nat_netns();
		return NULL;
	}

	free(command);
	snprintf(peers[0].ip, sizeof peers[0].ip, "203.0.113.1");
	snprintf(peers[1].ip, sizeof peers[1].ip, "10.1.0.2");
	snprintf(peers[2].ip, sizeof peers[2].ip, "10.2.0.2");
	assert(meshlink_add_invitation_address(peers[0].mesh, "203.0.113.1", NULL));
	invite_peers(peers, 3);
	return peers;
}

bool nat_force_rebind(void) {
	static const char *bins[] = {"/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack", NULL};
	const char *bin = NULL;
	char *command = NULL;
	int rc;
	int i;

	if(!nat_netns_name[1]) {
		return false;
	}

	for(i = 0; bins[i]; i++) {
		if(access(bins[i], X_OK) == 0) {
			bin = bins[i];
			break;
		}
	}

	if(!bin) {
		fprintf(stderr, "nat_force_rebind: conntrack is not installed\n");
		return false;
	}

	assert(asprintf(&command, "/bin/ip netns exec %s %s -D -p udp >/dev/null 2>&1", nat_netns_name[1], bin) > 0);
	rc = system(command);
	free(command);

	if(rc == -1 || !WIFEXITED(rc)) {
		return false;
	}

	/* 0: entries deleted. 1: table already empty. Anything else is a real failure. */
	return WEXITSTATUS(rc) == 0 || WEXITSTATUS(rc) == 1;
}

static const char *ipt_bin(void) {
	return access("/usr/sbin/iptables-legacy", X_OK) == 0 ? "/usr/sbin/iptables-legacy" : "iptables";
}

bool netns_set_dev_mtu(const char *ns, const char *dev, int mtu) {
	char *command = NULL;
	int rc;

	if(!ns || !dev || mtu < 68) {
		return false;
	}

	assert(asprintf(&command, "/bin/ip netns exec %s ip link set dev %s mtu %d", ns, dev, mtu) > 0);
	rc = system(command);
	free(command);
	return rc == 0;
}

bool netns_drop_udp_over(const char *ns, const char *chain, int ip_len) {
	char *command = NULL;
	int rc;

	if(!ns || !chain || ip_len < 1) {
		return false;
	}

	assert(asprintf(&command,
	                "/bin/ip netns exec %s %s -A %s -p udp -m length --length %d:65535 -j DROP",
	                ns, ipt_bin(), chain, ip_len) > 0);
	rc = system(command);
	free(command);
	return rc == 0;
}

bool nat_set_link_mtu(int side, int mtu) {
	if(side < 0 || side > 1 || !nat_netns_name[side]) {
		return false;
	}

	return netns_set_dev_mtu(nat_netns_name[side], "eth0", mtu);
}

bool nat_drop_udp_over(int side, int ip_len) {
	if(side < 0 || side > 1 || !nat_netns_name[side]) {
		return false;
	}

	return netns_drop_udp_over(nat_netns_name[side], "FORWARD", ip_len);
}

static bool nat_udp_egress(int side, int ip_len, bool remove, const char *dest) {
	char *command = NULL;
	int rc;

	if(side < 0 || side > 1 || !nat_netns_name[side] || ip_len < 1) {
		return false;
	}

	if(dest) {
		assert(asprintf(&command,
		                "/bin/ip netns exec %s %s -%s FORWARD -i lan -o eth0 -d %s -p udp -m length --length %d:65535 -j DROP",
		                nat_netns_name[side], ipt_bin(), remove ? "D" : "A", dest, ip_len) > 0);
	} else {
		assert(asprintf(&command,
		                "/bin/ip netns exec %s %s -%s FORWARD -i lan -o eth0 -p udp -m length --length %d:65535 -j DROP",
		                nat_netns_name[side], ipt_bin(), remove ? "D" : "A", ip_len) > 0);
	}

	rc = system(command);
	free(command);
	return rc == 0;
}

bool nat_drop_udp_egress(int side, int ip_len) {
	return nat_udp_egress(side, ip_len, false, NULL);
}

bool nat_undrop_udp_egress(int side, int ip_len) {
	return nat_udp_egress(side, ip_len, true, NULL);
}

bool nat_undrop_udp_over(int side, int ip_len) {
	char *command = NULL;
	int rc;

	if(side < 0 || side > 1 || !nat_netns_name[side] || ip_len < 1) {
		return false;
	}

	assert(asprintf(&command,
	                "/bin/ip netns exec %s %s -D FORWARD -p udp -m length --length %d:65535 -j DROP",
	                nat_netns_name[side], ipt_bin(), ip_len) > 0);
	rc = system(command);
	free(command);
	return rc == 0;
}

bool nat_set_conntrack_udp_timeout(int side, int sec) {
	char *command = NULL;
	FILE *fp;
	char line[64];
	int got = -1;
	const char *ns;

	if(side < 0 || side > 1 || !nat_netns_name[side] || sec < 1) {
		return false;
	}

	ns = nat_netns_name[side];
	assert(asprintf(&command,
	                "/bin/ip netns exec %s sysctl -w net.netfilter.nf_conntrack_udp_timeout=%d >/dev/null && "
	                "/bin/ip netns exec %s sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=%d >/dev/null && "
	                "/bin/ip netns exec %s sysctl -n net.netfilter.nf_conntrack_udp_timeout",
	                ns, sec, ns, sec, ns) > 0);
	fp = popen(command, "r");
	free(command);

	if(!fp) {
		return false;
	}

	if(fgets(line, sizeof line, fp)) {
		got = atoi(line);
	}

	pclose(fp);
	return got == sec;
}

static pthread_t nat_punisher_thread;
static volatile int nat_punisher_stop;
static int nat_punisher_side;
static unsigned long nat_punisher_last;
/* The other peer's WAN address. Side 1 is the cam NAT, so its app flow is to .2. */
static const char *nat_punish_dest(int side) {
	return side == 1 ? "203.0.113.2" : "203.0.113.3";
}

static bool nat_force_rebind_dst(int side, const char *dst) {
	static const char *bins[] = {"/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack", NULL};
	const char *bin = NULL;
	char *command = NULL;
	int rc;
	int i;

	if(!nat_netns_name[side] || !dst) {
		return false;
	}

	for(i = 0; bins[i]; i++) {
		if(access(bins[i], X_OK) == 0) {
			bin = bins[i];
			break;
		}
	}

	if(!bin) {
		return false;
	}

	assert(asprintf(&command, "/bin/ip netns exec %s %s -D -p udp -d %s >/dev/null 2>&1", nat_netns_name[side], bin, dst) > 0);
	rc = system(command);
	free(command);
	return rc != -1 && WIFEXITED(rc);
}

static unsigned long nat_forward_packets(int side) {
	char *command = NULL;
	FILE *fp;
	char line[512];
	unsigned long pkts = 0;

	assert(asprintf(&command, "/bin/ip netns exec %s %s -L FORWARD -v -x -n", nat_netns_name[side], ipt_bin()) > 0);
	fp = popen(command, "r");
	free(command);

	if(!fp) {
		return 0;
	}

	while(fgets(line, sizeof line, fp)) {
		unsigned long n = 0;

		/* The policy line also has a packet count. Only the DROP rule is a punish. */
		if(!strstr(line, "DROP")) {
			continue;
		}

		if(sscanf(line, "%lu", &n) == 1 && n > pkts) {
			pkts = n;
		}
	}

	pclose(fp);
	return pkts;
}

static void *nat_punisher_main(void *arg) {
	(void)arg;

	while(!nat_punisher_stop) {
		unsigned long pkts = nat_forward_packets(nat_punisher_side);

		if(pkts > nat_punisher_last) {
			nat_punisher_last = pkts;
			/* Only the flow toward the other peer. A full UDP flush also
			   rebinds the relay path and marks PLPMTU hostile at the base. */
			nat_force_rebind_dst(nat_punisher_side, nat_punish_dest(nat_punisher_side));
		}

		usleep(200000);
	}

	return NULL;
}

bool nat_oversize_punisher_start(int side, int ip_len) {
	if(!nat_udp_egress(side, ip_len, false, nat_punish_dest(side))) {
		return false;
	}

	nat_punisher_side = side;
	nat_punisher_stop = 0;
	nat_punisher_last = nat_forward_packets(side);
	return pthread_create(&nat_punisher_thread, NULL, nat_punisher_main, NULL) == 0;
}

void nat_oversize_punisher_stop(void) {
	if(!nat_punisher_thread) {
		return;
	}

	nat_punisher_stop = 1;
	pthread_join(nat_punisher_thread, NULL);
	nat_punisher_thread = 0;
}

void close_nat_hole_punch(peer_config_t *peers) {
	if(peers) {
		close_peers(peers, 3);
	}

	forget_nat_netns();
}
