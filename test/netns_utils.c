#define _GNU_SOURCE 1

#ifndef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "../src/meshlink.h"
#include "netns_utils.h"
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
	static peer_config_t peers[] = {
		{"relay", DEV_CLASS_BACKBONE, NULL, 0, NULL, {0}},
		{"app", DEV_CLASS_PORTABLE, NULL, 0, NULL, {0}},
		{"cam", DEV_CLASS_STATIONARY, NULL, 0, NULL, {0}},
	};
	const char *ipt = (access("/usr/sbin/iptables-legacy", X_OK) == 0) ? "/usr/sbin/iptables-legacy" : "iptables";
	const char *random = symmetric ? " --random" : "";
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
	   Symmetric (--random) must not DNAT: the observed port is not the socket,
	   and direct UDP has to stay down. */
	char dnat[640] = "";

	if(!symmetric) {
		int port1 = meshlink_get_port(peers[1].mesh);
		int port2 = meshlink_get_port(peers[2].mesh);

		assert(port1 > 0 && port2 > 0);
		snprintf(dnat, sizeof dnat,
		         "/bin/ip netns exec %s %s -t nat -A PREROUTING -i eth0 -p udp --dport %d -j DNAT --to-destination 10.1.0.2:%d;"
		         "/bin/ip netns exec %s %s -t nat -A PREROUTING -i eth0 -p udp --dport %d -j DNAT --to-destination 10.2.0.2:%d;",
		         nat_netns_name[0], ipt, port1, port1,
		         nat_netns_name[1], ipt, port2, port2);
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
	                nat_netns_name[0], ipt, random,
	                nat_netns_name[1], ipt, random) > 0);

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

void close_nat_hole_punch(peer_config_t *peers) {
	if(peers) {
		close_peers(peers, 3);
	}

	forget_nat_netns();
}
