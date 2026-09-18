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

/// SKIP (exit 77) when this environment cannot create netns.
static void require_netns(void) {
	if(getuid() != 0) {
		fprintf(stderr, "SKIP: netns tests require root\n");
		exit(77);
	}

	if(access("/bin/ip", X_OK) != 0) {
		fprintf(stderr, "SKIP: /bin/ip not found (need iproute2)\n");
		exit(77);
	}

	/* PID-unique name + delete-first so a leftover or parallel probe cannot false-SKIP. */
	char *add_cmd = NULL;
	char *del_cmd = NULL;
	assert(asprintf(&add_cmd, "/bin/ip netns add meshlink-netns-probe-%d >/dev/null 2>&1", getpid()) > 0);
	assert(asprintf(&del_cmd, "/bin/ip netns delete meshlink-netns-probe-%d >/dev/null 2>&1", getpid()) > 0);
	(void)system(del_cmd);

	if(system(add_cmd) != 0) {
		free(add_cmd);
		free(del_cmd);
		fprintf(stderr, "SKIP: cannot create netns (need CAP_SYS_ADMIN and shared /run/netns)\n");
		exit(77);
	}

	(void)system(del_cmd);
	free(add_cmd);
	free(del_cmd);
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

/// Make all nodes only be able to communicate via TCP
void set_peers_tcponly(peer_config_t *peers, int npeers) {
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
			exit(77);
		}
	}
}

void close_relay_peer_nut(peer_config_t *peers) {
	close_peers(peers, 3);
}
