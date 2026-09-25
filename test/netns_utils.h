#ifndef MESHLINK_TEST_NETNS_UTILS_H
#define MESHLINK_TEST_NETNS_UTILS_H

typedef struct peer_config {
	const char *name;
	const dev_class_t devclass;

	char *netns_name;
	int netns;
	meshlink_handle_t *mesh;
	char ip[32];
} peer_config_t;

/// True when this process can create a netns. Does not exit.
extern bool netns_available(void);
extern void change_peer_ip(peer_config_t *peer);
extern void change_peer_ip_to(peer_config_t *peer, const char *ipv4);
extern peer_config_t *setup_relay_peer_nut(const char *prefix);
extern peer_config_t *setup_relay_peer_nut_wan(const char *prefix);
extern peer_config_t *setup_relay_peer_nut_indirect(const char *prefix);
/// Drop UDP in each peer netns. False when iptables cannot install the rule.
extern bool set_peers_tcponly(peer_config_t *peers, int npeers);
extern void close_relay_peer_nut(peer_config_t *peers);

#endif
