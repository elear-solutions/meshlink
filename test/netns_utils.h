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

/// Backbone on 203.0.113.1, app and camera behind separate NATs.
/// A symmetric side uses MASQUERADE --random and no DNAT, so the backbone-observed port is not punchable.
/// NULL means the topology could not be built; nothing is left allocated.
extern peer_config_t *setup_nat_hole_punch(const char *prefix, bool symmetric);
extern peer_config_t *setup_nat_hole_punch_asymm(const char *prefix, bool app_symmetric, bool cam_symmetric);
extern void close_nat_hole_punch(peer_config_t *peers);
/// Delete UDP conntrack in the camera NAT namespace so the next send reallocates a port.
/// False when conntrack is missing or the namespace is gone. Callers must assert, not skip.
extern bool nat_force_rebind(void);

/// Link MTU of one device inside a netns. False if ip link fails.
extern bool netns_set_dev_mtu(const char *ns, const char *dev, int mtu);
/// DROP UDP whose IP length is at least ip_len. chain is OUTPUT or FORWARD.
extern bool netns_drop_udp_over(const char *ns, const char *chain, int ip_len);
/// side 0 is the app NAT, side 1 is the camera NAT. False if that NAT is not up.
extern bool nat_set_link_mtu(int side, int mtu);
extern bool nat_drop_udp_over(int side, int ip_len);
extern bool nat_undrop_udp_over(int side, int ip_len);
/// Cam-to-WAN only. Inbound forwards are left alone so the other direction can settle higher.
extern bool nat_drop_udp_egress(int side, int ip_len);
extern bool nat_undrop_udp_egress(int side, int ip_len);
extern bool nat_set_conntrack_udp_timeout(int side, int sec);
extern bool nat_oversize_punisher_start(int side, int ip_len);
extern void nat_oversize_punisher_stop(void);

#endif
