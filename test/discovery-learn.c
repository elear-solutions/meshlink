#ifdef NDEBUG
#undef NDEBUG
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "meshlink.h"
#include "devtools.h"

static meshlink_handle_t *open_mesh(const char *dir, const char *name, int devclass) {
	assert(meshlink_destroy(dir));

	meshlink_handle_t *mesh = meshlink_open(dir, name, "discovery-learn", devclass);

	assert(mesh);
	return mesh;
}

static void close_mesh(meshlink_handle_t *mesh) {
	meshlink_close(mesh);
}

static bool inject_peer(meshlink_handle_t *mesh, const char *self_name, int self_class, const char *peer, int peer_class) {
	return devtool_inject_add_edge(mesh, peer, peer_class, self_name, self_class);
}

static void assert_armed(meshlink_handle_t *mesh, unsigned fires) {
	int delay = devtool_lan_discovery_query_delay_ms(mesh);

	assert(devtool_lan_discovery_query_pending(mesh));
	assert(delay >= 150 && delay <= 250);
	assert(devtool_lan_discovery_query_fires(mesh) == fires);
}

static void assert_idle(meshlink_handle_t *mesh, unsigned fires) {
	assert(!devtool_lan_discovery_query_pending(mesh));
	assert(devtool_lan_discovery_query_delay_ms(mesh) == -1);
	assert(devtool_lan_discovery_query_fires(mesh) == fires);
}

static struct sockaddr_in lan_addr(void) {
	struct sockaddr_in in;

	memset(&in, 0, sizeof in);
	in.sin_family = AF_INET;
	in.sin_port = htons(655);
	assert(inet_pton(AF_INET, "192.168.1.50", &in.sin_addr) == 1);
	return in;
}

static void stamp_presence(meshlink_handle_t *mesh, const char *name) {
	struct sockaddr_in in = lan_addr();
	meshlink_node_t *node = meshlink_get_node(mesh, name);

	assert(node);
	assert(devtool_learn_discovery_address(mesh, node, (struct sockaddr *)&in));
}

static void assert_stale_recent(meshlink_handle_t *mesh, const char *name) {
	devtool_node_status_t status;
	meshlink_node_t *node = meshlink_get_node(mesh, name);

	assert(node);
	memset(&status, 0, sizeof status);
	devtool_get_node_status(mesh, node, &status);
	assert(status.recent_count > 0);
	devtool_free_node_status(&status);
}

static void test_higher_name_arms_and_coalesces(void) {
	meshlink_handle_t *mesh = open_mesh("discovery_learn_conf.higher", "a", DEV_CLASS_STATIONARY);

	assert(inject_peer(mesh, "a", DEV_CLASS_STATIONARY, "m", DEV_CLASS_STATIONARY));
	assert_armed(mesh, 0);

	assert(inject_peer(mesh, "a", DEV_CLASS_STATIONARY, "n", DEV_CLASS_STATIONARY));
	assert_armed(mesh, 0);

	devtool_note_inbound_mdns_query(mesh);
	assert_armed(mesh, 0);

	assert(devtool_fire_lan_discovery_query(mesh));
	assert_idle(mesh, 1);

	assert(inject_peer(mesh, "a", DEV_CLASS_STATIONARY, "m", DEV_CLASS_STATIONARY));
	assert_idle(mesh, 1);

	stamp_presence(mesh, "m");
	stamp_presence(mesh, "n");
	devtool_note_inbound_mdns_query(mesh);
	assert(!devtool_fire_lan_discovery_query(mesh));
	assert_idle(mesh, 1);

	close_mesh(mesh);
}

static void test_does_not_arm(void) {
	meshlink_handle_t *backbone_peer = open_mesh("discovery_learn_conf.backbone", "a", DEV_CLASS_STATIONARY);
	meshlink_handle_t *lower = open_mesh("discovery_learn_conf.lower", "m", DEV_CLASS_STATIONARY);
	meshlink_handle_t *nmn = open_mesh("discovery_learn_conf.nmn", "a", DEV_CLASS_BACKBONE);
	meshlink_handle_t *present = open_mesh("discovery_learn_conf.present", "a", DEV_CLASS_STATIONARY);

	assert(inject_peer(backbone_peer, "a", DEV_CLASS_STATIONARY, "z", DEV_CLASS_BACKBONE));
	assert_idle(backbone_peer, 0);

	assert(inject_peer(lower, "m", DEV_CLASS_STATIONARY, "a", DEV_CLASS_STATIONARY));
	assert_idle(lower, 0);

	assert(inject_peer(nmn, "a", DEV_CLASS_BACKBONE, "m", DEV_CLASS_STATIONARY));
	assert_idle(nmn, 0);

	assert(inject_peer(present, "a", DEV_CLASS_STATIONARY, "m", DEV_CLASS_STATIONARY));
	assert_armed(present, 0);
	stamp_presence(present, "m");
	assert(devtool_fire_lan_discovery_query(present));
	assert_idle(present, 0);
	devtool_note_inbound_mdns_query(present);
	assert_idle(present, 0);

	close_mesh(backbone_peer);
	close_mesh(lower);
	close_mesh(nmn);
	close_mesh(present);
}

static void test_stale_dhcp_address_still_arms(void) {
	meshlink_handle_t *mesh = open_mesh("discovery_learn_conf.dhcp", "a", DEV_CLASS_STATIONARY);
	meshlink_node_t *peer;

	assert(inject_peer(mesh, "a", DEV_CLASS_STATIONARY, "m", DEV_CLASS_STATIONARY));
	assert_armed(mesh, 0);
	stamp_presence(mesh, "m");
	assert_stale_recent(mesh, "m");

	assert(devtool_fire_lan_discovery_query(mesh));
	assert_idle(mesh, 0);

	peer = meshlink_get_node(mesh, "m");
	assert(peer);
	devtool_clear_lan_discovery_presence(mesh, peer);
	assert_stale_recent(mesh, "m");

	devtool_note_inbound_mdns_query(mesh);
	assert_armed(mesh, 0);
	assert(devtool_fire_lan_discovery_query(mesh));
	assert_idle(mesh, 1);

	stamp_presence(mesh, "m");
	devtool_note_inbound_mdns_query(mesh);
	assert(!devtool_fire_lan_discovery_query(mesh));
	assert_idle(mesh, 1);

	close_mesh(mesh);
}

static void test_late_query_and_stop(void) {
	meshlink_handle_t *mesh = open_mesh("discovery_learn_conf.late", "a", DEV_CLASS_PORTABLE);

	assert(inject_peer(mesh, "a", DEV_CLASS_PORTABLE, "m", DEV_CLASS_STATIONARY));
	assert_armed(mesh, 0);
	assert(devtool_fire_lan_discovery_query(mesh));
	assert_idle(mesh, 1);

	devtool_note_inbound_mdns_query(mesh);
	assert_armed(mesh, 1);
	devtool_note_inbound_mdns_query(mesh);
	assert(inject_peer(mesh, "a", DEV_CLASS_PORTABLE, "n", DEV_CLASS_PORTABLE));
	assert_armed(mesh, 1);

	assert(devtool_fire_lan_discovery_query(mesh));
	assert_idle(mesh, 2);

	devtool_note_inbound_mdns_query(mesh);
	assert_armed(mesh, 2);
	devtool_discovery_stop(mesh);
	assert_idle(mesh, 2);

	close_mesh(mesh);
}

int main(void) {
	test_higher_name_arms_and_coalesces();
	test_does_not_arm();
	test_stale_dhcp_address_still_arms();
	test_late_query_and_stop();
	return 0;
}
