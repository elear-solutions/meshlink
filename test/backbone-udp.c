#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

static struct sync_flag peer_up;

static void reachable_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	if(reachable && meshlink_get_self(mesh) != node) {
		set_sync_flag(&peer_up, true);
	}
}

static void destroy_conf(const char *path) {
	assert(meshlink_destroy(path));
}

static bool node_meta_connected(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *node = meshlink_get_node(mesh, name);
	devtool_node_status_t st;
	bool connected;

	assert(node);
	memset(&st, 0, sizeof st);
	devtool_get_node_status(mesh, node, &st);
	connected = st.meta_connected;
	devtool_free_node_status(&st);
	return connected;
}

static bool node_via_canonical(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *node = meshlink_get_node(mesh, name);
	devtool_node_status_t st;
	bool via;

	assert(node);
	memset(&st, 0, sizeof st);
	devtool_get_node_status(mesh, node, &st);
	via = st.meta_connected && st.meta_via_canonical;
	devtool_free_node_status(&st);
	return via;
}

static bool udp_working(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *node = meshlink_get_node(mesh, name);
	devtool_node_status_t st;
	bool working;

	assert(node);
	memset(&st, 0, sizeof st);
	devtool_get_node_status(mesh, node, &st);
	working = st.udp_status == DEVTOOL_UDP_WORKING;
	devtool_free_node_status(&st);
	return working;
}

static void test_camera_keeps_backbone_udp_warm(void) {
	destroy_conf("backbone_udp_t1_conf.1");
	destroy_conf("backbone_udp_t1_conf.2");

	meshlink_handle_t *bb = meshlink_open("backbone_udp_t1_conf.1", "aaa", "backbone-udp", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("backbone_udp_t1_conf.2", "bbb", "backbone-udp", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);
	devtool_set_backbone_udp_keepalive(cam, 2);

	join_meshlink_peer(bb, cam);
	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert_after(node_meta_connected(cam, "aaa"), 10);

	meshlink_node_t *bb_from_cam = meshlink_get_node(cam, "aaa");
	assert(bb_from_cam);
	assert_after(devtool_backbone_udp_timer_armed(cam), 5);
	assert_after(devtool_backbone_udp_confirmed(cam), 15);
	assert(udp_working(cam, "aaa"));
	assert(!devtool_liveness_probe_warranted(cam, bb_from_cam));

	sleep(6);
	assert(devtool_backbone_udp_confirmed(cam));
	assert(udp_working(cam, "aaa"));
	assert(devtool_backbone_udp_timer_armed(cam));
	assert(!devtool_liveness_probe_warranted(cam, bb_from_cam));

	assert(!devtool_backbone_udp_timer_armed(bb));
	assert(devtool_outgoing_count(bb) == 0);

	meshlink_close(bb);
	meshlink_close(cam);
	destroy_conf("backbone_udp_t1_conf.1");
	destroy_conf("backbone_udp_t1_conf.2");
	printf("backbone-udp T1 ok: camera keeps backbone UDP warm without channels\n");
}

static void test_canonical_is_not_a_udp_carrier(void) {
	destroy_conf("backbone_udp_t3_conf.1");
	destroy_conf("backbone_udp_t3_conf.2");

	meshlink_handle_t *bb = meshlink_open("backbone_udp_t3_conf.1", "aaa", "backbone-udp", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("backbone_udp_t3_conf.2", "bbb", "backbone-udp", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	devtool_set_external_ip_address(bb, meshlink_get_self(bb), NULL);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);
	devtool_set_backbone_udp_keepalive(cam, 2);

	int bb_port = meshlink_get_port(bb);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", bb_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	join_meshlink_peer(bb, cam);
	meshlink_node_t *node = meshlink_get_node(cam, "aaa");
	assert(node);
	forget_addresses(cam, node);
	assert(meshlink_set_canonical_address(cam, node, "127.0.0.1", relay_port_str));

	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert_after(node_via_canonical(cam, "aaa"), 5);

	forget_addresses(cam, node);
	sleep(4);
	forget_addresses(cam, node);

	struct sockaddr_storage ep;
	memset(&ep, 0, sizeof ep);

	if(devtool_backbone_udp_confirmed(cam) && devtool_backbone_udp_endpoint(cam, &ep)) {
		assert(!addr_is(&ep, "127.0.0.1", relay_port));
	} else {
		assert(!devtool_backbone_udp_confirmed(cam));
	}

	meshlink_close(bb);
	meshlink_close(cam);
	stop_tcp_relay(relay);
	destroy_conf("backbone_udp_t3_conf.1");
	destroy_conf("backbone_udp_t3_conf.2");
	printf("backbone-udp T3 ok: canonical TCP is not a UDP carrier\n");
}

static void test_demote_fails_exact_endpoint(void) {
	destroy_conf("backbone_udp_t4_conf.1");
	destroy_conf("backbone_udp_t4_conf.2");

	meshlink_handle_t *bb = meshlink_open("backbone_udp_t4_conf.1", "aaa", "backbone-udp", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("backbone_udp_t4_conf.2", "bbb", "backbone-udp", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);
	devtool_set_backbone_udp_keepalive(cam, 2);

	join_meshlink_peer(bb, cam);
	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert_after(devtool_backbone_udp_confirmed(cam), 15);

	meshlink_node_t *node = meshlink_get_node(cam, "aaa");
	assert(node);

	struct sockaddr_storage live;
	memset(&live, 0, sizeof live);
	assert(devtool_backbone_udp_endpoint(cam, &live));

	devtool_set_udp_confirmed(cam, node, false);
	assert(!devtool_backbone_udp_confirmed(cam));

	struct sockaddr_storage failed;
	memset(&failed, 0, sizeof failed);
	assert(devtool_backbone_udp_failed_endpoint(cam, &failed));
	assert(port_of(&failed) == port_of(&live));
	assert(devtool_backbone_udp_timer_armed(cam));

	assert_after(devtool_backbone_udp_confirmed(cam), 15);

	meshlink_close(bb);
	meshlink_close(cam);
	destroy_conf("backbone_udp_t4_conf.1");
	destroy_conf("backbone_udp_t4_conf.2");
	printf("backbone-udp T4 ok: demote fails the exact endpoint and retries\n");
}

static void assert_backbone_udp_cleared(meshlink_handle_t *cam, const char *name) {
	assert(!devtool_backbone_udp_timer_armed(cam));
	assert(!devtool_backbone_udp_confirmed(cam));

	if(name && meshlink_get_node(cam, name)) {
		assert(!udp_working(cam, name));
	}
}

static void confirm_camera_to_backbone(const char *pfx, meshlink_handle_t **bb, meshlink_handle_t **cam) {
	char p1[64], p2[64];

	snprintf(p1, sizeof p1, "%s.1", pfx);
	snprintf(p2, sizeof p2, "%s.2", pfx);
	destroy_conf(p1);
	destroy_conf(p2);

	*bb = meshlink_open(p1, "aaa", "backbone-udp", DEV_CLASS_BACKBONE);
	*cam = meshlink_open(p2, "bbb", "backbone-udp", DEV_CLASS_PORTABLE);
	assert(*bb && *cam);
	meshlink_enable_discovery(*bb, false);
	meshlink_enable_discovery(*cam, false);
	devtool_set_backbone_udp_keepalive(*cam, 2);

	join_meshlink_peer(*bb, *cam);
	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(*cam, reachable_cb);
	assert(meshlink_start(*cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert_after(devtool_backbone_udp_confirmed(*cam), 15);
	assert(udp_working(*cam, "aaa"));
}

static void test_stop_clears_node_udp(void) {
	meshlink_handle_t *bb, *cam;
	meshlink_node_t *node;
	devtool_node_status_t st;

	confirm_camera_to_backbone("backbone_udp_t5a_conf", &bb, &cam);
	node = meshlink_get_node(cam, "aaa");
	assert(node);
	assert(meshlink_blacklist(cam, node));
	assert_after(!devtool_backbone_udp_timer_armed(cam), 5);
	assert_backbone_udp_cleared(cam, "aaa");
	memset(&st, 0, sizeof st);
	devtool_get_node_status(cam, node, &st);
	assert(st.plpmtu_state == DEVTOOL_PLPMTU_DISABLED);
	assert(st.udp_status != DEVTOOL_UDP_WORKING);
	assert(st.udp_status != DEVTOOL_UDP_TRYING);
	devtool_free_node_status(&st);
	meshlink_close(bb);
	meshlink_close(cam);
	destroy_conf("backbone_udp_t5a_conf.1");
	destroy_conf("backbone_udp_t5a_conf.2");

	confirm_camera_to_backbone("backbone_udp_t5b_conf", &bb, &cam);
	node = meshlink_get_node(cam, "aaa");
	assert(node);
	devtool_set_node_devclass(cam, node, DEV_CLASS_PORTABLE);
	assert(devtool_node_has_conflict_backbone(cam, node));
	assert_after(!devtool_backbone_udp_timer_armed(cam), 5);
	assert_backbone_udp_cleared(cam, "aaa");
	memset(&st, 0, sizeof st);
	devtool_get_node_status(cam, node, &st);
	assert(st.plpmtu_state == DEVTOOL_PLPMTU_DISABLED);
	assert(st.udp_status != DEVTOOL_UDP_WORKING);
	assert(st.udp_status != DEVTOOL_UDP_TRYING);
	devtool_free_node_status(&st);
	meshlink_close(bb);
	meshlink_close(cam);
	destroy_conf("backbone_udp_t5b_conf.1");
	destroy_conf("backbone_udp_t5b_conf.2");

	confirm_camera_to_backbone("backbone_udp_t5c_conf", &bb, &cam);
	node = meshlink_get_node(cam, "aaa");
	assert(node);
	meshlink_close(bb);
	bb = NULL;
	assert_after(!node_meta_connected(cam, "aaa"), 15);

	{
		int tries;
		bool forgot = false;

		for(tries = 0; tries < 20; tries++) {
			if(meshlink_forget_node(cam, node)) {
				forgot = true;
				break;
			}

			sleep(1);
		}

		assert(forgot);
	}

	assert(!meshlink_get_node(cam, "aaa"));
	assert_backbone_udp_cleared(cam, NULL);
	meshlink_close(cam);
	destroy_conf("backbone_udp_t5c_conf.1");
	destroy_conf("backbone_udp_t5c_conf.2");

	printf("backbone-udp T5 ok: stop clears dedicated and node UDP state\n");
}

static void test_unknown_does_not_require_backbone_udp(void) {
	destroy_conf("backbone_udp_t6_conf.1");
	destroy_conf("backbone_udp_t6_conf.2");

	meshlink_handle_t *bb = meshlink_open("backbone_udp_t6_conf.1", "aaa", "backbone-udp", DEV_CLASS_BACKBONE);
	meshlink_handle_t *unk = meshlink_open("backbone_udp_t6_conf.2", "ddd", "backbone-udp", DEV_CLASS_UNKNOWN);
	assert(bb && unk);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(unk, false);

	join_meshlink_peer(bb, unk);
	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(unk, reachable_cb);
	assert(meshlink_start(unk));
	assert(wait_sync_flag(&peer_up, 15));
	assert_after(node_meta_connected(unk, "aaa"), 10);
	sleep(2);
	assert(!devtool_backbone_udp_timer_armed(unk));
	assert(!devtool_backbone_udp_confirmed(unk));
	assert(devtool_backbone_intent_purpose(unk) == 1);

	meshlink_close(bb);
	meshlink_close(unk);
	destroy_conf("backbone_udp_t6_conf.1");
	destroy_conf("backbone_udp_t6_conf.2");
	printf("backbone-udp T6 ok: UNKNOWN does not originate backbone UDP\n");
}

static void test_establish_backoff_resets_on_new_dest(void) {
	destroy_conf("backbone_udp_t7_conf.1");
	destroy_conf("backbone_udp_t7_conf.2");

	meshlink_handle_t *bb = meshlink_open("backbone_udp_t7_conf.1", "aaa", "backbone-udp", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("backbone_udp_t7_conf.2", "bbb", "backbone-udp", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	devtool_set_external_ip_address(bb, meshlink_get_self(bb), NULL);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);

	int bb_port = meshlink_get_port(bb);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", bb_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	join_meshlink_peer(bb, cam);
	meshlink_node_t *node = meshlink_get_node(cam, "aaa");
	assert(node);
	forget_addresses(cam, node);
	assert(meshlink_set_canonical_address(cam, node, "127.0.0.1", relay_port_str));
	devtool_force_meta(cam, node, true);

	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert_after(node_via_canonical(cam, "aaa"), 5);
	assert_after(devtool_backbone_udp_establish_step(cam) >= 1, 5);
	assert(devtool_backbone_udp_timer_armed(cam));
	assert(!devtool_backbone_udp_confirmed(cam));

	devtool_force_meta(cam, node, false);
	struct sockaddr_in sa = ipv4("127.0.0.1", (uint16_t)bb_port);
	assert(devtool_learn_discovery_address(cam, node, (struct sockaddr *)&sa));
	assert_after(devtool_backbone_udp_confirmed(cam), 15);
	assert(devtool_backbone_udp_establish_step(cam) == 0);

	meshlink_close(bb);
	meshlink_close(cam);
	stop_tcp_relay(relay);
	destroy_conf("backbone_udp_t7_conf.1");
	destroy_conf("backbone_udp_t7_conf.2");
	printf("backbone-udp T7 ok: establishment backs off and resets on a new dest\n");
}

static void test_duplicate_discovery_does_not_reset_backoff(void) {
	destroy_conf("backbone_udp_t8_conf.1");
	destroy_conf("backbone_udp_t8_conf.2");

	meshlink_handle_t *bb = meshlink_open("backbone_udp_t8_conf.1", "aaa", "backbone-udp", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("backbone_udp_t8_conf.2", "bbb", "backbone-udp", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	devtool_set_external_ip_address(bb, meshlink_get_self(bb), NULL);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);

	int bb_port = meshlink_get_port(bb);
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", bb_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	join_meshlink_peer(bb, cam);
	meshlink_node_t *node = meshlink_get_node(cam, "aaa");
	assert(node);
	forget_addresses(cam, node);
	assert(meshlink_set_canonical_address(cam, node, "127.0.0.1", relay_port_str));
	devtool_force_meta(cam, node, true);

	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert_after(node_via_canonical(cam, "aaa"), 5);

	struct sockaddr_in sa = ipv4("127.0.0.1", 65534);
	assert(devtool_learn_discovery_address(cam, node, (struct sockaddr *)&sa));
	assert_after(devtool_backbone_udp_establish_step(cam) >= 2, 8);

	unsigned step = devtool_backbone_udp_establish_step(cam);
	assert(step >= 2);
	assert(devtool_learn_discovery_address(cam, node, (struct sockaddr *)&sa));
	assert(devtool_learn_discovery_address(cam, node, (struct sockaddr *)&sa));
	assert(devtool_learn_discovery_address(cam, node, (struct sockaddr *)&sa));
	assert(devtool_backbone_udp_establish_step(cam) >= step);
	assert(!devtool_backbone_udp_confirmed(cam));

	meshlink_close(bb);
	meshlink_close(cam);
	stop_tcp_relay(relay);
	destroy_conf("backbone_udp_t8_conf.1");
	destroy_conf("backbone_udp_t8_conf.2");
	printf("backbone-udp T8 ok: duplicate discovery does not reset establishment backoff\n");
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	test_camera_keeps_backbone_udp_warm();
	test_canonical_is_not_a_udp_carrier();
	test_demote_fails_exact_endpoint();
	test_stop_clears_node_udp();
	test_unknown_does_not_require_backbone_udp();
	test_establish_backoff_resets_on_new_dest();
	test_duplicate_discovery_does_not_reset_backoff();
	return 0;
}
