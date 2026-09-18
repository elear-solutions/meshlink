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

static void test_backbone_initiates_nothing(void) {
	destroy_conf("connection_policy_t1_conf.1");
	destroy_conf("connection_policy_t1_conf.2");
	destroy_conf("connection_policy_t1_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t1_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("connection_policy_t1_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *cam2 = meshlink_open("connection_policy_t1_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);
	meshlink_enable_discovery(cam2, false);

	join_meshlink_peer(bb, cam);
	join_meshlink_peer(bb, cam2);

	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(bb, reachable_cb);
	assert(meshlink_start(cam));
	assert(meshlink_start(cam2));
	assert(wait_sync_flag(&peer_up, 15));

	assert_after(devtool_outgoing_count(bb) == 0, 5);
	assert(!devtool_self_initiates_meta(bb));
	assert(devtool_self_initiates_meta(cam));
	assert(devtool_outgoing_count(cam) == 1);
	assert(devtool_backbone_intent_purpose(cam) == 1); /* META_PURPOSE_BACKBONE_REQUIRED */
	assert(!strcmp(devtool_backbone_intent_name(cam), "aaa"));
	assert(devtool_outgoing_count(cam2) == 1);
	assert(!strcmp(devtool_backbone_intent_name(cam2), "aaa"));

	meshlink_close(bb);
	meshlink_close(cam);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t1_conf.1");
	destroy_conf("connection_policy_t1_conf.2");
	destroy_conf("connection_policy_t1_conf.3");
}

static void test_local_peers_do_not_steal_backbone_slot(void) {
	destroy_conf("connection_policy_t2_conf.1");
	destroy_conf("connection_policy_t2_conf.2");
	destroy_conf("connection_policy_t2_conf.3");
	destroy_conf("connection_policy_t2_conf.4");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t2_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("connection_policy_t2_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *p1 = meshlink_open("connection_policy_t2_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	meshlink_handle_t *p2 = meshlink_open("connection_policy_t2_conf.4", "ddd", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam && p1 && p2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);
	meshlink_enable_discovery(p1, false);
	meshlink_enable_discovery(p2, false);

	join_meshlink_peer(bb, cam);
	join_meshlink_peer(bb, p1);
	join_meshlink_peer(bb, p2);

	char *ex1 = meshlink_export(p1);
	char *ex2 = meshlink_export(p2);
	assert(ex1 && ex2);
	assert(meshlink_import(cam, ex1));
	assert(meshlink_import(cam, ex2));
	free(ex1);
	free(ex2);

	/* Local peers are known before the camera is started. */
	assert(meshlink_get_node(cam, "ccc"));
	assert(meshlink_get_node(cam, "ddd"));
	assert(meshlink_get_node(cam, "aaa"));

	/* Backbone host is down when the camera starts: intent must still exist and
	   must not be replaced by a local peer. */
	meshlink_stop(bb);
	assert(meshlink_start(cam));
	assert(meshlink_start(p1));
	assert(meshlink_start(p2));
	assert_after(devtool_outgoing_count(cam) == 1, 5);
	assert(devtool_backbone_intent_purpose(cam) == 1); /* META_PURPOSE_BACKBONE_REQUIRED */
	assert(!strcmp(devtool_backbone_intent_name(cam), "aaa"));
	assert(devtool_outgoing_count(p1) == 1);
	assert(!strcmp(devtool_backbone_intent_name(p1), "aaa"));

	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(bb));
	assert(wait_sync_flag(&peer_up, 15));
	assert(devtool_outgoing_count(cam) == 1);
	assert(!strcmp(devtool_backbone_intent_name(cam), "aaa"));

	meshlink_close(bb);
	meshlink_close(cam);
	meshlink_close(p1);
	meshlink_close(p2);
	destroy_conf("connection_policy_t2_conf.1");
	destroy_conf("connection_policy_t2_conf.2");
	destroy_conf("connection_policy_t2_conf.3");
	destroy_conf("connection_policy_t2_conf.4");
}

static void test_conflict_backbone_excluded_from_pools(void) {
	destroy_conf("connection_policy_t3_conf.1");
	destroy_conf("connection_policy_t3_conf.2");

	meshlink_handle_t *a = meshlink_open("connection_policy_t3_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("connection_policy_t3_conf.2", "bbb", "connection-policy", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	join_meshlink_peer(a, b);
	assert(meshlink_start(b));
	assert(devtool_node_has_conflict_backbone(b, meshlink_get_self(b)));

	sleep(2);
	assert(devtool_outgoing_count(a) == 0);
	assert(devtool_outgoing_count(b) == 0);
	assert(!devtool_backbone_intent_name(a));
	assert(!devtool_backbone_intent_name(b));

	meshlink_close(a);
	meshlink_close(b);
	destroy_conf("connection_policy_t3_conf.1");
	destroy_conf("connection_policy_t3_conf.2");
}

static void test_blacklist_drops_backbone_intent(void) {
	destroy_conf("connection_policy_t4_conf.1");
	destroy_conf("connection_policy_t4_conf.2");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t4_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("connection_policy_t4_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);

	join_meshlink_peer(bb, cam);
	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert(devtool_outgoing_count(cam) == 1);

	meshlink_node_t *node = meshlink_get_node(cam, "aaa");
	assert(node);
	assert(meshlink_blacklist(cam, node));
	assert_after(devtool_outgoing_count(cam) == 0, 5);
	assert(!devtool_backbone_intent_name(cam));

	{
		devtool_node_status_t st;
		memset(&st, 0, sizeof st);
		devtool_get_node_status(cam, node, &st);
		assert(!st.meta_connected);
		devtool_free_node_status(&st);
	}

	meshlink_close(bb);
	meshlink_close(cam);
	destroy_conf("connection_policy_t4_conf.1");
	destroy_conf("connection_policy_t4_conf.2");
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

static void test_reclassified_backbone_closes_sockets(void) {
	destroy_conf("connection_policy_t5_conf.1");
	destroy_conf("connection_policy_t5_conf.2");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t5_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("connection_policy_t5_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);

	join_meshlink_peer(bb, cam);
	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert(devtool_outgoing_count(cam) == 1);
	assert_after(node_meta_connected(cam, "aaa"), 5);

	meshlink_node_t *node = meshlink_get_node(cam, "aaa");
	assert(node);
	devtool_set_node_devclass(cam, node, DEV_CLASS_PORTABLE);
	assert(devtool_node_has_conflict_backbone(cam, node));
	assert_after(devtool_outgoing_count(cam) == 0, 5);
	assert(!devtool_backbone_intent_name(cam));
	assert_after(!node_meta_connected(cam, "aaa"), 5);

	meshlink_close(bb);
	meshlink_close(cam);
	destroy_conf("connection_policy_t5_conf.1");
	destroy_conf("connection_policy_t5_conf.2");
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

static void test_intent_survives_failed_epoch(void) {
	destroy_conf("connection_policy_t6_conf.1");
	destroy_conf("connection_policy_t6_conf.2");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t6_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("connection_policy_t6_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);

	join_meshlink_peer(bb, cam);
	meshlink_node_t *node = meshlink_get_node(cam, "aaa");
	assert(node);
	forget_addresses(cam, node);
	hint_address(cam, node, "127.0.0.1", find_closed_port("127.0.0.1"));

	meshlink_stop(bb);
	size_t mark = log_mark();
	assert(meshlink_start(cam));
	assert_after(devtool_outgoing_count(cam) == 1, 5);
	assert_after(devtool_backbone_intent_retry_step(cam) >= 1, 5);
	assert(devtool_backbone_intent_purpose(cam) == 1);
	assert(!strcmp(devtool_backbone_intent_name(cam), "aaa"));
	assert(log_find(mark, "Trying to re-establish outgoing connection in ") >= 0);

	meshlink_close(bb);
	meshlink_close(cam);
	destroy_conf("connection_policy_t6_conf.1");
	destroy_conf("connection_policy_t6_conf.2");
}

static void test_dead_direct_then_canonical(void) {
	destroy_conf("connection_policy_t7_conf.1");
	destroy_conf("connection_policy_t7_conf.2");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t7_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("connection_policy_t7_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);

	int bb_port = meshlink_get_port(bb);
	int dead_port = find_closed_port("127.0.0.1");
	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", bb_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);

	join_meshlink_peer(bb, cam);
	meshlink_node_t *node = meshlink_get_node(cam, "aaa");
	assert(node);
	forget_addresses(cam, node);
	hint_address(cam, node, "127.0.0.1", dead_port);
	assert(meshlink_set_canonical_address(cam, node, "127.0.0.1", relay_port_str));

	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	size_t mark = log_mark();
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert(devtool_outgoing_count(cam) == 1);
	assert(devtool_backbone_intent_retry_step(cam) == 0);

	char recent_needle[128], canonical_needle[128];
	snprintf(recent_needle, sizeof recent_needle, "Trying to connect to aaa at 127.0.0.1 port %d (recent)", dead_port);
	snprintf(canonical_needle, sizeof canonical_needle, "Trying to connect to aaa at 127.0.0.1 port %d (canonical)", relay_port);
	long recent_at = log_find(mark, recent_needle);
	long canonical_at = log_find(mark, canonical_needle);
	assert(recent_at >= 0);
	assert(canonical_at >= 0);
	assert(recent_at < canonical_at);

	meshlink_set_node_status_cb(cam, NULL);
	meshlink_close(bb);
	meshlink_close(cam);
	stop_tcp_relay(relay);
	destroy_conf("connection_policy_t7_conf.1");
	destroy_conf("connection_policy_t7_conf.2");
}

static void test_canonical_hint_keeps_one_intent(void) {
	destroy_conf("connection_policy_t8_conf.1");
	destroy_conf("connection_policy_t8_conf.2");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t8_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("connection_policy_t8_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	assert(bb && cam);
	/* Drop findmyip so REQ_EXTERNAL does not advertise a WAN dest Docker cannot hairpin. */
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

	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam, reachable_cb);
	assert(meshlink_start(cam));
	assert(wait_sync_flag(&peer_up, 15));
	assert_after(node_via_canonical(cam, "aaa"), 5);
	assert(devtool_outgoing_count(cam) == 1);

	hint_address(cam, node, "127.0.0.1", bb_port);
	assert_after(node_meta_connected(cam, "aaa") && !node_via_canonical(cam, "aaa"), 15);
	assert(devtool_outgoing_count(cam) == 1);
	assert(devtool_backbone_intent_purpose(cam) == 1);
	assert(devtool_backbone_intent_retry_step(cam) == 0);

	meshlink_set_node_status_cb(cam, NULL);
	meshlink_close(bb);
	meshlink_close(cam);
	stop_tcp_relay(relay);
	destroy_conf("connection_policy_t8_conf.1");
	destroy_conf("connection_policy_t8_conf.2");
}

static void plant_lan_discovery(meshlink_handle_t *viewer, meshlink_handle_t *peer) {
	meshlink_node_t *n = meshlink_get_node(viewer, meshlink_get_self(peer)->name);
	struct sockaddr_in sa;

	assert(n);
	sa = ipv4("127.0.0.1", (uint16_t)meshlink_get_port(peer));
	assert(devtool_learn_discovery_address(viewer, n, (struct sockaddr *)&sa));
}

static void exchange_all(meshlink_handle_t **nodes, unsigned n) {
	unsigned i, j;

	for(i = 0; i < n; i++) {
		for(j = i + 1; j < n; j++) {
			exchange_meshlink_pair(nodes[i], nodes[j]);
		}
	}
}

static void plant_lan_full_mesh(meshlink_handle_t **nodes, unsigned n) {
	unsigned i, j;

	for(i = 0; i < n; i++) {
		for(j = 0; j < n; j++) {
			if(i != j) {
				plant_lan_discovery(nodes[i], nodes[j]);
			}
		}
	}
}

static bool local_overlay_connected(meshlink_handle_t **cams, unsigned n) {
	bool seen[16];
	unsigned queue[16];
	unsigned qh = 0, qt = 0, vis = 0, i;

	assert(n > 0 && n < 16);
	memset(seen, 0, sizeof seen);
	queue[qt++] = 0;
	seen[0] = true;

	while(qh < qt) {
		unsigned u = queue[qh++];
		vis++;

		for(i = 0; i < n; i++) {
			if(seen[i] || i == u) {
				continue;
			}

			if(node_meta_connected(cams[u], meshlink_get_self(cams[i])->name)) {
				seen[i] = true;
				queue[qt++] = i;
			}
		}
	}

	return vis == n;
}

static void test_two_cameras_one_local_meta(void) {
	destroy_conf("connection_policy_t9_conf.1");
	destroy_conf("connection_policy_t9_conf.2");
	destroy_conf("connection_policy_t9_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t9_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam1 = meshlink_open("connection_policy_t9_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *cam2 = meshlink_open("connection_policy_t9_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);

	join_meshlink_peer(bb, cam1);
	join_meshlink_peer(bb, cam2);
	exchange_meshlink_pair(cam1, cam2);

	init_sync_flag(&peer_up);
	meshlink_set_node_status_cb(cam1, reachable_cb);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	assert(wait_sync_flag(&peer_up, 15));

	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_local_adjacency_count(cam1) == 1 && devtool_local_adjacency_count(cam2) == 1, 15);
	assert(devtool_outgoing_count(cam1) == 2);
	assert(devtool_lan_intent_count(cam1) == 1);
	assert(devtool_outgoing_count(cam2) == 1);
	assert(devtool_lan_intent_count(cam2) == 0);
	assert(devtool_backbone_intent_purpose(cam1) == 1);
	assert(node_meta_connected(cam1, "ccc"));
	assert(node_meta_connected(cam2, "bbb"));

	meshlink_set_node_status_cb(cam1, NULL);
	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t9_conf.1");
	destroy_conf("connection_policy_t9_conf.2");
	destroy_conf("connection_policy_t9_conf.3");
}

static void test_four_cameras_k4(void) {
	const char *names[] = {"bbb", "ccc", "ddd", "eee"};
	meshlink_handle_t *cams[4];
	unsigned i;
	char path[64];

	destroy_conf("connection_policy_t10_conf.1");

	for(i = 0; i < 4; i++) {
		snprintf(path, sizeof path, "connection_policy_t10_conf.%u", i + 2);
		destroy_conf(path);
	}

	meshlink_handle_t *bb = meshlink_open("connection_policy_t10_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	assert(bb);
	meshlink_enable_discovery(bb, false);

	for(i = 0; i < 4; i++) {
		snprintf(path, sizeof path, "connection_policy_t10_conf.%u", i + 2);
		cams[i] = meshlink_open(path, names[i], "connection-policy", DEV_CLASS_STATIONARY);
		assert(cams[i]);
		meshlink_enable_discovery(cams[i], false);
		join_meshlink_peer(bb, cams[i]);
	}

	exchange_all(cams, 4);
	assert(meshlink_start(bb));

	for(i = 0; i < 4; i++) {
		assert(meshlink_start(cams[i]));
	}

	assert_after(node_meta_connected(cams[0], "aaa"), 15);
	plant_lan_full_mesh(cams, 4);

	for(i = 0; i < 4; i++) {
		assert_after(devtool_local_adjacency_count(cams[i]) == 3, 20);
		assert(devtool_backbone_intent_purpose(cams[i]) == 1);
		assert(devtool_outgoing_count(cams[i]) == 1 + (3 - i));
	}

	meshlink_close(bb);

	for(i = 0; i < 4; i++) {
		meshlink_close(cams[i]);
		snprintf(path, sizeof path, "connection_policy_t10_conf.%u", i + 2);
		destroy_conf(path);
	}

	destroy_conf("connection_policy_t10_conf.1");
}

static void test_six_cameras_bounded_connected(void) {
	const char *names[] = {"bbb", "ccc", "ddd", "eee", "fff", "ggg"};
	meshlink_handle_t *cams[6];
	unsigned i;
	char path[64];

	destroy_conf("connection_policy_t11_conf.1");

	for(i = 0; i < 6; i++) {
		snprintf(path, sizeof path, "connection_policy_t11_conf.%u", i + 2);
		destroy_conf(path);
	}

	meshlink_handle_t *bb = meshlink_open("connection_policy_t11_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	assert(bb);
	meshlink_enable_discovery(bb, false);

	for(i = 0; i < 6; i++) {
		snprintf(path, sizeof path, "connection_policy_t11_conf.%u", i + 2);
		cams[i] = meshlink_open(path, names[i], "connection-policy", DEV_CLASS_STATIONARY);
		assert(cams[i]);
		meshlink_enable_discovery(cams[i], false);
		join_meshlink_peer(bb, cams[i]);
	}

	exchange_all(cams, 6);
	assert(meshlink_start(bb));

	for(i = 0; i < 6; i++) {
		assert(meshlink_start(cams[i]));
	}

	assert_after(node_meta_connected(cams[0], "aaa"), 15);
	plant_lan_full_mesh(cams, 6);

	for(i = 0; i < 6; i++) {
		assert_after(devtool_local_adjacency_count(cams[i]) <= 3 && devtool_local_adjacency_count(cams[i]) >= 2, 20);
		assert(devtool_local_adjacency_count(cams[i]) <= 3);
		assert(devtool_backbone_intent_purpose(cams[i]) == 1);
	}

	assert_after(local_overlay_connected(cams, 6), 20);

	meshlink_close(bb);

	for(i = 0; i < 6; i++) {
		meshlink_close(cams[i]);
		snprintf(path, sizeof path, "connection_policy_t11_conf.%u", i + 2);
		destroy_conf(path);
	}

	destroy_conf("connection_policy_t11_conf.1");
}

static void test_hint_does_not_create_lan(void) {
	destroy_conf("connection_policy_t12_conf.1");
	destroy_conf("connection_policy_t12_conf.2");
	destroy_conf("connection_policy_t12_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t12_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam1 = meshlink_open("connection_policy_t12_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *cam2 = meshlink_open("connection_policy_t12_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);

	join_meshlink_peer(bb, cam1);
	join_meshlink_peer(bb, cam2);
	exchange_meshlink_pair(cam1, cam2);
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	assert_after(devtool_outgoing_count(cam1) == 1, 5);

	hint_address(cam1, meshlink_get_node(cam1, "ccc"), "127.0.0.1", meshlink_get_port(cam2));
	sleep(3);
	assert(devtool_lan_intent_count(cam1) == 0);
	assert(devtool_outgoing_count(cam1) == 1);
	assert(devtool_local_adjacency_count(cam1) == 0);

	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t12_conf.1");
	destroy_conf("connection_policy_t12_conf.2");
	destroy_conf("connection_policy_t12_conf.3");
}

static void test_lan_survives_backbone_stop(void) {
	destroy_conf("connection_policy_t13_conf.1");
	destroy_conf("connection_policy_t13_conf.2");
	destroy_conf("connection_policy_t13_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t13_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam1 = meshlink_open("connection_policy_t13_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *cam2 = meshlink_open("connection_policy_t13_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);

	join_meshlink_peer(bb, cam1);
	join_meshlink_peer(bb, cam2);
	exchange_meshlink_pair(cam1, cam2);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	assert_after(node_meta_connected(cam1, "aaa"), 15);
	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(node_meta_connected(cam1, "ccc"), 15);

	meshlink_stop(bb);
	sleep(2);
	assert(node_meta_connected(cam1, "ccc"));
	assert(node_meta_connected(cam2, "bbb"));
	assert(devtool_local_adjacency_count(cam1) == 1);

	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t13_conf.1");
	destroy_conf("connection_policy_t13_conf.2");
	destroy_conf("connection_policy_t13_conf.3");
}

static void test_lan_skips_blacklist_and_conflict(void) {
	destroy_conf("connection_policy_t14_conf.1");
	destroy_conf("connection_policy_t14_conf.2");
	destroy_conf("connection_policy_t14_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t14_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam1 = meshlink_open("connection_policy_t14_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *cam2 = meshlink_open("connection_policy_t14_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);

	join_meshlink_peer(bb, cam1);
	join_meshlink_peer(bb, cam2);
	exchange_meshlink_pair(cam1, cam2);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	assert_after(node_meta_connected(cam1, "aaa"), 15);
	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_lan_intent_count(cam1) == 1, 15);

	meshlink_node_t *peer = meshlink_get_node(cam1, "ccc");
	assert(peer);
	assert(meshlink_blacklist(cam1, peer));
	assert_after(devtool_lan_intent_count(cam1) == 0, 5);
	assert_after(!node_meta_connected(cam1, "ccc"), 5);

	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t14_conf.1");
	destroy_conf("connection_policy_t14_conf.2");
	destroy_conf("connection_policy_t14_conf.3");

	destroy_conf("connection_policy_t14b_conf.1");
	destroy_conf("connection_policy_t14b_conf.2");
	destroy_conf("connection_policy_t14b_conf.3");

	bb = meshlink_open("connection_policy_t14b_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	cam1 = meshlink_open("connection_policy_t14b_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	cam2 = meshlink_open("connection_policy_t14b_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);
	join_meshlink_peer(bb, cam1);
	join_meshlink_peer(bb, cam2);
	exchange_meshlink_pair(cam1, cam2);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_lan_intent_count(cam1) == 1, 15);
	peer = meshlink_get_node(cam1, "ccc");
	devtool_set_node_devclass(cam1, peer, DEV_CLASS_BACKBONE);
	assert(devtool_node_has_conflict_backbone(cam1, peer));
	assert_after(devtool_lan_intent_count(cam1) == 0, 5);

	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t14b_conf.1");
	destroy_conf("connection_policy_t14b_conf.2");
	destroy_conf("connection_policy_t14b_conf.3");
}

static void test_fourth_non_desired_inbound_refused(void) {
	const char *names[] = {"bbb", "ccc", "ddd", "eee", "fff", "ggg"};
	meshlink_handle_t *cams[6];
	unsigned i;
	char path[64];

	destroy_conf("connection_policy_t15_conf.1");

	for(i = 0; i < 6; i++) {
		snprintf(path, sizeof path, "connection_policy_t15_conf.%u", i + 2);
		destroy_conf(path);
	}

	destroy_conf("connection_policy_t15_conf.8");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t15_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	assert(bb);
	meshlink_enable_discovery(bb, false);

	for(i = 0; i < 6; i++) {
		snprintf(path, sizeof path, "connection_policy_t15_conf.%u", i + 2);
		cams[i] = meshlink_open(path, names[i], "connection-policy", DEV_CLASS_STATIONARY);
		assert(cams[i]);
		meshlink_enable_discovery(cams[i], false);
		join_meshlink_peer(bb, cams[i]);
	}

	exchange_all(cams, 6);
	assert(meshlink_start(bb));

	for(i = 0; i < 6; i++) {
		assert(meshlink_start(cams[i]));
	}

	assert_after(node_meta_connected(cams[0], "aaa"), 15);
	plant_lan_full_mesh(cams, 6);

	for(i = 0; i < 6; i++) {
		assert_after(devtool_local_adjacency_count(cams[i]) <= 3, 20);
	}

	meshlink_handle_t *extra = meshlink_open("connection_policy_t15_conf.8", "abb", "connection-policy", DEV_CLASS_PORTABLE);
	assert(extra);
	meshlink_enable_discovery(extra, false);
	join_meshlink_peer(bb, extra);
	exchange_meshlink_pair(extra, cams[4]); /* fff */
	assert(meshlink_start(extra));
	plant_lan_discovery(extra, cams[4]);
	sleep(5);
	assert(devtool_local_adjacency_count(cams[4]) <= 3);
	assert(!node_meta_connected(cams[4], "abb"));

	meshlink_close(extra);
	meshlink_close(bb);

	for(i = 0; i < 6; i++) {
		meshlink_close(cams[i]);
		snprintf(path, sizeof path, "connection_policy_t15_conf.%u", i + 2);
		destroy_conf(path);
	}

	destroy_conf("connection_policy_t15_conf.1");
	destroy_conf("connection_policy_t15_conf.8");
}

static void test_rejected_wan_duplicate_keeps_local(void) {
	destroy_conf("connection_policy_t16_conf.1");
	destroy_conf("connection_policy_t16_conf.2");
	destroy_conf("connection_policy_t16_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t16_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam1 = meshlink_open("connection_policy_t16_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *cam2 = meshlink_open("connection_policy_t16_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);

	join_meshlink_peer(bb, cam1);
	join_meshlink_peer(bb, cam2);
	exchange_meshlink_pair(cam1, cam2);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	assert_after(node_meta_connected(cam1, "aaa"), 15);
	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_local_adjacency_count(cam2) == 1, 15);
	assert(node_meta_connected(cam2, "bbb"));

	struct sockaddr_in wan = ipv4("203.0.113.8", 9);
	meshlink_node_t *peer = meshlink_get_node(cam2, "bbb");
	assert(peer);
	assert(!devtool_try_ack_replace(cam2, peer, (struct sockaddr *)&wan, DEV_CLASS_STATIONARY));
	assert(devtool_local_adjacency_count(cam2) == 1);
	assert(node_meta_connected(cam2, "bbb"));
	assert(!devtool_try_ack_replace(cam2, peer, (struct sockaddr *)&wan, DEV_CLASS_UNKNOWN));
	assert(devtool_local_adjacency_count(cam2) == 1);
	assert(node_meta_connected(cam2, "bbb"));

	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t16_conf.1");
	destroy_conf("connection_policy_t16_conf.2");
	destroy_conf("connection_policy_t16_conf.3");
}

static void test_stale_persisted_addresses_need_fresh_discovery(void) {
	destroy_conf("connection_policy_t17_conf.1");
	destroy_conf("connection_policy_t17_conf.2");
	destroy_conf("connection_policy_t17_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t17_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam1 = meshlink_open("connection_policy_t17_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *cam2 = meshlink_open("connection_policy_t17_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);

	join_meshlink_peer(bb, cam1);
	join_meshlink_peer(bb, cam2);
	exchange_meshlink_pair(cam1, cam2);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	assert_after(node_meta_connected(cam1, "aaa"), 15);
	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_lan_intent_count(cam1) == 1 && node_meta_connected(cam1, "ccc"), 15);

	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);

	bb = meshlink_open("connection_policy_t17_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	cam1 = meshlink_open("connection_policy_t17_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	cam2 = meshlink_open("connection_policy_t17_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	assert_after(node_meta_connected(cam1, "aaa"), 15);
	sleep(2);
	assert(devtool_lan_intent_count(cam1) == 0);
	assert(devtool_lan_intent_count(cam2) == 0);
	assert(devtool_local_adjacency_count(cam1) == 0);
	assert(devtool_local_adjacency_count(cam2) == 0);

	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_lan_intent_count(cam1) == 1 && node_meta_connected(cam1, "ccc"), 15);

	meshlink_stop(cam2);
	sleep(1);
	meshlink_hint_network_change(cam1);
	assert_after(devtool_lan_intent_count(cam1) == 0, 5);
	assert(!node_meta_connected(cam1, "ccc"));

	assert(meshlink_start(cam2));
	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_lan_intent_count(cam1) == 1 && node_meta_connected(cam1, "ccc"), 15);

	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t17_conf.1");
	destroy_conf("connection_policy_t17_conf.2");
	destroy_conf("connection_policy_t17_conf.3");
}

static void test_unknown_class_not_lan_eligible(void) {
	destroy_conf("connection_policy_t18_conf.1");
	destroy_conf("connection_policy_t18_conf.2");
	destroy_conf("connection_policy_t18_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t18_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam = meshlink_open("connection_policy_t18_conf.2", "bbb", "connection-policy", DEV_CLASS_STATIONARY);
	meshlink_handle_t *unk = meshlink_open("connection_policy_t18_conf.3", "ddd", "connection-policy", DEV_CLASS_UNKNOWN);
	assert(bb && cam && unk);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam, false);
	meshlink_enable_discovery(unk, false);

	join_meshlink_peer(bb, cam);
	join_meshlink_peer(bb, unk);
	exchange_meshlink_pair(cam, unk);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam));
	assert(meshlink_start(unk));
	assert_after(node_meta_connected(cam, "aaa"), 15);
	plant_lan_discovery(cam, unk);
	plant_lan_discovery(unk, cam);
	sleep(3);
	assert(devtool_lan_intent_count(cam) == 0);
	assert(devtool_lan_intent_count(unk) == 0);
	assert(devtool_local_adjacency_count(cam) == 0);
	assert(devtool_local_adjacency_count(unk) == 0);
	assert(devtool_backbone_intent_purpose(cam) == 1);
	assert(devtool_backbone_intent_purpose(unk) == 1);
	assert(!devtool_backbone_udp_timer_armed(unk));

	meshlink_close(bb);
	meshlink_close(cam);
	meshlink_close(unk);
	destroy_conf("connection_policy_t18_conf.1");
	destroy_conf("connection_policy_t18_conf.2");
	destroy_conf("connection_policy_t18_conf.3");
}

static void test_epoch_retires_live_lan_adjacency(void) {
	destroy_conf("connection_policy_t19_conf.1");
	destroy_conf("connection_policy_t19_conf.2");
	destroy_conf("connection_policy_t19_conf.3");

	meshlink_handle_t *bb = meshlink_open("connection_policy_t19_conf.1", "aaa", "connection-policy", DEV_CLASS_BACKBONE);
	meshlink_handle_t *cam1 = meshlink_open("connection_policy_t19_conf.2", "bbb", "connection-policy", DEV_CLASS_PORTABLE);
	meshlink_handle_t *cam2 = meshlink_open("connection_policy_t19_conf.3", "ccc", "connection-policy", DEV_CLASS_STATIONARY);
	assert(bb && cam1 && cam2);
	meshlink_enable_discovery(bb, false);
	meshlink_enable_discovery(cam1, false);
	meshlink_enable_discovery(cam2, false);

	join_meshlink_peer(bb, cam1);
	join_meshlink_peer(bb, cam2);
	exchange_meshlink_pair(cam1, cam2);
	assert(meshlink_start(bb));
	assert(meshlink_start(cam1));
	assert(meshlink_start(cam2));
	assert_after(node_meta_connected(cam1, "aaa"), 15);
	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_local_adjacency_count(cam1) == 1 && node_meta_connected(cam1, "ccc"), 15);
	assert(devtool_lan_intent_count(cam1) == 1);

	meshlink_hint_network_change(cam1);
	assert_after(devtool_local_adjacency_count(cam1) == 0, 2);
	assert(devtool_lan_intent_count(cam1) == 0);
	assert(!node_meta_connected(cam1, "ccc"));

	sleep(2);
	assert(devtool_lan_intent_count(cam1) == 0);
	assert(devtool_local_adjacency_count(cam1) == 0);
	assert(!node_meta_connected(cam1, "ccc"));

	plant_lan_discovery(cam1, cam2);
	plant_lan_discovery(cam2, cam1);
	assert_after(devtool_lan_intent_count(cam1) == 1 && node_meta_connected(cam1, "ccc"), 15);

	meshlink_close(bb);
	meshlink_close(cam1);
	meshlink_close(cam2);
	destroy_conf("connection_policy_t19_conf.1");
	destroy_conf("connection_policy_t19_conf.2");
	destroy_conf("connection_policy_t19_conf.3");
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);
	test_backbone_initiates_nothing();
	test_local_peers_do_not_steal_backbone_slot();
	test_conflict_backbone_excluded_from_pools();
	test_blacklist_drops_backbone_intent();
	test_reclassified_backbone_closes_sockets();
	test_intent_survives_failed_epoch();
	test_dead_direct_then_canonical();
	test_canonical_hint_keeps_one_intent();
	test_two_cameras_one_local_meta();
	test_four_cameras_k4();
	test_six_cameras_bounded_connected();
	test_hint_does_not_create_lan();
	test_lan_survives_backbone_stop();
	test_lan_skips_blacklist_and_conflict();
	test_fourth_non_desired_inbound_refused();
	test_rejected_wan_duplicate_keeps_local();
	test_stale_persisted_addresses_need_fresh_discovery();
	test_unknown_class_not_lan_eligible();
	test_epoch_retires_live_lan_adjacency();
	free_captured_log();
	return 0;
}
