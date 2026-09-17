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

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	test_backbone_initiates_nothing();
	test_local_peers_do_not_steal_backbone_slot();
	test_conflict_backbone_excluded_from_pools();
	test_blacklist_drops_backbone_intent();
	test_reclassified_backbone_closes_sockets();
	return 0;
}
