#ifdef NDEBUG
#undef NDEBUG
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "meshlink.h"
#include "utils.h"
#include "devtools.h"
#include "netns_utils.h"

#define NO_LAN_REASON "no on-link candidate or LAN evidence"
#define DISCOVERY_TRIES 10
#define DISCOVERY_BROADCAST_TRIES 3

static struct sync_flag accepted;
static struct sync_flag received;

static void receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;

	if(len) {
		set_sync_flag(&received, true);
	}
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)port;
	(void)data;
	(void)len;
	meshlink_set_channel_receive_cb(mesh, channel, receive_cb);
	set_sync_flag(&accepted, true);
	return true;
}

static void discovery_counts(meshlink_handle_t *mesh, const char *peer, devtool_node_status_t *st) {
	meshlink_node_t *node = meshlink_get_node(mesh, peer);

	assert(node);
	memset(st, 0, sizeof *st);
	devtool_get_node_status(mesh, node, st);
}

static void log_counts(const char *who, const devtool_node_status_t *st) {
	fprintf(stderr, "%s local discovery: runs=%u broadcasts=%u unicasts=%u skips=%u carrier_failures=%u confirms=%u reason=%s udp=%d\n",
	        who, st->local_discovery_runs, st->local_discovery_broadcasts, st->local_discovery_unicasts,
	        st->local_discovery_skips, st->local_discovery_carrier_failures, st->local_discovery_confirms,
	        st->local_discovery_skip_reason ? st->local_discovery_skip_reason : "-", st->udp_status);
}

static bool deliver(meshlink_handle_t *mesh, meshlink_node_t *peer, uint16_t port, const char *payload) {
	meshlink_channel_t *channel;

	reset_sync_flag(&accepted);
	reset_sync_flag(&received);
	channel = meshlink_channel_open(mesh, peer, port, receive_cb, NULL, 0);
	assert(channel);
	assert(wait_sync_flag(&accepted, 20));
	assert(meshlink_channel_send(mesh, channel, payload, strlen(payload)) == (ssize_t)strlen(payload));
	assert(wait_sync_flag(&received, 20));
	return true;
}

static bool reason_is(const devtool_node_status_t *st, const char *reason) {
	return st->local_discovery_skip_reason && !strcmp(st->local_discovery_skip_reason, reason);
}

/* No ladder ever armed, and the last refusal came after the key exchange.
   A refusal that still reads "no valid key" means the recheck never ran. */
static void assert_wan_refused(const devtool_node_status_t *st, bool strict) {
	assert(!st->local_discovery_runs);
	assert(!st->local_discovery_broadcasts && !st->local_discovery_unicasts);
	assert(!st->local_discovery_carrier_failures);

	if(strict) {
		assert(reason_is(st, NO_LAN_REASON));
	} else {
		assert(!st->local_discovery_skip_reason || reason_is(st, NO_LAN_REASON));
	}
}

/* App 10.1.0.2/24 and cam 10.2.0.2/24 are different subnets. Neither has
   on-link evidence for the other, so local discovery must refuse to probe. */
static bool wan_only(void) {
	peer_config_t *peers = setup_nat_hole_punch("ldeliga", false);
	meshlink_node_t *cam;
	devtool_node_status_t app_st;
	devtool_node_status_t cam_st;

	if(!peers) {
		fprintf(stderr, "local-discovery-eligibility: NAT topology unavailable\n");
		return false;
	}

	meshlink_set_channel_accept_cb(peers[2].mesh, accept_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after((cam = meshlink_get_node(peers[1].mesh, "cam")) != NULL, 20);
	assert_after(meshlink_get_node_reachability(peers[1].mesh, cam, NULL, NULL), 20);
	assert(deliver(peers[1].mesh, cam, 7, "Hello"));
	sleep(5);
	discovery_counts(peers[1].mesh, "cam", &app_st);
	discovery_counts(peers[2].mesh, "app", &cam_st);
	log_counts("wan app->cam", &app_st);
	log_counts("wan cam->app", &cam_st);
	assert_wan_refused(&app_st, true);
	assert_wan_refused(&cam_st, false);
	devtool_free_node_status(&app_st);
	devtool_free_node_status(&cam_st);

	assert(deliver(peers[1].mesh, cam, 8, "World"));
	close_nat_hole_punch(peers);
	return true;
}

/* 10.1.0.77 is on app's subnet and names no host. It earns a bounded unicast
   ladder after the key exchange, never a broadcast. */
static bool planted_false_local(void) {
	peer_config_t *peers = setup_nat_hole_punch("ldeligb", false);
	meshlink_node_t *cam;
	devtool_node_status_t st;
	struct sockaddr_in in;

	if(!peers) {
		fprintf(stderr, "local-discovery-eligibility: NAT topology unavailable\n");
		return false;
	}

	meshlink_set_channel_accept_cb(peers[2].mesh, accept_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after((cam = meshlink_get_node(peers[1].mesh, "cam")) != NULL, 20);
	assert_after(meshlink_get_node_reachability(peers[1].mesh, cam, NULL, NULL), 20);
	memset(&in, 0, sizeof in);
	in.sin_family = AF_INET;
	inet_pton(AF_INET, "10.1.0.77", &in.sin_addr);
	in.sin_port = htons(9);
	assert(devtool_plant_recent_address(peers[1].mesh, cam, (struct sockaddr *)&in));
	assert(deliver(peers[1].mesh, cam, 7, "Hello"));
	sleep(5);
	discovery_counts(peers[1].mesh, "cam", &st);
	log_counts("planted app->cam", &st);
	assert(st.local_discovery_runs >= 1);
	assert(!st.local_discovery_broadcasts);
	assert(st.local_discovery_unicasts <= st.local_discovery_runs * DISCOVERY_TRIES);
	assert(!reason_is(&st, "no valid key"));
	devtool_free_node_status(&st);

	assert(deliver(peers[1].mesh, cam, 8, "World"));
	close_nat_hole_punch(peers);
	return true;
}

static bool udp_working(meshlink_handle_t *mesh, const char *peer) {
	devtool_node_status_t st;
	bool working;

	discovery_counts(mesh, peer, &st);
	working = st.udp_status == DEVTOOL_UDP_WORKING;
	devtool_free_node_status(&st);
	return working;
}

/* Peers on one bridge. Key-ready arms a ladder, but a direct punch can confirm
   UDP before its timer fires. The controlled restart attempts discovery while
   holding the mesh lock, before inbound punch replies can cancel the ladder. */
static bool lan_still_discovers(void) {
	peer_config_t *peers = setup_relay_peer_nut("ldeliglan");
	meshlink_node_t *nut;
	devtool_node_status_t st;
	uint32_t runs_before;
	uint32_t sends_before;

	meshlink_set_channel_accept_cb(peers[2].mesh, accept_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(peers[i].mesh));
	}

	assert_after((nut = meshlink_get_node(peers[1].mesh, "nut")) != NULL, 20);
	assert_after(meshlink_get_node_reachability(peers[1].mesh, nut, NULL, NULL), 20);
	assert(deliver(peers[1].mesh, nut, 7, "Hello"));
	assert_after(udp_working(peers[1].mesh, "nut"), 20);
	discovery_counts(peers[1].mesh, "nut", &st);
	log_counts("lan peer->nut first", &st);
	assert(st.local_discovery_runs >= 1);
	assert(st.local_discovery_broadcasts <= st.local_discovery_runs * DISCOVERY_BROADCAST_TRIES);
	assert(!reason_is(&st, "no valid key"));
	runs_before = st.local_discovery_runs;
	sends_before = st.local_discovery_broadcasts + st.local_discovery_unicasts;
	devtool_free_node_status(&st);

	/* Startup probes may have spent the shared budget. This controlled carrier
	   check needs tokens for both the demotion's punch and the discovery tick. */
	devtool_set_probe_budget(peers[1].mesh, 30, 30, 2);
	assert(devtool_restart_local_discovery(peers[1].mesh, nut));
	assert_after(udp_working(peers[1].mesh, "nut"), 20);

	discovery_counts(peers[1].mesh, "nut", &st);
	log_counts("lan peer->nut restarted", &st);
	assert(st.local_discovery_runs > runs_before);
	assert(st.local_discovery_broadcasts + st.local_discovery_unicasts > sends_before);
	assert(st.local_discovery_broadcasts <= st.local_discovery_runs * DISCOVERY_BROADCAST_TRIES);
	devtool_free_node_status(&st);

	devtool_reset_node_counters(peers[1].mesh, nut, &st);
	devtool_free_node_status(&st);
	discovery_counts(peers[1].mesh, "nut", &st);
	assert(!st.local_discovery_runs && !st.local_discovery_broadcasts && !st.local_discovery_unicasts);
	assert(!st.local_discovery_skips && !st.local_discovery_carrier_failures && !st.local_discovery_confirms);
	devtool_free_node_status(&st);

	assert(deliver(peers[1].mesh, nut, 8, "World"));
	close_relay_peer_nut(peers);
	return true;
}

int main(void) {
	init_sync_flag(&accepted);
	init_sync_flag(&received);
	assert(wan_only());
	assert(planted_false_local());
	assert(lan_still_discovers());
	return 0;
}
