#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

#define PKT_RELAY_SPTPS 8
#define MTU 1451

static struct sync_flag received;
static struct sync_flag bar_learned;
static struct sync_flag baz_learned;
static struct sync_flag leftover_udp;
static struct sync_flag dest_down;
static struct sync_flag foo_down;

static bool leftover(const char *text) {
	return text && (strstr(text, "Ignoring failed REQ_SPTPS via UDP")
	                || strstr(text, "Got REQ_SPTPS via UDP")
	                || strstr(text, "Sending REQ_SPTPS via UDP"));
}

static void any_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	if(leftover(text)) {
		set_sync_flag(&leftover_udp, true);
	}

	log_cb(mesh, level, text);
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)port;
	(void)data;
	(void)len;
	return true;
}

static void chan_recv(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;
	(void)len;
}

static void receive_cb(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len) {
	(void)mesh;
	(void)source;

	if(len == 5 && !memcmp(data, "Hello", 5)) {
		set_sync_flag(&received, true);
	}
}

static void bar_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;
	(void)reachable;

	if(!strcmp(node->name, "baz") || !strcmp(node->name, "foo")) {
		set_sync_flag(&bar_learned, true);
	}
}

static void baz_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(!strcmp(node->name, "bar") && !reachable) {
		set_sync_flag(&dest_down, true);
	}

	if(!strcmp(node->name, "foo") && !reachable) {
		set_sync_flag(&foo_down, true);
	}

	if(!strcmp(node->name, "bar") || !strcmp(node->name, "foo")) {
		set_sync_flag(&baz_learned, true);
	}
}

static bool udp_working(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *n = meshlink_get_node(mesh, name);

	if(!n) {
		return false;
	}

	devtool_node_status_t st;
	devtool_get_node_status(mesh, n, &st);
	bool ok = st.udp_status == DEVTOOL_UDP_WORKING;
	devtool_free_node_status(&st);
	return ok;
}

static bool hop_key_ready(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *n = meshlink_get_node(mesh, name);

	if(!n || !meshlink_get_node_reachability(mesh, n, NULL, NULL)) {
		return false;
	}

	devtool_node_status_t st;
	devtool_get_node_status(mesh, n, &st);
	bool ok = st.validkey;
	devtool_free_node_status(&st);
	return ok;
}

static void wait_hop_udp(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *n = meshlink_get_node(mesh, name);

	assert(n);
	assert_after(hop_key_ready(mesh, name), 20);
	devtool_set_udp_confirmed(mesh, n, true);
}

static void wait_keys(meshlink_handle_t **mesh) {
	/* Star: cameras have UDP to the backbone, not to each other. */
	assert_after(udp_working(mesh[2], "foo") && udp_working(mesh[1], "foo"), 25);
}

static void send_hello(meshlink_handle_t *from, const char *dest) {
	meshlink_node_t *dst = meshlink_get_node(from, dest);
	assert(dst);

	for(int i = 0; i < 10; i++) {
		set_sync_flag(&received, false);
		assert(meshlink_send(from, dst, "Hello", 5));

		if(wait_sync_flag(&received, 1)) {
			return;
		}
	}

	assert(wait_sync_flag(&received, 5));
}

static void test_einval(void) {
	assert(!devtool_force_relay_path(NULL, NULL, NULL));
	devtool_set_udp_confirmed(NULL, NULL, false);
	assert(!devtool_send_raw_record(NULL, NULL, 0, NULL, 0));
	assert(!devtool_set_minmtu(NULL, NULL, 0));
	devtool_clear_relay_reports(NULL);
	assert(!devtool_seed_relay_report(NULL, NULL, NULL, 0, false));
	assert(!devtool_has_relay_report(NULL, NULL, NULL));
	assert(!devtool_relay_report_have_reported(NULL, NULL, NULL));
	assert(devtool_relay_report_count(NULL) == 0);
	assert(!devtool_fill_relay_reports(NULL, 1, 0, false));
	devtool_fail_relay_reports(NULL, true);
	assert(!devtool_handle_relay_aliased(NULL, NULL, NULL, 0));
	assert(!devtool_send_meta_sptps(NULL, NULL, 0, NULL, 0));
	devtool_fail_relay_realloc(NULL, true);
	assert(!devtool_handle_req_relay_mtu(NULL, NULL, NULL));
	assert(!devtool_relay_cover_unit(NULL, NULL, NULL, NULL));
}

int main(void) {
	init_sync_flag(&received);
	init_sync_flag(&bar_learned);
	init_sync_flag(&baz_learned);
	init_sync_flag(&leftover_udp);
	init_sync_flag(&dest_down);
	init_sync_flag(&foo_down);

	test_einval();

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, any_log);

	const char *name[3] = {"foo", "bar", "baz"};
	meshlink_handle_t *mesh[3];
	char *data[3];

	for(int i = 0; i < 3; i++) {
		char *path = NULL;
		assert(asprintf(&path, "relay_cover_conf.%d", i) != -1 && path);
		assert(meshlink_destroy(path));
		mesh[i] = meshlink_open(path, name[i], "relay-cover", i ? DEV_CLASS_STATIONARY : DEV_CLASS_BACKBONE);
		assert(mesh[i]);
		free(path);

		if(!i) {
			devtool_set_external_ip_address(mesh[i], meshlink_get_self(mesh[i]), "127.0.0.1");
		}

		assert(meshlink_set_canonical_address(mesh[i], meshlink_get_self(mesh[i]), "localhost", NULL));
		meshlink_enable_discovery(mesh[i], false);
		data[i] = meshlink_export(mesh[i]);
		assert(data[i]);
	}

	join_meshlink_peer(mesh[0], mesh[1]);
	join_meshlink_peer(mesh[0], mesh[2]);
	for(int i = 0; i < 3; i++) {
		free(data[i]);
	}

	meshlink_set_log_cb(mesh[0], MESHLINK_DEBUG, any_log);
	meshlink_set_log_cb(mesh[1], MESHLINK_DEBUG, any_log);
	meshlink_set_log_cb(mesh[2], MESHLINK_DEBUG, any_log);
	meshlink_set_node_status_cb(mesh[1], bar_status_cb);
	meshlink_set_node_status_cb(mesh[2], baz_status_cb);
	meshlink_set_receive_cb(mesh[1], receive_cb);

	for(int i = 0; i < 3; i++) {
		assert(meshlink_start(mesh[i]));
	}

	assert(wait_sync_flag(&bar_learned, 10));
	assert(wait_sync_flag(&baz_learned, 10));
	wait_keys(mesh);

	send_hello(mesh[2], "bar");
	assert(!check_sync_flag(&leftover_udp));

	assert(devtool_handle_req_relay_mtu(mesh[2], meshlink_get_node(mesh[2], "foo"), "bad"));
	devtool_fail_relay_realloc(mesh[2], false);

	assert(devtool_set_minmtu(mesh[2], meshlink_get_node(mesh[2], "foo"), MTU));
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), true);
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "foo"), true);
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "bar"), true);
	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "bar"), false);

	uint8_t raw[8] = { 0 };
	assert(devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "foo"), PKT_RELAY_SPTPS, raw, sizeof(raw)));

	assert(!devtool_force_relay_path(mesh[2], NULL, meshlink_get_node(mesh[2], "foo")));
	assert(!devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], "bar"), meshlink_get_node(mesh[2], "bar")));

	assert(meshlink_destroy("relay_cover_conf.qux"));
	meshlink_handle_t *qux = meshlink_open("relay_cover_conf.qux", "qux", "relay-cover", DEV_CLASS_BACKBONE);
	assert(qux);
	char *qux_export = meshlink_export(qux);
	assert(qux_export);
	assert(meshlink_import(mesh[2], qux_export));
	free(qux_export);
	meshlink_close(qux);
	assert_after(meshlink_get_node(mesh[2], "qux"), 5);
	assert(!devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], "bar"), meshlink_get_node(mesh[2], "qux")));

	assert(devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], "bar"), meshlink_get_node(mesh[2], "foo")));
	meshlink_hint_network_change(mesh[2]);
	send_hello(mesh[2], "bar");

	set_sync_flag(&foo_down, false);
	meshlink_stop(mesh[0]);
	assert(wait_sync_flag(&foo_down, 20));
	/* Star: cameras have no graph path once the unique backbone is down.
	   A send must not emit leftover ASCII REQ_SPTPS via UDP. */
	set_sync_flag(&received, false);
	assert(meshlink_send(mesh[2], meshlink_get_node(mesh[2], "bar"), "Hello", 5));
	sleep(1);
	assert(!check_sync_flag(&leftover_udp));

	assert(meshlink_start(mesh[0]));
	wait_hop_udp(mesh[2], "foo");
	assert(devtool_force_relay_path(mesh[2], meshlink_get_node(mesh[2], "bar"), meshlink_get_node(mesh[2], "foo")));

	set_sync_flag(&dest_down, false);
	meshlink_stop(mesh[1]);
	assert(wait_sync_flag(&dest_down, 20));

	assert(meshlink_start(mesh[1]));
	wait_hop_udp(mesh[2], "foo");

	meshlink_set_channel_accept_cb(mesh[1], accept_cb);
	meshlink_channel_t *ch = meshlink_channel_open(mesh[2], meshlink_get_node(mesh[2], "bar"), 1, chan_recv, NULL, 0);
	assert(ch);
	usleep(200000);

	assert(devtool_relay_cover_unit(mesh[2], meshlink_get_node(mesh[2], "foo"),
	                               meshlink_get_node(mesh[2], "bar"), meshlink_get_node(mesh[2], "foo")));

	devtool_clear_relay_reports(mesh[2]);
	assert(devtool_seed_relay_report(mesh[2], "foo", "bar", 0, true));
	assert(devtool_has_relay_report(mesh[2], "foo", "bar"));
	assert(devtool_relay_report_have_reported(mesh[2], "foo", "bar"));
	assert(devtool_relay_report_count(mesh[2]) >= 1);
	assert(devtool_fill_relay_reports(mesh[2], 2, 1, false));
	devtool_fail_relay_reports(mesh[2], false);
	devtool_fail_relay_realloc(mesh[2], false);
	assert(devtool_handle_req_relay_mtu(mesh[2], meshlink_get_node(mesh[2], "foo"), "0 foo baz 21 bar 100"));

	devtool_set_udp_confirmed(mesh[2], meshlink_get_node(mesh[2], "bar"), true);
	(void)devtool_send_raw_record(mesh[2], meshlink_get_node(mesh[2], "bar"), 0, NULL, 0);
	meshlink_channel_abort(mesh[2], ch);

	assert(meshlink_destroy("relay_cover_conf.qux"));

	for(int i = 0; i < 3; i++) {
		meshlink_close(mesh[i]);
		char *path = NULL;
		assert(asprintf(&path, "relay_cover_conf.%d", i) != -1 && path);
		assert(meshlink_destroy(path));
		free(path);
	}

	assert(!check_sync_flag(&leftover_udp));
	return 0;
}
