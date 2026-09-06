#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/meshlink.h"
#include "utils.h"

static struct sync_flag probe_log_flag;
static struct sync_flag probe_reply_flag;
static int probe_request_logs;
static int probe_reply_logs;

static void probe_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	int probe_len = 0;
	char node_name[64];
	char address[128];
	char port[32];

	log_cb(mesh, level, text);

	if(sscanf(text, "Sending MTU probe length %d to %63s at %127s port %31s",
	                &probe_len, node_name, address, port) == 4) {
		assert(probe_len >= 64);
		assert(node_name[0]);
		assert(address[0]);
		assert(port[0]);
		probe_request_logs++;
		set_sync_flag(&probe_log_flag, true);
	} else if(strstr(text, "Sending MTU probe reply")) {
		probe_reply_logs++;
		set_sync_flag(&probe_reply_flag, true);
	}
}

int main(void) {
	init_sync_flag(&probe_log_flag);
	init_sync_flag(&probe_reply_flag);
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, probe_log_cb);

	meshlink_handle_t *mesh_a, *mesh_b;
	open_meshlink_pair(&mesh_a, &mesh_b, "mtu-probe-log");

	meshlink_set_log_cb(mesh_a, MESHLINK_DEBUG, probe_log_cb);
	meshlink_set_log_cb(mesh_b, MESHLINK_DEBUG, probe_log_cb);

	start_meshlink_pair(mesh_a, mesh_b);

	assert(wait_sync_flag(&probe_log_flag, 15));
	assert(wait_sync_flag(&probe_reply_flag, 15));

	assert(probe_request_logs >= 1);
	assert(probe_reply_logs >= 1);

	close_meshlink_pair(mesh_a, mesh_b);
	return 0;
}
