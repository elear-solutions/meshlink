#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>

#include "meshlink.h"
#include "utils.h"

static struct sync_flag bar_reachable;
static struct sync_flag pmtu_flag;

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && !strcmp(node->name, "bar")) {
		set_sync_flag(&bar_reachable, true);
	}
}

static void pmtu_cb(meshlink_handle_t *mesh, meshlink_node_t *node, uint16_t pmtu) {
	(void)mesh;

	if(pmtu && !strcmp(node->name, "bar")) {
		set_sync_flag(&pmtu_flag, true);
	}
}

int main(void) {
	init_sync_flag(&bar_reachable);
	init_sync_flag(&pmtu_flag);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	assert(meshlink_destroy("import_export_conf.1"));
	assert(meshlink_destroy("import_export_conf.2"));

	meshlink_handle_t *mesh1 = meshlink_open("import_export_conf.1", "foo", "import-export", DEV_CLASS_BACKBONE);
	assert(mesh1);

	meshlink_handle_t *mesh2 = meshlink_open("import_export_conf.2", "bar", "import-export", DEV_CLASS_STATIONARY);
	assert(mesh2);

	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	assert(meshlink_set_canonical_address(mesh1, meshlink_get_self(mesh1), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh2, meshlink_get_self(mesh2), "localhost", NULL));

	char *data = meshlink_export(mesh1);
	assert(data);

	assert(meshlink_import(mesh2, data));
	free(data);

	data = meshlink_export(mesh2);
	assert(data);

	assert(meshlink_import(mesh1, data));

	/* Importing twice is fine */
	assert(meshlink_import(mesh1, data));
	free(data);

	assert(!meshlink_import(mesh1, "Garbage\n"));

	time_t last_reachable;
	time_t last_unreachable;
	meshlink_node_t *bar = meshlink_get_node(mesh1, "bar");
	assert(bar);
	assert(!meshlink_get_node_reachability(mesh1, bar, &last_reachable, &last_unreachable));
	assert(!last_reachable);
	assert(!last_unreachable);

	/* Import does not elect a backbone. Join so bar owns a BACKBONE_REQUIRED intent. */
	meshlink_close(mesh1);
	meshlink_close(mesh2);
	assert(meshlink_destroy("import_export_conf.1"));
	assert(meshlink_destroy("import_export_conf.2"));

	mesh1 = meshlink_open("import_export_conf.1", "foo", "import-export", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("import_export_conf.2", "bar", "import-export", DEV_CLASS_STATIONARY);
	assert(mesh1 && mesh2);
	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);
	assert(meshlink_set_canonical_address(mesh1, meshlink_get_self(mesh1), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh2, meshlink_get_self(mesh2), "localhost", NULL));
	join_meshlink_peer(mesh1, mesh2);

	bar = meshlink_get_node(mesh1, "bar");
	assert(bar);
	assert(!meshlink_get_node_reachability(mesh1, bar, &last_reachable, &last_unreachable));

	meshlink_set_node_status_cb(mesh1, status_cb);
	meshlink_set_node_pmtu_cb(mesh1, pmtu_cb);

	assert(meshlink_start(mesh2));

	assert(wait_sync_flag(&bar_reachable, 10));
	assert(wait_sync_flag(&pmtu_flag, 10));

	assert(meshlink_get_node_reachability(mesh1, bar, &last_reachable, &last_unreachable));
	assert(last_reachable);

	meshlink_stop(mesh1);
	meshlink_stop(mesh2);

	assert(!meshlink_get_node_reachability(mesh1, bar, &last_reachable, &last_unreachable));
	assert(last_reachable);
	assert(last_unreachable);
	assert(last_reachable <= last_unreachable);

	meshlink_close(mesh2);
	meshlink_close(mesh1);
	assert(meshlink_destroy("import_export_conf.1"));
	assert(meshlink_destroy("import_export_conf.2"));
}
