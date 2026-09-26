#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "meshlink.h"
#include "utils.h"

/* After finding 5, META is a star: cameras dial the stored backbone only.
   The old all-BACKBONE import chain never comes up, and two nodes with the
   same name cannot build independent META paths until finding 7. Production
   already refuses a second invitation for a live name. */

static struct sync_flag foo_up;

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && !strcmp(node->name, "foo")) {
		set_sync_flag(&foo_up, true);
	}
}

int main(void) {
	init_sync_flag(&foo_up);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	assert(meshlink_destroy("duplicate_conf.hub"));
	assert(meshlink_destroy("duplicate_conf.foo"));
	assert(meshlink_destroy("duplicate_conf.bar"));
	assert(meshlink_destroy("duplicate_conf.foo2"));

	meshlink_handle_t *hub = meshlink_open("duplicate_conf.hub", "hub", "duplicate", DEV_CLASS_BACKBONE);
	meshlink_handle_t *foo = meshlink_open("duplicate_conf.foo", "foo", "duplicate", DEV_CLASS_STATIONARY);
	meshlink_handle_t *bar = meshlink_open("duplicate_conf.bar", "bar", "duplicate", DEV_CLASS_STATIONARY);
	meshlink_handle_t *foo2 = meshlink_open("duplicate_conf.foo2", "foo", "duplicate", DEV_CLASS_STATIONARY);
	assert(hub && foo && bar && foo2);

	meshlink_enable_discovery(hub, false);
	meshlink_enable_discovery(foo, false);
	meshlink_enable_discovery(bar, false);
	meshlink_enable_discovery(foo2, false);

	assert(meshlink_set_canonical_address(hub, meshlink_get_self(hub), "localhost", NULL));
	join_meshlink_peer(hub, foo);
	join_meshlink_peer(hub, bar);

	meshlink_set_node_status_cb(hub, status_cb);
	assert(meshlink_start(foo));
	assert(meshlink_start(bar));
	assert(wait_sync_flag(&foo_up, 15));

	meshlink_errno = MESHLINK_OK;
	char *again = meshlink_invite(hub, NULL, "foo");
	assert(!again);
	assert(meshlink_errno == MESHLINK_EEXIST);

	meshlink_close(hub);
	meshlink_close(foo);
	meshlink_close(bar);
	meshlink_close(foo2);
	assert(meshlink_destroy("duplicate_conf.hub"));
	assert(meshlink_destroy("duplicate_conf.foo"));
	assert(meshlink_destroy("duplicate_conf.bar"));
	assert(meshlink_destroy("duplicate_conf.foo2"));
}
