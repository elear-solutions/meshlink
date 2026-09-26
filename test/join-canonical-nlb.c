#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* Android-shaped fresh join: hostname canonical NLB, invitation URL is that
   hostname, first autoconnect is classified canonical, NLB stays out of recent[]. */

static struct sync_flag peer_reachable;
static devtool_node_status_t status_at_reachable;

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	if(!reachable || strcmp(node->name, "foo") || check_sync_flag(&peer_reachable)) {
		return;
	}

	devtool_get_node_status(mesh, node, &status_at_reachable);
	set_sync_flag(&peer_reachable, true);
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	assert(meshlink_destroy("join_canonical_nlb_conf.1"));
	assert(meshlink_destroy("join_canonical_nlb_conf.2"));

	meshlink_handle_t *foo = meshlink_open("join_canonical_nlb_conf.1", "foo", "join-canonical-nlb", DEV_CLASS_BACKBONE);
	meshlink_handle_t *bar = meshlink_open("join_canonical_nlb_conf.2", "bar", "join-canonical-nlb", DEV_CLASS_PORTABLE);
	assert(foo && bar);
	meshlink_enable_discovery(foo, false);
	meshlink_enable_discovery(bar, false);

	int foo_port = meshlink_get_port(foo);
	assert(foo_port > 0);

	int relay_port = 0;
	tcp_relay_t *relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", foo_port);
	char relay_port_str[16];
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);
	assert(meshlink_set_canonical_address(foo, meshlink_get_self(foo), "localhost", relay_port_str));

	assert(meshlink_start(foo));
	char *url = meshlink_invite_ex(foo, NULL, "bar", MESHLINK_INVITE_PUBLIC | MESHLINK_INVITE_IPV4);
	assert(url);
	assert(strstr(url, "localhost"));
	assert(meshlink_join(bar, url));
	free(url);

	meshlink_node_t *foo_on_bar = meshlink_get_node(bar, "foo");
	assert(foo_on_bar);
	forget_addresses(bar, foo_on_bar);

	init_sync_flag(&peer_reachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
	meshlink_set_node_status_cb(bar, status_cb);

	size_t mark = log_mark();
	assert(meshlink_start(bar));
	assert(wait_sync_flag(&peer_reachable, 20));
	meshlink_set_node_status_cb(bar, NULL);

	assert(status_at_reachable.meta_connected);
	assert(status_at_reachable.meta_via_canonical);
	assert(port_of(&status_at_reachable.meta_address) == relay_port);

	for(size_t i = 0; i < status_at_reachable.recent_count; i++) {
		assert(!addr_is(&status_at_reachable.recent[i], "127.0.0.1", relay_port)
		       || !(status_at_reachable.recent_cap[i] & 0x01));
	}

	devtool_free_node_status(&status_at_reachable);

	char recent_needle[128], canonical_needle[128];
	snprintf(recent_needle, sizeof recent_needle, "bar: Trying to connect to foo at 127.0.0.1 port %d (recent)", relay_port);
	snprintf(canonical_needle, sizeof canonical_needle, "bar: Trying to connect to foo at 127.0.0.1 port %d (canonical)", relay_port);
	assert(log_find(mark, recent_needle) < 0);
	assert(log_find(mark, canonical_needle) >= 0);

	printf("join-canonical-nlb ok: first META was canonical port %d, NLB absent from recent[]\n", relay_port);

	meshlink_stop(bar);
	meshlink_stop(foo);
	meshlink_close(bar);
	meshlink_close(foo);
	assert(meshlink_destroy("join_canonical_nlb_conf.1"));
	assert(meshlink_destroy("join_canonical_nlb_conf.2"));
	stop_tcp_relay(relay);

	/* Default invite is LOCAL-then-PUBLIC. Join hits foo's listen port, which
	   must not be planted as the hostname canonical cache. */
	assert(meshlink_destroy("join_canonical_local_conf.1"));
	assert(meshlink_destroy("join_canonical_local_conf.2"));

	foo = meshlink_open("join_canonical_local_conf.1", "foo", "join-canonical-local", DEV_CLASS_BACKBONE);
	bar = meshlink_open("join_canonical_local_conf.2", "bar", "join-canonical-local", DEV_CLASS_PORTABLE);
	assert(foo && bar);
	meshlink_enable_discovery(foo, false);
	meshlink_enable_discovery(bar, false);

	foo_port = meshlink_get_port(foo);
	assert(foo_port > 0);

	relay_port = 0;
	relay = start_tcp_relay("127.0.0.1", &relay_port, "127.0.0.1", foo_port);
	snprintf(relay_port_str, sizeof relay_port_str, "%d", relay_port);
	assert(meshlink_set_canonical_address(foo, meshlink_get_self(foo), "localhost", relay_port_str));

	assert(meshlink_start(foo));
	url = meshlink_invite(foo, NULL, "bar");
	assert(url);
	assert(meshlink_join(bar, url));
	free(url);

	foo_on_bar = meshlink_get_node(bar, "foo");
	assert(foo_on_bar);

	devtool_node_status_t planted;
	memset(&planted, 0, sizeof planted);
	devtool_get_node_status(bar, foo_on_bar, &planted);

	for(size_t i = 0; i < planted.canonical_resolved_count; i++) {
		assert(port_of(&planted.canonical_resolved[i]) != foo_port);
	}

	devtool_free_node_status(&planted);

	forget_addresses(bar, foo_on_bar);
	init_sync_flag(&peer_reachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
	meshlink_set_node_status_cb(bar, status_cb);
	assert(meshlink_start(bar));
	assert(wait_sync_flag(&peer_reachable, 20));
	meshlink_set_node_status_cb(bar, NULL);

	assert(status_at_reachable.meta_connected);
	assert(status_at_reachable.meta_via_canonical);

	devtool_free_node_status(&status_at_reachable);

	printf("join-canonical-nlb ok: LOCAL-first invite did not plant listen port %d as NLB\n", foo_port);

	meshlink_stop(bar);
	meshlink_stop(foo);
	meshlink_close(bar);
	meshlink_close(foo);
	assert(meshlink_destroy("join_canonical_local_conf.1"));
	assert(meshlink_destroy("join_canonical_local_conf.2"));
	stop_tcp_relay(relay);
	free_captured_log();
	return 0;
}
