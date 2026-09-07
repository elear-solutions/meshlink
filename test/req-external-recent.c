#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* T9: a REQ_EXTERNAL from a peer puts its external IP:port into recent[], a repeated
   REQ_EXTERNAL does not add a second copy, and a REQ_EXTERNAL that equals our own
   external IP:port (hairpin) is not remembered at all.

   Here a is directly connected to b, so the address that just authenticated stays in
   front and the REQ_EXTERNAL one is kept behind it as a fallback (over a canonical
   connection it goes to the front and is probed: see canonical-migrate T5).

   b advertises a TEST-NET-3 address as its external IP so the entry that comes from
   REQ_EXTERNAL cannot be confused with what UDP learns (127.0.0.1). */

#define EXT_IP "203.0.113.10"

static struct sync_flag peer_reachable;
static const char *watched_peer;

static int recent_occurrences(const devtool_node_status_t *st, const char *ip, int port) {
	int count = 0;

	for(size_t i = 0; i < st->recent_count; i++) {
		if(addr_is(&st->recent[i], ip, port)) {
			count++;
		}
	}

	return count;
}

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && !strcmp(node->name, watched_peer)) {
		set_sync_flag(&peer_reachable, true);
	}
}

struct pair {
	meshlink_handle_t *a;
	meshlink_handle_t *b;
	meshlink_node_t *a_b;
	int b_port;
	char conf_a[64];
	char conf_b[64];
};

/* a (PORTABLE) connects directly to b (STATIONARY) on loopback; b advertises EXT_IP.
   If self_ext is set, it becomes a's own external address before anything connects. */
static void open_direct_pair(struct pair *p, const char *prefix, const char *self_ext) {
	snprintf(p->conf_a, sizeof p->conf_a, "%s_conf.1", prefix);
	snprintf(p->conf_b, sizeof p->conf_b, "%s_conf.2", prefix);
	assert(meshlink_destroy(p->conf_a));
	assert(meshlink_destroy(p->conf_b));

	p->a = meshlink_open(p->conf_a, "a", prefix, DEV_CLASS_PORTABLE);
	p->b = meshlink_open(p->conf_b, "b", prefix, DEV_CLASS_STATIONARY);
	assert(p->a && p->b);

	meshlink_enable_discovery(p->a, false);
	meshlink_enable_discovery(p->b, false);

	p->b_port = meshlink_get_port(p->b);
	assert(p->b_port > 0);

	devtool_set_external_ip_address(p->b, meshlink_get_self(p->b), EXT_IP);

	if(self_ext) {
		devtool_set_external_ip_address(p->a, meshlink_get_self(p->a), self_ext);
	}

	exchange_meshlink_pair(p->a, p->b);

	p->a_b = meshlink_get_node(p->a, "b");
	assert(p->a_b);
	forget_addresses(p->a, p->a_b);
	hint_address(p->a, p->a_b, "127.0.0.1", p->b_port);

	watched_peer = "b";
	init_sync_flag(&peer_reachable);
	meshlink_set_node_status_cb(p->a, status_cb);
}

static void close_direct_pair(struct pair *p) {
	meshlink_stop(p->a);
	meshlink_stop(p->b);
	meshlink_close(p->a);
	meshlink_close(p->b);
	assert(meshlink_destroy(p->conf_a));
	assert(meshlink_destroy(p->conf_b));
}

static bool ext_in_recent(meshlink_handle_t *mesh, meshlink_node_t *node, int port) {
	devtool_node_status_t st;
	devtool_get_node_status(mesh, node, &st);
	bool found = recent_occurrences(&st, EXT_IP, port) > 0;
	devtool_free_node_status(&st);
	return found;
}

/* The REQ_EXTERNAL address is in recent[] exactly once, and everything in front of it
   is one of b's real addresses on b's port: the loopback address that authenticated,
   plus whatever UDP learned since (the container interface via broadcast probes). */
static void assert_ext_once_behind_real_addresses(struct pair *p) {
	devtool_node_status_t st;
	devtool_get_node_status(p->a, p->a_b, &st);

	assert(st.external_ip_address);
	char want_ext[64];
	snprintf(want_ext, sizeof want_ext, "%s %d", EXT_IP, p->b_port);
	assert(!strcmp(st.external_ip_address, want_ext));

	assert(st.recent_count >= 2);
	assert(recent_occurrences(&st, EXT_IP, p->b_port) == 1);
	assert(recent_occurrences(&st, "127.0.0.1", p->b_port) == 1);
	assert(!addr_is(&st.recent[0], EXT_IP, p->b_port));

	for(size_t i = 0; i < st.recent_count && !addr_is(&st.recent[i], EXT_IP, p->b_port); i++) {
		assert(port_of(&st.recent[i]) == p->b_port);
	}

	/* Direct connection, nothing to upgrade. */
	assert(st.meta_connected);
	assert(!st.meta_via_canonical);
	assert(!st.upgrade_probe_active);

	devtool_free_node_status(&st);
}

static void test_learn_and_dedupe(void) {
	printf("\n=== T9a: REQ_EXTERNAL lands in recent[] once, behind the authenticated address ===\n");

	struct pair p;
	open_direct_pair(&p, "req_external_recent_t9a", NULL);

	assert(meshlink_start(p.b));
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 15));

	assert_after(log_count("a: Got REQ_EXTERNAL from b") >= 1, 5);
	assert_after(ext_in_recent(p.a, p.a_b, p.b_port), 5);
	assert_ext_once_behind_real_addresses(&p);

	printf("T9a: learned %s:%d from REQ_EXTERNAL\n", EXT_IP, p.b_port);

	/* A second connection means a second REQ_KEY/REQ_EXTERNAL round trip. The
	   loopback address is still in front, so the reconnect is direct right away
	   and the repeated REQ_EXTERNAL must not add a second TEST-NET entry. */
	int got_before = log_count("a: Got REQ_EXTERNAL from b");
	init_sync_flag(&peer_reachable);
	meshlink_stop(p.a);
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 30));

	assert_after(log_count("a: Got REQ_EXTERNAL from b") > got_before, 10);
	assert_ext_once_behind_real_addresses(&p);

	printf("T9a ok: %d REQ_EXTERNALs received, one recent[] entry\n", log_count("a: Got REQ_EXTERNAL from b"));

	close_direct_pair(&p);
}

static void test_own_external_not_added(void) {
	printf("\n=== T9b: REQ_EXTERNAL equal to our own external IP:port is not remembered ===\n");

	/* a pins its own external address to what b will advertise: same public IP:port
	   means a hairpin, which is never a useful direct address for b. b_port is only
	   known after open, so the pair is opened first and a's external set from it. */
	struct pair p;
	open_direct_pair(&p, "req_external_recent_t9b", NULL);

	char self_ext[64];
	snprintf(self_ext, sizeof self_ext, "%s %d", EXT_IP, p.b_port);
	devtool_set_external_ip_address(p.a, meshlink_get_self(p.a), self_ext);

	assert(meshlink_start(p.b));
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 15));

	assert_after(log_count("a: Got REQ_EXTERNAL from b") >= 1, 5);
	assert_after(log_count("a: Not remembering REQ_EXTERNAL address of b: it is our own external address") >= 1, 5);

	devtool_node_status_t st;
	devtool_get_node_status(p.a, p.a_b, &st);
	assert(recent_occurrences(&st, EXT_IP, p.b_port) == 0);
	assert(recent_occurrences(&st, "127.0.0.1", p.b_port) == 1);

	/* Whatever else is there was learned over UDP from b's real interfaces. */
	for(size_t i = 0; i < st.recent_count; i++) {
		assert(port_of(&st.recent[i]) == p.b_port);
	}

	devtool_free_node_status(&st);

	printf("T9b ok: own external %s not added, recent[] only holds b's real addresses\n", self_ext);

	close_direct_pair(&p);
}

/* T9c: a learns b only through c. A forwarded REQ_EXTERNAL must not land at
   recent[0] when a has no proven address for b — that would make the next
   outgoing walk dial the untrusted address first. */
static void test_forwarded_empty_recent(void) {
	printf("\n=== T9c: forwarded REQ_EXTERNAL is not remembered when recent[] is empty ===\n");

	assert(meshlink_destroy("req_ext_t9c_conf.1"));
	assert(meshlink_destroy("req_ext_t9c_conf.2"));
	assert(meshlink_destroy("req_ext_t9c_conf.3"));

	meshlink_handle_t *a = meshlink_open("req_ext_t9c_conf.1", "a", "req_ext_t9c", DEV_CLASS_STATIONARY);
	meshlink_handle_t *b = meshlink_open("req_ext_t9c_conf.2", "b", "req_ext_t9c", DEV_CLASS_STATIONARY);
	meshlink_handle_t *c = meshlink_open("req_ext_t9c_conf.3", "c", "req_ext_t9c", DEV_CLASS_BACKBONE);
	assert(a && b && c);

	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	meshlink_enable_discovery(c, false);

	int c_port = meshlink_get_port(c);
	int b_port = meshlink_get_port(b);
	assert(c_port > 0 && b_port > 0);

	devtool_set_external_ip_address(b, meshlink_get_self(b), EXT_IP);

	exchange_meshlink_pair(a, c);
	exchange_meshlink_pair(b, c);
	exchange_meshlink_pair(a, b);

	meshlink_node_t *a_c = meshlink_get_node(a, "c");
	meshlink_node_t *a_b = meshlink_get_node(a, "b");
	meshlink_node_t *b_c = meshlink_get_node(b, "c");
	assert(a_c && a_b && b_c);

	forget_addresses(a, a_c);
	hint_address(a, a_c, "127.0.0.1", c_port);
	forget_addresses(a, a_b);
	assert(meshlink_clear_canonical_address(a, a_b));
	forget_addresses(b, b_c);
	hint_address(b, b_c, "127.0.0.1", c_port);

	assert(meshlink_start(c));
	assert(meshlink_start(a));
	assert(meshlink_start(b));
	assert_after(meshlink_get_node_reachability(a, a_c, NULL, NULL), 15);
	assert_after(meshlink_get_node_reachability(b, b_c, NULL, NULL), 15);

	/* Reachable through c is enough for the UDP key path to forward REQ_EXTERNAL. */
	assert_after(meshlink_get_node_reachability(a, a_b, NULL, NULL), 15);
	forget_addresses(a, a_b);
	assert_after(log_count("a: Got REQ_EXTERNAL from b") >= 1, 10);

	devtool_node_status_t st;
	devtool_get_node_status(a, a_b, &st);

	if(recent_occurrences(&st, EXT_IP, b_port) > 0) {
		assert(!addr_is(&st.recent[0], EXT_IP, b_port));
	}

	devtool_free_node_status(&st);

	printf("T9c ok: forwarded REQ_EXTERNAL did not become recent[0]\n");

	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_stop(c);
	meshlink_close(a);
	meshlink_close(b);
	meshlink_close(c);
	assert(meshlink_destroy("req_ext_t9c_conf.1"));
	assert(meshlink_destroy("req_ext_t9c_conf.2"));
	assert(meshlink_destroy("req_ext_t9c_conf.3"));
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	test_learn_and_dedupe();
	test_own_external_not_added();
	test_forwarded_empty_recent();

	free_captured_log();
	return 0;
}
