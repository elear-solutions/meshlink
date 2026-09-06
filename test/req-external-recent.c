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

/* T9: a REQ_EXTERNAL from a peer puts its external IP:port at the front of recent[],
   a repeated REQ_EXTERNAL does not add a second copy, and a REQ_EXTERNAL that equals
   our own external IP:port (hairpin) is not remembered at all.

   b advertises a TEST-NET-3 address as its external IP so the entry that comes from
   REQ_EXTERNAL cannot be confused with what UDP learns (127.0.0.1). */

#define EXT_IP "203.0.113.10"

static struct sync_flag peer_reachable;
static const char *watched_peer;

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char *captured_log;
static size_t captured_len;

static void capture_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	log_cb(mesh, level, text);

	assert(pthread_mutex_lock(&log_mutex) == 0);
	size_t add = strlen(text) + 32;
	captured_log = realloc(captured_log, captured_len + add + 1);
	assert(captured_log);
	captured_len += snprintf(captured_log + captured_len, add + 1, "%s: %s\n", mesh ? mesh->name : "-", text);
	assert(pthread_mutex_unlock(&log_mutex) == 0);
}

static int log_count(const char *needle) {
	int count = 0;

	assert(pthread_mutex_lock(&log_mutex) == 0);

	for(const char *p = captured_log; p && (p = strstr(p, needle)); p++) {
		count++;
	}

	assert(pthread_mutex_unlock(&log_mutex) == 0);
	return count;
}

static struct sockaddr_in ipv4(const char *ip, uint16_t port) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	assert(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
	return sa;
}

static bool addr_is(const struct sockaddr_storage *ss, const char *ip, int port) {
	if(ss->ss_family != AF_INET) {
		return false;
	}

	struct sockaddr_in want = ipv4(ip, (uint16_t)port);
	const struct sockaddr_in *got = (const struct sockaddr_in *)ss;
	return got->sin_addr.s_addr == want.sin_addr.s_addr && got->sin_port == want.sin_port;
}

static int port_of(const struct sockaddr_storage *ss) {
	if(ss->ss_family == AF_INET) {
		return ntohs(((const struct sockaddr_in *)ss)->sin_port);
	}

	if(ss->ss_family == AF_INET6) {
		return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
	}

	return -1;
}

static int recent_occurrences(const devtool_node_status_t *st, const char *ip, int port) {
	int count = 0;

	for(size_t i = 0; i < st->recent_count; i++) {
		if(addr_is(&st->recent[i], ip, port)) {
			count++;
		}
	}

	return count;
}

static void forget_addresses(meshlink_handle_t *mesh, meshlink_node_t *node) {
	struct sockaddr_in unset;
	memset(&unset, 0, sizeof unset);
	unset.sin_family = AF_UNSPEC;
	devtool_update_node_udp(mesh, node, (struct sockaddr *)&unset);
}

static void hint(meshlink_handle_t *mesh, meshlink_node_t *node, const char *ip, int port) {
	struct sockaddr_in sa = ipv4(ip, (uint16_t)port);
	meshlink_hint_address(mesh, node, (struct sockaddr *)&sa);
}

static void exchange(meshlink_handle_t *a, meshlink_handle_t *b) {
	char *data = meshlink_export(a);
	assert(data);
	assert(meshlink_import(b, data));
	free(data);

	data = meshlink_export(b);
	assert(data);
	assert(meshlink_import(a, data));
	free(data);
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

	exchange(p->a, p->b);

	p->a_b = meshlink_get_node(p->a, "b");
	assert(p->a_b);
	forget_addresses(p->a, p->a_b);
	hint(p->a, p->a_b, "127.0.0.1", p->b_port);

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

/* The REQ_EXTERNAL address went to the front when it arrived. The only other thing
   that touches recent[] on a afterwards is UDP learning b's real addresses (loopback,
   and the container interface via broadcast probes), all on b's port; those may have
   been moved in front of it since. */
static void assert_ext_front_and_once(struct pair *p) {
	devtool_node_status_t st;
	devtool_get_node_status(p->a, p->a_b, &st);

	assert(st.external_ip_address);
	char want_ext[64];
	snprintf(want_ext, sizeof want_ext, "%s %d", EXT_IP, p->b_port);
	assert(!strcmp(st.external_ip_address, want_ext));

	assert(st.recent_count >= 2);
	assert(recent_occurrences(&st, EXT_IP, p->b_port) == 1);
	assert(recent_occurrences(&st, "127.0.0.1", p->b_port) == 1);

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
	printf("\n=== T9a: REQ_EXTERNAL lands in recent[] once, at the front ===\n");

	struct pair p;
	open_direct_pair(&p, "req_external_recent_t9a", NULL);

	assert(meshlink_start(p.b));
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 15));

	assert_after(log_count("a: Got REQ_EXTERNAL from b") >= 1, 5);
	assert_after(ext_in_recent(p.a, p.a_b, p.b_port), 5);
	assert_ext_front_and_once(&p);

	printf("T9a: learned %s:%d from REQ_EXTERNAL\n", EXT_IP, p.b_port);

	/* A second connection means a second REQ_KEY/REQ_EXTERNAL round trip. The
	   TEST-NET address is now first in recent[], so the reconnect tries it (and
	   fails) before the loopback address: that is the direct-first order at work. */
	int got_before = log_count("a: Got REQ_EXTERNAL from b");
	init_sync_flag(&peer_reachable);
	meshlink_stop(p.a);
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 30));

	assert_after(log_count("a: Got REQ_EXTERNAL from b") > got_before, 10);
	assert_ext_front_and_once(&p);

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

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);

	test_learn_and_dedupe();
	test_own_external_not_added();

	free(captured_log);
	return 0;
}
