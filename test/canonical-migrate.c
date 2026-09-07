#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* Hitless migration of a meta connection from the canonical (relay) address to a
   direct one, driven by the upgrade probe.

   T5:  connect via relay, learn a direct address from REQ_EXTERNAL, migrate: the
        node never goes unreachable, a channel keeps streaming, the relay saw one connect.
   T6:  the first direct address is a black hole: probes back off (5s, 10s) while the
        relay connection stays up and the channel keeps streaming; a real address then wins.
   T7:  two nodes that both reach each other via relays end with one connection each
        and no "Two outgoing connections" warning.
   T8:  the peer dies while migrated: the reconnect tries its direct port first, falls
        back to the relay once the peer is back on a new port, then re-migrates.
   T14: a third node connected to the peer keeps seeing the migrating node as
        reachable and ends up with exactly one edge pair between the two.
   T15: a third node does not seed the relay's address from the indirect edge.
   T16: a peer that repeats its ACK over a probe held as a spare is rejected. */

#define MSG_LEN 6

/* --- upgrade probe hook ----------------------------------------------------- */

static size_t stream_bytes(void);

struct probe_event {
	time_t when;
	devtool_upgrade_probe_stage_t stage;
	char mesh[16];
	char node[16];
	bool canonical_still_up;    /* peer's meta connection active and via canonical at this event */
	int backoff;                /* peer's upgrade_backoff right after this event */
	size_t streamed;            /* bytes the channel stream had delivered at this event */
};

static pthread_mutex_t probe_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct probe_event probe_events[64];
static int nprobe_events;
static struct sync_flag probe_succeeded;
static struct sync_flag probe_failed;

static void upgrade_probe_hook(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_upgrade_probe_stage_t stage) {
	devtool_node_status_t st;
	devtool_get_node_status(mesh, node, &st);

	assert(pthread_mutex_lock(&probe_mutex) == 0);

	if(nprobe_events < 64) {
		struct probe_event *ev = &probe_events[nprobe_events++];
		ev->when = time(NULL);
		ev->stage = stage;
		snprintf(ev->mesh, sizeof ev->mesh, "%s", mesh->name);
		snprintf(ev->node, sizeof ev->node, "%s", node->name);
		ev->canonical_still_up = st.meta_connected && st.meta_via_canonical;
		ev->backoff = st.upgrade_backoff;
		ev->streamed = stream_bytes();
	}

	assert(pthread_mutex_unlock(&probe_mutex) == 0);
	devtool_free_node_status(&st);

	fprintf(stderr, "*** upgrade probe %s -> %s: %s (backoff %d)\n", mesh->name, node->name,
	        stage == DEVTOOL_UPGRADE_PROBE_STARTED ? "started" : stage == DEVTOOL_UPGRADE_PROBE_SUCCEEDED ? "succeeded" : "failed", st.upgrade_backoff);

	if(stage == DEVTOOL_UPGRADE_PROBE_SUCCEEDED) {
		set_sync_flag(&probe_succeeded, true);
	} else if(stage == DEVTOOL_UPGRADE_PROBE_FAILED) {
		set_sync_flag(&probe_failed, true);
	}
}

static void reset_probe_events(void) {
	assert(pthread_mutex_lock(&probe_mutex) == 0);
	nprobe_events = 0;
	memset(probe_events, 0, sizeof probe_events);
	assert(pthread_mutex_unlock(&probe_mutex) == 0);
	init_sync_flag(&probe_succeeded);
	init_sync_flag(&probe_failed);
}

static int count_probe_events(devtool_upgrade_probe_stage_t stage) {
	int count = 0;
	assert(pthread_mutex_lock(&probe_mutex) == 0);

	for(int i = 0; i < nprobe_events; i++) {
		if(probe_events[i].stage == stage) {
			count++;
		}
	}

	assert(pthread_mutex_unlock(&probe_mutex) == 0);
	return count;
}

/* Bytes the stream had delivered when the (first) SUCCEEDED event was recorded. */
static size_t streamed_at_success(void) {
	size_t streamed = 0;
	assert(pthread_mutex_lock(&probe_mutex) == 0);

	for(int i = 0; i < nprobe_events; i++) {
		if(probe_events[i].stage == DEVTOOL_UPGRADE_PROBE_SUCCEEDED) {
			streamed = probe_events[i].streamed;
			break;
		}
	}

	assert(pthread_mutex_unlock(&probe_mutex) == 0);
	return streamed;
}

/* --- node / meta status ----------------------------------------------------- */

static pthread_mutex_t status_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sync_flag peer_reachable;
static struct sync_flag peer_unreachable;
static devtool_node_status_t status_at_reachable;
static const char *watched_peer;
static int unreachable_count;
static int hint_port_on_reachable;  /* T6/T16: direct address to hint the moment the peer comes up, 0 = none */
static bool repeat_ack_on_reachable; /* T16: make the probe started by that hint send its ACK twice */

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	if(strcmp(node->name, watched_peer)) {
		return;
	}

	if(!reachable) {
		assert(pthread_mutex_lock(&status_mutex) == 0);
		unreachable_count++;
		assert(pthread_mutex_unlock(&status_mutex) == 0);
		set_sync_flag(&peer_unreachable, true);
		return;
	}

	if(check_sync_flag(&peer_reachable)) {
		return;
	}

	/* Runs inside ack_h(), before the key exchange: nothing has been learned over
	   UDP yet, so a hinted address is the only direct address and is probed first.
	   Our own ACK for this connection has already been sent, so the next one is the probe's. */
	if(hint_port_on_reachable) {
		devtool_repeat_next_ack = repeat_ack_on_reachable;
		hint_address(mesh, node, "127.0.0.1", hint_port_on_reachable);
	}

	devtool_get_node_status(mesh, node, &status_at_reachable);
	set_sync_flag(&peer_reachable, true);
}

static int get_unreachable_count(void) {
	assert(pthread_mutex_lock(&status_mutex) == 0);
	int count = unreachable_count;
	assert(pthread_mutex_unlock(&status_mutex) == 0);
	return count;
}

static void watch_peer(meshlink_handle_t *mesh, const char *peer) {
	watched_peer = peer;
	hint_port_on_reachable = 0;
	repeat_ack_on_reachable = false;
	init_sync_flag(&peer_reachable);
	init_sync_flag(&peer_unreachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
	assert(pthread_mutex_lock(&status_mutex) == 0);
	unreachable_count = 0;
	assert(pthread_mutex_unlock(&status_mutex) == 0);
	meshlink_set_node_status_cb(mesh, status_cb);
}

/* Net number of active meta connections per node name, from devtool_set_meta_status_cb. */
static struct {
	char mesh[16];
	char node[16];
	int net;
} meta_counts[8];
static int nmeta_counts;

static void meta_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool up) {
	assert(pthread_mutex_lock(&status_mutex) == 0);
	int i;

	for(i = 0; i < nmeta_counts; i++) {
		if(!strcmp(meta_counts[i].mesh, mesh->name) && !strcmp(meta_counts[i].node, node->name)) {
			break;
		}
	}

	if(i == nmeta_counts) {
		assert(nmeta_counts < 8);
		snprintf(meta_counts[i].mesh, sizeof meta_counts[i].mesh, "%s", mesh->name);
		snprintf(meta_counts[i].node, sizeof meta_counts[i].node, "%s", node->name);
		meta_counts[i].net = 0;
		nmeta_counts++;
	}

	meta_counts[i].net += up ? 1 : -1;
	assert(pthread_mutex_unlock(&status_mutex) == 0);
}

static void reset_meta_counts(void) {
	assert(pthread_mutex_lock(&status_mutex) == 0);
	nmeta_counts = 0;
	assert(pthread_mutex_unlock(&status_mutex) == 0);
}

static int meta_net_count(const char *mesh, const char *node) {
	int net = -1;
	assert(pthread_mutex_lock(&status_mutex) == 0);

	for(int i = 0; i < nmeta_counts; i++) {
		if(!strcmp(meta_counts[i].mesh, mesh) && !strcmp(meta_counts[i].node, node)) {
			net = meta_counts[i].net;
		}
	}

	assert(pthread_mutex_unlock(&status_mutex) == 0);
	return net;
}

/* --- channel stream a -> b, checked for order and completeness ------------- */

static pthread_mutex_t stream_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t stream_received;
static bool stream_mismatch;
static struct sync_flag channel_ready;

/* Message number seq as MSG_LEN zero-padded digits. */
static void format_msg(char msg[static MSG_LEN + 1], size_t seq) {
	char buf[32];
	assert(seq < 1000000);
	snprintf(buf, sizeof buf, "%06zu", seq);
	memcpy(msg, buf, MSG_LEN + 1);
}

static char expected_byte(size_t offset) {
	char msg[MSG_LEN + 1];
	format_msg(msg, offset / MSG_LEN);
	return msg[offset % MSG_LEN];
}

static void b_receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;

	assert(pthread_mutex_lock(&stream_mutex) == 0);

	for(size_t i = 0; i < len; i++) {
		if(((const char *)data)[i] != expected_byte(stream_received + i)) {
			stream_mismatch = true;
		}
	}

	stream_received += len;
	assert(pthread_mutex_unlock(&stream_mutex) == 0);
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	if(port != 7) {
		return false;
	}

	meshlink_set_channel_receive_cb(mesh, channel, b_receive_cb);

	if(data) {
		b_receive_cb(mesh, channel, data, len);
	}

	return true;
}

static void poll_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, size_t len) {
	(void)len;
	meshlink_set_channel_poll_cb(mesh, channel, NULL);
	set_sync_flag(&channel_ready, true);
}

static void reset_stream(void) {
	assert(pthread_mutex_lock(&stream_mutex) == 0);
	stream_received = 0;
	stream_mismatch = false;
	assert(pthread_mutex_unlock(&stream_mutex) == 0);
	init_sync_flag(&channel_ready);
}

static size_t stream_bytes(void) {
	assert(pthread_mutex_lock(&stream_mutex) == 0);
	size_t n = stream_received;
	assert(pthread_mutex_unlock(&stream_mutex) == 0);
	return n;
}

static bool stream_ok(void) {
	assert(pthread_mutex_lock(&stream_mutex) == 0);
	bool ok = !stream_mismatch;
	assert(pthread_mutex_unlock(&stream_mutex) == 0);
	return ok;
}

static meshlink_channel_t *open_stream(meshlink_handle_t *a, meshlink_node_t *b) {
	reset_stream();
	meshlink_channel_t *channel = meshlink_channel_open(a, b, 7, NULL, NULL, 0);
	assert(channel);
	meshlink_set_channel_poll_cb(a, channel, poll_cb);
	assert(wait_sync_flag(&channel_ready, 15));
	return channel;
}

/* Send message number seq, retrying while the send buffer is full. */
static void stream_send(meshlink_handle_t *a, meshlink_channel_t *channel, size_t seq) {
	char msg[MSG_LEN + 1];
	format_msg(msg, seq);

	for(int tries = 0; tries < 1000; tries++) {
		ssize_t sent = meshlink_channel_send(a, channel, msg, MSG_LEN);

		if(sent == MSG_LEN) {
			return;
		}

		assert(sent == 0 || sent == -1);
		usleep(10000);
	}

	assert(!"channel send kept failing");
}

/* Keep streaming until the probe succeeds (or deadline seconds pass), then send
   after_count more messages so the stream provably continues on the new connection.
   Returns the total number of messages sent. */
static size_t stream_across_migration(meshlink_handle_t *a, meshlink_channel_t *channel, size_t after_count, int deadline) {
	time_t started = time(NULL);
	size_t seq = 0;

	while(!check_sync_flag(&probe_succeeded)) {
		stream_send(a, channel, seq++);
		usleep(5000);
		assert(time(NULL) - started < deadline);
	}

	for(size_t i = 0; i < after_count; i++) {
		stream_send(a, channel, seq++);
	}

	assert_after(stream_bytes() == seq * MSG_LEN, 15);
	assert(stream_ok());
	return seq;
}

/* --- helpers ---------------------------------------------------------------- */

static void set_canonical_address(meshlink_handle_t *mesh, const char *host, int port) {
	char port_str[16];
	snprintf(port_str, sizeof port_str, "%d", port);
	assert(meshlink_set_canonical_address(mesh, meshlink_get_self(mesh), host, port_str));
}

struct pair {
	meshlink_handle_t *a;
	meshlink_handle_t *b;
	meshlink_node_t *a_b;       /* b as seen by a */
	meshlink_node_t *b_a;       /* a as seen by b */
	int b_port;
	int relay_port;
	tcp_relay_t *relay;
	char conf_a[64];
	char conf_b[64];
};

/* a (PORTABLE) reaches b (STATIONARY) only through a relay standing in for the
   canonical address. With b_external set, b tells a its direct address via REQ_EXTERNAL.
   relay_host is the loopback address the relay listens on: 127.0.0.1 makes the relay
   indistinguishable from b by IP, another 127/8 address makes it recognisable. */
static void open_relayed_pair_via(struct pair *p, const char *prefix, bool b_external, const char *relay_host) {
	memset(p, 0, sizeof *p);
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

	p->relay = start_tcp_relay(relay_host, &p->relay_port, "127.0.0.1", p->b_port);
	set_canonical_address(p->b, relay_host, p->relay_port);

	if(b_external) {
		devtool_set_external_ip_address(p->b, meshlink_get_self(p->b), "127.0.0.1");
	}

	exchange_meshlink_pair(p->a, p->b);

	p->a_b = meshlink_get_node(p->a, "b");
	p->b_a = meshlink_get_node(p->b, "a");
	assert(p->a_b && p->b_a);
	forget_addresses(p->a, p->a_b);

	meshlink_set_channel_accept_cb(p->b, accept_cb);
}

static void open_relayed_pair(struct pair *p, const char *prefix, bool b_external) {
	open_relayed_pair_via(p, prefix, b_external, "127.0.0.1");
}

static void close_relayed_pair(struct pair *p) {
	meshlink_stop(p->a);
	meshlink_stop(p->b);
	meshlink_close(p->a);
	meshlink_close(p->b);
	assert(meshlink_destroy(p->conf_a));
	assert(meshlink_destroy(p->conf_b));
	stop_tcp_relay(p->relay);
}

static void assert_via_canonical_at_reachable(struct pair *p) {
	assert(status_at_reachable.meta_connected);
	assert(status_at_reachable.meta_is_outgoing);
	assert(status_at_reachable.meta_via_canonical);
	assert(port_of(&status_at_reachable.meta_address) == p->relay_port);
	devtool_free_node_status(&status_at_reachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
}

static void assert_direct(meshlink_handle_t *mesh, meshlink_node_t *node, int port) {
	devtool_node_status_t st;
	devtool_get_node_status(mesh, node, &st);
	assert(st.meta_connected);
	assert(!st.meta_via_canonical);
	assert(port_of(&st.meta_address) == port);
	assert(!st.upgrade_probe_active);
	assert(st.upgrade_backoff == 0);
	devtool_free_node_status(&st);
}

/* True once mesh's meta connection with node is up, direct and not via anything. */
static bool connected_direct(meshlink_handle_t *mesh, meshlink_node_t *node, int port) {
	devtool_node_status_t st;
	devtool_get_node_status(mesh, node, &st);
	bool direct = st.meta_connected && !st.meta_via_canonical && port_of(&st.meta_address) == port && !st.upgrade_probe_active;
	devtool_free_node_status(&st);
	return direct;
}

/* --- T5 --------------------------------------------------------------------- */

static void test_migrate_from_req_external(void) {
	printf("\n=== T5: relay first, REQ_EXTERNAL learns direct, hitless migration ===\n");

	struct pair p;
	open_relayed_pair(&p, "canonical_migrate_t5", true);
	reset_probe_events();
	watch_peer(p.a, "b");

	assert(meshlink_start(p.b));
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 15));
	assert_via_canonical_at_reachable(&p);
	assert(tcp_relay_accept_count(p.relay) == 1);

	/* Stream across the swap. The probe fires as soon as REQ_EXTERNAL arrives, which
	   can be before the channel is even open, so how much went through the relay is
	   reported rather than asserted (T6 pins the overlap); what is asserted is that
	   the stream carries on, complete and in order, on the direct connection. */
	meshlink_channel_t *channel = open_stream(p.a, p.a_b);
	size_t sent = stream_across_migration(p.a, channel, 500, 20);
	size_t before = streamed_at_success();

	assert(check_sync_flag(&probe_succeeded));
	assert(before < sent * MSG_LEN);

	assert_direct(p.a, p.a_b, p.b_port);
	assert(get_unreachable_count() == 0);
	assert(tcp_relay_accept_count(p.relay) == 1);
	assert(count_probe_events(DEVTOOL_UPGRADE_PROBE_FAILED) == 0);
	assert(log_contains("a: Got REQ_EXTERNAL from b"));
	assert(log_contains("a: Migrated meta connection to b from canonical to direct "));

	/* b's side swapped too: one active connection with a, not via anything. */
	devtool_node_status_t st;
	devtool_get_node_status(p.b, p.b_a, &st);
	assert(st.meta_connected);
	assert(!st.meta_via_canonical);
	devtool_free_node_status(&st);

	/* The direct address is now what a would try first. */
	devtool_get_node_status(p.a, p.a_b, &st);
	assert(st.recent_count >= 1);
	assert(port_of(&st.recent[0]) == p.b_port);

	for(size_t i = 0; i < st.recent_count; i++) {
		assert(port_of(&st.recent[i]) != p.relay_port);
	}

	devtool_free_node_status(&st);

	printf("T5 ok: migrated to port %d, %zu bytes streamed in order (%zu before the swap), relay accepts %d\n", p.b_port, sent * MSG_LEN, before, tcp_relay_accept_count(p.relay));

	meshlink_channel_close(p.a, channel);
	meshlink_set_node_status_cb(p.a, NULL);
	close_relayed_pair(&p);
}

/* --- T6 --------------------------------------------------------------------- */

static void test_black_hole_backoff(void) {
	printf("\n=== T6: black-hole direct address: backoff, relay stays up, then a real address wins ===\n");

	struct pair p;
	open_relayed_pair(&p, "canonical_migrate_t6", false);
	reset_probe_events();
	watch_peer(p.a, "b");

	int hole_port = 0;
	int hole_fd = start_black_hole("127.0.0.1", &hole_port);

	/* The black hole is hinted from the reachable callback, so it is the only direct
	   address a knows when the canonical connection comes up and is probed right away.
	   UDP then learns b's real addresses (loopback, and the container interface via
	   broadcast probes) in front of it. The rotation continues after the failed slot,
	   so depending on how many were learned the black hole is hit once or twice more
	   before a real address wins; every failure must back off (5s, then 10s). */
	hint_port_on_reachable = hole_port;
	time_t hinted_at = time(NULL);

	assert(meshlink_start(p.b));
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 15));
	assert_via_canonical_at_reachable(&p);

	/* The first probe hangs for its 5 s timeout, so the stream provably runs through
	   the relay before the swap and, with the extra batch, after it. */
	meshlink_channel_t *channel = open_stream(p.a, p.a_b);
	size_t sent = stream_across_migration(p.a, channel, 500, 90);
	size_t before = streamed_at_success();

	assert(time(NULL) - hinted_at < 90);
	assert(sent > 500 + 100);
	assert(before > 0);
	assert(before < sent * MSG_LEN);

	assert(get_unreachable_count() == 0);
	assert(tcp_relay_accept_count(p.relay) == 1);
	assert_direct(p.a, p.a_b, p.b_port);

	/* Event sequence: started, failed(5), [started, failed(10),] started, succeeded(0).
	   Every failure must leave the canonical connection untouched. */
	assert(pthread_mutex_lock(&probe_mutex) == 0);
	int failures = 0;
	int expected_backoff = 5;
	int last_backoff = 0;
	time_t last_failure = 0;
	bool succeeded = false;

	for(int i = 0; i < nprobe_events; i++) {
		struct probe_event *ev = &probe_events[i];
		assert(!strcmp(ev->mesh, "a") && !strcmp(ev->node, "b"));

		switch(ev->stage) {
		case DEVTOOL_UPGRADE_PROBE_STARTED:
			if(last_failure) {
				/* Retries honour the backoff set by the previous failure (1s slack for clock granularity). */
				assert(ev->when - last_failure >= last_backoff - 1);
			}

			assert(ev->canonical_still_up);
			break;

		case DEVTOOL_UPGRADE_PROBE_FAILED:
			assert(!succeeded);
			assert(ev->canonical_still_up);
			assert(ev->backoff == expected_backoff);
			last_backoff = expected_backoff;
			expected_backoff *= 2;
			last_failure = ev->when;
			failures++;
			break;

		case DEVTOOL_UPGRADE_PROBE_SUCCEEDED:
			assert(ev->backoff == 0);
			succeeded = true;
			break;
		}
	}

	assert(pthread_mutex_unlock(&probe_mutex) == 0);
	assert(succeeded);
	assert(failures >= 1 && failures <= 2);

	printf("T6 ok: %d black-hole failures with doubling backoff, relay stayed up, %zu bytes streamed (%zu before the swap), migrated to port %d\n", failures, sent * MSG_LEN, before, p.b_port);

	meshlink_channel_close(p.a, channel);
	meshlink_set_node_status_cb(p.a, NULL);
	close(hole_fd);
	close_relayed_pair(&p);
}

/* --- T7 --------------------------------------------------------------------- */

static void test_both_sides_migrate(void) {
	printf("\n=== T7: both sides reach each other via relays and migrate ===\n");

	assert(meshlink_destroy("canonical_migrate_t7_conf.1"));
	assert(meshlink_destroy("canonical_migrate_t7_conf.2"));

	/* Both STATIONARY: each autoconnects to the other. */
	meshlink_handle_t *a = meshlink_open("canonical_migrate_t7_conf.1", "a", "canonical_migrate_t7", DEV_CLASS_STATIONARY);
	meshlink_handle_t *b = meshlink_open("canonical_migrate_t7_conf.2", "b", "canonical_migrate_t7", DEV_CLASS_STATIONARY);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	int a_port = meshlink_get_port(a);
	int b_port = meshlink_get_port(b);
	assert(a_port > 0 && b_port > 0);

	int relay_a_port = 0, relay_b_port = 0;
	tcp_relay_t *relay_a = start_tcp_relay("127.0.0.1", &relay_a_port, "127.0.0.1", a_port);
	tcp_relay_t *relay_b = start_tcp_relay("127.0.0.1", &relay_b_port, "127.0.0.1", b_port);
	set_canonical_address(a, "127.0.0.1", relay_a_port);
	set_canonical_address(b, "127.0.0.1", relay_b_port);
	devtool_set_external_ip_address(a, meshlink_get_self(a), "127.0.0.1");
	devtool_set_external_ip_address(b, meshlink_get_self(b), "127.0.0.1");

	exchange_meshlink_pair(a, b);

	meshlink_node_t *a_b = meshlink_get_node(a, "b");
	meshlink_node_t *b_a = meshlink_get_node(b, "a");
	assert(a_b && b_a);
	forget_addresses(a, a_b);
	forget_addresses(b, b_a);

	reset_probe_events();
	reset_meta_counts();
	devtool_set_meta_status_cb(a, meta_status_cb);
	devtool_set_meta_status_cb(b, meta_status_cb);
	watch_peer(a, "b");

	size_t mark = log_mark();
	assert(meshlink_start(a));
	assert(meshlink_start(b));
	assert(wait_sync_flag(&peer_reachable, 15));
	devtool_free_node_status(&status_at_reachable);

	/* Whichever side kept its outgoing canonical connection migrates it. */
	assert(wait_sync_flag(&probe_succeeded, 30));
	sleep(3);

	devtool_node_status_t st;
	devtool_get_node_status(a, a_b, &st);
	assert(st.meta_connected);
	assert(!st.meta_via_canonical);
	assert(!st.upgrade_probe_active);
	devtool_free_node_status(&st);

	devtool_get_node_status(b, b_a, &st);
	assert(st.meta_connected);
	assert(!st.meta_via_canonical);
	assert(!st.upgrade_probe_active);
	devtool_free_node_status(&st);

	assert(meta_net_count("a", "b") == 1);
	assert(meta_net_count("b", "a") == 1);
	assert(log_find(mark, "Two outgoing connections to the same node!") < 0);
	assert(tcp_relay_accept_count(relay_a) + tcp_relay_accept_count(relay_b) >= 1);

	printf("T7 ok: one direct connection per side, relays accepted a=%d b=%d\n", tcp_relay_accept_count(relay_a), tcp_relay_accept_count(relay_b));

	meshlink_set_node_status_cb(a, NULL);
	devtool_set_meta_status_cb(a, NULL);
	devtool_set_meta_status_cb(b, NULL);
	meshlink_stop(a);
	meshlink_stop(b);
	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("canonical_migrate_t7_conf.1"));
	assert(meshlink_destroy("canonical_migrate_t7_conf.2"));
	stop_tcp_relay(relay_a);
	stop_tcp_relay(relay_b);
}

/* --- T8 --------------------------------------------------------------------- */

static void test_peer_restart_on_new_port(void) {
	printf("\n=== T8: peer dies while migrated, comes back on a new port behind the relay ===\n");

	struct pair p;
	open_relayed_pair(&p, "canonical_migrate_t8", true);
	reset_probe_events();
	watch_peer(p.a, "b");

	assert(meshlink_start(p.b));
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 15));
	assert_via_canonical_at_reachable(&p);
	assert(wait_sync_flag(&probe_succeeded, 20));
	assert_direct(p.a, p.a_b, p.b_port);

	int old_b_port = p.b_port;
	int relay_accepts = tcp_relay_accept_count(p.relay);
	assert(relay_accepts == 1);

	/* Kill b. a's reconnect must try the direct port it just used before the relay. */
	size_t mark = log_mark();
	meshlink_stop(p.b);
	assert(wait_sync_flag(&peer_unreachable, 15));

	int new_b_port = find_closed_port("127.0.0.1");
	assert(new_b_port != old_b_port);
	assert(meshlink_set_port(p.b, new_b_port));
	assert(meshlink_get_port(p.b) == new_b_port);
	tcp_relay_set_target(p.relay, new_b_port);

	reset_probe_events();
	init_sync_flag(&peer_reachable);
	memset(&status_at_reachable, 0, sizeof status_at_reachable);
	assert(meshlink_start(p.b));

	/* Fallback: the old direct port is dead, the relay forwards to the new one. */
	assert(wait_sync_flag(&peer_reachable, 45));
	assert_via_canonical_at_reachable(&p);
	assert(tcp_relay_accept_count(p.relay) > relay_accepts);

	/* Any of b's learned direct addresses (loopback or container interface) counts. */
	char direct_needle[128], canonical_needle[128];
	snprintf(direct_needle, sizeof direct_needle, " port %d (recent)", old_b_port);
	snprintf(canonical_needle, sizeof canonical_needle, "a: Trying to connect to b at 127.0.0.1 port %d (canonical)", p.relay_port);
	long direct_at = log_find(mark, direct_needle);
	long canonical_at = log_find(mark, canonical_needle);
	assert(direct_at >= 0);
	assert(canonical_at >= 0);
	assert(direct_at < canonical_at);

	/* b advertises its new port over REQ_EXTERNAL: a re-migrates. */
	assert(wait_sync_flag(&probe_succeeded, 30));
	assert_direct(p.a, p.a_b, new_b_port);

	printf("T8 ok: direct port %d tried first, fell back to relay, re-migrated to new port %d\n", old_b_port, new_b_port);

	meshlink_set_node_status_cb(p.a, NULL);
	close_relayed_pair(&p);
}

/* --- T14 -------------------------------------------------------------------- */

/* Number of bidirectional edges between x and y in mesh's view of the graph
   (devtool_get_all_edges reports each such pair once, in pointer order). */
static void test_third_node_view(void) {
	printf("\n=== T14: a third node keeps seeing the migrating node, ends with one edge pair ===\n");

	struct pair p;
	open_relayed_pair(&p, "canonical_migrate_t14", true);

	/* c (STATIONARY) connects directly to b and, like b, never initiates towards a
	   (PORTABLE). a would autoconnect to c though, which would give c a second path
	   to a and hide any flap of the a<->b edge; a blacklists c so c only ever sees a
	   through b. */
	assert(meshlink_destroy("canonical_migrate_t14_conf.3"));
	meshlink_handle_t *c = meshlink_open("canonical_migrate_t14_conf.3", "c", "canonical_migrate_t14", DEV_CLASS_STATIONARY);
	assert(c);
	meshlink_enable_discovery(c, false);

	exchange_meshlink_pair(p.a, c);
	exchange_meshlink_pair(p.b, c);

	meshlink_node_t *a_c = meshlink_get_node(p.a, "c");
	meshlink_node_t *c_a = meshlink_get_node(c, "a");
	meshlink_node_t *c_b = meshlink_get_node(c, "b");
	assert(a_c && c_a && c_b);
	assert(meshlink_blacklist(p.a, a_c));
	forget_addresses(c, c_b);
	hint_address(c, c_b, "127.0.0.1", p.b_port);

	reset_probe_events();
	reset_meta_counts();
	devtool_set_meta_status_cb(p.b, meta_status_cb);
	watch_peer(c, "a");

	assert(meshlink_start(p.b));
	assert(meshlink_start(c));
	assert_after(count_edge_pairs(c, "b", "c") == 1, 15);

	/* b and c connect to each other at the same time; when c loses the tie-break its
	   address walk moves on to b's canonical address, so c may touch the relay once,
	   possibly after the b<->c edge pair is already visible. The relay's accept count
	   therefore cannot tell a's use apart from c's; a's own connect attempts to the
	   canonical address can. */
	char canonical_needle[128];
	snprintf(canonical_needle, sizeof canonical_needle, "a: Trying to connect to b at 127.0.0.1 port %d (canonical)", p.relay_port);
	size_t mark = log_mark();

	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 15));
	devtool_free_node_status(&status_at_reachable);
	assert_after(count_edge_pairs(c, "a", "b") == 1, 5);

	assert(wait_sync_flag(&probe_succeeded, 20));
	assert_direct(p.a, p.a_b, p.b_port);

	/* Let the ADD_EDGE that replaced a's edge reach c, then check its view. */
	sleep(3);

	assert(get_unreachable_count() == 0);
	assert(meshlink_get_node_reachability(c, c_a, NULL, NULL));
	assert(count_edge_pairs(c, "a", "b") == 1);
	assert(count_edge_pairs(c, "b", "c") == 1);
	assert(count_edge_pairs(c, "a", "c") == 0);

	/* Exactly those two pairs, and nothing in c's graph points at the relay. */
	size_t nedges = 0;
	devtool_edge_t *edges = devtool_get_all_edges(c, NULL, &nedges);
	assert(edges && nedges == 2);

	for(size_t i = 0; i < nedges; i++) {
		assert(port_of(&edges[i].address) != p.relay_port);
	}

	free(edges);

	/* b itself has exactly one live connection with a, and a went through the relay once. */
	assert(meta_net_count("b", "a") == 1);
	assert(log_count_from(mark, canonical_needle) == 1);

	printf("T14 ok: c saw a reachable throughout, %zu edge pairs, one of them a<->b\n", nedges);

	meshlink_set_node_status_cb(c, NULL);
	devtool_set_meta_status_cb(p.b, NULL);
	meshlink_stop(c);
	meshlink_close(c);
	assert(meshlink_destroy("canonical_migrate_t14_conf.3"));
	close_relayed_pair(&p);
}

/* T15: the relay edge is marked OPTION_INDIRECT, so a third node that learns b only
   through a's edge does not seed the relay's address into its recent[] for b.

   The relay listens on 127.0.0.2 here: with everything on 127.0.0.1 the edge address
   (relay IP + b's port) is b's real address and the leak would be invisible. d connects
   to a only and blacklists b, so the sole way an address for b can reach d's recent[]
   is graph seeding from a's a->b edge. */
static void test_third_node_does_not_seed_relay(void) {
	printf("\n=== T15: third node does not seed the relay address from an indirect edge ===\n");

	const char *relay_ip = "127.0.0.2";

	if(!loopback_alias_available(relay_ip)) {
		printf("T15 skipped: cannot bind %s on this host\n", relay_ip);
		return;
	}

	struct pair p;
	open_relayed_pair_via(&p, "canonical_migrate_t15", false, relay_ip);

	assert(meshlink_destroy("canonical_migrate_t15_conf.3"));
	meshlink_handle_t *d = meshlink_open("canonical_migrate_t15_conf.3", "d", "canonical_migrate_t15", DEV_CLASS_PORTABLE);
	assert(d);
	meshlink_enable_discovery(d, false);

	exchange_meshlink_pair(p.a, d);
	exchange_meshlink_pair(p.b, d);

	meshlink_node_t *d_a = meshlink_get_node(d, "a");
	meshlink_node_t *d_b = meshlink_get_node(d, "b");
	assert(d_a && d_b);
	assert(meshlink_blacklist(d, d_b));
	forget_addresses(d, d_a);
	forget_addresses(d, d_b);

	/* d is attached to a before b comes up, so d hears a's relay edge the moment a
	   authenticates with b, well before a's UDP probes can learn b's real address and
	   the upgrade replaces the edge with a direct one. */
	hint_address(d, d_a, "127.0.0.1", meshlink_get_port(p.a));
	assert(meshlink_start(p.a));
	assert(meshlink_start(d));
	assert_after(meshlink_get_node_reachability(d, d_a, NULL, NULL), 15);

	size_t mark = log_mark();
	assert(meshlink_start(p.b));
	assert_after(count_edge_pairs(d, "a", "b") == 1, 30);

	/* d received a's edge to b with the relay's address and OPTION_INDIRECT: the ADD_EDGE
	   body reads "<from> <devclass> <submesh> <to> <address> <port> <devclass> <submesh>
	   <options> ..." with "." for the core mesh and options in hex. */
	char needle[128];
	snprintf(needle, sizeof needle, " a %d . b %s %d %d . %x ", DEV_CLASS_PORTABLE, relay_ip, p.b_port, DEV_CLASS_STATIONARY, EDGE_OPTION_INDIRECT | EDGE_OPTION_PMTU_DISCOVERY);
	assert(log_find(mark, needle) >= 0);

	devtool_node_status_t st;
	devtool_get_node_status(d, d_b, &st);

	for(size_t i = 0; i < st.recent_count; i++) {
		char ip[INET6_ADDRSTRLEN] = "?";
		const struct sockaddr_in *sin = (const struct sockaddr_in *)&st.recent[i];

		if(sin->sin_family == AF_INET) {
			inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip);
		}

		printf("d recent[%zu] for b: %s port %d\n", i, ip, port_of(&st.recent[i]));
		assert(!addr_is(&st.recent[i], relay_ip, p.b_port));
	}

	printf("T15 ok: d reaches b through a's indirect edge, %zu recent[] entries for b, none the relay's\n", st.recent_count);
	devtool_free_node_status(&st);

	meshlink_stop(d);
	meshlink_close(d);
	assert(meshlink_destroy("canonical_migrate_t15_conf.3"));
	close_relayed_pair(&p);
}

/* T16: b holds a's probe as a spare and a, misbehaving, sends its ACK twice. The second
   ACK must be rejected: handling it like the first would make upgrade_hold_spare() evict
   the very connection it is about to hold and go on using it after it was freed. b drops
   the spare instead, and both sides still end up with exactly one, direct, connection. */
static void test_repeated_ack_on_spare_is_rejected(void) {
	printf("\n=== T16: a repeated ACK on a held spare is rejected, no double hold ===\n");

	struct pair p;
	open_relayed_pair(&p, "canonical_migrate_t16", false);
	reset_probe_events();
	reset_meta_counts();
	devtool_set_meta_status_cb(p.a, meta_status_cb);
	devtool_set_meta_status_cb(p.b, meta_status_cb);
	watch_peer(p.a, "b");

	/* Like T6, the direct address is hinted from the reachable callback so the probe it
	   starts is the first one (before UDP learns b's address), and that probe's ACK is
	   the one a doubles. */
	hint_port_on_reachable = p.b_port;
	repeat_ack_on_reachable = true;

	size_t mark = log_mark();
	assert(meshlink_start(p.b));
	assert(meshlink_start(p.a));
	assert(wait_sync_flag(&peer_reachable, 15));
	assert_via_canonical_at_reachable(&p);
	assert(tcp_relay_accept_count(p.relay) == 1);

	/* b holds the probe as a spare on the first ACK and drops it on the second; it must
	   not "supersede" the spare with itself, which is what the use-after-free looked like. */
	assert_after(log_find(mark, "b: Got bad ACK from a: connection already active") >= 0, 15);
	assert(!devtool_repeat_next_ack);
	long held_at = log_find(mark, "b: Holding direct connection from a at 127.0.0.1 port ");
	long rejected_at = log_find(mark, "b: Got bad ACK from a: connection already active");
	assert(held_at >= 0 && held_at < rejected_at);
	assert(log_find(mark, "b: Dropping superseded spare connection with a") < 0);

	/* b's deferred ACK may or may not have left before it dropped the spare, so a either
	   migrated onto a connection that dies at once (and reconnects directly after the
	   backoff) or saw its probe fail and probes again. Either way: one direct connection
	   per side, nothing left over. */
	assert_after(connected_direct(p.a, p.a_b, p.b_port) && meta_net_count("a", "b") == 1 && meta_net_count("b", "a") == 1, 45);
	sleep(2);
	assert_direct(p.a, p.a_b, p.b_port);
	assert(meta_net_count("a", "b") == 1);
	assert(meta_net_count("b", "a") == 1);
	assert(tcp_relay_accept_count(p.relay) == 1);
	assert(log_find(mark, "Two outgoing connections to the same node!") < 0);

	devtool_node_status_t st;
	devtool_get_node_status(p.b, p.b_a, &st);
	assert(st.meta_connected);
	assert(!st.meta_via_canonical);
	devtool_free_node_status(&st);

	printf("T16 ok: repeated ACK rejected by b, both sides settled on one direct connection (a probes: %d started, %d failed)\n",
	       count_probe_events(DEVTOOL_UPGRADE_PROBE_STARTED), count_probe_events(DEVTOOL_UPGRADE_PROBE_FAILED));

	meshlink_set_node_status_cb(p.a, NULL);
	devtool_set_meta_status_cb(p.a, NULL);
	devtool_set_meta_status_cb(p.b, NULL);
	close_relayed_pair(&p);
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, capture_log_cb);
	devtool_upgrade_probe = upgrade_probe_hook;

	test_migrate_from_req_external();
	test_black_hole_backoff();
	test_both_sides_migrate();
	test_peer_restart_on_new_port();
	test_third_node_view();
	test_third_node_does_not_seed_relay();
	test_repeated_ack_on_spare_is_rejected();

	free_captured_log();
	return 0;
}
