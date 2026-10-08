/* Internal control-plane tests count records accepted by the real META writer.
   The event loop clock is controlled so retry boundaries need no sleeps. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include "meshlink_internal.h"
#include "connection.h"
#include "connection_policy.h"
#include "node.h"
#include "net.h"
#include "path_policy.h"
#include "protocol.h"
#include <assert.h>

typedef struct {
	meshlink_handle_t *mesh;
	node_t *peer;
	node_t *backbone;
	connection_t *meta;
	int reader;
} fixture_t;

static void unused_io(event_loop_t *loop, void *data, int flags) {
	(void)loop;
	(void)data;
	(void)flags;
	abort();
}

static fixture_t fixture(const char *self, const char *peer) {
	fixture_t f = {0};
	f.mesh = meshlink_open_ephemeral(self, "peer-control", DEV_CLASS_STATIONARY);
	assert(f.mesh);
	f.mesh->loop.now = (struct timespec) {100, 0};
	init_outgoings(f.mesh);
	/* Keep connection dialing out of these control-owner tests. */
	f.mesh->connection_policy_busy = true;

	f.backbone = new_node();
	f.backbone->name = strdup("backbone");
	f.backbone->devclass = DEV_CLASS_BACKBONE;
	f.backbone->status.reachable = true;
	f.backbone->status.validkey = true;
	node_add(f.mesh, f.backbone);
	assert(connection_policy_set_backbone(f.mesh, f.backbone->name));

	int fd[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
	f.reader = fd[1];
	f.meta = new_connection();
	f.meta->name = strdup("backbone");
	f.meta->socket = fd[0];
	f.meta->node = f.backbone;
	f.meta->status.active = true;
	f.meta->allow_request = ID; /* Plaintext buffer: inspect accepted records. */
	f.meta->protocol_minor = 4;
	connection_add(f.mesh, f.meta);
	io_add(&f.mesh->loop, &f.meta->io, unused_io, NULL, fd[0], IO_READ);
	f.backbone->connection = f.meta;

	f.peer = new_node();
	f.peer->name = strdup(peer);
	f.peer->devclass = DEV_CLASS_STATIONARY;
	f.peer->session_id = 1;
	f.peer->status.reachable = true;
	f.peer->devtool_force_meta = true;
	f.peer->nexthop = f.backbone;
	node_add(f.mesh, f.peer);
	return f;
}

static void close_fixture(fixture_t *f) {
	f->backbone->connection = NULL;
	connection_del(f->mesh, f->meta);
	close(f->reader);
	meshlink_close(f->mesh);
}

static bool same_time(struct timespec a, struct timespec b) {
	return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}

static void before_deadline(fixture_t *f, struct timespec deadline) {
	f->mesh->loop.now = deadline;
	if(f->mesh->loop.now.tv_nsec) {
		f->mesh->loop.now.tv_nsec--;
	} else {
		f->mesh->loop.now.tv_sec--;
		f->mesh->loop.now.tv_nsec = 999999999;
	}
}

static void expect_delay(fixture_t *f, struct timespec deadline, unsigned seconds) {
	int64_t ns = (int64_t)(deadline.tv_sec - f->mesh->loop.now.tv_sec) * 1000000000
	             + deadline.tv_nsec - f->mesh->loop.now.tv_nsec;
	assert(ns >= (int64_t)seconds * 1000000000);
	assert(ns <= (int64_t)seconds * 1000000000 + 30000000);
}

static unsigned take_requests(fixture_t *f, int extension) {
	unsigned count = 0;
	char *line;
	while((line = buffer_readline(&f->meta->outbuf))) {
		int request, ext;
		assert(sscanf(line, "%d", &request) == 1);
		if(request == REQ_KEY && sscanf(line, "%*d %*s %*s %d", &ext) == 1 && ext == extension) {
			count++;
		}
	}
	return count;
}

static void learn_key(fixture_t *f, fixture_t *other) {
	char *key = ecdsa_get_base64_public_key(other->mesh->private_key);
	char request[MAX_STRING_SIZE];
	snprintf(request, sizeof request, "%d %s %s %d %s", REQ_KEY, f->peer->name, f->mesh->self->name, ANS_PUBKEY, key);
	free(key);
	assert(req_key_h(f->mesh, f->meta, request));
}

static unsigned deliver(fixture_t *from, fixture_t *to) {
	unsigned count = 0;
	char *line;
	while((line = buffer_readline(&from->meta->outbuf))) {
		int request;
		assert(sscanf(line, "%d", &request) == 1);
		if(request == REQ_KEY) {
			assert(req_key_h(to->mesh, to->meta, line));
		} else {
			assert(request == ANS_KEY);
			assert(ans_key_h(to->mesh, to->meta, line));
		}
		count++;
	}
	return count;
}

static void finish_handshake(fixture_t *a, fixture_t *b) {
	for(unsigned i = 0; i < 10; i++) {
		unsigned count = deliver(a, b) + deliver(b, a);
		if(!count) {
			break;
		}
	}
	assert(a->peer->status.validkey && b->peer->status.validkey);
	assert(a->peer->key_retry_phase == NODE_KEX_IDLE && b->peer->key_retry_phase == NODE_KEX_IDLE);
	assert(!a->peer->status.waitingforkey && !b->peer->status.waitingforkey);
	assert(!a->peer->key_retry_step && !b->peer->key_retry_step);
	assert(!a->peer->key_retry_wanted && !b->peer->key_retry_wanted);
	assert(!a->peer->key_delivery_uncertain && !b->peer->key_delivery_uncertain);
	assert(same_time(a->peer->key_retry_at, (struct timespec) {0, 0}));
	assert(same_time(b->peer->key_retry_at, (struct timespec) {0, 0}));
}

static void test_channel_start(void) {
	fixture_t f = fixture("a", "b");
	meshlink_channel_t *one = meshlink_channel_open(f.mesh, (meshlink_node_t *)f.peer, 1, NULL, NULL, 0);
	assert(one);
	/* The demand hook and UTCP's actual SYN share the acquisition request. */
	assert(take_requests(&f, REQ_PUBKEY) == 1);
	assert(f.peer->key_retry_phase == NODE_KEX_PUBLIC_KEY && f.peer->key_retry_step == 1);
	assert(!f.peer->key_retry_epoch && !f.peer->sptps_restart_count);
	struct timespec deadline = f.peer->key_retry_at;
	meshlink_channel_t *two = meshlink_channel_open(f.mesh, (meshlink_node_t *)f.peer, 2, NULL, NULL, 0);
	assert(two && f.peer->peer_udp.channel_count == 2);
	path_peer_ensure_udp_key(f.mesh, f.peer);
	assert(node_kex_ensure(f.mesh, f.peer));
	assert(take_requests(&f, REQ_PUBKEY) == 0);
	assert(same_time(deadline, f.peer->key_retry_at));
	assert(f.peer->peer_udp.requests_sent == 1);
	meshlink_channel_close(f.mesh, one);
	meshlink_channel_close(f.mesh, two);
	close_fixture(&f);
}

static void test_key_phases(void) {
	fixture_t a = fixture("a", "b"), b = fixture("b", "a");
	static const unsigned ladder[] = {2, 5, 10, 30, 60, 60};
	for(unsigned i = 0; i < sizeof ladder / sizeof *ladder; i++) {
		assert(node_kex_ensure(a.mesh, a.peer));
		assert(take_requests(&a, REQ_PUBKEY) == 1);
		expect_delay(&a, a.peer->key_retry_at, ladder[i]);
		before_deadline(&a, a.peer->key_retry_at);
		node_kex_watchdog(a.mesh);
		assert(node_kex_ensure(a.mesh, a.peer));
		assert(take_requests(&a, REQ_PUBKEY) == 0);
		a.mesh->loop.now = a.peer->key_retry_at;
	}
	/* A public-key reply bypasses acquisition backoff and starts at two seconds. */
	learn_key(&a, &b);
	assert(a.peer->key_retry_phase == NODE_KEX_HANDSHAKE && a.peer->key_retry_step == 1);
	assert(a.peer->key_retry_epoch == 1 && a.peer->sptps_restart_count == 1);
	expect_delay(&a, a.peer->key_retry_at, 2);
	assert(take_requests(&a, REQ_KEY) == 1); /* Drop the initial handshake. */
	char *key = ecdsa_get_base64_public_key(a.mesh->private_key);
	b.peer->ecdsa = ecdsa_set_base64_public_key(key);
	free(key);
	assert(b.peer->ecdsa);

	struct timespec deadline = a.peer->key_retry_at;
	before_deadline(&a, deadline);
	node_kex_watchdog(a.mesh);
	path_peer_ensure_udp_key(a.mesh, a.peer);
	assert(node_kex_ensure(a.mesh, a.peer));
	assert(take_requests(&a, REQ_KEY) == 0 && a.peer->sptps_restart_count == 1);
	/* Keep dropping starts to exercise the entire handshake ladder and cap. */
	for(unsigned i = 1; i < sizeof ladder / sizeof *ladder; i++) {
		a.mesh->loop.now = a.peer->key_retry_at;
		node_kex_watchdog(a.mesh);
		assert(a.peer->key_retry_epoch == i + 1);
		expect_delay(&a, a.peer->key_retry_at, ladder[i]);
		if(i + 1 < sizeof ladder / sizeof *ladder) {
			assert(take_requests(&a, REQ_KEY) == 1);
		}
	}
	finish_handshake(&a, &b);
	uint32_t epoch = a.peer->key_retry_epoch;
	assert(epoch == 6 && b.peer->key_retry_epoch == 1);
	a.mesh->loop.now.tv_sec += 100;
	node_kex_watchdog(a.mesh);
	assert(node_kex_ensure(a.mesh, a.peer));
	assert(take_requests(&a, REQ_KEY) == 0);
	/* Explicit forced rekey remains available even with a valid session. */
	assert(send_req_key(a.mesh, a.peer));
	assert(a.peer->key_retry_epoch == epoch + 1 && a.peer->key_retry_step == 1);
	finish_handshake(&a, &b);
	close_fixture(&a);
	close_fixture(&b);
}

static void test_simultaneous_start(void) {
	fixture_t a = fixture("a", "b"), b = fixture("b", "a");
	assert(node_kex_ensure(a.mesh, a.peer));
	assert(node_kex_ensure(b.mesh, b.peer));
	/* Receiving each other's public-key request opens the handshake immediately.
	   The existing name tie-break makes b switch to responder without backoff. */
	finish_handshake(&a, &b);
	assert(a.peer->key_retry_epoch == 1 && b.peer->key_retry_epoch == 2);
	close_fixture(&a);
	close_fixture(&b);
}

static void test_send_failures(void) {
	fixture_t f = fixture("a", "b"), other = fixture("b", "a");
	f.meta->meta_teardown = true;
	assert(!node_kex_ensure(f.mesh, f.peer));
	assert(!f.peer->key_retry_step && take_requests(&f, REQ_PUBKEY) == 0);
	expect_delay(&f, f.peer->key_retry_at, 2);
	f.meta->meta_teardown = false;
	assert(node_kex_ensure(f.mesh, f.peer));
	assert(take_requests(&f, REQ_PUBKEY) == 0);
	f.mesh->loop.now = f.peer->key_retry_at;
	node_kex_watchdog(f.mesh);
	assert(f.peer->key_retry_step == 1 && take_requests(&f, REQ_PUBKEY) == 1);
	f.meta->meta_teardown = true;
	learn_key(&f, &other);
	assert(f.peer->key_retry_phase == NODE_KEX_HANDSHAKE && !f.peer->key_retry_step);
	assert(take_requests(&f, REQ_KEY) == 0);
	f.meta->meta_teardown = false;
	f.mesh->loop.now = f.peer->key_retry_at;
	node_kex_watchdog(f.mesh);
	assert(f.peer->key_retry_step == 1 && take_requests(&f, REQ_KEY) == 1);
	/* Delivery uncertainty is an explicit early retry, shared by all callers. */
	node_kex_mark_uncertain(f.mesh, f.peer);
	assert(node_kex_ensure(f.mesh, f.peer));
	assert(f.peer->key_retry_step == 2 && take_requests(&f, REQ_KEY) == 1);
	assert(node_kex_ensure(f.mesh, f.peer));
	assert(take_requests(&f, REQ_KEY) == 0);
	uint32_t epoch = f.peer->key_retry_epoch;
	f.peer->nexthop = NULL;
	f.mesh->loop.now = f.peer->key_retry_at;
	node_kex_watchdog(f.mesh);
	assert(f.peer->key_retry_step == 2 && f.peer->key_retry_epoch == epoch);
	assert(take_requests(&f, REQ_KEY) == 0);
	f.peer->nexthop = f.backbone;
	f.peer->status.blacklisted = true;
	f.mesh->loop.now = f.peer->key_retry_at;
	node_kex_watchdog(f.mesh);
	assert(!node_kex_ensure(f.mesh, f.peer));
	assert(take_requests(&f, REQ_KEY) == 0);
	f.peer->status.blacklisted = false;
	node_kex_on_session_change(f.mesh, f.peer);
	assert(!f.peer->key_retry_epoch && f.peer->key_retry_phase == NODE_KEX_IDLE);
	assert(node_kex_ensure(f.mesh, f.peer));
	assert(f.peer->key_retry_step == 1 && f.peer->key_retry_epoch == 1);
	assert(take_requests(&f, REQ_KEY) == 1);
	close_fixture(&f);
	close_fixture(&other);
}

static void test_key_learned_without_route(void) {
	fixture_t f = fixture("a", "b"), other = fixture("b", "a");
	assert(node_kex_ensure(f.mesh, f.peer));
	assert(take_requests(&f, REQ_PUBKEY) == 1);
	f.peer->nexthop = NULL;
	/* Simulate the route retiring after parsing the reply but before the owner
	   starts SPTPS. The key is still usable when META is restored. */
	char *key = ecdsa_get_base64_public_key(other.mesh->private_key);
	f.peer->ecdsa = ecdsa_set_base64_public_key(key);
	free(key);
	assert(f.peer->ecdsa);
	assert(!node_kex_ensure(f.mesh, f.peer));
	assert(f.peer->key_retry_phase == NODE_KEX_HANDSHAKE && !f.peer->key_retry_step);
	assert(!f.peer->key_retry_epoch);
	struct timespec deadline = f.peer->key_retry_at;
	assert(node_kex_ensure(f.mesh, f.peer));
	assert(same_time(deadline, f.peer->key_retry_at));
	f.peer->nexthop = f.backbone;
	assert(node_kex_ensure(f.mesh, f.peer));
	assert(take_requests(&f, REQ_KEY) == 0);
	f.mesh->loop.now = deadline;
	node_kex_watchdog(f.mesh);
	assert(take_requests(&f, REQ_KEY) == 1);
	assert(f.peer->key_retry_step == 1 && f.peer->key_retry_epoch == 1);
	expect_delay(&f, f.peer->key_retry_at, 2);
	close_fixture(&f);
	close_fixture(&other);
}

static sockaddr_t public_endpoint(unsigned port) {
	sockaddr_t sa = {0};
	sa.in.sin_family = AF_INET;
	sa.in.sin_addr.s_addr = htonl(0xcb007109); /* 203.0.113.9 */
	sa.in.sin_port = htons(port);
	return sa;
}

static void test_punch_cadence(void) {
	fixture_t f = fixture("a", "b");
	f.peer->status.validkey = true;
	assert(path_channel_acquire(f.mesh, f.peer));
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 1);
	struct timespec deadline = f.peer->peer_udp.next_request;
	sockaddr_t first = public_endpoint(4000), moved = public_endpoint(4001);
	f.mesh->loop.now.tv_nsec = 17000000;
	path_note_punch_endpoint(f.mesh, f.peer, &first);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 0);
	assert(same_time(deadline, f.peer->peer_udp.next_request));
	assert(f.peer->peer_udp.challenge.active && f.peer->peer_udp.challenge.endpoint.in.sin_port == first.in.sin_port);
	uint64_t nonce = f.peer->peer_udp.challenge.nonce;
	path_note_punch_endpoint(f.mesh, f.peer, &first);
	assert(f.peer->peer_udp.challenge.nonce == nonce);
	assert(path_channel_acquire(f.mesh, f.peer));
	path_note_punch_endpoint(f.mesh, f.peer, &moved);
	assert(f.peer->peer_udp.challenge.nonce != nonce);
	assert(f.peer->peer_udp.challenge.endpoint.in.sin_port == moved.in.sin_port);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 0);
	assert(same_time(deadline, f.peer->peer_udp.next_request));
	before_deadline(&f, deadline);
	path_route_tick(f.mesh, f.peer);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 0);
	f.mesh->loop.now = deadline;
	path_route_tick(f.mesh, f.peer);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 1);
	/* A changed hint resets future backoff while preserving the current deadline. */
	assert(f.peer->peer_udp.next_request.tv_sec == f.mesh->loop.now.tv_sec + 1);
	path_route_tick(f.mesh, f.peer);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 0);
	static const unsigned ladder[] = {2, 5, 10, 30, 30};
	for(unsigned i = 0; i < sizeof ladder / sizeof *ladder; i++) {
		f.mesh->loop.now = f.peer->peer_udp.next_request;
		path_route_tick(f.mesh, f.peer);
		assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 1);
		assert(f.peer->peer_udp.next_request.tv_sec == f.mesh->loop.now.tv_sec + ladder[i]);
	}
	/* A session change stays stopped even when a new hint arrives. */
	f.peer->session_id++;
	f.mesh->loop.now = f.peer->peer_udp.next_request;
	path_route_tick(f.mesh, f.peer);
	assert(f.peer->peer_udp.ladder_stopped);
	path_note_punch_endpoint(f.mesh, f.peer, &first);
	path_route_tick(f.mesh, f.peer);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 0);
	assert(f.peer->peer_udp.ladder_stopped);
	f.mesh->lan_network_epoch++;
	path_route_tick(f.mesh, f.peer);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 1);
	assert(!f.peer->peer_udp.ladder_stopped);
	/* A failed META write does not advance the punch ladder. */
	f.mesh->loop.now = f.peer->peer_udp.next_request;
	unsigned step = f.peer->peer_udp.request_step;
	f.meta->meta_teardown = true;
	path_route_tick(f.mesh, f.peer);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 0 && f.peer->peer_udp.request_step == step);
	f.meta->meta_teardown = false;
	path_route_tick(f.mesh, f.peer);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 1);
	path_channel_release(f.mesh, f.peer);
	path_channel_release(f.mesh, f.peer);
	f.mesh->loop.now.tv_sec += PATH_PEER_UDP_GRACE_SEC + 1;
	path_route_tick(f.mesh, f.peer);
	assert(!path_peer_udp_demanded(f.mesh, f.peer));
	assert(path_channel_acquire(f.mesh, f.peer));
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 1);
	f.peer->status.udp_confirmed = true;
	f.peer->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	f.mesh->loop.now = f.peer->peer_udp.next_request;
	path_route_tick(f.mesh, f.peer);
	assert(take_requests(&f, REQ_PUNCH_ENDPOINT) == 0);
	close_fixture(&f);
}

int main(void) {
	fprintf(stderr, "channel start\n");
	test_channel_start();
	fprintf(stderr, "key phases\n");
	test_key_phases();
	fprintf(stderr, "simultaneous start\n");
	test_simultaneous_start();
	fprintf(stderr, "send failures\n");
	test_send_failures();
	fprintf(stderr, "key learned without route\n");
	test_key_learned_without_route();
	fprintf(stderr, "punch cadence\n");
	test_punch_cadence();
	return 0;
}
