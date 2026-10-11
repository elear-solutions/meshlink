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
#include "net_upgrade.h"
#include "net_upgrade_internal.h"
#include "netutl.h"
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

static void test_lost_signature(void) {
	fixture_t a = fixture("a", "b"), b = fixture("b", "a");
	char *key = ecdsa_get_base64_public_key(b.mesh->private_key);
	a.peer->ecdsa = ecdsa_set_base64_public_key(key);
	free(key);
	key = ecdsa_get_base64_public_key(a.mesh->private_key);
	b.peer->ecdsa = ecdsa_set_base64_public_key(key);
	free(key);
	assert(a.peer->ecdsa && b.peer->ecdsa);
	assert(node_kex_ensure(a.mesh, a.peer));
	assert(deliver(&a, &b) == 1);

	/* The responder queues KEX first, then SIG. Deliver KEX and drop SIG. */
	char *kex = buffer_readline(&b.meta->outbuf);
	assert(kex && atoi(kex) == ANS_KEY);
	assert(ans_key_h(a.mesh, a.meta, kex));
	assert(a.peer->sptps.state == SPTPS_SIG);
	assert(b.meta->outbuf.len > b.meta->outbuf.offset);
	assert(take_requests(&b, REQ_KEY) == 0);
	assert(deliver(&a, &b) == 1); /* Our SIG completes the other side. */
	assert(b.peer->status.validkey);
	assert(take_requests(&b, REQ_KEY) == 0);
	assert(!a.peer->status.validkey && a.peer->status.waitingforkey);

	struct timespec deadline = a.peer->key_retry_at;
	before_deadline(&a, deadline);
	assert(node_kex_ensure(a.mesh, a.peer));
	assert(take_requests(&a, REQ_KEY) == 0 && a.peer->sptps_restart_count == 1);
	a.mesh->loop.now = deadline;
	node_kex_watchdog(a.mesh);
	assert(a.peer->key_retry_epoch == 2 && a.peer->key_retry_step == 2);
	finish_handshake(&a, &b);
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

static void test_backbone_private_exchange(void) {
	fixture_t f = fixture("cam", "other");
	sockaddr_t sa;
	uint64_t qid;

	f.meta->protocol_minor = PROT_MINOR_BACKBONE_PRIVATE;
	f.backbone->session_id = 42;
	f.mesh->lan_network_epoch = 3;
	memset(&sa, 0, sizeof sa);
	sa.sa.sa_family = AF_INET;
	assert(inet_pton(AF_INET, "10.30.1.9", &sa.in.sin_addr) == 1);
	sa.in.sin_port = htons(4000);

	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	qid = f.mesh->bb_private.query_id;
	assert(qid);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);

	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid + 1, 42, 1, 300, &sa, PATH_CAP_BOTH));
	assert(f.mesh->bb_private.count == 0);
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid, 7, 1, 300, &sa, PATH_CAP_BOTH));
	assert(f.mesh->bb_private.count == 0);
	f.backbone->connection = NULL;
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid, 42, 1, 300, &sa, PATH_CAP_BOTH));
	assert(f.mesh->bb_private.count == 0);
	f.backbone->connection = f.meta;

	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid, 42, 4, 300, &sa, PATH_CAP_BOTH));
	assert(f.mesh->bb_private.count == 1);
	assert(f.mesh->bb_private.revision == 4);
	assert(f.mesh->bb_private.network_epoch == 3);
	assert(path_backbone_private_vouches(f.mesh, f.backbone, &sa));

	f.mesh->bb_private.query_id = qid + 9;
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid + 9, 42, 3, 300, &sa, PATH_CAP_UDP));
	assert(f.mesh->bb_private.revision == 4);
	assert(f.mesh->bb_private.query_id == qid + 9);

	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid + 9, 42, 5, 300, NULL, 0));
	assert(f.mesh->bb_private.empty);
	assert(f.mesh->bb_private.ladder_step == 5);
	assert(!path_backbone_private_vouches(f.mesh, f.backbone, &sa));

	close_fixture(&f);

	f = fixture("cam", "other");
	f.meta->protocol_minor = 8;
	f.backbone->session_id = 42;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	close_fixture(&f);
}

static sockaddr_t v4_endpoint(const char *ip, uint16_t port) {
	sockaddr_t sa;

	memset(&sa, 0, sizeof sa);
	sa.sa.sa_family = AF_INET;
	assert(inet_pton(AF_INET, ip, &sa.in.sin_addr) == 1);
	sa.in.sin_port = htons(port);
	return sa;
}

/* A member with one vouched private endpoint from session 42. */
static fixture_t private_fixture(const sockaddr_t *sa) {
	fixture_t f = fixture("cam", "other");
	uint64_t qid;

	f.meta->protocol_minor = PROT_MINOR_BACKBONE_PRIVATE;
	f.backbone->session_id = 42;
	f.mesh->lan_network_epoch = 3;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	qid = f.mesh->bb_private.query_id;
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid, 42, 1, 300, sa, PATH_CAP_BOTH));
	assert(path_backbone_private_vouches(f.mesh, f.backbone, sa));
	return f;
}

static void set_backbone_udp(fixture_t *f, const sockaddr_t *sa, address_source_t src) {
	f->mesh->backbone_udp.node = f->backbone;
	f->mesh->backbone_udp.confirmed = true;
	f->mesh->backbone_udp.source = src;
	f->mesh->backbone_udp.endpoint = *sa;
}

static void set_route_udp(fixture_t *f, const sockaddr_t *sa, address_source_t src, bool suspect) {
	memset(&f->backbone->active_route, 0, sizeof f->backbone->active_route);
	f->backbone->active_route.kind = DATA_ROUTE_DIRECT_UDP;
	f->backbone->active_route.udp_endpoint = *sa;
	f->backbone->active_route.endpoint_source = src;
	f->backbone->active_route.local = path_address_is_local(sa);
	f->backbone->active_route.suspect = suspect;
}

static void test_backbone_private_policy(void) {
	sockaddr_t priv = v4_endpoint("10.30.1.9", 4000);
	sockaddr_t pub = v4_endpoint("203.0.113.2", 4000);
	fixture_t f = private_fixture(&priv);
	path_target_t target;

	/* PREFER_PRIVATE never withholds public, even after private was proven. */
	f.mesh->bb_private.ever_proven = true;
	assert(path_backbone_private_public_data_allowed(f.mesh, f.backbone));

	/* PRIVATE_ONLY allows public only until this session proves private. */
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_PRIVATE_ONLY;
	f.mesh->bb_private.ever_proven = false;
	assert(path_backbone_private_public_data_allowed(f.mesh, f.backbone));
	f.mesh->bb_private.ever_proven = true;
	assert(!path_backbone_private_public_data_allowed(f.mesh, f.backbone));

	/* A recorded public route is not a way around PRIVATE_ONLY. */
	set_backbone_udp(&f, &pub, ADDR_SRC_UDP_REFLEXIVE);
	set_route_udp(&f, &pub, ADDR_SRC_UDP_REFLEXIVE, false);
	assert(!path_active_send_target(f.mesh, f.backbone, &target));

	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_PREFER_PRIVATE;
	assert(path_active_send_target(f.mesh, f.backbone, &target));
	assert(target.kind == DATA_ROUTE_DIRECT_UDP);
	assert(!sockaddrcmp(&target.udp_endpoint, &pub));

	/* A suspect private UDP route has no public temporary fallback under
	   PRIVATE_ONLY; it keeps carrying on the private endpoint. */
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_PRIVATE_ONLY;
	set_backbone_udp(&f, &priv, ADDR_SRC_BACKBONE_PRIVATE);
	set_route_udp(&f, &priv, ADDR_SRC_BACKBONE_PRIVATE, true);
	assert(!path_has_live_fallback(f.mesh, f.backbone));
	assert(path_active_send_target(f.mesh, f.backbone, &target));
	assert(target.kind == DATA_ROUTE_DIRECT_UDP);
	assert(!target.temporary_fallback);
	assert(!sockaddrcmp(&target.udp_endpoint, &priv));

	/* PREFER_PRIVATE may use the public META connection as the fallback. */
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_PREFER_PRIVATE;
	assert(path_has_live_fallback(f.mesh, f.backbone));

	memset(&f.mesh->backbone_udp, 0, sizeof f.mesh->backbone_udp);
	memset(&f.backbone->active_route, 0, sizeof f.backbone->active_route);
	close_fixture(&f);
}

static void test_backbone_private_independent_transports(void) {
	sockaddr_t priv = v4_endpoint("10.30.1.9", 4000);
	sockaddr_t other = v4_endpoint("10.30.1.10", 4000);
	fixture_t f = private_fixture(&priv);
	const char *reason;
	outgoing_t dialed;

	/* Private META is the live carrier on the vouched listener we dialed. */
	memset(&dialed, 0, sizeof dialed);
	f.meta->outgoing = &dialed;
	f.meta->address = priv;
	f.meta->status.private_carrier = true;
	f.mesh->backbone_udp.node = f.backbone;

	/* Healthy private META stops queries but not private UDP validation. */
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	assert(f.mesh->backbone_udp.cand.active);
	assert(!sockaddrcmp(&f.mesh->backbone_udp.cand.endpoint, &priv));
	path_backbone_udp_clear_candidate(f.mesh);

	/* A second vouched listener does not pull a still-vouched carrier over. */
	f.mesh->bb_private.query_id = 77;
	f.mesh->bb_private.endpoints[0].meta_state = BB_EP_PROVEN;
	{
		char line[MAXBUFSIZE];
		snprintf(line, sizeof line, "%d backbone cam %d 77 42 2 300 2 10.30.1.9 4000 %u 10.30.1.10 4000 %u",
		         REQ_KEY, ANS_BACKBONE_PRIVATE, (unsigned)PATH_CAP_BOTH, (unsigned)PATH_CAP_BOTH);
		assert(path_backbone_private_handle_answer(f.mesh, f.meta, f.backbone, line));
	}
	assert(f.mesh->bb_private.count == 2);
	assert(!path_backbone_private_meta_superseded(f.mesh, f.backbone));
	reason = path_upgrade_ineligible_reason(f.mesh, f.backbone);
	assert(reason && !strcmp(reason, "already-direct"));

	/* Once the carrier's own address leaves the set, the replacement may cut over. */
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, 0, 42, 3, 300, &other, PATH_CAP_BOTH));
	assert(f.mesh->bb_private.count == 2); /* query 0 is never in flight */
	f.mesh->bb_private.query_id = 78;
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, 78, 42, 3, 300, &other, PATH_CAP_BOTH));
	assert(f.mesh->bb_private.count == 1);
	assert(path_backbone_private_meta_superseded(f.mesh, f.backbone));
	reason = path_upgrade_ineligible_reason(f.mesh, f.backbone);
	assert(!reason || strcmp(reason, "already-direct"));

	f.meta->outgoing = NULL;
	path_backbone_udp_clear_candidate(f.mesh);
	memset(&f.mesh->backbone_udp, 0, sizeof f.mesh->backbone_udp);
	close_fixture(&f);
}

/* Proof is bound to the member's network, the set revision and the backbone
   session. A backbone that restarts on the same IP and port starts from nothing. */
static void test_backbone_private_stale_proofs(void) {
	sockaddr_t priv = v4_endpoint("10.30.1.9", 4000);
	fixture_t f = private_fixture(&priv);
	sockaddr_t out;
	char line[MAXBUFSIZE];
	uint64_t qid;
	uint64_t nonce;

	f.mesh->backbone_udp.node = f.backbone;
	assert(f.meta->status.bb_private_asked);

	/* A reconnect asks at once although the set is current: the backbone
	   pushes CHANGED only on connections that asked. */
	f.meta->status.bb_private_asked = false;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	assert(f.meta->status.bb_private_asked);
	qid = f.mesh->bb_private.query_id;
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid, 42, 1, 300, &priv, PATH_CAP_BOTH));
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	path_backbone_udp_clear_candidate(f.mesh);

	/* Member network change: the set stops vouching and the member asks at
	   once, not at the set's expiry. One query is in flight at a time. */
	f.mesh->lan_network_epoch++;
	assert(!path_backbone_private_vouches(f.mesh, f.backbone, &priv));
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	assert(!f.mesh->backbone_udp.cand.active);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	qid = f.mesh->bb_private.query_id;
	assert(qid);
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid, 42, 2, 300, &priv, PATH_CAP_BOTH));
	assert(path_backbone_private_vouches(f.mesh, f.backbone, &priv));

	/* Having authenticated at the backbone's off-subnet listener does not
	   keep it dialable without the exchange. Other peers keep AUTH_DIRECT. */
	assert(path_is_meta_candidate(f.backbone, &priv, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH));
	assert(path_is_meta_candidate(f.peer, &priv, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH));
	f.mesh->lan_network_epoch++;
	assert(!path_is_meta_candidate(f.backbone, &priv, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH));
	assert(!path_is_udp_candidate(f.backbone, &priv, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH));
	assert(path_is_meta_candidate(f.peer, &priv, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH));
	f.mesh->lan_network_epoch--;

	/* A UDP proof started under revision 2 is void once revision 3 lands. */
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	assert(f.mesh->backbone_udp.cand.active);
	nonce = f.mesh->backbone_udp.cand.nonce;
	f.mesh->bb_private.query_id = 90;
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, 90, 42, 3, 300, &priv, PATH_CAP_BOTH));
	path_backbone_udp_observe_reply(f.mesh, f.backbone, &priv, nonce, NULL);
	assert(!f.mesh->backbone_udp.confirmed);
	assert(!f.mesh->bb_private.ever_proven);

	/* The same reply for the current revision is a proof. */
	path_backbone_udp_clear_candidate(f.mesh);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.mesh->backbone_udp.cand.active);
	nonce = f.mesh->backbone_udp.cand.nonce;
	path_backbone_udp_observe_reply(f.mesh, f.backbone, &priv, nonce, NULL);
	assert(f.mesh->backbone_udp.confirmed);
	assert(f.mesh->backbone_udp.source == ADDR_SRC_BACKBONE_PRIVATE);
	assert(f.mesh->bb_private.endpoints[0].udp_state == BB_EP_PROVEN);
	assert(f.mesh->bb_private.ever_proven);
	assert(path_backbone_private_fill_udp(f.mesh, f.backbone, &out));

	/* Losing that carrier makes the endpoint provable again. */
	path_backbone_udp_reset(f.mesh, f.backbone);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.mesh->bb_private.endpoints[0].udp_state != BB_EP_PROVEN);
	assert(f.mesh->backbone_udp.cand.active);
	path_backbone_udp_clear_candidate(f.mesh);

	/* Restart on the same IP and port: new session, same address. What
	   check_reachability does on a session change wipes every proof. */
	f.backbone->session_id = 43;
	path_backbone_private_on_session_change(f.mesh, f.backbone);
	path_backbone_udp_reset(f.mesh, f.backbone);
	assert(!f.mesh->backbone_udp.confirmed);
	assert(!f.mesh->bb_private.ever_proven);
	assert(!f.mesh->bb_private.count);
	assert(!path_backbone_private_vouches(f.mesh, f.backbone, &priv));
	assert(!path_backbone_private_fill_udp(f.mesh, f.backbone, &out));
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_PRIVATE_ONLY;
	assert(path_backbone_private_public_data_allowed(f.mesh, f.backbone));
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_PREFER_PRIVATE;

	/* A late answer or CHANGED from the old session is refused, although it
	   names the same endpoint. */
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	qid = f.mesh->bb_private.query_id;
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid, 42, 9, 300, &priv, PATH_CAP_BOTH));
	assert(!f.mesh->bb_private.count);
	assert(f.mesh->bb_private.query_id == qid);
	snprintf(line, sizeof line, "%d backbone cam %d 42 10", REQ_KEY, REQ_BACKBONE_PRIVATE_CHANGED);
	assert(path_backbone_private_handle_changed(f.mesh, f.meta, f.backbone, line));
	assert(!f.mesh->bb_private.changed_pending);
	assert(f.mesh->bb_private.query_id == qid);

	/* The new session's answer is accepted at a lower revision and starts unproven. */
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, qid, 43, 1, 300, &priv, PATH_CAP_BOTH));
	assert(f.mesh->bb_private.count == 1);
	assert(f.mesh->bb_private.session_id == 43);
	assert(f.mesh->bb_private.endpoints[0].meta_state == BB_EP_IDLE);
	assert(f.mesh->bb_private.endpoints[0].udp_state == BB_EP_IDLE);

	/* Within a session, CHANGED must move the revision forward to matter. */
	snprintf(line, sizeof line, "%d backbone cam %d 43 1", REQ_KEY, REQ_BACKBONE_PRIVATE_CHANGED);
	assert(path_backbone_private_handle_changed(f.mesh, f.meta, f.backbone, line));
	assert(!f.mesh->bb_private.changed_pending);
	snprintf(line, sizeof line, "%d backbone cam %d 43 2", REQ_KEY, REQ_BACKBONE_PRIVATE_CHANGED);
	assert(path_backbone_private_handle_changed(f.mesh, f.meta, f.backbone, line));
	assert(f.mesh->bb_private.changed_pending);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);

	path_backbone_udp_stop(f.mesh);
	close_fixture(&f);
}

static void fire_candidate_timer(fixture_t *f) {
	timeout_t *t = &f->mesh->backbone_udp.cand.timer;

	assert(t->cb);
	t->cb(&f->mesh->loop, t->data);
}

/* Replace the set with one that no longer names the old endpoint. */
static void withdraw_endpoint(fixture_t *f, const sockaddr_t *gone, const sockaddr_t *other, uint32_t revision) {
	f->mesh->bb_private.query_id = 500 + revision;
	assert(path_backbone_private_test_offer(f->mesh, f->meta, f->backbone, 500 + revision, 42, revision, 300, other, PATH_CAP_BOTH));
	assert(!path_backbone_private_knows(f->mesh, gone));
}

/* A direct META standby that was dialed from the private set. */
static connection_t *private_standby(fixture_t *f, const sockaddr_t *sa) {
	connection_t *c = new_connection();

	c->name = strdup("backbone");
	c->socket = -1;
	c->node = f->backbone;
	c->mesh = f->mesh;
	c->address = *sa;
	c->allow_request = ALL;
	c->status.active = true;
	c->status.spare = true;
	c->status.initiator = true;
	c->status.bb_private_probe = true;
	return c;
}

static void send_cutover_reply(fixture_t *f, connection_t *c, int request) {
	upgrade_cutover_snapshot_t snap;
	char line[64];

	upgrade_cutover_snapshot(f->backbone, &snap);
	assert(snap.id);
	snprintf(line, sizeof line, "%d %" PRIu64 "\n", request, snap.id);

	if(request == REQ_META_CUTOVER_READY) {
		assert(meta_cutover_ready_h(f->mesh, c, line));
	} else {
		assert(meta_cutover_ack_h(f->mesh, c, line));
	}
}

/* Authority is checked when a proof or a commit lands, not only when it starts. */
static void test_backbone_private_races(void) {
	sockaddr_t priv = v4_endpoint("10.30.1.9", 4000);
	sockaddr_t other = v4_endpoint("10.30.1.10", 4000);
	fixture_t f = private_fixture(&priv);
	upgrade_cutover_snapshot_t snap;
	connection_t *standby;
	uint64_t nonce;
	int meta_fd;

	/* A UDP reply that arrives after the set expired is not a proof. */
	f.mesh->backbone_udp.node = f.backbone;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.mesh->backbone_udp.cand.active);
	nonce = f.mesh->backbone_udp.cand.nonce;
	f.mesh->loop.now = f.mesh->bb_private.expires_at;
	assert(!path_backbone_private_vouches(f.mesh, f.backbone, &priv));
	path_backbone_udp_observe_reply(f.mesh, f.backbone, &priv, nonce, NULL);
	assert(!f.mesh->backbone_udp.confirmed);
	assert(f.mesh->backbone_udp.source != ADDR_SRC_BACKBONE_PRIVATE);
	assert(!f.mesh->bb_private.ever_proven);
	assert(!f.mesh->backbone_udp.cand.active);
	path_backbone_udp_stop(f.mesh);
	close_fixture(&f);

	/* Probes the scheduler did not send are not unanswered, and are not queued. */
	f = private_fixture(&priv);
	f.mesh->backbone_udp.node = f.backbone;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.mesh->backbone_udp.cand.active);
	path_scheduler_set_budget(f.mesh, 0, 0, PATH_SCHED_MAX_TRANSACTIONS);

	for(int i = 0; i < 2 * PATH_BACKBONE_UDP_ESTABLISH_MISS; i++) {
		fire_candidate_timer(&f);
	}

	assert(f.mesh->backbone_udp.cand.active);
	assert(f.mesh->backbone_udp.cand.unanswered == 0);
	assert(f.mesh->bb_private.endpoints[0].udp_state != BB_EP_FAILED);
	assert(!f.mesh->bb_private.endpoints[0].udp_failures);
	assert(!f.mesh->probe_queue || !f.mesh->probe_queue->count);
	path_backbone_udp_stop(f.mesh);
	close_fixture(&f);

	/* Withdrawn after the barrier started: READY does not lead to COMMIT. */
	f = private_fixture(&priv);
	standby = private_standby(&f, &priv);
	assert(upgrade_cutover_begin(f.mesh, f.backbone, f.meta, standby));
	withdraw_endpoint(&f, &priv, &other, 2);
	send_cutover_reply(&f, f.meta, REQ_META_CUTOVER_READY);
	upgrade_cutover_snapshot(f.backbone, &snap);
	assert(!snap.state);
	assert(f.backbone->connection == f.meta);
	assert(standby->meta_teardown);
	free_connection(standby);
	close_fixture(&f);

	/* Withdrawn before the barrier: the probe's provenance still requires
	   authority although the address is no longer in the set at all. */
	f = private_fixture(&priv);
	withdraw_endpoint(&f, &priv, &other, 2);
	standby = private_standby(&f, &priv);
	assert(!upgrade_cutover_begin(f.mesh, f.backbone, f.meta, standby));
	assert(f.backbone->connection == f.meta);

	/* An ordinary LAN standby at the same address is not held to the set. */
	standby->status.bb_private_probe = false;
	assert(upgrade_cutover_begin(f.mesh, f.backbone, f.meta, standby));
	upgrade_cutover_test_abort(f.mesh, f.backbone);
	free_connection(standby);
	close_fixture(&f);

	/* An expired advertisement no longer names the address. An ordinary
	   on-link standby is not held. A probe dialed from the set still needs
	   a live voucher. */
	f = private_fixture(&priv);
	f.mesh->loop.now = f.mesh->bb_private.expires_at;
	assert(!path_backbone_private_knows(f.mesh, &priv));
	assert(!path_backbone_private_vouches(f.mesh, f.backbone, &priv));
	standby = private_standby(&f, &priv);
	standby->status.bb_private_probe = false;
	assert(upgrade_cutover_begin(f.mesh, f.backbone, f.meta, standby));
	upgrade_cutover_test_abort(f.mesh, f.backbone);
	standby->status.bb_private_probe = true;
	assert(!upgrade_cutover_begin(f.mesh, f.backbone, f.meta, standby));
	free_connection(standby);
	close_fixture(&f);

	/* Withdrawn after COMMIT went out: the peer has committed, so ACK still
	   completes, but the withdrawn connection does not stay primary. */
	f = private_fixture(&priv);
	standby = private_standby(&f, &priv);
	assert(upgrade_cutover_begin(f.mesh, f.backbone, f.meta, standby));
	send_cutover_reply(&f, f.meta, REQ_META_CUTOVER_READY);
	upgrade_cutover_snapshot(f.backbone, &snap);
	assert(snap.state == META_CUTOVER_INIT_WAIT_ACK);
	withdraw_endpoint(&f, &priv, &other, 2);
	meta_fd = f.meta->socket;
	f.meta->socket = -1; /* keep the fixture's primary out of terminate_connection */
	send_cutover_reply(&f, standby, REQ_META_CUTOVER_ACK);
	upgrade_cutover_snapshot(f.backbone, &snap);
	assert(!snap.state);
	assert(f.backbone->connection == standby);
	assert(!standby->status.private_carrier);
	assert(standby->meta_teardown);
	f.meta->socket = meta_fd;
	f.backbone->connection = f.meta;
	free_connection(standby);
	close_fixture(&f);
}

/* The backbone side: minor-8 members never get the exchange, minor-9
   members are answered within the reply window and pushed CHANGED. */
static void test_backbone_private_publisher(void) {
	fixture_t f = fixture("nmn", "other");
	char request[MAX_STRING_SIZE];
	uint32_t revision;

	/* This mesh is the backbone. The fixture's "backbone" node is a member here. */
	free(f.mesh->backbone.name);
	f.mesh->backbone.name = strdup("nmn");
	f.mesh->backbone.node = f.mesh->self;
	assert(connection_policy_is_backbone(f.mesh, f.mesh->self));
	assert(!connection_policy_is_backbone(f.mesh, f.backbone));
	snprintf(request, sizeof request, "%d backbone nmn %d 5", REQ_KEY, REQ_BACKBONE_PRIVATE);

	f.meta->protocol_minor = PROT_MINOR_BACKBONE_PRIVATE - 1;
	assert(path_backbone_private_handle_request(f.mesh, f.meta, f.backbone, request));
	assert(take_requests(&f, ANS_BACKBONE_PRIVATE) == 0);
	assert(!f.meta->status.bb_private_queried);
	/* Even a subscribed minor-8 connection is never sent CHANGED. */
	f.meta->status.bb_private_queried = true;
	f.mesh->bb_private.publish_hash ^= 1;
	path_backbone_private_publish_refresh(f.mesh);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE_CHANGED) == 0);
	f.meta->status.bb_private_queried = false;

	f.meta->protocol_minor = PROT_MINOR_BACKBONE_PRIVATE;
	assert(path_backbone_private_handle_request(f.mesh, f.meta, f.backbone, request));
	assert(take_requests(&f, ANS_BACKBONE_PRIVATE) == 1);
	assert(f.meta->status.bb_private_queried);
	assert(path_backbone_private_handle_request(f.mesh, f.meta, f.backbone, request));
	assert(take_requests(&f, ANS_BACKBONE_PRIVATE) == 0);
	f.mesh->loop.now.tv_sec += BB_PRIVATE_REPLY_MIN_SEC;
	assert(path_backbone_private_handle_request(f.mesh, f.meta, f.backbone, request));
	assert(take_requests(&f, ANS_BACKBONE_PRIVATE) == 1);

	revision = f.mesh->bb_private.publish_revision;
	path_backbone_private_publish_refresh(f.mesh);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE_CHANGED) == 0);
	assert(f.mesh->bb_private.publish_revision == revision);
	f.mesh->bb_private.publish_hash ^= 1;
	path_backbone_private_publish_refresh(f.mesh);
	assert(f.mesh->bb_private.publish_revision == revision + 1);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE_CHANGED) == 1);

	close_fixture(&f);
}

int main(void) {
	fprintf(stderr, "channel start\n");
	test_channel_start();
	fprintf(stderr, "key phases\n");
	test_key_phases();
	fprintf(stderr, "simultaneous start\n");
	test_simultaneous_start();
	fprintf(stderr, "lost signature\n");
	test_lost_signature();
	fprintf(stderr, "send failures\n");
	test_send_failures();
	fprintf(stderr, "key learned without route\n");
	test_key_learned_without_route();
	fprintf(stderr, "punch cadence\n");
	test_punch_cadence();
	fprintf(stderr, "backbone private exchange\n");
	test_backbone_private_exchange();
	fprintf(stderr, "backbone private policy\n");
	test_backbone_private_policy();
	fprintf(stderr, "backbone private independent transports\n");
	test_backbone_private_independent_transports();
	fprintf(stderr, "backbone private stale proofs\n");
	test_backbone_private_stale_proofs();
	fprintf(stderr, "backbone private races\n");
	test_backbone_private_races();
	fprintf(stderr, "backbone private publisher\n");
	test_backbone_private_publisher();
	return 0;
}
