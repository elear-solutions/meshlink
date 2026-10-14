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
#include "meta.h"
#include "path_policy.h"
#include "protocol.h"
#include <assert.h>
#include <net/if.h>

typedef struct {
	meshlink_handle_t *mesh;
	node_t *peer;
	node_t *backbone;
	connection_t *meta;
	int reader;
	unsigned synchronous_writes;
	unsigned *private_query_attempts;
} fixture_t;

static void unused_io(event_loop_t *loop, void *data, int flags) {
	(void)loop;
	(void)data;
	(void)flags;
	abort();
}

static fixture_t fixture_with_config(const char *self, const char *peer, const char *confbase) {
	fixture_t f = {0};
	f.mesh = confbase ? meshlink_open(confbase, self, "peer-control", DEV_CLASS_STATIONARY)
	         : meshlink_open_ephemeral(self, "peer-control", DEV_CLASS_STATIONARY);
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

static fixture_t fixture(const char *self, const char *peer) {
	return fixture_with_config(self, peer, NULL);
}

static void free_query_counter(fixture_t *f) {
	f->mesh->priv = NULL;
	free(f->private_query_attempts);
	f->private_query_attempts = NULL;
}

static void close_fixture(fixture_t *f) {
	free_query_counter(f);
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
	meshlink_set_backbone_path_policy(f.mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
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
	meshlink_set_backbone_path_policy(f.mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	f.meta->protocol_minor = 8;
	f.backbone->session_id = 42;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	close_fixture(&f);
}

/* Failed writes have no in-flight query. Their deadline belongs only to the
   attempted META socket/network, including a first write with asked == false. */
/* Observe submissions to the real writer, including rejected writes. Accepted
   records are counted independently by take_requests() reading its output. */
static void count_private_query_attempt(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)level;
	if(!mesh || !mesh->priv || strncmp(text, "Sending REQ_KEY ", 16)) {
		return;
	}
	const char *request = strstr(text, ": ");
	int extension;
	if(request && sscanf(request + 2, "%*d %*s %*s %d", &extension) == 1
	                && extension == REQ_BACKBONE_PRIVATE) {
		unsigned *attempts = mesh->priv;
		(*attempts)++;
	}
}

static fixture_t failed_private_query(bool empty) {
	fixture_t f = fixture("cam", "other");
	meshlink_set_backbone_path_policy(f.mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	f.meta->protocol_minor = PROT_MINOR_BACKBONE_PRIVATE;
	f.backbone->session_id = 42;
	f.private_query_attempts = calloc(1, sizeof *f.private_query_attempts);
	assert(f.private_query_attempts);
	f.mesh->priv = f.private_query_attempts;
	meshlink_set_log_cb(f.mesh, MESHLINK_DEBUG, count_private_query_attempt);
	if(empty) {
		path_backbone_private_tick(f.mesh, f.backbone);
		assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
		assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone,
		                f.mesh->bb_private.query_id, 42, 1, 300, NULL, PATH_CAP_NONE));
		f.mesh->loop.now = f.mesh->bb_private.next_query_at;
	}
	f.meta->meta_teardown = true;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	assert(f.mesh->bb_private.query_hold && !f.mesh->bb_private.query_id);
	assert(*f.private_query_attempts == (empty ? 2 : 1));
	if(empty) {
		time_t delay = f.mesh->bb_private.next_query_at.tv_sec - f.mesh->loop.now.tv_sec;
		assert(delay >= 96 && delay <= 144);
	}
	return f;
}

static void test_private_query_failure_pacing(void) {
	fixture_t f = failed_private_query(false);
	assert(!f.meta->status.bb_private_asked);
	assert(f.mesh->bb_private.ladder_step == 1);
	struct timespec deadline = f.mesh->bb_private.next_query_at;
	for(int i = 0; i < 5; i++) {
		path_backbone_private_tick(f.mesh, f.backbone);
		assert(f.mesh->bb_private.query_hold);
		assert(*f.private_query_attempts == 1);
		assert(f.mesh->bb_private.ladder_step == 1);
		assert(same_time(deadline, f.mesh->bb_private.next_query_at));
	}
	before_deadline(&f, deadline);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(same_time(deadline, f.mesh->bb_private.next_query_at));
	assert(*f.private_query_attempts == 1);
	f.meta->meta_teardown = false;
	f.mesh->loop.now = deadline;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	assert(!f.mesh->bb_private.query_hold && f.mesh->bb_private.query_id);
	assert(*f.private_query_attempts == 2);
	deadline = f.mesh->bb_private.next_query_at;
	/* An accepted query remains pending even across a network change. */
	connection_policy_advance_network_epoch(f.mesh);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	assert(same_time(deadline, f.mesh->bb_private.next_query_at));
	/* A timeout followed by a failed write climbs once. */
	f.mesh->loop.now = deadline;
	f.meta->meta_teardown = true;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.mesh->bb_private.query_hold && f.mesh->bb_private.ladder_step == 2);
	assert(*f.private_query_attempts == 3);
	deadline = f.mesh->bb_private.next_query_at;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(same_time(deadline, f.mesh->bb_private.next_query_at));
	assert(f.mesh->bb_private.ladder_step == 2);
	assert(*f.private_query_attempts == 3);
	f.meta->meta_teardown = false;
	f.mesh->loop.now = deadline;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone,
	                f.mesh->bb_private.query_id, 42, 1, 300, NULL, PATH_CAP_NONE));
	assert(!f.mesh->bb_private.query_hold && !f.mesh->bb_private.query_id);
	assert(*f.private_query_attempts == 4);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	close_fixture(&f);
}

/* SPTPS can synchronously dispatch a response from its send callback. Count
   actual META writes and require the answer's deadline to survive member_send. */
static bool synchronous_private_answer(void *handle, uint8_t type, const void *data, size_t len) {
	fixture_t *f = handle;
	assert(type == 0 && f->mesh->bb_private.query_id);
	assert(send_meta_sptps(f->meta, type, data, len));
	f->synchronous_writes++;
	assert(path_backbone_private_test_offer(f->mesh, f->meta, f->backbone,
	                f->mesh->bb_private.query_id, 42, 1, 300, NULL, PATH_CAP_NONE));
	return true;
}

static void test_private_query_synchronous_answer(void) {
	fixture_t f = failed_private_query(false);
	f.meta->meta_teardown = false;
	f.meta->allow_request = ALL;
	f.meta->sptps.handle = &f;
	f.meta->sptps.outstate = true;
	f.meta->sptps.send_data = synchronous_private_answer;
	f.meta->sptps.outcipher = chacha_poly1305_init();
	assert(f.meta->sptps.outcipher);
	uint8_t key[CHACHA_POLY1305_KEYLEN] = {0};
	assert(chacha_poly1305_set_key(f.meta->sptps.outcipher, key));
	f.mesh->loop.now = f.mesh->bb_private.next_query_at;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.synchronous_writes == 1 && f.meta->outbuf.len > 0);
	assert(f.meta->status.bb_private_asked);
	assert(!f.mesh->bb_private.query_id && !f.mesh->bb_private.query_hold);
	assert(f.mesh->bb_private.empty && f.mesh->bb_private.ladder_step == 5);
	assert(f.mesh->bb_private.next_query_at.tv_sec == f.mesh->loop.now.tv_sec + 120);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.synchronous_writes == 1);
	close_fixture(&f);
}

static bool synchronous_private_network_change(void *handle, uint8_t type, const void *data, size_t len) {
	fixture_t *f = handle;
	uint64_t id = f->mesh->bb_private.query_id;
	assert(id && type == 0);
	assert(send_meta_sptps(f->meta, type, data, len));
	f->synchronous_writes++;
	connection_policy_advance_network_epoch(f->mesh);
	assert(f->mesh->bb_private.query_id == id);
	return true;
}

static void test_private_query_accepted_network_reentrancy(void) {
	fixture_t f = failed_private_query(false);
	f.meta->meta_teardown = false;
	f.meta->allow_request = ALL;
	f.meta->sptps.handle = &f;
	f.meta->sptps.outstate = true;
	f.meta->sptps.send_data = synchronous_private_network_change;
	f.meta->sptps.outcipher = chacha_poly1305_init();
	assert(f.meta->sptps.outcipher);
	uint8_t key[CHACHA_POLY1305_KEYLEN] = {0};
	assert(chacha_poly1305_set_key(f.meta->sptps.outcipher, key));
	f.mesh->loop.now = f.mesh->bb_private.next_query_at;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.synchronous_writes == 1 && f.meta->outbuf.len > 0);
	assert(f.mesh->bb_private.query_id && f.meta->status.bb_private_asked);
	assert(!f.mesh->bb_private.query_hold);
	struct timespec deadline = f.mesh->bb_private.next_query_at;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.synchronous_writes == 1);
	assert(same_time(deadline, f.mesh->bb_private.next_query_at));
	assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone,
	                f.mesh->bb_private.query_id, 42, 1, 300, NULL, PATH_CAP_NONE));
	close_fixture(&f);
}

static void test_private_query_failed_reconnect(void) {
	fixture_t f = failed_private_query(true);
	struct timespec deadline = f.mesh->bb_private.next_query_at;
	/* Retire through production, then allocate and register a fresh connection.
	   This also works if malloc reuses the old address or the session is warm. */
	terminate_connection(f.mesh, f.meta, false);
	close(f.reader);
	int fd[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
	f.reader = fd[1];
	f.meta = new_connection();
	f.meta->name = strdup("backbone");
	f.meta->socket = fd[0];
	f.meta->node = f.backbone;
	f.meta->status.active = true;
	f.meta->allow_request = ID;
	f.meta->protocol_minor = PROT_MINOR_BACKBONE_PRIVATE;
	connection_add(f.mesh, f.meta);
	io_add(&f.mesh->loop, &f.meta->io, unused_io, NULL, fd[0], IO_READ);
	f.backbone->connection = f.meta;
	assert(f.backbone->session_id == 42);
	assert(!same_time(f.mesh->loop.now, deadline));
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	assert(!f.mesh->bb_private.query_hold);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	close_fixture(&f);
}

static void test_private_query_failed_network_change(void) {
	fixture_t f = failed_private_query(true);
	struct timespec deadline = f.mesh->bb_private.next_query_at;
	f.meta->meta_teardown = false;
	/* Query-context retirement must preserve transport-specific cooldowns. */
	bb_private_endpoint_t endpoint = {0};
	endpoint.sa = public_endpoint(4000);
	endpoint.cap = PATH_CAP_BOTH;
	endpoint.meta_state = BB_EP_FAILED;
	endpoint.udp_state = BB_EP_FAILED;
	endpoint.meta_failures = 3;
	endpoint.udp_failures = 4;
	endpoint.meta_retry_at = (struct timespec) {1000, 0};
	endpoint.udp_retry_at = (struct timespec) {1100, 0};
	f.mesh->bb_private.endpoints[0] = endpoint;
	f.mesh->bb_private.count = 1;
	/* The high bits must matter even when the advertisement's low bits match. */
	f.mesh->lan_network_epoch += UINT64_C(1) << 32;
	connection_policy_advance_network_epoch(f.mesh);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	assert(f.mesh->loop.now.tv_sec < deadline.tv_sec);
	assert(!f.mesh->bb_private.query_hold && f.mesh->bb_private.query_id);
	assert(f.mesh->bb_private.count == 1);
	bb_private_endpoint_t *saved = &f.mesh->bb_private.endpoints[0];
	assert(!sockaddrcmp(&endpoint.sa, &saved->sa) && saved->cap == endpoint.cap);
	assert(saved->meta_state == BB_EP_FAILED && saved->udp_state == BB_EP_FAILED);
	assert(saved->meta_failures == 3 && saved->udp_failures == 4);
	assert(same_time(saved->meta_retry_at, endpoint.meta_retry_at));
	assert(same_time(saved->udp_retry_at, endpoint.udp_retry_at));
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	close_fixture(&f);

	/* Identical low epoch bits cannot alias an obsolete failed context. */
	f = failed_private_query(true);
	f.meta->meta_teardown = false;
	f.mesh->lan_network_epoch += UINT64_C(1) << 32;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	assert(!f.mesh->bb_private.query_hold);
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
	meshlink_set_backbone_path_policy(f.mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
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

	/* ONLY_PRIVATE allows public only until this session proves private. */
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_ONLY_PRIVATE;
	f.mesh->bb_private.ever_proven = false;
	assert(path_backbone_private_public_data_allowed(f.mesh, f.backbone));
	f.mesh->bb_private.ever_proven = true;
	assert(!path_backbone_private_public_data_allowed(f.mesh, f.backbone));

	/* A recorded public route is not a way around ONLY_PRIVATE. */
	set_backbone_udp(&f, &pub, ADDR_SRC_UDP_REFLEXIVE);
	set_route_udp(&f, &pub, ADDR_SRC_UDP_REFLEXIVE, false);
	assert(!path_active_send_target(f.mesh, f.backbone, &target));

	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_PREFER_PRIVATE;
	assert(path_active_send_target(f.mesh, f.backbone, &target));
	assert(target.kind == DATA_ROUTE_DIRECT_UDP);
	assert(!sockaddrcmp(&target.udp_endpoint, &pub));

	/* A suspect private UDP route has no public temporary fallback under
	   ONLY_PRIVATE; it keeps carrying on the private endpoint. */
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_ONLY_PRIVATE;
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
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_ONLY_PRIVATE;
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

static void assert_hold_retired(fixture_t *f) {
	assert(!f->mesh->bb_private.query_hold);
	assert(!f->mesh->bb_private.hold_connection_generation);
	assert(!f->mesh->bb_private.hold_network_epoch);
	assert(!f->mesh->bb_private.hold_session_id);
}

static void test_private_query_retirement(void) {
	fixture_t f = failed_private_query(true);
	f.mesh->bb_private.publish_revision = 17;
	f.mesh->bb_private.publish_hash = 12345;
	f.backbone->session_id++;
	path_backbone_private_on_session_change(f.mesh, f.backbone);
	assert_hold_retired(&f);
	assert(!f.mesh->bb_private.query_id && !f.mesh->bb_private.count);
	assert(same_time(f.mesh->bb_private.next_query_at, (struct timespec) {0, 0}));
	assert(f.mesh->bb_private.publish_revision == 17);
	assert(f.mesh->bb_private.publish_hash == 12345);
	f.meta->meta_teardown = false;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	close_fixture(&f);

	f = failed_private_query(true);
	meshlink_stop(f.mesh);
	f.meta = NULL;
	assert_hold_retired(&f);
	assert(same_time(f.mesh->bb_private.next_query_at, (struct timespec) {0, 0}));
	assert(!f.mesh->connections->count);
	free_query_counter(&f);
	close(f.reader);
	meshlink_close(f.mesh);

	/* Direct list cleanup also retires context, independently of terminate. */
	f = failed_private_query(false);
	close_fixture(&f);
}

static void test_private_query_failed_cutover(void) {
	fixture_t f = failed_private_query(true);
	struct timespec deadline = f.mesh->bb_private.next_query_at;
	connection_t *old = f.meta;
	int old_reader = f.reader;
	int old_fd = old->socket;
	int fd[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
	sockaddr_t public = public_endpoint(4000);
	connection_t *standby = private_standby(&f, &public);
	standby->status.bb_private_probe = false;
	standby->protocol_minor = PROT_MINOR_BACKBONE_PRIVATE;
	standby->allow_request = ID;
	standby->socket = fd[0];
	connection_add(f.mesh, standby);
	io_add(&f.mesh->loop, &standby->io, unused_io, NULL, fd[0], IO_READ);
	assert(standby->generation != old->generation);
	/* Keep the old object alive through promotion to test normalization even
	   before the retiring object's destructor clears anything. */
	old->socket = -1;
	old->meta_teardown = false;
	old->status.bb_private_queried = true;
	old->bb_private_reply_at = 321;
	old->activated_at = 50;
	assert(upgrade_cutover_begin(f.mesh, f.backbone, old, standby));
	send_cutover_reply(&f, old, REQ_META_CUTOVER_READY);
	send_cutover_reply(&f, standby, REQ_META_CUTOVER_ACK);
	assert(f.backbone->connection == standby);
	assert(standby->status.bb_private_asked && standby->status.bb_private_queried);
	assert(standby->activated_at == 50 && standby->bb_private_reply_at == 321);
	f.meta = standby;
	f.reader = fd[1];
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 1);
	assert_hold_retired(&f);
	assert(f.mesh->loop.now.tv_sec < deadline.tv_sec);
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
	old->socket = old_fd;
	connection_del(f.mesh, old);
	close(old_reader);
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

static void test_backbone_private_default(void) {
	const char *confbase = "peer-control-private-default";
	sockaddr_t sa = v4_endpoint("10.30.1.9", 4000);
	assert(meshlink_destroy(confbase));

	for(unsigned persistent = 0; persistent < 2; persistent++) {
		fixture_t f = fixture_with_config("cam", "other", persistent ? confbase : NULL);
		path_probe_tap_t tap = {.swallow = true};
		path_scheduler_set_tap(f.mesh, &tap);
		assert(f.mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
		f.meta->protocol_minor = PROT_MINOR_BACKBONE_PRIVATE;
		f.backbone->session_id = 42;
		f.mesh->backbone_udp.node = f.backbone;

		for(unsigned i = 0; i < 20; i++) {
			path_backbone_private_tick(f.mesh, f.backbone);
			f.mesh->loop.now.tv_sec += 120;
		}

		assert(take_requests(&f, REQ_BACKBONE_PRIVATE) == 0);
		assert(!f.mesh->bb_private.query_id && !f.mesh->backbone_udp.cand.active);
		assert(!f.backbone->upgrade_probe && !tap.count);

		/* Even a matching late answer and a newer CHANGED cannot install work. */
		f.mesh->bb_private.query_id = 123;
		assert(path_backbone_private_test_offer(f.mesh, f.meta, f.backbone, 123, 42, 1, 300, &sa, PATH_CAP_BOTH));
		assert(!f.mesh->bb_private.count && f.mesh->bb_private.query_id == 123);
		char line[MAX_STRING_SIZE];
		snprintf(line, sizeof line, "%d backbone cam %d 42 2", REQ_KEY, REQ_BACKBONE_PRIVATE_CHANGED);
		assert(path_backbone_private_handle_changed(f.mesh, f.meta, f.backbone, line));
		assert(!f.mesh->bb_private.changed_pending && f.mesh->bb_private.query_id == 123);

		/* Planted private provenance is ineligible even for public/loopback IPs. */
		const char *addresses[] = {"10.30.1.9", "203.0.113.2", "127.0.0.1"};
		for(unsigned i = 0; i < sizeof addresses / sizeof addresses[0]; i++) {
			sockaddr_t planted = v4_endpoint(addresses[i], 4000);
			assert(!path_is_meta_candidate(f.backbone, &planted, ADDR_SRC_BACKBONE_PRIVATE, PATH_CAP_BOTH));
			assert(!path_is_udp_candidate(f.backbone, &planted, ADDR_SRC_BACKBONE_PRIVATE, PATH_CAP_BOTH));
		}

		f.mesh->bb_private.ever_proven = true;
		assert(path_backbone_private_public_data_allowed(f.mesh, f.backbone));
		path_backbone_private_note_meta_proven(f.mesh, f.backbone, &sa);
		assert(!path_backbone_private_fill_meta(f.mesh, f.backbone));
		path_backbone_udp_stop(f.mesh);
		close_fixture(&f);
	}

	assert(meshlink_destroy(confbase));
}

static void test_backbone_private_disabled_candidate(void) {
	sockaddr_t sa = v4_endpoint("10.30.1.9", 4000);
	fixture_t f = private_fixture(&sa);
	f.mesh->backbone_udp.node = f.backbone;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.mesh->backbone_udp.cand.active);
	uint64_t nonce = f.mesh->backbone_udp.cand.nonce;
	path_probe_tap_t tap = {.swallow = true};
	path_scheduler_set_tap(f.mesh, &tap);
	/* Bypass lifecycle cleanup to exercise every late-entry guard. */
	f.mesh->backbone_path_policy = MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE;
	fire_candidate_timer(&f);
	assert(!f.mesh->backbone_udp.cand.active && !tap.count);
	path_backbone_udp_observe_reply(f.mesh, f.backbone, &sa, nonce, NULL);
	assert(!f.mesh->backbone_udp.confirmed && !f.mesh->bb_private.ever_proven);
	f.mesh->backbone_udp.endpoint = sa;
	f.mesh->backbone_udp.source = ADDR_SRC_BACKBONE_PRIVATE;
	f.mesh->backbone_udp.liveness_nonce = nonce;
	path_backbone_udp_observe_reply(f.mesh, f.backbone, &sa, nonce, NULL);
	assert(!f.mesh->backbone_udp.confirmed);
	connection_t *standby = private_standby(&f, &sa);
	assert(!upgrade_cutover_begin(f.mesh, f.backbone, f.meta, standby));
	free_connection(standby);
	path_backbone_udp_stop(f.mesh);
	close_fixture(&f);
}

static void test_backbone_private_cache_provenance(void) {
	sockaddr_t sa = v4_endpoint("10.30.1.9", 4000);
	fixture_t f = private_fixture(&sa);
	local_iface_addr_t iface = {.ifindex = 1, .flags = IFF_UP, .prefix_len = 24};
	iface.address = v4_endpoint("10.30.1.2", 0);
	assert(local_network_set_snapshot(f.mesh, &iface, 1));
	/* Refresh the voucher into the new network epoch. */
	f.mesh->bb_private.network_epoch = f.mesh->lan_network_epoch;
	assert(local_network_on_link(f.mesh, &sa));
	connection_t *standby = private_standby(&f, &sa);
	standby->status.active = false;
	standby->status.spare = false;
	upgrade_hold_standby(f.mesh, standby, f.backbone, "4000", DEV_CLASS_BACKBONE);
	assert(f.backbone->recent_source[0] == ADDR_SRC_BACKBONE_PRIVATE);
	/* Graph observations must not erase the feature's provenance. */
	node_add_recent_address_cap(f.mesh, f.backbone, &sa, ADDR_SRC_EDGE_DIRECT, PATH_CAP_BOTH);
	assert(f.backbone->recent_source[0] == ADDR_SRC_BACKBONE_PRIVATE);
	free_edge(standby->edge);
	standby->edge = NULL;
	free_connection(standby);
	f.meta->address = sa;
	f.meta->status.private_carrier = true;
	path_reclassify_active_meta(f.mesh, f.backbone);
	assert(f.backbone->recent_source[0] == ADDR_SRC_BACKBONE_PRIVATE);
	meshlink_set_backbone_path_policy(f.mesh, MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	assert(!path_is_meta_candidate(f.backbone, &sa, f.backbone->recent_source[0], PATH_CAP_BOTH));
	assert(path_sanitize_recent(f.mesh, f.backbone));
	assert(!f.backbone->recent[0].sa.sa_family);
	/* Independent LAN/application evidence survives both learning orders. */
	address_source_t independent[] = {ADDR_SRC_AUTH_DIRECT, ADDR_SRC_DISCOVERY, ADDR_SRC_HINT};
	for(unsigned i = 0; i < sizeof independent / sizeof independent[0]; i++) {
		memset(f.backbone->recent, 0, sizeof f.backbone->recent);
		memset(f.backbone->recent_source, 0, sizeof f.backbone->recent_source);
		node_add_recent_address_cap(f.mesh, f.backbone, &sa, ADDR_SRC_BACKBONE_PRIVATE, PATH_CAP_BOTH);
		node_add_recent_address_cap(f.mesh, f.backbone, &sa, independent[i], PATH_CAP_BOTH);
		assert(f.backbone->recent_source[0] == independent[i]);
		assert(path_is_meta_candidate(f.backbone, &sa, f.backbone->recent_source[0], PATH_CAP_BOTH));
		node_add_recent_address_cap(f.mesh, f.backbone, &sa, ADDR_SRC_BACKBONE_PRIVATE, PATH_CAP_BOTH);
		assert(f.backbone->recent_source[0] == independent[i]);
	}
	f.meta->status.private_carrier = false;
	close_fixture(&f);

	f = private_fixture(&sa);
	f.mesh->backbone_udp.node = f.backbone;
	path_backbone_private_tick(f.mesh, f.backbone);
	assert(f.mesh->backbone_udp.cand.active && f.mesh->backbone_udp.cand.timer.cb);
	f.mesh->bb_private.publish_revision = 17;
	f.mesh->bb_private.publish_hash = 12345;
	meshlink_set_backbone_path_policy(f.mesh, MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	assert(!f.mesh->backbone_udp.cand.active && !f.mesh->backbone_udp.cand.nonce);
	assert(!f.mesh->backbone_udp.cand.timer.cb);
	assert(!f.mesh->bb_private.count && !f.mesh->bb_private.query_id);
	assert(f.mesh->bb_private.publish_revision == 17 && f.mesh->bb_private.publish_hash == 12345);
	path_backbone_udp_stop(f.mesh);
	close_fixture(&f);
}

static void test_backbone_private_lifecycle(void) {
	const char *confbase = "peer-control-private-lifecycle";
	assert(MESHLINK_BACKBONE_PATH_PREFER_PRIVATE == 0);
	assert(MESHLINK_BACKBONE_PATH_ONLY_PRIVATE == 1);
	assert(MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE == 2);
	assert(meshlink_destroy(confbase));
	meshlink_handle_t *mesh = meshlink_open(confbase, "cam", "peer-control", DEV_CLASS_STATIONARY);
	assert(mesh && mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	meshlink_set_backbone_path_policy(NULL, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	assert(meshlink_errno == MESHLINK_EINVAL);
	meshlink_set_backbone_path_policy(mesh, (meshlink_backbone_path_policy_t)-1);
	assert(meshlink_errno == MESHLINK_EINVAL && mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	meshlink_enable_discovery(mesh, false);
	assert(meshlink_start(mesh));
	meshlink_errno = MESHLINK_OK;
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	assert(meshlink_errno == MESHLINK_OK);
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	assert(meshlink_errno == MESHLINK_ENOTSUP && mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_ONLY_PRIVATE);
	assert(meshlink_errno == MESHLINK_ENOTSUP && mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	meshlink_stop(mesh);
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	assert(meshlink_start(mesh));
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_ONLY_PRIVATE);
	assert(mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_ONLY_PRIVATE);
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	assert(mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	assert(meshlink_errno == MESHLINK_ENOTSUP && mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	meshlink_stop(mesh);
	/* Startup/shutdown windows use the lifecycle flag, not loop.running. */
	mesh->threadstarted = true;
	assert(!mesh->loop.running);
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	assert(meshlink_errno == MESHLINK_ENOTSUP && mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	mesh->threadstarted = false;
	mesh->bb_private.query_id = 123;
	mesh->bb_private.query_hold = true;
	mesh->bb_private.next_query_at.tv_sec = 300;
	mesh->bb_private.ever_proven = true;
	mesh->bb_private.publish_revision = 17;
	mesh->bb_private.publish_hash = 12345;
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	assert(!mesh->bb_private.query_id && !mesh->bb_private.query_hold && !mesh->bb_private.ever_proven);
	assert(!mesh->bb_private.next_query_at.tv_sec && !mesh->backbone_udp.cand.nonce);
	assert(mesh->bb_private.publish_revision == 17 && mesh->bb_private.publish_hash == 12345);
	assert(meshlink_start(mesh));
	meshlink_stop(mesh);
	meshlink_set_backbone_path_policy(mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	meshlink_close(mesh);
	mesh = meshlink_open(confbase, "cam", "peer-control", DEV_CLASS_STATIONARY);
	assert(mesh && mesh->backbone_path_policy == MESHLINK_BACKBONE_PATH_DISABLE_PRIVATE);
	meshlink_close(mesh);
	assert(meshlink_destroy(confbase));
}

int main(void) {
	test_backbone_private_default();
	test_backbone_private_disabled_candidate();
	test_backbone_private_lifecycle();
	test_backbone_private_cache_provenance();
	const char *regression = getenv("MESHLINK_PRIVATE_QUERY_REGRESSION");
	if(regression) {
		fprintf(stderr, "private query regression %s\n", regression);
		if(!strcmp(regression, "reconnect")) {
			test_private_query_failed_reconnect();
		} else {
			assert(!strcmp(regression, "network"));
			test_private_query_failed_network_change();
		}
		return 0;
	}
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
	test_private_query_failure_pacing();
	test_private_query_synchronous_answer();
	test_private_query_accepted_network_reentrancy();
	test_private_query_failed_reconnect();
	test_private_query_failed_network_change();
	test_private_query_retirement();
	test_private_query_failed_cutover();
	return 0;
}
