/* utcp unit tests: a new SYN never matches a CLOSED connection.

   Two utcp instances are joined by in-memory queues. "A2" stands for the peer
   coming back as a new process: a fresh utcp that opens its connection from the
   same port pair as the first "A" did. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include <assert.h>
#include <string.h>
#include <time.h>

#include "utcp_priv.h"

#define SERVER_PORT 7
#define QUEUE_LEN 64
#define MAX_ACCEPTED 4

struct packet {
	uint8_t data[2048];
	size_t len;
};

struct conn_stats {
	size_t bytes;
	unsigned calls;
	unsigned resets;
};

struct endpoint {
	struct utcp *utcp;
	struct endpoint *peer;

	struct packet inbox[QUEUE_LEN];
	unsigned head;
	unsigned tail;

	unsigned sent_syn_ack;
	unsigned sent_rst;
	unsigned sent;

	struct utcp_connection *accepted[MAX_ACCEPTED];
	struct conn_stats accepted_stats[MAX_ACCEPTED];
	unsigned naccepted;

	unsigned draws;
};

static ssize_t on_recv(struct utcp_connection *c, const void *data, size_t len) {
	struct conn_stats *stats = c->priv;

	stats->calls++;

	if(data && len) {
		stats->bytes += len;
	} else {
		stats->resets++;
	}

	return len;
}

static void on_accept(struct utcp_connection *c, uint16_t port) {
	assert(port == SERVER_PORT);

	struct endpoint *ep = c->utcp->priv;
	assert(ep->naccepted < MAX_ACCEPTED);

	ep->accepted[ep->naccepted] = c;
	utcp_accept(c, on_recv, &ep->accepted_stats[ep->naccepted]);
	ep->naccepted++;
}

static ssize_t on_send(struct utcp *utcp, const void *data, size_t len) {
	struct endpoint *ep = utcp->priv;
	struct endpoint *peer = ep->peer;
	struct hdr hdr;

	assert(len >= sizeof(hdr) && len <= sizeof(peer->inbox[0].data));
	memcpy(&hdr, data, sizeof(hdr));

	ep->sent++;

	if((hdr.ctl & (SYN | ACK)) == (SYN | ACK)) {
		ep->sent_syn_ack++;
	}

	if(hdr.ctl & RST) {
		ep->sent_rst++;
	}

	if(peer) {
		assert(peer->tail - peer->head < QUEUE_LEN);
		struct packet *p = &peer->inbox[peer->tail++ % QUEUE_LEN];
		memcpy(p->data, data, len);
		p->len = len;
	}

	return len;
}

/* Every endpoint draws the same sequence, as every fresh process does with an unseeded
   generator: the same first port pair and ISN. That is what a relaunched peer looks like. */
static uint32_t on_random(struct utcp *utcp, uint32_t max) {
	static const uint32_t sequence[] = {0x0123, 0xaaaa, 0x5555};
	struct endpoint *ep = utcp->priv;
	uint32_t value = sequence[ep->draws++ % (sizeof(sequence) / sizeof(*sequence))];

	assert(value < max);
	return value;
}

static void endpoint_init(struct endpoint *ep, bool listening) {
	memset(ep, 0, sizeof(*ep));
	ep->utcp = utcp_init(listening ? on_accept : NULL, NULL, on_send, on_random, ep);
	assert(ep->utcp);
}

static void deliver(struct endpoint *ep) {
	while(ep->head != ep->tail) {
		struct packet *p = &ep->inbox[ep->head++ % QUEUE_LEN];
		utcp_recv(ep->utcp, p->data, p->len);
	}
}

static void pump(struct endpoint *a, struct endpoint *b) {
	while(a->head != a->tail || b->head != b->tail) {
		deliver(a);
		deliver(b);
	}
}

static void discard(struct endpoint *ep) {
	ep->head = ep->tail;
}

static struct utcp_connection *open_connection(struct endpoint *ep, struct conn_stats *stats) {
	struct utcp_connection *c = utcp_connect(ep->utcp, SERVER_PORT, on_recv, stats);
	assert(c);
	return c;
}

/* A connects to B, then B resets everything but its owner has not closed the connection yet. */
struct scenario {
	struct endpoint a;
	struct endpoint b;
	struct conn_stats a_stats;
	struct utcp_connection *a_conn;
	struct utcp_connection *old;
	struct conn_stats *old_stats;
};

static void scenario_init(struct scenario *s) {
	memset(s, 0, sizeof(*s));

	endpoint_init(&s->a, false);
	endpoint_init(&s->b, true);
	s->a.peer = &s->b;
	s->b.peer = &s->a;

	s->a_conn = open_connection(&s->a, &s->a_stats);
	pump(&s->a, &s->b);

	assert(s->a_conn->state == ESTABLISHED);
	assert(s->b.naccepted == 1);

	s->old = s->b.accepted[0];
	s->old_stats = &s->b.accepted_stats[0];
	assert(s->old->state == ESTABLISHED);

	utcp_reset_all_connections(s->b.utcp);

	assert(s->old->state == CLOSED);
	assert(!s->old->reapable);
	assert(s->old_stats->resets == 1);
}

static void scenario_exit(struct scenario *s, struct endpoint *a2) {
	utcp_exit(s->a.utcp);
	utcp_exit(s->b.utcp);

	if(a2) {
		utcp_exit(a2->utcp);
	}
}

/* The relaunched peer: same port pair, same ISN, new utcp instance. */
static struct utcp_connection *relaunch(struct scenario *s, struct endpoint *a2, struct conn_stats *stats) {
	endpoint_init(a2, false);
	a2->peer = &s->b;
	s->b.peer = a2;

	struct utcp_connection *c = open_connection(a2, stats);

	assert(c->src == s->a_conn->src);
	assert(c->dst == s->a_conn->dst);
	assert(c->snd.iss == s->a_conn->snd.iss);
	assert(c->src == 0x8123);
	assert(c->snd.iss == 0xaaaa5555);
	assert(c->src == s->old->dst);

	return c;
}

static void test_syn_for_closed_connection_is_accepted(void) {
	struct scenario s;
	struct endpoint a2;
	struct conn_stats a2_stats = {0};

	scenario_init(&s);
	discard(&s.a);

	unsigned rst_before = s.b.sent_rst;
	unsigned syn_ack_before = s.b.sent_syn_ack;

	struct utcp_connection *c2 = relaunch(&s, &a2, &a2_stats);
	pump(&a2, &s.b);

	// The new SYN is answered with SYN|ACK, not RST, and becomes a new connection.

	assert(s.b.sent_rst == rst_before);
	assert(s.b.sent_syn_ack == syn_ack_before + 1);
	assert(s.b.naccepted == 2);
	assert(c2->state == ESTABLISHED);

	struct utcp_connection *fresh = s.b.accepted[1];
	assert(fresh != s.old);
	assert(fresh->state == ESTABLISHED);

	// The old handle is still valid and still CLOSED.

	assert(s.old->state == CLOSED);
	assert(s.b.utcp->nconnections == 2);

	// Data for the port pair goes to the new connection only.

	unsigned old_calls = s.old_stats->calls;
	assert(utcp_send(c2, "hello", 5) == 5);
	pump(&a2, &s.b);

	assert(s.b.accepted_stats[1].bytes == 5);
	assert(s.old_stats->calls == old_calls);

	// The owner closes the old handle: that succeeds, and utcp frees it without touching the new connection.

	assert(utcp_close(s.old) == 0);
	assert(s.old->reapable);

	utcp_timeout(s.b.utcp);
	assert(s.b.utcp->nconnections == 1);
	assert(s.b.utcp->connections[0] == fresh);

	assert(utcp_send(c2, "again", 5) == 5);
	pump(&a2, &s.b);

	assert(s.b.accepted_stats[1].bytes == 10);
	assert(s.old_stats->calls == old_calls);

	scenario_exit(&s, &a2);
}

static void test_old_connection_behaves_as_closed_after_new_syn(void) {
	struct scenario s;
	struct endpoint a2;
	struct conn_stats a2_stats = {0};

	scenario_init(&s);
	discard(&s.a);

	struct utcp_connection *c2 = relaunch(&s, &a2, &a2_stats);
	pump(&a2, &s.b);
	assert(c2->state == ESTABLISHED);

	errno = 0;
	assert(utcp_send(s.old, "x", 1) == -1);
	assert(errno == ENOTCONN);

	// A CLOSED connection that was never closed by its owner can be aborted, and then it is reapable.

	unsigned sent_before = s.b.sent;
	assert(utcp_abort(s.old) == 0);
	assert(s.old->reapable);
	assert(s.b.sent == sent_before);

	utcp_timeout(s.b.utcp);
	assert(s.b.utcp->nconnections == 1);

	scenario_exit(&s, &a2);
}

static void test_syn_for_reapable_connection_is_accepted(void) {
	struct scenario s;
	struct endpoint a2;
	struct conn_stats a2_stats = {0};

	scenario_init(&s);
	discard(&s.a);

	// The owner already closed the old connection, but utcp has not reaped it yet.

	assert(utcp_close(s.old) == 0);
	assert(s.old->reapable);
	assert(s.b.utcp->nconnections == 1);

	unsigned rst_before = s.b.sent_rst;
	struct utcp_connection *c2 = relaunch(&s, &a2, &a2_stats);
	pump(&a2, &s.b);

	assert(s.b.sent_rst == rst_before);
	assert(s.b.naccepted == 2);
	assert(c2->state == ESTABLISHED);
	assert(s.b.accepted[1]->state == ESTABLISHED);

	assert(utcp_send(c2, "hello", 5) == 5);
	pump(&a2, &s.b);
	assert(s.b.accepted_stats[1].bytes == 5);

	utcp_timeout(s.b.utcp);
	assert(s.b.utcp->nconnections == 1);
	assert(s.b.utcp->connections[0] == s.b.accepted[1]);

	scenario_exit(&s, &a2);
}

static void test_non_syn_packet_for_closed_connection_gets_rst(void) {
	struct scenario s;

	scenario_init(&s);

	// A never saw the reset, so it keeps sending on the old port pair.

	discard(&s.a);
	unsigned rst_before = s.b.sent_rst;
	unsigned old_calls = s.old_stats->calls;

	assert(utcp_send(s.a_conn, "x", 1) == 1);
	pump(&s.a, &s.b);

	assert(s.b.sent_rst == rst_before + 1);
	assert(s.b.naccepted == 1);
	assert(s.old_stats->calls == old_calls);
	assert(s.old->state == CLOSED);
	assert(s.b.utcp->nconnections == 1);

	// A SYN|ACK is not a new connection either.

	struct hdr hdr = {
		.src = s.old->dst,
		.dst = s.old->src,
		.seq = 1,
		.ack = 1,
		.wnd = 1000,
		.ctl = SYN | ACK,
	};

	rst_before = s.b.sent_rst;
	assert(utcp_recv(s.b.utcp, &hdr, sizeof(hdr)) >= 0);
	assert(s.b.sent_rst == rst_before + 1);
	assert(s.b.naccepted == 1);

	scenario_exit(&s, NULL);
}

int main(void) {
	test_syn_for_closed_connection_is_accepted();
	test_old_connection_behaves_as_closed_after_new_syn();
	test_syn_for_reapable_connection_is_accepted();
	test_non_syn_packet_for_closed_connection_gets_rst();
	return 0;
}
