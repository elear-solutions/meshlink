/* A node's utcp takes the source port and ISN of a new channel from the per-mesh PRNG.
   The mesh is stopped, so nothing else draws from the PRNG between seeding it and opening channels. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include <assert.h>
#include <string.h>

#include "meshlink_internal.h"
#include "xoshiro.h"
#include "utils.h"
#include "utcp-peek.h"

#define PORT 7

struct expected {
	uint16_t port;
	uint32_t iss;
};

/* What the first channel opened on a mesh seeded with state must use: the port
   from one draw, the ISN from the next two. */
static struct expected expected_from(const uint64_t state[4]) {
	uint64_t copy[4];
	memcpy(copy, state, sizeof(copy));

	struct expected e;
	e.port = 0x8000 | (xoshiro(copy) % 0x8000);
	e.iss = (uint32_t)(xoshiro(copy) % 0x10000) << 16;
	e.iss |= (uint32_t)(xoshiro(copy) % 0x10000);

	return e;
}

static meshlink_channel_t *open_channel(meshlink_handle_t *mesh, meshlink_node_t *node, const uint64_t state[4]) {
	if(state) {
		memcpy(mesh->prng_state, state, sizeof(mesh->prng_state));
	}

	meshlink_channel_t *channel = meshlink_channel_open(mesh, node, PORT, NULL, NULL, 0);
	assert(channel);

	return channel;
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	meshlink_handle_t *a, *b;
	open_meshlink_pair(&a, &b, "channels_utcp_prng");
	stop_meshlink_pair(a, b);

	meshlink_node_t *b_node = meshlink_get_node(a, "b");
	assert(b_node);

	static const uint64_t seed1[4] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x0f1e2d3c4b5a6978ULL, 0x1122334455667788ULL};
	static const uint64_t seed2[4] = {0x8877665544332211ULL, 0x0badc0de0badc0deULL, 0xdeadbeefdeadbeefULL, 0x13579bdf02468aceULL};

	// The first port and ISN follow the PRNG state, and the port has its high bit set.

	struct expected e1 = expected_from(seed1);
	struct expected e2 = expected_from(seed2);
	assert(e1.port != e2.port || e1.iss != e2.iss);

	meshlink_channel_t *c1 = open_channel(a, b_node, seed1);
	assert(utcp_peek_src(c1->c) == e1.port);
	assert(utcp_peek_src(c1->c) & 0x8000);
	assert(utcp_peek_dst(c1->c) == PORT);
	assert(utcp_peek_iss(c1->c) == e1.iss);

	// A different state gives a different port and ISN.

	meshlink_channel_t *c2 = open_channel(a, b_node, seed2);
	assert(utcp_peek_src(c2->c) == e2.port);
	assert(utcp_peek_iss(c2->c) == e2.iss);

	// While a channel uses the port, the same state skips to the next free port, keeping the high bit.

	meshlink_channel_t *c3 = open_channel(a, b_node, seed1);
	assert(utcp_peek_src(c3->c) == (uint16_t)((e1.port + 1) | 0x8000));
	assert(utcp_peek_iss(c3->c) == e1.iss);

	meshlink_channel_close(a, c1);
	meshlink_channel_close(a, c2);
	meshlink_channel_close(a, c3);

	close_meshlink_pair(a, b);

	return 0;
}
