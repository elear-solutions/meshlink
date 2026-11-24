/* utcp unit tests: ephemeral ports and ISNs come from the random source given to utcp_init(). */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utcp_priv.h"

struct source {
	const uint32_t *script;
	unsigned length;
	unsigned draws;
	uint32_t last_max[8];

	// Used instead of the script when set: a small generator, seeded per instance.
	bool seeded;
	uint32_t state;
};

static uint32_t on_random(struct utcp *utcp, uint32_t max) {
	struct source *src = utcp->priv;
	uint32_t value;

	if(src->draws < sizeof(src->last_max) / sizeof(*src->last_max)) {
		src->last_max[src->draws] = max;
	}

	if(src->seeded) {
		src->state = src->state * 1664525U + 1013904223U;
		value = (src->state >> 8) % max;
	} else {
		value = src->script[src->draws % src->length];
	}

	src->draws++;
	assert(value < max);
	return value;
}

static ssize_t on_send(struct utcp *utcp, const void *data, size_t len) {
	(void)utcp;
	(void)data;
	return len;
}

static struct utcp *new_utcp(struct source *src) {
	struct utcp *utcp = utcp_init(NULL, NULL, on_send, on_random, src);
	assert(utcp);
	return utcp;
}

static void test_requires_random_source(void) {
	errno = 0;
	assert(!utcp_init(NULL, NULL, on_send, NULL, NULL));
	assert(errno == EFAULT);
}

static void test_first_port_and_isn_come_from_the_source(void) {
	static const uint32_t script[] = {0x1234, 0xabcd, 0x5678};
	struct source src = {.script = script, .length = 3};
	struct utcp *utcp = new_utcp(&src);

	struct utcp_connection *c = utcp_connect(utcp, 7, NULL, NULL);
	assert(c);

	// One draw for the port, then two for the 32 bit ISN.

	assert(src.draws == 3);
	assert(src.last_max[0] == 0x8000);
	assert(src.last_max[1] == 0x10000);
	assert(src.last_max[2] == 0x10000);

	assert(c->src == 0x9234);
	assert(c->dst == 7);
	assert(c->snd.iss == 0xabcd5678);

	utcp_exit(utcp);
}

static void test_different_seeds_give_different_port_and_isn(void) {
	struct source one = {.seeded = true, .state = 1};
	struct source two = {.seeded = true, .state = 2};
	struct utcp *u1 = new_utcp(&one);
	struct utcp *u2 = new_utcp(&two);

	struct utcp_connection *c1 = utcp_connect(u1, 7, NULL, NULL);
	struct utcp_connection *c2 = utcp_connect(u2, 7, NULL, NULL);
	assert(c1 && c2);

	assert(c1->src != c2->src);
	assert(c1->snd.iss != c2->snd.iss);

	// The same seed gives the same port and ISN again.

	struct source again = {.seeded = true, .state = 1};
	struct utcp *u3 = new_utcp(&again);
	struct utcp_connection *c3 = utcp_connect(u3, 7, NULL, NULL);
	assert(c3);

	assert(c3->src == c1->src);
	assert(c3->snd.iss == c1->snd.iss);

	utcp_exit(u1);
	utcp_exit(u2);
	utcp_exit(u3);
}

static void test_port_keeps_high_bit(void) {
	static const uint32_t lowest[] = {0, 0, 0};
	static const uint32_t highest[] = {0x7fff, 0xffff, 0xffff};
	struct source low = {.script = lowest, .length = 3};
	struct source high = {.script = highest, .length = 3};
	struct utcp *u1 = new_utcp(&low);
	struct utcp *u2 = new_utcp(&high);

	struct utcp_connection *c1 = utcp_connect(u1, 7, NULL, NULL);
	struct utcp_connection *c2 = utcp_connect(u2, 7, NULL, NULL);
	assert(c1 && c2);

	assert(c1->src == 0x8000);
	assert(c1->snd.iss == 0);
	assert(c2->src == 0xffff);
	assert(c2->snd.iss == 0xffffffff);

	utcp_exit(u1);
	utcp_exit(u2);
}

static void test_ports_in_use_are_skipped(void) {
	static const uint32_t script[] = {0x1234, 0, 0};
	struct source src = {.script = script, .length = 3};
	struct utcp *utcp = new_utcp(&src);

	struct utcp_connection *c1 = utcp_connect(utcp, 7, NULL, NULL);
	struct utcp_connection *c2 = utcp_connect(utcp, 7, NULL, NULL);
	struct utcp_connection *c3 = utcp_connect(utcp, 7, NULL, NULL);
	assert(c1 && c2 && c3);

	assert(c1->src == 0x9234);
	assert(c2->src == 0x9235);
	assert(c3->src == 0x9236);

	// The same source port to another destination is not in use.

	struct utcp_connection *c4 = utcp_connect(utcp, 8, NULL, NULL);
	assert(c4);
	assert(c4->src == 0x9234);

	utcp_exit(utcp);
}

static void test_skipping_wraps_to_the_high_half(void) {
	static const uint32_t script[] = {0x7fff, 0, 0};
	struct source src = {.script = script, .length = 3};
	struct utcp *utcp = new_utcp(&src);

	struct utcp_connection *c1 = utcp_connect(utcp, 7, NULL, NULL);
	struct utcp_connection *c2 = utcp_connect(utcp, 7, NULL, NULL);
	assert(c1 && c2);

	assert(c1->src == 0xffff);
	assert(c2->src == 0x8000);

	utcp_exit(utcp);
}

int main(void) {
	test_requires_random_source();
	test_first_port_and_isn_come_from_the_source();
	test_different_seeds_give_different_port_and_isn();
	test_port_keeps_high_bit();
	test_ports_in_use_are_skipped();
	test_skipping_wraps_to_the_high_half();
	return 0;
}
