/* utcp must not take ports or ISNs from the C library's rand(): nothing in a meshlink
   process seeds it, so every fresh process would open from the same port with the same ISN.
   rand() is wrapped at link time and any call fails the test. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utcp_priv.h"

static unsigned rand_calls;

int __real_rand(void);
int __wrap_rand(void);

int __wrap_rand(void) {
	rand_calls++;
	return __real_rand();
}

static ssize_t on_send(struct utcp *utcp, const void *data, size_t len) {
	(void)utcp;
	(void)data;
	return len;
}

int main(void) {
	struct utcp *utcp = utcp_init(NULL, NULL, on_send, NULL);
	assert(utcp);

	// Connections to the same destination get their ports and ISNs without rand().

	for(int i = 0; i < 8; i++) {
		struct utcp_connection *c = utcp_connect(utcp, 7, NULL, NULL);
		assert(c);
		assert(c->src & 0x8000);
	}

	assert(rand_calls == 0);

	utcp_exit(utcp);
	return 0;
}
