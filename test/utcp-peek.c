#include "system.h"
#include <time.h>
#include "utcp_priv.h"
#include "utcp-peek.h"

uint16_t utcp_peek_src(const struct utcp_connection *c) {
	return c->src;
}

uint16_t utcp_peek_dst(const struct utcp_connection *c) {
	return c->dst;
}

uint32_t utcp_peek_iss(const struct utcp_connection *c) {
	return c->snd.iss;
}
