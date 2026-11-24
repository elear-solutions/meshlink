#ifndef MESHLINK_TEST_UTCP_PEEK_H
#define MESHLINK_TEST_UTCP_PEEK_H

#include <stdint.h>

/* Tests that include meshlink_internal.h only see utcp's public connection struct.
   These read the port pair and ISN of a connection from utcp's own private header. */
struct utcp_connection;

uint16_t utcp_peek_src(const struct utcp_connection *c);
uint16_t utcp_peek_dst(const struct utcp_connection *c);
uint32_t utcp_peek_iss(const struct utcp_connection *c);

#endif
