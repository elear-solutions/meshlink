#ifndef MESHLINK_PATH_PROBE_H
#define MESHLINK_PATH_PROBE_H

/*
    path_probe.h -- PKT_PROBE payload layout
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdint.h>
#include <stdbool.h>
#include "sockaddr.h"

/* data[0] kind. Echo requests longer than 64 bytes are dropped, so a peer
   can never be forced to send an oversized reply. */
#define PROBE_KIND_ECHO_REQUEST 0
#define PROBE_KIND_ECHO_REPLY   1
#define PROBE_KIND_SIZE_REQUEST 2
#define PROBE_KIND_SIZE_ACK     3
#define PROBE_KIND_KEEPALIVE    4

#define PROBE_NONCE_OFFSET 1
#define PROBE_PURPOSE_OFFSET 9
#define PROBE_ACKLEN_OFFSET 10
/* Authenticated observation: marker, family, network-order port, address.
   IPv4 uses the first four address bytes; IPv6 uses all sixteen. */
#define PROBE_ENDPOINT_OFFSET 12
#define PROBE_ENDPOINT_LEN 20
#define PROBE_ENDPOINT_MARKER 0xa7
#define PROBE_ADDR_FAMILY_IPV4 4
#define PROBE_ADDR_FAMILY_IPV6 6
#define PROBE_PAD_OFFSET 14

#define PROBE_PURPOSE_NONE            0
#define PROBE_PURPOSE_LIVENESS        1
#define PROBE_PURPOSE_SUSPECT         2
#define PROBE_PURPOSE_REBIND          3
#define PROBE_PURPOSE_PUNCH           4
#define PROBE_PURPOSE_PROMOTION       5
#define PROBE_PURPOSE_BACKBONE        6
#define PROBE_PURPOSE_LOCAL_DISCOVERY 7
#define PROBE_PURPOSE_PLPMTU_RECOVERY 8

#define PROBE_PURPOSE_RELAY_HOP       9

#define PROBE_FIXED_LEN 64

void path_probe_write_endpoint(uint8_t *data, const sockaddr_t *endpoint);
bool path_probe_read_endpoint(const uint8_t *data, sockaddr_t *endpoint);

#endif
