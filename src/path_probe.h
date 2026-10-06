#ifndef MESHLINK_PATH_PROBE_H
#define MESHLINK_PATH_PROBE_H

/*
    path_probe.h -- PKT_PROBE payload layout
    Copyright (C) 2026 Elear Solutions
*/

#include <stdint.h>

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

#define PROBE_PURPOSE_NONE            0
#define PROBE_PURPOSE_LIVENESS        1
#define PROBE_PURPOSE_SUSPECT         2
#define PROBE_PURPOSE_REBIND          3
#define PROBE_PURPOSE_PUNCH           4
#define PROBE_PURPOSE_PROMOTION       5
#define PROBE_PURPOSE_BACKBONE        6
#define PROBE_PURPOSE_LOCAL_DISCOVERY 7

#define PROBE_FIXED_LEN 64

#endif
