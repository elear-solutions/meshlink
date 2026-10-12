#ifndef MESHLINK_PATH_TYPES_H
#define MESHLINK_PATH_TYPES_H

/*
    path_types.h -- address provenance and path capability types
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "sockaddr.h"

#include <stdbool.h>
#include <stdint.h>

/* How an address was learned. Persisted next to recent[]. */
typedef enum address_source_t {
	ADDR_SRC_UNKNOWN = 0,       /* legacy load or unclassified */
	ADDR_SRC_AUTH_DIRECT,       /* authenticated TCP from the peer itself */
	ADDR_SRC_DISCOVERY,         /* local mDNS / Catta */
	ADDR_SRC_HINT,              /* application or invitation hint */
	ADDR_SRC_EXTERNAL,          /* peer-vouched REQ_EXTERNAL */
	ADDR_SRC_EDGE_DIRECT,       /* graph edge that is not OPTION_INDIRECT */
	ADDR_SRC_CANONICAL,         /* canonical / NLB endpoint (never stored in recent[]) */
	ADDR_SRC_INDIRECT,          /* forwarded or OPTION_INDIRECT */
	ADDR_SRC_UDP_REFLEXIVE,     /* ANS_KEY / inbound remap / NAT-mapped UDP confirm */
	ADDR_SRC_BACKBONE_PRIVATE   /* runtime-only; sanitized to UNKNOWN on load */
} address_source_t;

/* Which transports may consume a recent[] slot. Independent of provenance. */
typedef uint8_t path_cap_t;
#define PATH_CAP_NONE 0x00
#define PATH_CAP_META 0x01
#define PATH_CAP_UDP  0x02
#define PATH_CAP_BOTH (PATH_CAP_META | PATH_CAP_UDP)

/* Authenticated TCP from a feature-owned probe is not LAN evidence. */
static inline address_source_t address_source_from_auth(bool bb_private_probe, bool private_carrier) {
	if(bb_private_probe || private_carrier) {
		return ADDR_SRC_BACKBONE_PRIVATE;
	}

	return ADDR_SRC_AUTH_DIRECT;
}

#endif
