#ifndef MESHLINK_PROTOCOL_KEY_INTERNAL_H
#define MESHLINK_PROTOCOL_KEY_INTERNAL_H

/*
    protocol_key_internal.h -- private ANS_KEY and punch handlers for the cover unit
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "connection.h"
#include "meshlink_internal.h"
#include "netutl.h"
#include "node.h"

/* True when a pre-filled address must not be forwarded. hint is the observation
   to send instead, or AF_UNSPEC when there is nothing to append. */
bool ans_key_backbone_hint(struct meshlink_handle *mesh, node_t *from, const char *address, sockaddr_t *hint) __attribute__((__warn_unused_result__));

bool req_punch_endpoint_h(struct meshlink_handle *mesh, struct connection_t *c, const char *request, node_t *from) __attribute__((__warn_unused_result__));

#endif
