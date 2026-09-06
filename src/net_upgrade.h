#ifndef MESHLINK_NET_UPGRADE_H
#define MESHLINK_NET_UPGRADE_H

/*
    net_upgrade.h -- upgrade a canonical (relay) meta connection to a direct one
    Copyright (C) 2014-2017 Guus Sliepen <guus@meshlink.io>

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
#include "node.h"

/* Backoff applied after a failed probe: 5, 10, 20, ... capped at 600 seconds. */
#define UPGRADE_BACKOFF_MIN 5
#define UPGRADE_BACKOFF_MAX 600

/* True if n is reached through its canonical address, we know a direct address
   for it, no probe is in flight and the backoff has expired. */
bool upgrade_probe_eligible(struct meshlink_handle *mesh, node_t *n) __attribute__((__warn_unused_result__));

/* Open a second, direct meta connection to n alongside the canonical one.
   When it authenticates, ack_h() migrates the node to it and drops the
   canonical connection; if it fails the canonical connection is untouched. */
void start_upgrade_probe(struct meshlink_handle *mesh, node_t *n);

/* Start a probe now if upgrade_probe_eligible(). */
void try_upgrade_probe(struct meshlink_handle *mesh, node_t *n);

/* Called from terminate_connection() for a probe that died before it became
   the node's connection. Applies the backoff. */
void upgrade_probe_failed(struct meshlink_handle *mesh, node_t *n);

/* Called from ack_h() when a probe authenticated. Clears probe state and backoff. */
void upgrade_probe_succeeded(struct meshlink_handle *mesh, connection_t *c);

/* Periodic sweep: start at most one probe per tick for an eligible node. */
void upgrade_probe_sweep(struct meshlink_handle *mesh);

/* Responder side. A probe that authenticated while we still have an active
   connection with the node is held as a spare (upgrade_hold_spare) and takes
   over the moment the old connection closes (upgrade_promote_spare), so the
   node never drops out of the graph. */
void upgrade_hold_spare(struct meshlink_handle *mesh, connection_t *c, node_t *n, const char *hisport, int devclass);
connection_t *upgrade_find_spare(struct meshlink_handle *mesh, const node_t *n) __attribute__((__warn_unused_result__));
void upgrade_promote_spare(struct meshlink_handle *mesh, connection_t *old, connection_t *spare);

#endif
