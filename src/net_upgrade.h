#ifndef MESHLINK_NET_UPGRADE_H
#define MESHLINK_NET_UPGRADE_H

/*
    net_upgrade.h -- upgrade a canonical (relay) meta connection to a direct one
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

/* Every way a probe can fail ends here: no address left to try, the socket
   could not be opened, or the connection died before ack_h(). Clears the probe,
   applies the backoff (unless a regular connection already made the node direct)
   and reports DEVTOOL_UPGRADE_PROBE_FAILED, so tests and logs see one shape. */
void upgrade_probe_failed(struct meshlink_handle *mesh, node_t *n, const char *reason);

/* Called from ack_h() when a probe authenticated. Clears probe state and backoff. */
void upgrade_probe_succeeded(struct meshlink_handle *mesh, connection_t *c);

/* True when an authenticated direct upgrade may keep the existing node SPTPS session.
   Do not key this off sptps.label alone. */
bool upgrade_should_preserve_node_session(struct meshlink_handle *mesh, const node_t *n, bool was_upgrade_probe, bool old_was_canonical) __attribute__((__warn_unused_result__));

/* Retired META: flush already-queued bytes, then close. Bounded timeout is cleanup only. */
#define UPGRADE_DRAIN_TIMEOUT_SEC 2
void upgrade_begin_drain(struct meshlink_handle *mesh, connection_t *c);

/* Periodic sweep: start at most one probe per tick for an eligible node. */
void upgrade_probe_sweep(struct meshlink_handle *mesh);

/* The responder of a probe withholds its ACK during the SPTPS handshake and sends
   it from ack_h() once the probe is held as a spare, so the prober only closes its
   old connection when we are ready to take over without a gap. */
bool upgrade_defers_ack(const connection_t *c) __attribute__((__warn_unused_result__));

/* Responder side. A probe that authenticated while we still have an active
   connection with the node is held as a spare next to it and takes over the
   moment the old connection closes, so the node never drops out of the graph.
   At most one spare per node: a newer probe evicts the older one. c must not be
   active yet (ack_h rejects a repeated ACK, so a held spare never comes back here). */
void upgrade_hold_spare(struct meshlink_handle *mesh, connection_t *c, node_t *n, const char *hisport, int devclass);

/* Close the spare held for n, if any. A caller that installs a new
   n->connection itself (ack_h) must do this before it terminates the old one,
   so that upgrade_connection_closing() cannot promote the spare underneath it. */
void upgrade_drop_spare(struct meshlink_handle *mesh, node_t *n);

/* The single hook terminate_connection() runs before it takes c down:
   - a probe that never authenticated -> upgrade_probe_failed()
   - a spare -> its prepared edge, which is not in the graph, is freed
   - the node's connection while a spare is held -> the spare becomes
     n->connection and its edge replaces the old one in one step
   Promotion is skipped while the event loop is not running (meshlink_stop,
   meshlink_close) and for blacklisted nodes: the spare is about to go too. */
void upgrade_connection_closing(struct meshlink_handle *mesh, connection_t *c);

#endif
