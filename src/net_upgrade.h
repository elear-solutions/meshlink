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

/* Standby authenticated. Clears the in-flight probe and backoff. Migration is logged at commit. */
void upgrade_probe_standby_ready(struct meshlink_handle *mesh, connection_t *c);

/* Commit succeeded. One probe-succeeded event and one migration log. */
void upgrade_probe_committed(struct meshlink_handle *mesh, connection_t *c);

/* Called from ack_h() when a probe authenticated. Clears probe state and backoff.
   Does not log the barrier commit; that happens when the ordered cutover finishes. */
void upgrade_probe_succeeded(struct meshlink_handle *mesh, connection_t *c);

/* True when an authenticated direct upgrade may keep the existing node SPTPS session.
   Do not key this off sptps.label alone. */
bool upgrade_should_preserve_node_session(struct meshlink_handle *mesh, const node_t *n, bool was_upgrade_probe, bool old_was_canonical) __attribute__((__warn_unused_result__));
bool upgrade_preserve_cover_unit(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));

/* Ordered barrier budget. Timeout with the old primary alive aborts.
   Timeout after it died emergency-promotes. Not a reason to switch by itself. */
#define META_CUTOVER_TIMEOUT_SEC 5

/* Retired META: flush already-queued bytes, then close. Not used for ordered cutover. */
#define UPGRADE_DRAIN_TIMEOUT_SEC 2
void upgrade_begin_drain(struct meshlink_handle *mesh, connection_t *c);

/* Periodic sweep: start at most one probe per tick for an eligible node. */
void upgrade_probe_sweep(struct meshlink_handle *mesh);

/* The responder withholds ACK until the direct socket is a standby. The ordered
   barrier, not this ACK, moves the node off the canonical socket. */
bool upgrade_defers_ack(const connection_t *c) __attribute__((__warn_unused_result__));

/* Both roles. c is authenticated and becomes the standby. The canonical socket
   stays node->connection until the ordered barrier commits. At most one standby:
   a newer probe evicts the older one. c must not be active yet. */
void upgrade_hold_standby(struct meshlink_handle *mesh, connection_t *c, node_t *n, const char *hisport, int devclass);

/* Initiator: freeze ordinary META and send PREPARE on the old primary. */
bool upgrade_cutover_begin(struct meshlink_handle *mesh, node_t *n, connection_t *old_primary, connection_t *standby);

/* True when ordinary META to c must be copied into the pending FIFO. */
bool upgrade_meta_enqueue_if_frozen(struct meshlink_handle *mesh, connection_t *c, const char *buffer, int length);

/* Standby sockets accept only PING, PONG, ACK, EMERGENCY, and the cutover request this state expects. */
bool upgrade_standby_allows(const connection_t *c, int reqno);

/* Test hook: send the READY that devtool_hold_cutover_ready withheld. */
bool upgrade_cutover_release_ready(struct meshlink_handle *mesh, struct node_t *n);

/* Test hook: abort and replay onto the live primary. */
void upgrade_cutover_test_abort(struct meshlink_handle *mesh, struct node_t *n);

/* 1 = held until promotion. 0 = barrier forced open, caller must run the handler.
   -1 = fail closed. Never means the record was discarded and accepted. */
int upgrade_standby_hold(struct meshlink_handle *mesh, connection_t *c, const char *request);

void upgrade_node_cleanup(struct meshlink_handle *mesh, node_t *n);

typedef struct upgrade_cutover_snapshot {
	int state;
	uint64_t id;
	bool timer_armed;
	unsigned pending_records;
	size_t pending_bytes;
	bool has_old;
	bool has_standby;
	struct sockaddr_storage old_address;
	struct sockaddr_storage standby_address;
} upgrade_cutover_snapshot_t;

void upgrade_cutover_snapshot(const node_t *n, upgrade_cutover_snapshot_t *out);
bool upgrade_cutover_cover_unit(struct meshlink_handle *mesh);

/* Close the spare held for n, if any. A caller that installs a new
   n->connection itself (ack_h) must do this before it terminates the old one,
   so that upgrade_connection_closing() cannot promote the spare underneath it. */
void upgrade_drop_spare(struct meshlink_handle *mesh, node_t *n);

/* The single hook terminate_connection() runs before it takes c down:
   - a probe that never authenticated -> upgrade_probe_failed()
   - a spare -> its prepared edge, which is not in the graph, is freed
   - the node's connection while a standby is held -> emergency sync
     (install the standby, keep the FIFO frozen, send EMERGENCY) or abort.
     It does not commit the barrier.
   Promotion is skipped while the event loop is not running (meshlink_stop,
   meshlink_close) and for blacklisted nodes: the spare is about to go too. */
void upgrade_connection_closing(struct meshlink_handle *mesh, connection_t *c);

#endif
