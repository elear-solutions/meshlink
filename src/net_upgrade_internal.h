#ifndef MESHLINK_NET_UPGRADE_INTERNAL_H
#define MESHLINK_NET_UPGRADE_INTERNAL_H

/*
    net_upgrade_internal.h -- private ordered-cutover state for net_upgrade.c
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

#include "system.h"

#include "connection.h"
#include "node.h"

/* Cover unit and the barrier share these limits. */
#define META_CUTOVER_MAX_RECORDS 256
#define META_CUTOVER_MAX_BYTES (256 * 1024)

typedef enum meta_cutover_state_t {
	META_CUTOVER_NONE = 0,
	META_CUTOVER_INIT_WAIT_READY,
	META_CUTOVER_INIT_WAIT_ACK,
	META_CUTOVER_RESP_WAIT_COMMIT,
	META_CUTOVER_EMERGENCY_PROMOTE,
	META_CUTOVER_EMERGENCY_SYNC, /* socket installed; ordinary META held until the peer agrees */
} meta_cutover_state_t;

typedef struct meta_pending_record_t {
	uint8_t *data;
	size_t length;
} meta_pending_record_t;

struct meta_cutover {
	meta_cutover_state_t state;
	uint64_t id;
	connection_t *old_primary;
	connection_t *new_standby;
	list_t *pending_records;
	size_t pending_bytes;
	timeout_t timer;
	bool freeze_ordinary_meta;
	bool emergency_sent;
	node_t *node;
};

/* Rearm keeps a live standby for another barrier. Drop closes that path. The log reason is not the switch. */
typedef enum {
	CUTOVER_ABORT_REARM,
	CUTOVER_ABORT_DROP,
} cutover_abort_disp_t;

/* Cover-unit knobs. Production code only reads them. */
extern bool cutover_fail_control_send;
extern bool cover_order_on;
extern char cover_order[8];

void standby_held_free(const void *p);
connection_t *find_spare(struct meshlink_handle *mesh, const node_t *n) __attribute__((__warn_unused_result__));
bool upgrade_standby_replay(struct meshlink_handle *mesh, connection_t *owner, connection_t *dispatch) __attribute__((__warn_unused_result__));
void upgrade_standby_drop_held(connection_t *c);
bool upgrade_cutover_abort(struct meshlink_handle *mesh, node_t *n, const char *reason, bool replay, cutover_abort_disp_t disp);
void upgrade_cutover_on_timeout(struct meshlink_handle *mesh, node_t *n);

#endif
