/*
    net_upgrade_cover.c -- ordered META cutover cover unit
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
#include "devtools.h"
#include "edge.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "net_upgrade.h"
#include "net_upgrade_internal.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "list.h"
#include "meta.h"
#include "protocol.h"
#include "xalloc.h"

#include <string.h>

static void cover_untrack(meshlink_handle_t *mesh, connection_t *c, list_action_t del) {
	if(!mesh || !mesh->connections || !c) {
		return;
	}

	mesh->connections->delete = NULL;
	list_delete(mesh->connections, c);
	mesh->connections->delete = del;
}

static bool cover_bail(meshlink_handle_t *mesh, node_t *n, connection_t *old, connection_t *neu, bool tracked, list_action_t del) {
	cover_order_on = false;
	cutover_fail_control_send = false;
	devtool_hold_cutover_ready = false;
	upgrade_standby_drop_held(neu);
	upgrade_node_cleanup(mesh, n);
	if(tracked) {
		cover_untrack(mesh, neu, del);
	}
	timeout_del(&mesh->loop, &old->drain_ev);
	timeout_del(&mesh->loop, &neu->drain_ev);
	free_connection(old);
	free_connection(neu);
	return false;
}

bool upgrade_cutover_cover_unit(meshlink_handle_t *mesh) {
	node_t n;
	connection_t *old;
	connection_t *neu;
	char request[64];
	struct meta_cutover *co;
	node_t *witness = NULL;
	bool witness_uncertain = false;
	int i;

	if(!mesh) {
		return false;
	}

	if(mesh->nodes) {
		for splay_each(node_t, it, mesh->nodes) {
			if(it != mesh->self) {
				witness = it;
				witness_uncertain = it->key_delivery_uncertain;
				break;
			}
		}
	}

	memset(&n, 0, sizeof(n));
	n.name = "cutover-unit";
	n.mesh = mesh;
	old = new_connection();
	neu = new_connection();
	old->socket = -1;
	neu->socket = -1;
	old->name = xstrdup("cutover-old");
	neu->name = xstrdup("cutover-new");
	old->node = &n;
	neu->node = &n;
	old->status.active = true;
	neu->status.active = true;
	neu->status.spare = true;
	old->allow_request = ALL;
	neu->allow_request = ALL;
	neu->status.initiator = true;
	old->mesh = mesh;
	neu->mesh = mesh;
	n.connection = old;

	if(!upgrade_meta_enqueue_if_frozen(mesh, old, "1 ping\n", 7)) {
		/* Not frozen yet. */
	}

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	co = n.meta_cutover;

	if(!co || co->state != META_CUTOVER_INIT_WAIT_READY || !co->freeze_ordinary_meta) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	if(!upgrade_meta_enqueue_if_frozen(mesh, old, "8 1\n", 4)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	if(co->pending_records->count != 1) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	snprintf(request, sizeof(request), "%d 1\n", REQ_META_CUTOVER_READY);

	if(!meta_cutover_ready_h(mesh, old, request) || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_READY) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_READY, co->id);

	if(!meta_cutover_ready_h(mesh, old, request) || !n.meta_cutover || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_ACK) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	if(!meta_cutover_ready_h(mesh, old, request) || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_ACK) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_ACK, co->id);

	if(!meta_cutover_ack_h(mesh, old, request)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	if(!n.meta_cutover || n.connection != old) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	if(!meta_cutover_ack_h(mesh, neu, request)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	if(n.meta_cutover || n.connection != neu || neu->status.spare) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	/* Responder path: standby failure rolls back; old death emergency-promotes. */
	n.connection = old;
	neu->status.spare = true;
	neu->status.active = true;
	old->status.active = true;

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	upgrade_cutover_abort(mesh, &n, "cover standby", true, CUTOVER_ABORT_REARM);

	if(n.meta_cutover || n.connection != old) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	old->status.active = false;
	upgrade_cutover_on_timeout(mesh, &n);

	if(n.meta_cutover || n.connection != neu) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	/* Overflow aborts back to the live primary and does not switch. */
	n.connection = old;
	old->status.active = true;
	neu->status.spare = true;
	neu->status.active = true;

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	for(i = 0; i < META_CUTOVER_MAX_RECORDS + 2; i++) {
		char rec[32];
		int len = snprintf(rec, sizeof(rec), "8 %d\n", i);
		upgrade_meta_enqueue_if_frozen(mesh, old, rec, len);
	}

	if(n.meta_cutover || n.connection != old) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	/* Timeout with the old primary alive stays canonical. */
	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	upgrade_cutover_on_timeout(mesh, &n);

	if(n.meta_cutover || n.connection != old || !neu->status.spare) {
		if(neu->status.spare) {
			neu->status.spare = false;
		}

		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	/* Responder PREPARE/COMMIT, then an early primary death that must not flush
	   until EMERGENCY, including a record that arrived on the standby first. */
	if(mesh->connections) {
		list_action_t del = mesh->connections->delete;
		const char *queued = "5 1 queued\n";
		unsigned pending;

		list_insert_tail(mesh->connections, neu);
		n.connection = old;
		old->status.active = true;
		neu->status.spare = true;
		neu->status.active = true;
		neu->status.initiator = false;
		snprintf(request, sizeof(request), "%d 42\n", REQ_META_CUTOVER_PREPARE);

		if(!meta_cutover_prepare_h(mesh, old, request) || !n.meta_cutover
		                || n.meta_cutover->state != META_CUTOVER_RESP_WAIT_COMMIT || n.connection != old) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		if(!upgrade_meta_enqueue_if_frozen(mesh, old, queued, (int)strlen(queued))
		                || n.meta_cutover->pending_records->count != 1) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_COMMIT, n.meta_cutover->id);

		if(!meta_cutover_commit_h(mesh, neu, request) || n.meta_cutover || n.connection != neu || neu->status.spare) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		if(!meta_cutover_commit_h(mesh, neu, request) || n.connection != neu) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		n.connection = old;
		old->status.active = true;
		neu->status.spare = true;
		neu->status.active = true;
		neu->status.initiator = true;
		n.key_delivery_uncertain = false;

		if(!upgrade_cutover_begin(mesh, &n, old, neu)
		                || !upgrade_meta_enqueue_if_frozen(mesh, old, queued, (int)strlen(queued))) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		pending = n.meta_cutover->pending_records->count;
		upgrade_connection_closing(mesh, old);

		if(!n.meta_cutover || n.meta_cutover->state != META_CUTOVER_EMERGENCY_SYNC
		                || n.connection != neu || neu->status.spare
		                || !n.meta_cutover->pending_records
		                || n.meta_cutover->pending_records->count != pending) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_EMERGENCY, n.meta_cutover->id);

		if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || n.connection != neu
		                || !n.key_delivery_uncertain) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || n.connection != neu) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		/* Record hits the standby before this side has cutover state. Primary
		   death installs the socket but must not replay until EMERGENCY. */
		n.connection = old;
		old->status.active = true;
		neu->status.spare = true;
		neu->status.active = true;
		n.key_delivery_uncertain = false;
		upgrade_standby_drop_held(neu);

		if(!receive_request(mesh, neu, "5 1 held\n") || !neu->standby_held || neu->standby_held->count != 1) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		upgrade_connection_closing(mesh, old);

		if(!n.meta_cutover || n.meta_cutover->state != META_CUTOVER_EMERGENCY_SYNC
		                || n.connection != neu || !neu->standby_held || neu->standby_held->count != 1) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		snprintf(request, sizeof(request), "%d 99\n", REQ_META_CUTOVER_EMERGENCY);

		if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || neu->standby_held
		                || !n.key_delivery_uncertain) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		/* EMERGENCY before PREPARE promotes this standby and does not touch other nodes. */
		n.connection = old;
		old->status.active = true;
		neu->status.spare = true;
		neu->status.active = true;
		n.key_delivery_uncertain = false;
		snprintf(request, sizeof(request), "%d 7\n", REQ_META_CUTOVER_EMERGENCY);

		if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || n.connection != neu
		                || neu->status.spare || !n.key_delivery_uncertain) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		n.connection = old;
		old->status.active = true;
		neu->status.spare = true;
		neu->status.active = true;
		neu->status.initiator = true;

		if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		mesh->retiring_outgoing = true;
		upgrade_connection_closing(mesh, old);
		mesh->retiring_outgoing = false;

		if(n.meta_cutover || n.connection != old || !neu->status.spare) {
			return cover_bail(mesh, &n, old, neu, true, del);
		}

		cover_untrack(mesh, neu, del);
	}

	{
		const char *why;
		struct meta_cutover marker;

		memset(&marker, 0, sizeof marker);
		n.meta_cutover = &marker;
		why = path_upgrade_ineligible_reason(mesh, &n);
		n.meta_cutover = NULL;

		if(!why || strcmp(why, "cutover-active")) {
			return cover_bail(mesh, &n, old, neu, false, NULL);
		}
	}

	/* READY already moved the initiator to INIT_WAIT_ACK. The responder's
	   EMERGENCY must still be echoed and must promote with uncertainty. */
	n.connection = old;
	old->status.active = true;
	neu->status.spare = true;
	neu->status.active = true;
	neu->status.initiator = true;
	n.key_delivery_uncertain = false;

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_READY, n.meta_cutover->id);

	if(!meta_cutover_ready_h(mesh, old, request) || !n.meta_cutover
	                || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_ACK) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_EMERGENCY, n.meta_cutover->id);

	if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || n.connection != neu
	                || neu->status.spare || !n.key_delivery_uncertain) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	/* Close in INIT_WAIT_ACK, then ACK. The close holds the FIFO. The ACK is ordered proof. */
	n.connection = old;
	old->status.active = true;
	neu->status.spare = true;
	neu->status.active = true;
	neu->status.initiator = true;

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_READY, n.meta_cutover->id);

	if(!meta_cutover_ready_h(mesh, old, request) || !n.meta_cutover
	                || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_ACK) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	n.key_delivery_uncertain = true;
	upgrade_connection_closing(mesh, old);

	if(!n.meta_cutover || n.meta_cutover->state != META_CUTOVER_EMERGENCY_SYNC
	                || n.connection != neu || neu->status.spare || !n.key_delivery_uncertain) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_ACK, n.meta_cutover->id);

	if(!meta_cutover_ack_h(mesh, neu, request) || n.meta_cutover || n.connection != neu
	                || n.key_delivery_uncertain) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	/* A full standby hold with no barrier fails the socket instead of accepting a drop. */
	n.connection = old;
	neu->status.spare = true;
	neu->status.active = true;
	upgrade_standby_drop_held(neu);

	for(i = 0; i < META_CUTOVER_MAX_RECORDS; i++) {
		if(upgrade_standby_hold(mesh, neu, "5 1 held\n") != 1) {
			return cover_bail(mesh, &n, old, neu, false, NULL);
		}
	}

	if(upgrade_standby_hold(mesh, neu, "5 1 overflow\n") != -1 || receive_request(mesh, neu, "5 1 overflow\n")
	                || n.connection != old || !neu->status.spare) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	upgrade_standby_drop_held(neu);

	/* The same overflow during a live barrier forces sync and then runs the record. */
	n.key_delivery_uncertain = false;

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	for(i = 0; i < META_CUTOVER_MAX_RECORDS; i++) {
		if(upgrade_standby_hold(mesh, neu, "5 1 held\n") != 1) {
			return cover_bail(mesh, &n, old, neu, false, NULL);
		}
	}

	if(!receive_request(mesh, neu, "5 1 overflow\n") || n.meta_cutover || n.connection != neu
	                || neu->status.spare || neu->standby_held || !n.key_delivery_uncertain) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	/* A handler failure during replay is not success. socket < 0 is not terminated here. */
	neu->standby_held = list_alloc(standby_held_free);
	list_insert_tail(neu->standby_held, xstrdup("6\n"));

	if(upgrade_standby_replay(mesh, neu, neu) || neu->standby_held || !neu->meta_teardown) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	/* READY-release failure aborts immediately. Overflow delivers its trigger
	   only after outbound-then-inbound replay. A failed replay retires both
	   sockets, and a later primary close cannot promote that standby.
	   Malformed and stale controls, and a timeout while the old primary is
	   alive, stay on the canonical socket. */
	{
		list_action_t del = NULL;
		bool tracked = false;
		char trigger[] = "10 cover\n";

#define COVER_BAIL() return cover_bail(mesh, &n, old, neu, tracked, del)

		if(!mesh->connections) {
			COVER_BAIL();
		}

		del = mesh->connections->delete;
		list_insert_tail(mesh->connections, neu);
		tracked = true;
		n.connection = old;
		old->status.active = true;
		neu->status.spare = true;
		neu->status.active = true;
		neu->status.initiator = false;
		old->meta_teardown = false;
		neu->meta_teardown = false;
		old->meta_replay_failed = false;
		neu->meta_replay_failed = false;
		n.key_delivery_uncertain = false;

		if(!meta_cutover_ready_h(mesh, old, "18\n") || !meta_cutover_ready_h(mesh, old, "18 1\n")
		                || n.meta_cutover || n.connection != old) {
			COVER_BAIL();
		}

		if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
			COVER_BAIL();
		}

		upgrade_cutover_on_timeout(mesh, &n);

		if(n.meta_cutover || n.connection != old || !neu->status.spare || neu->meta_teardown) {
			COVER_BAIL();
		}

		devtool_hold_cutover_ready = true;
		snprintf(request, sizeof(request), "%d 77\n", REQ_META_CUTOVER_PREPARE);

		if(!meta_cutover_prepare_h(mesh, old, request) || !n.meta_cutover
		                || n.meta_cutover->state != META_CUTOVER_RESP_WAIT_COMMIT) {
			COVER_BAIL();
		}

		devtool_hold_cutover_ready = false;
		cutover_fail_control_send = true;

		if(upgrade_cutover_release_ready(mesh, &n) || n.meta_cutover || n.connection != old
		                || old->meta_teardown || neu->meta_teardown) {
			COVER_BAIL();
		}

		cutover_fail_control_send = false;

		if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
			COVER_BAIL();
		}

		for(i = 0; i < META_CUTOVER_MAX_RECORDS; i++) {
			char rec[32];
			int len = snprintf(rec, sizeof(rec), "5 %d\n", i);

			if(!upgrade_meta_enqueue_if_frozen(mesh, old, rec, len)) {
				COVER_BAIL();
			}
		}

		if(upgrade_standby_hold(mesh, neu, "9\n") != 1) {
			COVER_BAIL();
		}

		cover_order[0] = '\0';
		cover_order_on = true;

		if(!send_meta(mesh, old, trigger, (int)strlen(trigger)) || strcmp(cover_order, "OI")
		                || n.meta_cutover || n.connection != old || old->meta_teardown || neu->meta_teardown
		                || neu->standby_held) {
			COVER_BAIL();
		}

		cover_order_on = false;

		if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
			COVER_BAIL();
		}

		for(i = 0; i < META_CUTOVER_MAX_RECORDS; i++) {
			char rec[32];
			int len = snprintf(rec, sizeof(rec), "5 %d\n", i);

			if(!upgrade_meta_enqueue_if_frozen(mesh, old, rec, len)) {
				COVER_BAIL();
			}
		}

		if(upgrade_standby_hold(mesh, neu, "6\n") != 1) {
			COVER_BAIL();
		}

		cover_order[0] = '\0';
		cover_order_on = true;

		if(send_meta(mesh, old, trigger, (int)strlen(trigger)) || strcmp(cover_order, "OIF")
		                || n.meta_cutover || n.connection != old || !old->meta_teardown || !neu->meta_teardown
		                || find_spare(mesh, &n)) {
			COVER_BAIL();
		}

		cover_order_on = false;
		upgrade_connection_closing(mesh, old);

		if(n.meta_cutover || n.connection != old || !neu->meta_teardown) {
			COVER_BAIL();
		}

		cover_untrack(mesh, neu, del);
		tracked = false;
		old->meta_teardown = false;
		neu->meta_teardown = false;
		old->meta_replay_failed = false;
		neu->meta_replay_failed = false;
		timeout_del(&mesh->loop, &old->drain_ev);
		timeout_del(&mesh->loop, &neu->drain_ev);
#undef COVER_BAIL
	}

	if(witness && witness->key_delivery_uncertain != witness_uncertain) {
		return cover_bail(mesh, &n, old, neu, false, NULL);
	}

	free_connection(old);
	free_connection(neu);
	return true;
}

