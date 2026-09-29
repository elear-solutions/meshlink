/*
    net_upgrade.c -- upgrade a canonical (relay) meta connection to a direct one
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
#include "connection_policy.h"
#include "devtools.h"
#include "edge.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "net_upgrade.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "list.h"
#include "meta.h"
#include "protocol.h"
#include "xalloc.h"

#include <assert.h>
#include <inttypes.h>

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

static const char *cutover_state_name(meta_cutover_state_t state);
static bool upgrade_cutover_abort(meshlink_handle_t *mesh, node_t *n, const char *reason, bool replay);
static bool cutover_fail_control_send;
static bool cover_order_on;
static char cover_order[8];

static void cover_order_mark(char mark) {
	size_t used;

	if(!cover_order_on) {
		return;
	}

	used = strlen(cover_order);

	if(used + 1 < sizeof cover_order) {
		cover_order[used] = mark;
		cover_order[used + 1] = '\0';
	}
}
static void upgrade_cutover_on_timeout(meshlink_handle_t *mesh, node_t *n);
static bool cutover_promote(meshlink_handle_t *mesh, node_t *n, bool send_ack, bool uncertain, bool close_old);
static void cutover_enter_emergency_sync(meshlink_handle_t *mesh, node_t *n);
static bool cutover_finish_sync(meshlink_handle_t *mesh, node_t *n, bool uncertain);
static bool upgrade_standby_replay(meshlink_handle_t *mesh, connection_t *owner, connection_t *dispatch);
static void upgrade_standby_drop_held(connection_t *c);
static bool upgrade_standby_force_sync(meshlink_handle_t *mesh, connection_t *c);
static struct meta_cutover *upgrade_cutover_create(node_t *n);

/* Only the side that owns the outgoing_t probes; the peer migrates when the
   probe shows up as a second inbound connection. */
bool upgrade_probe_eligible(meshlink_handle_t *mesh, node_t *n) {
	return !path_upgrade_ineligible_reason(mesh, n);
}

/* Pick the next recent[] slot that is not the address we are already connected
   to, rotating through the list so a dead front entry does not starve the rest.
   Like everywhere else, recent[] ends at the first unset slot. Returns false if
   there is nothing to try. */
static bool pick_probe_address(node_t *n, sockaddr_t *out) {
	int count = 0;

	while(count < MAX_RECENT && n->recent[count].sa.sa_family != AF_UNSPEC) {
		count++;
	}

	for(int i = 0; i < count; i++) {
		int idx = (n->upgrade_recent_idx + i) % count;
		const sockaddr_t *sa = &n->recent[idx];

		if(n->connection && !sockaddrcmp(sa, &n->connection->address)) {
			continue;
		}

		if(n->startup_skip_sa.sa.sa_family && !sockaddrcmp(sa, &n->startup_skip_sa)) {
			continue;
		}

		if(!path_is_meta_candidate(n, sa, n->recent_source[idx], n->recent_cap[idx])) {
			continue;
		}

		*out = *sa;
		n->upgrade_recent_idx = (idx + 1) % count;
		return true;
	}

	return false;
}

static void apply_backoff(meshlink_handle_t *mesh, node_t *n) {
	if(n->upgrade_backoff) {
		n->upgrade_backoff *= 2;

		if(n->upgrade_backoff > UPGRADE_BACKOFF_MAX) {
			n->upgrade_backoff = UPGRADE_BACKOFF_MAX;
		}
	} else {
		n->upgrade_backoff = UPGRADE_BACKOFF_MIN;
	}

	n->upgrade_next_try = mesh->loop.now.tv_sec + n->upgrade_backoff;
}

void start_upgrade_probe(meshlink_handle_t *mesh, node_t *n) {
	sockaddr_t sa;

	if(!pick_probe_address(n, &sa)) {
		upgrade_probe_failed(mesh, n, "no direct address left to try");
		return;
	}

	connection_t *c = new_connection();
	c->outgoing = NULL;
	c->status.upgrade_probe = true;
	c->name = xstrdup(n->name);
	c->address = sa;

	path_log_validation(mesh, n, &c->address, "probe-start", "direct META");

	if(!connect_meta_socket(mesh, c)) {
		free_connection(c);
		upgrade_probe_failed(mesh, n, "could not connect");
		return;
	}

	n->upgrade_probe = c;
	devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_STARTED);
}

static void path_upgrade_packet(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	node_t *n = req->node;

	if(upgrade_probe_eligible(mesh, n)) {
		start_upgrade_probe(mesh, n);
	}
}

static path_transaction_priority_t path_upgrade_priority(meshlink_handle_t *mesh, node_t *n) {
	return (n && n == connection_policy_backbone(mesh)) ? PATH_TX_BACKBONE_REQUIRED : PATH_TX_CHANNEL_PROMOTION;
}

void try_upgrade_probe(meshlink_handle_t *mesh, node_t *n) {
	path_probe_request_t req;
	path_transaction_priority_t prio;

	if(!upgrade_probe_eligible(mesh, n)) {
		return;
	}

	prio = path_upgrade_priority(mesh, n);
	memset(&req, 0, sizeof req);
	req.node = n;
	req.priority = prio;
	req.send = path_upgrade_packet;
	(void)path_scheduler_emit_packet(mesh, NULL, &req);
}

void upgrade_probe_failed(meshlink_handle_t *mesh, node_t *n, const char *reason) {
	connection_t *c = n->connection;

	n->upgrade_probe = NULL;

	if(c && c->status.active && !path_meta_is_canonical(n, c)) {
		/* A regular connection got there first: nothing left to upgrade, so no backoff. */
		path_log_validation(mesh, n, NULL, "probe-abandoned", reason);
	} else {
		apply_backoff(mesh, n);
		char detail[64];
		snprintf(detail, sizeof detail, "%s backoff=%d", reason, n->upgrade_backoff);
		path_log_validation(mesh, n, NULL, "probe-failed", detail);
	}

	devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_FAILED);
}

void upgrade_probe_standby_ready(meshlink_handle_t *mesh, connection_t *c) {
	node_t *n = c->node;

	c->status.upgrade_probe = false;
	n->upgrade_probe = NULL;
	n->upgrade_backoff = 0;
	n->upgrade_next_try = 0;

	path_log_validation(mesh, n, &c->address, "probe-validated", "direct META standby");
	logger(mesh, MESHLINK_INFO, "META cutover standby authenticated with %s", n->name);
}

void upgrade_probe_committed(meshlink_handle_t *mesh, connection_t *c) {
	node_t *n = c->node;

	path_log_validation(mesh, n, &c->address, "probe-succeeded", "direct META");
	path_log_meta(mesh, n, &c->address, "migrated canonical -> direct");
	path_consider_route_promotion(mesh, NULL, PATH_PROMOTION_META_DIRECT);
	devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_SUCCEEDED);
	logger(mesh, MESHLINK_INFO, "META cutover committed with %s", n->name);
}

void upgrade_probe_succeeded(meshlink_handle_t *mesh, connection_t *c) {
	upgrade_probe_standby_ready(mesh, c);
	upgrade_probe_committed(mesh, c);
}

bool upgrade_should_preserve_node_session(meshlink_handle_t *mesh, const node_t *n, bool was_upgrade_probe, bool old_was_canonical) {
	(void)mesh;

	if(!n || !was_upgrade_probe || !old_was_canonical) {
		return false;
	}

	if(!n->status.validkey || n->status.waitingforkey) {
		return false;
	}

	if(!n->sptps.state) {
		return false;
	}

	if(n->session_id && n->prevedge && n->prevedge->reverse
	                && n->prevedge->reverse->session_id
	                && n->prevedge->reverse->session_id != n->session_id) {
		return false;
	}

	return true;
}

bool upgrade_preserve_cover_unit(meshlink_handle_t *mesh) {
	node_t n;
	edge_t pred;
	edge_t reverse;

	memset(&n, 0, sizeof n);
	memset(&pred, 0, sizeof pred);
	memset(&reverse, 0, sizeof reverse);
	n.name = "preserve";
	n.status.validkey = true;
	n.sptps.state = SPTPS_SECONDARY_KEX;

	if(!upgrade_should_preserve_node_session(mesh, &n, true, true)) {
		return false;
	}

	if(upgrade_should_preserve_node_session(mesh, &n, false, true)
	                || upgrade_should_preserve_node_session(mesh, &n, true, false)
	                || upgrade_should_preserve_node_session(NULL, NULL, true, true)) {
		return false;
	}

	n.status.validkey = false;

	if(upgrade_should_preserve_node_session(mesh, &n, true, true)) {
		return false;
	}

	n.status.validkey = true;
	n.sptps.state = 0;

	if(upgrade_should_preserve_node_session(mesh, &n, true, true)) {
		return false;
	}

	n.sptps.state = SPTPS_KEX;
	n.status.waitingforkey = true;

	if(upgrade_should_preserve_node_session(mesh, &n, true, true)) {
		return false;
	}

	n.status.waitingforkey = false;
	n.sptps.state = SPTPS_SECONDARY_KEX;
	n.session_id = 1;
	reverse.session_id = 2;
	pred.reverse = &reverse;
	n.prevedge = &pred;

	if(upgrade_should_preserve_node_session(mesh, &n, true, true)) {
		return false;
	}

	reverse.session_id = 1;

	if(!upgrade_should_preserve_node_session(mesh, &n, true, true)) {
		return false;
	}

	return true;
}

static void drain_timeout_handler(event_loop_t *loop, void *data) {
	connection_t *c = data;
	meshlink_handle_t *mesh = loop->data;

	logger(mesh, MESHLINK_INFO, "Drain timeout for old META with %s, closing", c->name ? c->name : "?");
	terminate_connection(mesh, c, false);
}

void upgrade_begin_drain(meshlink_handle_t *mesh, connection_t *c) {
	if(!mesh || !c) {
		return;
	}

	c->status.drain_only = true;
	c->outgoing = NULL;

	timeout_add(&mesh->loop, &c->drain_ev, drain_timeout_handler, c, &(struct timespec) {
		UPGRADE_DRAIN_TIMEOUT_SEC, 0
	});

	if(c->outbuf.len <= c->outbuf.offset) {
		terminate_connection(mesh, c, false);
		return;
	}

	if(c->io.cb) {
		io_set(&mesh->loop, &c->io, IO_WRITE);
	}

	logger(mesh, MESHLINK_INFO, "Draining old META connection with %s", c->name ? c->name : "?");
}

bool upgrade_defers_ack(const connection_t *c) {
	return (c->flags & PROTOCOL_UPGRADE) && !c->status.initiator;
}

static void standby_timeout_handler(event_loop_t *loop, void *data) {
	connection_t *c = data;
	meshlink_handle_t *mesh = loop->data;

	if(!c->status.spare) {
		return;
	}

	/* PREPARE/READY owns the deadline once the barrier exists. */
	if(c->node && c->node->meta_cutover) {
		return;
	}

	logger(mesh, MESHLINK_INFO, "Standby with %s expired before cutover, closing", c->name ? c->name : "?");
	terminate_connection(mesh, c, false);
}

static void standby_held_free(const void *p) {
	free((void *)p);
}

int upgrade_standby_hold(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	size_t len;

	if(!c || !request) {
		return -1;
	}

	len = strlen(request);

	if(!c->standby_held) {
		c->standby_held = list_alloc(standby_held_free);
	}

	if(c->standby_held->count >= META_CUTOVER_MAX_RECORDS || c->standby_held_bytes + len > META_CUTOVER_MAX_BYTES) {
		logger(mesh, MESHLINK_ERROR, "Standby hold overflow from %s records=%u bytes=%zu",
		       c->name ? c->name : "?", c->standby_held->count, c->standby_held_bytes);

		/* Do not drop the record and report success. Promote if this standby
		   is already in a barrier; otherwise the caller fails the socket. */
		if(upgrade_standby_force_sync(mesh, c)) {
			return 0;
		}

		return -1;
	}

	list_insert_tail(c->standby_held, xstrdup(request));
	c->standby_held_bytes += len;
	logger(mesh, MESHLINK_DEBUG, "Holding request %d from standby %s until promotion", atoi(request), c->name ? c->name : "?");
	return 1;
}

/* Detach owner's held queue and dispatch it on dispatch, FIFO. Never frees
   either connection. A failure while dispatch is already inside receive_request()
   is reported through meta_replay_failed; otherwise the socket is shut down and
   the META I/O path frees it later. */
static bool upgrade_standby_replay(meshlink_handle_t *mesh, connection_t *owner, connection_t *dispatch) {
	list_t *q;

	if(!owner || !owner->standby_held) {
		return true;
	}

	if(!dispatch) {
		upgrade_standby_drop_held(owner);
		return false;
	}

	q = owner->standby_held;
	owner->standby_held = NULL;
	owner->standby_held_bytes = 0;

	if(q->head) {
		cover_order_mark('I');
		logger(mesh, MESHLINK_INFO, "META cutover replay inbound on %s", dispatch && dispatch->name ? dispatch->name : "?");
	}

	while(q->head) {
		char *request = list_get_head(q);
		bool nested = dispatch->meta_receive_depth > 0;
		bool ok = receive_request(mesh, dispatch, request);

		list_delete_head(q);

		if(!ok) {
			while(q->head) {
				list_delete_head(q);
			}

			list_free(q);
			cover_order_mark('F');

			if(nested) {
				dispatch->meta_replay_failed = true;
			} else {
				connection_defer_teardown(mesh, dispatch);
			}

			return false;
		}
	}

	list_free(q);
	return true;
}

static void upgrade_standby_drop_held(connection_t *c) {
	list_t *q;

	if(!c || !c->standby_held) {
		return;
	}

	q = c->standby_held;
	c->standby_held = NULL;
	c->standby_held_bytes = 0;

	while(q->head) {
		list_delete_head(q);
	}

	list_free(q);
}

static connection_t *find_spare(meshlink_handle_t *mesh, const node_t *n) {
	for list_each(connection_t, c, mesh->connections) {
		if(c->status.spare && c->status.active && c->node == n && !c->meta_teardown && !c->meta_replay_failed) {
			return c;
		}
	}

	return NULL;
}

void upgrade_drop_spare(meshlink_handle_t *mesh, node_t *n) {
	connection_t *spare = find_spare(mesh, n);

	if(spare) {
		logger(mesh, MESHLINK_INFO, "Dropping superseded standby connection with %s", n->name);
		terminate_connection(mesh, spare, false);
	}
}

/* The peer probed us to replace its canonical connection. Its old connection stays
   the node's connection until the peer closes it; this one is fully authenticated and
   pinged like any other, with its edge prepared but not yet in the graph. */
void upgrade_hold_standby(meshlink_handle_t *mesh, connection_t *c, node_t *n, const char *hisport, int devclass) {
	/* ack_h() rejects a repeated ACK before it gets here, so c cannot be the standby
	   about to be dropped. */
	assert(!c->status.active && !c->status.spare);

	/* A re-probe means the peer gave up on the previous one (its ACK never made it
	   there); that spare is half-open at best and must not be the one promoted. */
	upgrade_drop_spare(mesh, n);

	c->node = n;
	c->allow_request = ALL;
	c->last_key_renewal = mesh->loop.now.tv_sec;
	c->status.active = true;

	if(!c->activated_at) {
		c->activated_at = mesh->loop.now.tv_sec;
	}

	c->status.spare = true;
	c->edge = new_connection_edge(mesh, c, n, hisport, devclass);

	node_add_recent_address_cap(mesh, n, &c->address, ADDR_SRC_AUTH_DIRECT, PATH_CAP_BOTH);

	/* Until PREPARE arrives, this is the only deadline. The barrier timer replaces it. */
	timeout_add(&mesh->loop, &c->drain_ev, standby_timeout_handler, c, &(struct timespec) {
		META_CUTOVER_TIMEOUT_SEC, 0
	});

	if(mesh->log_level <= MESHLINK_INFO) {
		char *hostname = sockaddr2hostname(&c->address);
		logger(mesh, MESHLINK_INFO, "Holding direct connection from %s at %s as standby", n->name, hostname);
		free(hostname);
	}
}

void upgrade_hold_spare(meshlink_handle_t *mesh, connection_t *c, node_t *n, const char *hisport, int devclass) {
	upgrade_hold_standby(mesh, c, n, hisport, devclass);
}

/* During meshlink_stop()/meshlink_close() every connection is torn down and a
   blacklisted node has both of its sockets shut already: promoting would only
   flap the node's status and broadcast an edge that is gone a moment later.
   Intent retirement and a LAN epoch advance close the primary on purpose and
   must not promote the standby underneath that. */
static bool may_promote(meshlink_handle_t *mesh, const node_t *n) {
	return mesh->loop.running && !n->status.blacklisted && !mesh->retiring_outgoing && !mesh->lan_epoch_retiring;
}

void upgrade_connection_closing(meshlink_handle_t *mesh, connection_t *c) {
	if(c->status.upgrade_probe && !c->status.active) {
		node_t *n = lookup_node(mesh, c->name);

		if(n && n->upgrade_probe == c) {
			upgrade_probe_failed(mesh, n, "connection closed before it authenticated");
		}

		return;
	}

	node_t *n = c->node;
	struct meta_cutover *co = n ? n->meta_cutover : NULL;

	if(c->status.spare) {
		/* Abort owns the held queue when it can still replay onto the primary.
		   Dropping here first would discard records the old socket can deliver. */
		if(co && co->new_standby == c && co->state != META_CUTOVER_EMERGENCY_PROMOTE && co->state != META_CUTOVER_EMERGENCY_SYNC) {
			upgrade_cutover_abort(mesh, n, "standby closed", true);
		} else {
			upgrade_standby_drop_held(c);
		}

		/* Not in the graph unless commit already moved it, and commit clears spare. */
		if(c->edge) {
			free_edge(c->edge);
			c->edge = NULL;
		}

		return;
	}

	if(!n || n->connection != c) {
		return;
	}

	co = n->meta_cutover;

	if(co && co->state == META_CUTOVER_EMERGENCY_PROMOTE) {
		return;
	}

	if(co && co->state == META_CUTOVER_EMERGENCY_SYNC) {
		if(c == n->connection || c == co->new_standby) {
			upgrade_cutover_abort(mesh, n, "sync socket closed", false);
		}

		return;
	}

	if(co && co->old_primary != c) {
		return;
	}

	if(!co) {
		connection_t *spare;

		/* This close is the deferred teardown of a replay that already failed.
		   The rejected standby is not a promotion candidate. */
		if(c->meta_teardown || c->meta_replay_failed) {
			return;
		}

		/* PREPARE never arrived. The standby is live, but this peer has no
		   barrier id yet. Install it and wait for the initiator's EMERGENCY. */
		spare = find_spare(mesh, n);

		if(!spare || !spare->status.active || !may_promote(mesh, n)) {
			return;
		}

		co = upgrade_cutover_create(n);
		co->old_primary = c;
		co->new_standby = spare;
		co->freeze_ordinary_meta = true;
		timeout_del(&mesh->loop, &spare->drain_ev);
		logger(mesh, MESHLINK_INFO, "META cutover emergency sync with %s before PREPARE", n->name);
		cutover_enter_emergency_sync(mesh, n);
		return;
	}

	if(!may_promote(mesh, n) || !co->new_standby || !co->new_standby->status.active) {
		connection_t *standby = co->new_standby;

		upgrade_cutover_abort(mesh, n, "primary closed", false);

		/* meshlink_stop() is already walking mesh->connections. Terminating the
		   spare here unlinks a list node that walk still holds. Stop closes it
		   on its own iteration. A live mesh still drops the spare now, or it
		   would sit until the drain timer with the barrier already gone. */
		if(mesh->loop.running && standby && standby->status.spare && standby->socket >= 0) {
			terminate_connection(mesh, standby, false);
		}

		return;
	}

	/* READY already proved the peer drained its old socket. A later close of
	   that socket is the peer finishing the barrier, not a lost record. */
	if(co->state == META_CUTOVER_INIT_WAIT_ACK) {
		logger(mesh, MESHLINK_INFO, "META cutover primary closed after READY with %s id=%" PRIu64 " state=%s",
		       n->name, co->id, cutover_state_name(co->state));
		cutover_promote(mesh, n, false, false, false);
		return;
	}

	logger(mesh, MESHLINK_INFO, "META cutover emergency sync with %s id=%" PRIu64 " state=%s",
	       n->name, co->id, cutover_state_name(co->state));
	cutover_enter_emergency_sync(mesh, n);
}

static const char *cutover_state_name(meta_cutover_state_t state) {
	switch(state) {
	case META_CUTOVER_NONE:
		return "none";

	case META_CUTOVER_INIT_WAIT_READY:
		return "init-wait-ready";

	case META_CUTOVER_INIT_WAIT_ACK:
		return "init-wait-ack";

	case META_CUTOVER_RESP_WAIT_COMMIT:
		return "resp-wait-commit";

	case META_CUTOVER_EMERGENCY_PROMOTE:
		return "emergency";

	case META_CUTOVER_EMERGENCY_SYNC:
		return "emergency-sync";

	default:
		return "?";
	}
}

static void pending_record_free(const void *p) {
	meta_pending_record_t *r = (meta_pending_record_t *)p;

	if(!r) {
		return;
	}

	free(r->data);
	free(r);
}

static void cutover_timeout_cb(event_loop_t *loop, void *data) {
	upgrade_cutover_on_timeout(loop->data, data);
}

static void upgrade_cutover_assert(const meshlink_handle_t *mesh, const node_t *n) {
	const struct meta_cutover *co;

	(void)mesh;

	if(!n) {
		return;
	}

	co = n->meta_cutover;

	if(!co) {
		return;
	}

	assert(co->node == n);
	assert(co->old_primary != co->new_standby);
	assert(co->id != 0 || co->state == META_CUTOVER_NONE || co->state == META_CUTOVER_EMERGENCY_SYNC);

	if(co->state == META_CUTOVER_INIT_WAIT_READY || co->state == META_CUTOVER_INIT_WAIT_ACK || co->state == META_CUTOVER_RESP_WAIT_COMMIT) {
		assert(n->connection == co->old_primary);
		assert(co->new_standby);
		assert(co->new_standby->status.spare);
		assert(co->freeze_ordinary_meta);
		assert(co->pending_records);
	}

	if(co->state == META_CUTOVER_EMERGENCY_SYNC) {
		assert(co->new_standby);
		assert(n->connection == co->new_standby);
		assert(!co->new_standby->status.spare);
		assert(co->freeze_ordinary_meta);
		assert(co->pending_records);
	}
}

static struct meta_cutover *upgrade_cutover_create(node_t *n) {
	struct meta_cutover *co;

	if(n->meta_cutover) {
		return n->meta_cutover;
	}

	co = xzalloc(sizeof(*co));
	co->node = n;
	co->pending_records = list_alloc(pending_record_free);
	n->meta_cutover = co;
	return co;
}

static uint64_t cutover_new_id(meshlink_handle_t *mesh) {
	uint64_t id = 0;

	while(!id) {
		id = ((uint64_t)(uint32_t)prng(mesh, 0x7fffffff) << 32) ^ (uint32_t)prng(mesh, 0x7fffffff);
	}

	return id;
}

static bool send_cutover(meshlink_handle_t *mesh, connection_t *c, int req, uint64_t id) {
	char buf[96];
	int len;
	const char *name = "META_CUTOVER";

	if(req == REQ_META_CUTOVER_PREPARE) {
		name = "PREPARE";
	} else if(req == REQ_META_CUTOVER_READY) {
		name = "READY";
	} else if(req == REQ_META_CUTOVER_COMMIT) {
		name = "COMMIT";
	} else if(req == REQ_META_CUTOVER_ACK) {
		name = "ACK";
	} else if(req == REQ_META_CUTOVER_EMERGENCY) {
		name = "EMERGENCY";
	}

	if(cutover_fail_control_send) {
		return false;
	}

	len = snprintf(buf, sizeof(buf), "%d %" PRIu64 "\n", req, id);

	if(len < 0 || (size_t)len >= sizeof(buf)) {
		return false;
	}

	logger(mesh, MESHLINK_INFO, "META cutover send %s id=%" PRIu64 " to %s via %s", name, id, c->node ? c->node->name : "?", c->status.spare ? "standby" : "primary");
	return send_meta_cutover_control(mesh, c, buf, len);
}

static bool parse_cutover_id(const char *request, uint64_t *id) {
	unsigned long long value = 0;

	if(sscanf(request, "%*d %llu", &value) != 1 || !value) {
		return false;
	}

	*id = (uint64_t)value;
	return true;
}

static void cutover_arm(meshlink_handle_t *mesh, struct meta_cutover *co) {
	timeout_del(&mesh->loop, &co->timer);
	timeout_add(&mesh->loop, &co->timer, cutover_timeout_cb, co->node, &(struct timespec) {
		META_CUTOVER_TIMEOUT_SEC, 0
	});
}

static list_t *cutover_take_queue(struct meta_cutover *co) {
	list_t *q = co->pending_records;

	co->pending_records = NULL;
	co->pending_bytes = 0;
	co->freeze_ordinary_meta = false;
	return q;
}

static void flush_queue(meshlink_handle_t *mesh, connection_t *c, list_t *q) {
	if(!q) {
		return;
	}

	if(q->head) {
		cover_order_mark('O');
		logger(mesh, MESHLINK_INFO, "META cutover replay outbound to %s", c && c->name ? c->name : "?");
	}

	while(q->head) {
		meta_pending_record_t *r = list_get_head(q);

		if(c && c->socket >= 0 && c->status.active) {
			send_meta(mesh, c, (const char *)r->data, (int)r->length);
		}

		list_delete_head(q);
	}

	list_free(q);
}

static void drop_queue(list_t *q) {
	if(!q) {
		return;
	}

	while(q->head) {
		list_delete_head(q);
	}

	list_free(q);
}

static void cutover_note_failure(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh->loop.running || n->status.blacklisted) {
		return;
	}

	apply_backoff(mesh, n);
	devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_FAILED);
}

static void cutover_rearm_standby(meshlink_handle_t *mesh, connection_t *standby) {
	if(!standby || !standby->status.spare || !standby->status.active || standby->socket < 0
	                || standby->meta_teardown || standby->meta_replay_failed) {
		return;
	}

	if(standby->node && standby->node->meta_cutover) {
		return;
	}

	timeout_del(&mesh->loop, &standby->drain_ev);
	timeout_add(&mesh->loop, &standby->drain_ev, standby_timeout_handler, standby, &(struct timespec) {
		META_CUTOVER_TIMEOUT_SEC, 0
	});
}

static bool upgrade_cutover_abort(meshlink_handle_t *mesh, node_t *n, const char *reason, bool replay) {
	struct meta_cutover *co;
	connection_t *old;
	connection_t *standby;
	list_t *q;
	bool leave_standby;
	bool replay_ok = true;

	if(!n || !n->meta_cutover) {
		return false;
	}

	co = n->meta_cutover;
	logger(mesh, MESHLINK_INFO, "META cutover abort with %s id=%" PRIu64 " state=%s reason=%s queue=%u",
	       n->name, co->id, cutover_state_name(co->state), reason ? reason : "?",
	       co->pending_records ? co->pending_records->count : 0);

	old = co->old_primary;
	standby = co->new_standby;
	leave_standby = reason && strcmp(reason, "standby closed") && strcmp(reason, "node deleted") && strcmp(reason, "sync socket closed");
	timeout_del(&mesh->loop, &co->timer);
	q = cutover_take_queue(co);
	n->meta_cutover = NULL;
	free(co);

	if(replay && old && old->status.active && n->connection == old) {
		/* Outbound plaintext first, then held inbound, so a replayed request's
		   reply cannot pass META that was already queued locally. The caller
		   sends an overflow trigger only when this returns true. */
		flush_queue(mesh, old, q);
		replay_ok = upgrade_standby_replay(mesh, standby, old);

		if(!replay_ok) {
			connection_defer_teardown(mesh, standby);
			leave_standby = false;
		}
	} else {
		drop_queue(q);
		upgrade_standby_drop_held(standby);
	}

	if(leave_standby) {
		cutover_rearm_standby(mesh, standby);
	}

	cutover_note_failure(mesh, n);
	return replay_ok;
}

static bool cutover_log_commit(meshlink_handle_t *mesh, node_t *n, connection_t *neu, uint64_t id, bool initiator, bool uncertain) {
	if(neu && neu->socket >= 0) {
		path_consider_route_promotion(mesh, NULL, PATH_PROMOTION_META_DIRECT);

		if(initiator) {
			path_log_validation(mesh, n, &neu->address, "probe-succeeded", "direct META");
			path_log_meta(mesh, n, &neu->address, "migrated canonical -> direct");
			devtool_upgrade_probe(mesh, (meshlink_node_t *)n, DEVTOOL_UPGRADE_PROBE_SUCCEEDED);
		}
	}

	logger(mesh, MESHLINK_INFO, "META cutover committed with %s id=%" PRIu64 " role=%s uncertain=%s",
	       n->name, id, initiator ? "initiator" : "responder", uncertain ? "yes" : "no");

	if(uncertain) {
		node_kex_mark_uncertain(mesh, n);
	}

	if(!neu) {
		return true;
	}

	/* Caller owns teardown. Replay must not free neu while receive_request()
	   is still on it. */
	return upgrade_standby_replay(mesh, neu, neu);
}

static bool cutover_promote(meshlink_handle_t *mesh, node_t *n, bool send_ack, bool uncertain, bool close_old) {
	struct meta_cutover *co = n->meta_cutover;
	connection_t *old;
	connection_t *neu;
	list_t *q;
	uint64_t id;
	bool initiator;

	if(!co || !co->new_standby) {
		return false;
	}

	co->state = META_CUTOVER_EMERGENCY_PROMOTE;
	old = co->old_primary;
	neu = co->new_standby;
	id = co->id;
	initiator = neu->status.initiator;
	q = cutover_take_queue(co);

	if(old && old->outgoing && !neu->outgoing) {
		neu->outgoing = old->outgoing;
		neu->outgoing_generation = old->outgoing_generation;
		old->outgoing = NULL;
	}

	if(old && old->edge) {
		edge_del(mesh, old->edge);
		old->edge = NULL;
	}

	timeout_del(&mesh->loop, &neu->drain_ev);
	neu->status.spare = false;
	neu->status.upgrade_probe = false;
	install_node_connection(mesh, n, neu);

	if(send_ack) {
		send_cutover(mesh, neu, REQ_META_CUTOVER_ACK, id);
	}

	timeout_del(&mesh->loop, &co->timer);
	n->meta_cutover = NULL;
	free(co);

	flush_queue(mesh, neu, q);

	/* Drop the old socket before the new edge is announced, so the broadcast
	   cannot land on the socket we are retiring. */
	if(close_old && old && old != neu && old->socket >= 0 && old->status.active) {
		terminate_connection(mesh, old, false);
	}

	if(neu->socket >= 0 && neu->edge) {
		add_connection_edge(mesh, neu);
	}

	return cutover_log_commit(mesh, n, neu, id, initiator, uncertain);
}

static void cutover_send_emergency(meshlink_handle_t *mesh, struct meta_cutover *co) {
	if(!co || co->emergency_sent || !co->id || !co->new_standby) {
		return;
	}

	co->emergency_sent = true;
	send_cutover(mesh, co->new_standby, REQ_META_CUTOVER_EMERGENCY, co->id);
}

static void cutover_enter_emergency_sync(meshlink_handle_t *mesh, node_t *n) {
	struct meta_cutover *co = n->meta_cutover;
	connection_t *old;
	connection_t *neu;

	if(!co || !co->new_standby) {
		return;
	}

	old = co->old_primary;
	neu = co->new_standby;
	co->state = META_CUTOVER_EMERGENCY_SYNC;

	if(old && old->outgoing && !neu->outgoing) {
		neu->outgoing = old->outgoing;
		neu->outgoing_generation = old->outgoing_generation;
		old->outgoing = NULL;
	}

	if(old && old->edge) {
		edge_del(mesh, old->edge);
		old->edge = NULL;
	}

	timeout_del(&mesh->loop, &neu->drain_ev);
	neu->status.spare = false;
	neu->status.upgrade_probe = false;
	install_node_connection(mesh, n, neu);
	co->old_primary = NULL;

	/* Arm and send before the edge broadcast. ADD_EDGE is ordinary META and
	   can overflow the FIFO, which finishes the sync and frees co. */
	cutover_arm(mesh, co);
	cutover_send_emergency(mesh, co);

	if(neu->socket >= 0 && neu->edge) {
		add_connection_edge(mesh, neu);
	}

	if(n->meta_cutover != co) {
		return;
	}

	upgrade_cutover_assert(mesh, n);
}

static bool upgrade_standby_force_sync(meshlink_handle_t *mesh, connection_t *c) {
	node_t *n;
	struct meta_cutover *co;

	if(!mesh || !c || !c->status.spare) {
		return false;
	}

	n = c->node;
	co = n ? n->meta_cutover : NULL;

	if(!n || !co || co->new_standby != c || !may_promote(mesh, n)) {
		return false;
	}

	if(co->state != META_CUTOVER_INIT_WAIT_READY && co->state != META_CUTOVER_INIT_WAIT_ACK
	                && co->state != META_CUTOVER_RESP_WAIT_COMMIT) {
		return false;
	}

	logger(mesh, MESHLINK_WARNING, "META cutover forced sync with %s id=%" PRIu64 " state=%s",
	       n->name, co->id, cutover_state_name(co->state));
	co->emergency_sent = true;

	if(co->id) {
		send_cutover(mesh, c, REQ_META_CUTOVER_EMERGENCY, co->id);
	}

	if(!cutover_promote(mesh, n, false, true, true)) {
		return false;
	}

	return n->connection == c && !c->status.spare;
}

static bool cutover_finish_sync(meshlink_handle_t *mesh, node_t *n, bool uncertain) {
	struct meta_cutover *co = n->meta_cutover;
	connection_t *neu;
	list_t *q;
	uint64_t id;
	bool initiator;

	if(!co || !co->new_standby) {
		return false;
	}

	neu = co->new_standby;
	id = co->id;
	initiator = neu->status.initiator;
	q = cutover_take_queue(co);
	timeout_del(&mesh->loop, &co->timer);
	n->meta_cutover = NULL;
	free(co);

	flush_queue(mesh, neu, q);
	return cutover_log_commit(mesh, n, neu, id, initiator, uncertain);
}

static void upgrade_cutover_on_timeout(meshlink_handle_t *mesh, node_t *n) {
	struct meta_cutover *co;
	connection_t *standby;
	bool old_alive;

	if(!n || !n->meta_cutover) {
		return;
	}

	co = n->meta_cutover;

	if(co->state == META_CUTOVER_EMERGENCY_SYNC) {
		logger(mesh, MESHLINK_INFO, "META cutover emergency sync timeout with %s id=%" PRIu64, n->name, co->id);
		cutover_finish_sync(mesh, n, true);
		return;
	}

	old_alive = co->old_primary && co->old_primary->status.active && n->connection == co->old_primary;
	standby = co->new_standby;

	if(old_alive || !may_promote(mesh, n) || !standby || !standby->status.active) {
		logger(mesh, MESHLINK_INFO, "META cutover timeout with %s id=%" PRIu64 " old=%s",
		       n->name, co->id, old_alive ? "alive" : "dead");
		upgrade_cutover_abort(mesh, n, "timeout", old_alive);

		if(standby && standby->status.spare && standby->socket >= 0) {
			terminate_connection(mesh, standby, false);
		}

		return;
	}

	logger(mesh, MESHLINK_INFO, "META cutover timeout emergency promotion with %s id=%" PRIu64, n->name, co->id);
	cutover_promote(mesh, n, false, true, false);
}

bool upgrade_meta_enqueue_if_frozen(meshlink_handle_t *mesh, connection_t *c, const char *buffer, int length) {
	struct meta_cutover *co;
	meta_pending_record_t *r;

	if(!c || !c->node || !buffer || length < 0) {
		return false;
	}

	co = c->node->meta_cutover;

	if(!co || !co->freeze_ordinary_meta || !co->pending_records) {
		return false;
	}

	if(c != co->old_primary && c != co->new_standby) {
		return false;
	}

	if(co->pending_records->count >= META_CUTOVER_MAX_RECORDS || co->pending_bytes + (size_t)length > META_CUTOVER_MAX_BYTES) {
		logger(mesh, MESHLINK_WARNING, "META cutover queue overflow with %s id=%" PRIu64 " records=%u bytes=%zu",
		       c->node->name, co->id, co->pending_records->count, co->pending_bytes);

		if(co->state == META_CUTOVER_EMERGENCY_SYNC) {
			/* The old primary is already gone. Deliver what we have, then let
			   send_meta write this record behind that flush. */
			cutover_finish_sync(mesh, c->node, true);
		} else {
			upgrade_cutover_abort(mesh, c->node, "queue overflow", true);
		}

		return false;
	}

	r = xzalloc(sizeof(*r));
	r->length = (size_t)length;
	r->data = xmalloc((size_t)length ? (size_t)length : 1);

	if(length) {
		memcpy(r->data, buffer, (size_t)length);
	}

	list_insert_tail(co->pending_records, r);
	co->pending_bytes += (size_t)length;
	return true;
}

bool upgrade_standby_allows(const connection_t *c, int reqno) {
	const struct meta_cutover *co;

	if(!c || !c->status.spare) {
		return true;
	}

	if(reqno == PING || reqno == PONG || reqno == ACK || reqno == REQ_META_CUTOVER_EMERGENCY) {
		return true;
	}

	co = c->node ? c->node->meta_cutover : NULL;

	if(!co || c != co->new_standby) {
		return false;
	}

	if(co->state == META_CUTOVER_RESP_WAIT_COMMIT && reqno == REQ_META_CUTOVER_COMMIT) {
		return true;
	}

	if(co->state == META_CUTOVER_INIT_WAIT_ACK && reqno == REQ_META_CUTOVER_ACK) {
		return true;
	}

	return false;
}

bool upgrade_cutover_begin(meshlink_handle_t *mesh, node_t *n, connection_t *old_primary, connection_t *standby) {
	struct meta_cutover *co;

	if(!mesh || !n || !old_primary || !standby || old_primary == standby || n->connection != old_primary) {
		return false;
	}

	if(n->meta_cutover) {
		logger(mesh, MESHLINK_ERROR, "META cutover already active with %s", n->name);
		return false;
	}

	co = upgrade_cutover_create(n);
	co->state = META_CUTOVER_INIT_WAIT_READY;
	co->id = cutover_new_id(mesh);
	co->old_primary = old_primary;
	co->new_standby = standby;
	co->freeze_ordinary_meta = true;
	timeout_del(&mesh->loop, &standby->drain_ev);
	cutover_arm(mesh, co);
	upgrade_cutover_assert(mesh, n);

	if(!send_cutover(mesh, old_primary, REQ_META_CUTOVER_PREPARE, co->id)) {
		upgrade_cutover_abort(mesh, n, "prepare send failed", false);
		return false;
	}

	return true;
}

static bool cutover_stale(meshlink_handle_t *mesh, connection_t *c, const char *what) {
	logger(mesh, MESHLINK_WARNING, "META cutover stale %s from %s", what, c && c->name ? c->name : "?");
	return true;
}

bool meta_cutover_prepare_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	uint64_t id = 0;
	node_t *n;
	connection_t *standby;
	struct meta_cutover *co;

	if(!parse_cutover_id(request, &id)) {
		return cutover_stale(mesh, c, "PREPARE");
	}

	n = c->node;

	if(!n || c != n->connection) {
		return cutover_stale(mesh, c, "PREPARE socket");
	}

	co = n->meta_cutover;

	if(co && co->id == id && co->state == META_CUTOVER_RESP_WAIT_COMMIT && c == co->old_primary) {
		return true;
	}

	if(co) {
		return cutover_stale(mesh, c, "PREPARE busy");
	}

	standby = find_spare(mesh, n);

	if(!standby) {
		return cutover_stale(mesh, c, "PREPARE without standby");
	}

	co = upgrade_cutover_create(n);
	co->state = META_CUTOVER_RESP_WAIT_COMMIT;
	co->id = id;
	co->old_primary = c;
	co->new_standby = standby;
	co->freeze_ordinary_meta = true;
	timeout_del(&mesh->loop, &standby->drain_ev);
	cutover_arm(mesh, co);
	logger(mesh, MESHLINK_INFO, "META cutover recv PREPARE id=%" PRIu64 " from %s queue=%u", id, n->name, co->pending_records->count);

	if(devtool_hold_cutover_ready) {
		devtool_cutover_ready_held = true;
		logger(mesh, MESHLINK_INFO, "META cutover holding READY id=%" PRIu64 " from %s", id, n->name);
		return true;
	}

	if(!send_cutover(mesh, c, REQ_META_CUTOVER_READY, id)) {
		upgrade_cutover_abort(mesh, n, "ready send failed", true);
	}

	return true;
}

bool upgrade_cutover_release_ready(meshlink_handle_t *mesh, node_t *n) {
	struct meta_cutover *co;

	if(!mesh || !n) {
		return false;
	}

	co = n->meta_cutover;

	if(!co || co->state != META_CUTOVER_RESP_WAIT_COMMIT || !co->old_primary || !co->id) {
		return false;
	}

	if(!send_cutover(mesh, co->old_primary, REQ_META_CUTOVER_READY, co->id)) {
		upgrade_cutover_abort(mesh, n, "ready send failed", true);
		return false;
	}

	return true;
}

void upgrade_cutover_test_abort(meshlink_handle_t *mesh, node_t *n) {
	upgrade_cutover_abort(mesh, n, "test", true);
}

bool meta_cutover_ready_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	uint64_t id = 0;
	node_t *n;
	struct meta_cutover *co;

	if(!parse_cutover_id(request, &id)) {
		return cutover_stale(mesh, c, "READY");
	}

	n = c->node;
	co = n ? n->meta_cutover : NULL;

	if(co && co->id == id && co->state == META_CUTOVER_INIT_WAIT_ACK && c == co->old_primary) {
		return true;
	}

	if(!co || co->state != META_CUTOVER_INIT_WAIT_READY || co->id != id || c != co->old_primary) {
		return cutover_stale(mesh, c, "READY");
	}

	co->state = META_CUTOVER_INIT_WAIT_ACK;
	logger(mesh, MESHLINK_INFO, "META cutover recv READY id=%" PRIu64 " from %s", id, n->name);

	if(!send_cutover(mesh, co->new_standby, REQ_META_CUTOVER_COMMIT, id)) {
		upgrade_cutover_abort(mesh, n, "commit send failed", true);
	}

	return true;
}

bool meta_cutover_commit_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	uint64_t id = 0;
	node_t *n;
	struct meta_cutover *co;

	if(!parse_cutover_id(request, &id)) {
		return cutover_stale(mesh, c, "COMMIT");
	}

	n = c->node;
	co = n ? n->meta_cutover : NULL;

	if(!co || co->id != id || co->state != META_CUTOVER_RESP_WAIT_COMMIT || c != co->new_standby) {
		return cutover_stale(mesh, c, "COMMIT");
	}

	logger(mesh, MESHLINK_INFO, "META cutover recv COMMIT id=%" PRIu64 " from %s", id, n->name);
	return cutover_promote(mesh, n, true, false, true);
}

bool meta_cutover_ack_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	uint64_t id = 0;
	node_t *n;
	struct meta_cutover *co;

	if(!parse_cutover_id(request, &id)) {
		return cutover_stale(mesh, c, "ACK");
	}

	n = c->node;
	co = n ? n->meta_cutover : NULL;

	if(!co || co->id != id || co->state != META_CUTOVER_INIT_WAIT_ACK || c != co->new_standby) {
		return cutover_stale(mesh, c, "ACK");
	}

	logger(mesh, MESHLINK_INFO, "META cutover recv ACK id=%" PRIu64 " from %s", id, n->name);
	return cutover_promote(mesh, n, false, false, true);
}

bool meta_cutover_emergency_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	uint64_t id = 0;
	node_t *n;
	struct meta_cutover *co;

	if(!parse_cutover_id(request, &id)) {
		return cutover_stale(mesh, c, "EMERGENCY");
	}

	n = c->node;
	co = n ? n->meta_cutover : NULL;

	if(co && co->state == META_CUTOVER_EMERGENCY_SYNC && c == co->new_standby) {
		if(co->id && co->id != id) {
			return cutover_stale(mesh, c, "EMERGENCY id");
		}

		if(!co->id) {
			co->id = id;
		}

		logger(mesh, MESHLINK_INFO, "META cutover recv EMERGENCY id=%" PRIu64 " from %s", id, n->name);
		cutover_send_emergency(mesh, co);
		return cutover_finish_sync(mesh, n, true);
	}

	if(co && c == co->new_standby && co->id == id
	                && (co->state == META_CUTOVER_INIT_WAIT_READY || co->state == META_CUTOVER_INIT_WAIT_ACK
	                    || co->state == META_CUTOVER_RESP_WAIT_COMMIT)) {
		logger(mesh, MESHLINK_INFO, "META cutover recv EMERGENCY id=%" PRIu64 " from %s", id, n->name);
		co->emergency_sent = true;
		send_cutover(mesh, co->new_standby, REQ_META_CUTOVER_EMERGENCY, id);
		return cutover_promote(mesh, n, false, true, true);
	}

	/* PREPARE never landed. This standby is the only authenticated direct socket. */
	if(!co && c->status.spare && n && n->connection != c && may_promote(mesh, n)) {
		logger(mesh, MESHLINK_INFO, "META cutover recv EMERGENCY id=%" PRIu64 " from %s before PREPARE", id, n->name);
		co = upgrade_cutover_create(n);
		co->id = id;
		co->old_primary = n->connection;
		co->new_standby = c;
		co->freeze_ordinary_meta = true;
		co->emergency_sent = true;
		timeout_del(&mesh->loop, &c->drain_ev);
		send_cutover(mesh, c, REQ_META_CUTOVER_EMERGENCY, id);
		return cutover_promote(mesh, n, false, true, true);
	}

	return cutover_stale(mesh, c, "EMERGENCY");
}

void upgrade_node_cleanup(meshlink_handle_t *mesh, node_t *n) {
	if(!n || !n->meta_cutover) {
		return;
	}

	upgrade_cutover_abort(mesh, n, "node deleted", false);
}

void upgrade_cutover_snapshot(const node_t *n, upgrade_cutover_snapshot_t *out) {
	const struct meta_cutover *co;

	if(!out) {
		return;
	}

	memset(out, 0, sizeof(*out));

	if(!n || !n->meta_cutover) {
		return;
	}

	co = n->meta_cutover;
	out->state = (int)co->state;
	out->id = co->id;
	out->timer_armed = co->timer.cb != NULL;
	out->pending_records = co->pending_records ? co->pending_records->count : 0;
	out->pending_bytes = co->pending_bytes;
	out->has_old = co->old_primary != NULL;
	out->has_standby = co->new_standby != NULL;

	if(co->old_primary) {
		memcpy(&out->old_address, &co->old_primary->address, sizeof(out->old_address) < sizeof(co->old_primary->address) ? sizeof(out->old_address) : sizeof(co->old_primary->address));
	}

	if(co->new_standby) {
		memcpy(&out->standby_address, &co->new_standby->address, sizeof(out->standby_address) < sizeof(co->new_standby->address) ? sizeof(out->standby_address) : sizeof(co->new_standby->address));
	}
}

static void cover_untrack(meshlink_handle_t *mesh, connection_t *c, list_action_t del) {
	if(!mesh || !mesh->connections || !c) {
		return;
	}

	mesh->connections->delete = NULL;
	list_delete(mesh->connections, c);
	mesh->connections->delete = del;
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
		free_connection(old);
		free_connection(neu);
		return false;
	}

	co = n.meta_cutover;

	if(!co || co->state != META_CUTOVER_INIT_WAIT_READY || !co->freeze_ordinary_meta) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	if(!upgrade_meta_enqueue_if_frozen(mesh, old, "8 1\n", 4)) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	if(co->pending_records->count != 1) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	snprintf(request, sizeof(request), "%d 1\n", REQ_META_CUTOVER_READY);

	if(!meta_cutover_ready_h(mesh, old, request) || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_READY) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_READY, co->id);

	if(!meta_cutover_ready_h(mesh, old, request) || !n.meta_cutover || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_ACK) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	if(!meta_cutover_ready_h(mesh, old, request) || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_ACK) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_ACK, co->id);

	if(!meta_cutover_ack_h(mesh, old, request)) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	if(!n.meta_cutover || n.connection != old) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	if(!meta_cutover_ack_h(mesh, neu, request)) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	if(n.meta_cutover || n.connection != neu || neu->status.spare) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	/* Responder path: standby failure rolls back; old death emergency-promotes. */
	n.connection = old;
	neu->status.spare = true;
	neu->status.active = true;
	old->status.active = true;

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		free_connection(old);
		free_connection(neu);
		return false;
	}

	upgrade_cutover_abort(mesh, &n, "cover standby", true);

	if(n.meta_cutover || n.connection != old) {
		free_connection(old);
		free_connection(neu);
		return false;
	}

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		free_connection(old);
		free_connection(neu);
		return false;
	}

	old->status.active = false;
	upgrade_cutover_on_timeout(mesh, &n);

	if(n.meta_cutover || n.connection != neu) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	/* Overflow aborts back to the live primary and does not switch. */
	n.connection = old;
	old->status.active = true;
	neu->status.spare = true;
	neu->status.active = true;

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		free_connection(old);
		free_connection(neu);
		return false;
	}

	for(i = 0; i < META_CUTOVER_MAX_RECORDS + 2; i++) {
		char rec[32];
		int len = snprintf(rec, sizeof(rec), "8 %d\n", i);
		upgrade_meta_enqueue_if_frozen(mesh, old, rec, len);
	}

	if(n.meta_cutover || n.connection != old) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	/* Timeout with the old primary alive stays canonical. */
	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		free_connection(old);
		free_connection(neu);
		return false;
	}

	upgrade_cutover_on_timeout(mesh, &n);

	if(n.meta_cutover || n.connection != old || !neu->status.spare) {
		upgrade_node_cleanup(mesh, &n);

		if(neu->status.spare) {
			neu->status.spare = false;
		}

		free_connection(old);
		free_connection(neu);
		return false;
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
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		if(!upgrade_meta_enqueue_if_frozen(mesh, old, queued, (int)strlen(queued))
		                || n.meta_cutover->pending_records->count != 1) {
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_COMMIT, n.meta_cutover->id);

		if(!meta_cutover_commit_h(mesh, neu, request) || n.meta_cutover || n.connection != neu || neu->status.spare) {
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		if(!meta_cutover_commit_h(mesh, neu, request) || n.connection != neu) {
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		n.connection = old;
		old->status.active = true;
		neu->status.spare = true;
		neu->status.active = true;
		neu->status.initiator = true;
		n.key_delivery_uncertain = false;

		if(!upgrade_cutover_begin(mesh, &n, old, neu)
		                || !upgrade_meta_enqueue_if_frozen(mesh, old, queued, (int)strlen(queued))) {
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		pending = n.meta_cutover->pending_records->count;
		upgrade_connection_closing(mesh, old);

		if(!n.meta_cutover || n.meta_cutover->state != META_CUTOVER_EMERGENCY_SYNC
		                || n.connection != neu || neu->status.spare
		                || !n.meta_cutover->pending_records
		                || n.meta_cutover->pending_records->count != pending) {
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_EMERGENCY, n.meta_cutover->id);

		if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || n.connection != neu
		                || !n.key_delivery_uncertain) {
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || n.connection != neu) {
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
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
			upgrade_standby_drop_held(neu);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		upgrade_connection_closing(mesh, old);

		if(!n.meta_cutover || n.meta_cutover->state != META_CUTOVER_EMERGENCY_SYNC
		                || n.connection != neu || !neu->standby_held || neu->standby_held->count != 1) {
			upgrade_node_cleanup(mesh, &n);
			upgrade_standby_drop_held(neu);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		snprintf(request, sizeof(request), "%d 99\n", REQ_META_CUTOVER_EMERGENCY);

		if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || neu->standby_held
		                || !n.key_delivery_uncertain) {
			upgrade_node_cleanup(mesh, &n);
			upgrade_standby_drop_held(neu);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
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
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		n.connection = old;
		old->status.active = true;
		neu->status.spare = true;
		neu->status.active = true;
		neu->status.initiator = true;

		if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
		}

		mesh->retiring_outgoing = true;
		upgrade_connection_closing(mesh, old);
		mesh->retiring_outgoing = false;

		if(n.meta_cutover || n.connection != old || !neu->status.spare) {
			upgrade_node_cleanup(mesh, &n);
			cover_untrack(mesh, neu, del);
			free_connection(old);
			free_connection(neu);
			return false;
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
			free_connection(old);
			free_connection(neu);
			return false;
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
		free_connection(old);
		free_connection(neu);
		return false;
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_READY, n.meta_cutover->id);

	if(!meta_cutover_ready_h(mesh, old, request) || !n.meta_cutover
	                || n.meta_cutover->state != META_CUTOVER_INIT_WAIT_ACK) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	snprintf(request, sizeof(request), "%d %" PRIu64 "\n", REQ_META_CUTOVER_EMERGENCY, n.meta_cutover->id);

	if(!meta_cutover_emergency_h(mesh, neu, request) || n.meta_cutover || n.connection != neu
	                || neu->status.spare || !n.key_delivery_uncertain) {
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	/* A full standby hold with no barrier fails the socket instead of accepting a drop. */
	n.connection = old;
	neu->status.spare = true;
	neu->status.active = true;
	upgrade_standby_drop_held(neu);

	for(i = 0; i < META_CUTOVER_MAX_RECORDS; i++) {
		if(upgrade_standby_hold(mesh, neu, "5 1 held\n") != 1) {
			upgrade_standby_drop_held(neu);
			free_connection(old);
			free_connection(neu);
			return false;
		}
	}

	if(upgrade_standby_hold(mesh, neu, "5 1 overflow\n") != -1 || receive_request(mesh, neu, "5 1 overflow\n")
	                || n.connection != old || !neu->status.spare) {
		upgrade_standby_drop_held(neu);
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	upgrade_standby_drop_held(neu);

	/* The same overflow during a live barrier forces sync and then runs the record. */
	n.key_delivery_uncertain = false;

	if(!upgrade_cutover_begin(mesh, &n, old, neu)) {
		free_connection(old);
		free_connection(neu);
		return false;
	}

	for(i = 0; i < META_CUTOVER_MAX_RECORDS; i++) {
		if(upgrade_standby_hold(mesh, neu, "5 1 held\n") != 1) {
			upgrade_standby_drop_held(neu);
			upgrade_node_cleanup(mesh, &n);
			free_connection(old);
			free_connection(neu);
			return false;
		}
	}

	if(!receive_request(mesh, neu, "5 1 overflow\n") || n.meta_cutover || n.connection != neu
	                || neu->status.spare || neu->standby_held || !n.key_delivery_uncertain) {
		upgrade_standby_drop_held(neu);
		upgrade_node_cleanup(mesh, &n);
		free_connection(old);
		free_connection(neu);
		return false;
	}

	/* A handler failure during replay is not success. socket < 0 is not terminated here. */
	neu->standby_held = list_alloc(standby_held_free);
	list_insert_tail(neu->standby_held, xstrdup("6\n"));

	if(upgrade_standby_replay(mesh, neu, neu) || neu->standby_held || !neu->meta_teardown) {
		upgrade_standby_drop_held(neu);
		free_connection(old);
		free_connection(neu);
		return false;
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

#define COVER_BAIL() \
	do { \
		cover_order_on = false; \
		cutover_fail_control_send = false; \
		devtool_hold_cutover_ready = false; \
		upgrade_standby_drop_held(neu); \
		upgrade_node_cleanup(mesh, &n); \
		if(tracked) { \
			cover_untrack(mesh, neu, del); \
		} \
		timeout_del(&mesh->loop, &old->drain_ev); \
		timeout_del(&mesh->loop, &neu->drain_ev); \
		free_connection(old); \
		free_connection(neu); \
		return false; \
	} while(0)

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
		free_connection(old);
		free_connection(neu);
		return false;
	}

	free_connection(old);
	free_connection(neu);
	return true;
}

void upgrade_probe_sweep(meshlink_handle_t *mesh) {
	for splay_each(node_t, n, mesh->nodes) {
		try_upgrade_probe(mesh, n);
	}
}
