/*
    path_scheduler.c -- mesh-wide probe admission (finding 13)
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "event.h"
#include "list.h"
#include "meshlink_internal.h"
#include "node.h"
#include "path_policy.h"
#include "xalloc.h"

#include <string.h>

struct path_sched_txn {
	node_t *node;
	path_transaction_type_t type;
	path_transaction_priority_t priority;
	path_transaction_preempt_fn preempt;
};

typedef struct path_sched_item {
	path_probe_request_t req;
} path_sched_item_t;

static void path_scheduler_timer(event_loop_t *loop, void *data);
static void path_scheduler_arm(meshlink_handle_t *mesh, const struct timespec *delay);

static unsigned path_scheduler_max_txns(const meshlink_handle_t *mesh) {
	if(mesh->probe_max_transactions) {
		return mesh->probe_max_transactions;
	}

	return PATH_SCHED_MAX_TRANSACTIONS;
}

static bool path_scheduler_timespec_ge(const struct timespec *a, const struct timespec *b) {
	if(a->tv_sec != b->tv_sec) {
		return a->tv_sec > b->tv_sec;
	}

	return a->tv_nsec >= b->tv_nsec;
}

static void path_scheduler_sync_active(meshlink_handle_t *mesh) {
	mesh->probe_budget.active_transactions = mesh->probe_txns ? mesh->probe_txns->count : 0;
}

static bool path_scheduler_promotion_capped(const path_probe_request_t *req) {
	const node_t *node;

	if(!req || req->priority != PATH_TX_CHANNEL_PROMOTION || !req->node) {
		return false;
	}

	node = req->node;

	if(!node->promotion_candidate.active || !node->promotion_candidate.nonce) {
		return false;
	}

	return node->promotion_candidate.requests_sent >= PATH_PROMOTION_MAX_REQUESTS;
}

static void path_scheduler_note_promotion_emit(const path_probe_request_t *req) {
	node_t *node;

	if(!req || req->priority != PATH_TX_CHANNEL_PROMOTION || !req->node) {
		return;
	}

	node = req->node;

	if(!node->promotion_candidate.active || !node->promotion_candidate.nonce) {
		return;
	}

	if(node->promotion_candidate.requests_sent < 255) {
		node->promotion_candidate.requests_sent++;
	}
}

static bool path_scheduler_keepalive_priority(path_transaction_priority_t priority) {
	return priority == PATH_TX_BACKBONE_REQUIRED
	       || priority == PATH_TX_ACTIVE_ROUTE_RECOVERY
	       || priority == PATH_TX_CHANNEL_PROMOTION;
}

static void path_scheduler_drop_priority(meshlink_handle_t *mesh, node_t *node, path_transaction_priority_t priority) {
	if(!mesh || !node || !mesh->probe_queue) {
		return;
	}

	for list_each(path_sched_item_t, item, mesh->probe_queue) {
		if(item->req.node == node && item->req.priority == priority) {
			list_delete(mesh->probe_queue, item);
		}
	}
}

void path_scheduler_cancel_packets(meshlink_handle_t *mesh, node_t *node, path_transaction_priority_t priority) {
	path_scheduler_drop_priority(mesh, node, priority);
}

static void path_scheduler_evict(meshlink_handle_t *mesh, path_sched_txn_t *victim) {
	node_t *node;
	path_transaction_type_t type;
	path_transaction_priority_t priority;
	path_transaction_preempt_fn preempt;

	node = victim->node;
	type = victim->type;
	priority = victim->priority;
	preempt = victim->preempt;
	path_scheduler_cancel_packets(mesh, node, priority);
	list_delete(mesh->probe_txns, victim);
	path_scheduler_sync_active(mesh);

	if(preempt) {
		preempt(mesh, node, type);
	}
}

static path_sched_item_t *path_scheduler_find_packet(meshlink_handle_t *mesh, node_t *node, path_transaction_priority_t priority) {
	if(!mesh->probe_queue) {
		return NULL;
	}

	for list_each(path_sched_item_t, item, mesh->probe_queue) {
		if(item->req.node == node && item->req.priority == priority) {
			return item;
		}
	}

	return NULL;
}

static path_sched_txn_t *path_scheduler_find_txn(meshlink_handle_t *mesh, const node_t *node, path_transaction_type_t type) {
	if(!mesh || !mesh->probe_txns || !node) {
		return NULL;
	}

	for list_each(path_sched_txn_t, txn, mesh->probe_txns) {
		if(txn->node == node && txn->type == type) {
			return txn;
		}
	}

	return NULL;
}

/* Admitted validation shares 4 pkt/s and skips the parked 20/min bucket. */
static bool path_scheduler_skip_minute(const path_sched_txn_t *txn) {
	return txn && (txn->type == PATH_TXN_PMTU_DISCOVERY
	               || txn->type == PATH_TXN_PROMOTION
	               || txn->type == PATH_TXN_SUSPECT);
}

static path_sched_txn_t *path_scheduler_preempt_victim(meshlink_handle_t *mesh, path_transaction_priority_t incoming) {
	path_sched_txn_t *victim = NULL;

	for list_each(path_sched_txn_t, cur, mesh->probe_txns) {
		if(cur->priority <= incoming) {
			continue;
		}

		if(!victim || cur->priority > victim->priority) {
			victim = cur;
		}
	}

	return victim;
}

static bool path_scheduler_can_send(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	if(!req) {
		return false;
	}

	if(req->priority == PATH_TX_BACKBONE_REQUIRED) {
		return mesh->probe_budget.backbone_second_tokens > 0;
	}

	if(!mesh->probe_budget.second_tokens) {
		return false;
	}

	return req->skip_minute || mesh->probe_budget.minute_tokens > 0;
}

static void path_scheduler_consume(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	if(!req) {
		return;
	}

	if(req->priority == PATH_TX_BACKBONE_REQUIRED) {
		if(mesh->probe_budget.backbone_second_tokens) {
			mesh->probe_budget.backbone_second_tokens--;
		}

		return;
	}

	if(mesh->probe_budget.second_tokens) {
		mesh->probe_budget.second_tokens--;
		mesh->probe_budget.optional_packets_sent++;
	}

	if(!req->skip_minute && mesh->probe_budget.minute_tokens) {
		mesh->probe_budget.minute_tokens--;
	}
}

static int64_t path_scheduler_ms_until(const meshlink_handle_t *mesh, const struct timespec *when) {
	int64_t ms;

	if(!when->tv_sec && !when->tv_nsec) {
		return 1;
	}

	ms = (int64_t)(when->tv_sec - mesh->loop.now.tv_sec) * 1000
	     + (when->tv_nsec - mesh->loop.now.tv_nsec) / 1000000;

	if(ms < 1) {
		return 1;
	}

	return ms;
}

static void path_scheduler_next_delay(meshlink_handle_t *mesh, struct timespec *delay) {
	bool need_second = false;
	bool need_minute = false;
	bool need_backbone = false;
	int64_t wait_ms = 0;

	if(mesh->probe_queue) {
		for list_each(path_sched_item_t, item, mesh->probe_queue) {
			if(item->req.priority == PATH_TX_BACKBONE_REQUIRED) {
				need_backbone = true;
			} else if(item->req.skip_minute) {
				need_second = true;
			} else {
				need_second = true;
				need_minute = true;
			}
		}
	}

	if(need_second) {
		wait_ms = path_scheduler_ms_until(mesh, &mesh->probe_budget.second_refill_at);
	}

	if(need_minute) {
		int64_t min_ms = path_scheduler_ms_until(mesh, &mesh->probe_budget.minute_refill_at);

		if(!wait_ms || min_ms < wait_ms) {
			wait_ms = min_ms;
		}
	}

	if(need_backbone) {
		int64_t bb_ms = path_scheduler_ms_until(mesh, &mesh->probe_budget.backbone_refill_at);

		if(!wait_ms || bb_ms < wait_ms) {
			wait_ms = bb_ms;
		}
	}

	if(wait_ms < 1) {
		wait_ms = 1;
	}

	delay->tv_sec = wait_ms / 1000;
	delay->tv_nsec = (wait_ms % 1000) * 1000000L;
}

static void path_scheduler_arm(meshlink_handle_t *mesh, const struct timespec *delay) {
	struct timespec when = delay ? *delay : (struct timespec) {
		1, 0
	};

	if(!mesh->probe_scheduler.cb) {
		timeout_add(&mesh->loop, &mesh->probe_scheduler, path_scheduler_timer, mesh, &when);
	} else {
		timeout_set(&mesh->loop, &mesh->probe_scheduler, &when);
	}

	if(mesh->threadstarted && mesh->loop.pipefd[1] != -1 && !pthread_equal(mesh->thread, pthread_self())) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

static void path_scheduler_dispatch(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	path_scheduler_note_promotion_emit(req);
	path_scheduler_consume(mesh, req);

	if(req->send) {
		req->send(mesh, req);
	}
}

static path_sched_admit_t path_scheduler_enqueue(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	path_sched_item_t *item;
	struct timespec delay;

	if(path_scheduler_keepalive_priority(req->priority)) {
		item = path_scheduler_find_packet(mesh, req->node, req->priority);

		if(item) {
			item->req = *req;
			path_scheduler_next_delay(mesh, &delay);
			path_scheduler_arm(mesh, &delay);
			return PATH_SCHED_QUEUED;
		}
	}

	if(req->priority != PATH_TX_BACKBONE_REQUIRED
	                && mesh->probe_queue && mesh->probe_queue->count >= PATH_SCHED_PARKED_PACKETS_PER_MIN) {
		return PATH_SCHED_DENIED;
	}

	item = xzalloc(sizeof *item);
	item->req = *req;
	list_insert_tail(mesh->probe_queue, item);
	path_scheduler_next_delay(mesh, &delay);
	path_scheduler_arm(mesh, &delay);
	return PATH_SCHED_QUEUED;
}

static path_sched_item_t *path_scheduler_best_runnable(meshlink_handle_t *mesh) {
	path_sched_item_t *best = NULL;

	if(!mesh->probe_queue) {
		return NULL;
	}

	for list_each(path_sched_item_t, item, mesh->probe_queue) {
		if(!path_scheduler_can_send(mesh, &item->req)) {
			continue;
		}

		if(path_scheduler_promotion_capped(&item->req)) {
			list_delete(mesh->probe_queue, item);
			continue;
		}

		if(!best || item->req.priority < best->req.priority) {
			best = item;
		}
	}

	return best;
}

void path_scheduler_refill(meshlink_handle_t *mesh) {
	path_probe_budget_t *b;

	if(!mesh) {
		return;
	}

	b = &mesh->probe_budget;

	if(!b->second_refill_at.tv_sec || path_scheduler_timespec_ge(&mesh->loop.now, &b->second_refill_at)) {
		b->second_tokens = PATH_SCHED_PACKETS_PER_SEC;
		b->second_refill_at = mesh->loop.now;
		b->second_refill_at.tv_sec += 1;
	}

	if(!b->minute_refill_at.tv_sec || path_scheduler_timespec_ge(&mesh->loop.now, &b->minute_refill_at)) {
		b->minute_tokens = PATH_SCHED_PARKED_PACKETS_PER_MIN;
		b->minute_refill_at = mesh->loop.now;
		b->minute_refill_at.tv_sec += 60;
	}

	if(!b->backbone_refill_at.tv_sec || path_scheduler_timespec_ge(&mesh->loop.now, &b->backbone_refill_at)) {
		b->backbone_second_tokens = PATH_SCHED_BACKBONE_RESERVE_PPS;
		b->backbone_refill_at = mesh->loop.now;
		b->backbone_refill_at.tv_sec += 1;
	}
}

void path_scheduler_drain(meshlink_handle_t *mesh) {
	path_sched_item_t *item;

	if(!mesh || !mesh->probe_queue) {
		return;
	}

	path_scheduler_refill(mesh);

	while((item = path_scheduler_best_runnable(mesh))) {
		path_probe_request_t req = item->req;
		list_delete(mesh->probe_queue, item);
		path_scheduler_dispatch(mesh, &req);
	}

	path_scheduler_sync_active(mesh);

	if(mesh->probe_queue && mesh->probe_queue->count) {
		struct timespec delay;
		path_scheduler_next_delay(mesh, &delay);
		path_scheduler_arm(mesh, &delay);
	}
}

static void path_scheduler_timer(event_loop_t *loop, void *data) {
	(void)loop;
	path_scheduler_drain(data);
}

void path_scheduler_init(meshlink_handle_t *mesh) {
	if(!mesh) {
		return;
	}

	if(!mesh->probe_queue) {
		mesh->probe_queue = list_alloc((list_action_t)free);
	}

	if(!mesh->probe_txns) {
		mesh->probe_txns = list_alloc((list_action_t)free);
	}

	path_scheduler_refill(mesh);
	path_scheduler_sync_active(mesh);
}

void path_scheduler_stop(meshlink_handle_t *mesh) {
	if(!mesh) {
		return;
	}

	timeout_del(&mesh->loop, &mesh->probe_scheduler);

	if(mesh->probe_queue) {
		list_delete_list(mesh->probe_queue);
		mesh->probe_queue = NULL;
	}

	if(mesh->probe_txns) {
		list_delete_list(mesh->probe_txns);
		mesh->probe_txns = NULL;
	}

	memset(&mesh->probe_budget, 0, sizeof mesh->probe_budget);
	mesh->probe_max_transactions = 0;
}

path_sched_txn_t *path_scheduler_begin_transaction(meshlink_handle_t *mesh, node_t *node, path_transaction_type_t type, path_transaction_priority_t priority, path_transaction_preempt_fn preempt) {
	path_sched_txn_t *txn;

	if(!mesh || !node) {
		return NULL;
	}

	path_scheduler_init(mesh);
	txn = path_scheduler_find_txn(mesh, node, type);

	if(txn) {
		if(preempt) {
			txn->preempt = preempt;
		}

		return txn;
	}

	if(mesh->probe_txns->count >= path_scheduler_max_txns(mesh)) {
		path_sched_txn_t *victim = NULL;

		/* Promotion and suspect last for seconds. At cap they steal the
		   globally lowest-priority live slot so two other-node PMTU or
		   promotion searches cannot block active-route recovery. Equal
		   priority stays FIFO: the first occupant is not displaced.
		   Eviction drops queued packets and notifies the owner so the
		   victim state machine cannot run outside the cap. */
		if(type == PATH_TXN_PROMOTION || type == PATH_TXN_SUSPECT) {
			victim = path_scheduler_preempt_victim(mesh, priority);
		}

		if(!victim) {
			return NULL;
		}

		path_scheduler_evict(mesh, victim);
	}

	txn = xzalloc(sizeof *txn);
	txn->node = node;
	txn->type = type;
	txn->priority = priority;
	txn->preempt = preempt;
	list_insert_tail(mesh->probe_txns, txn);
	path_scheduler_sync_active(mesh);
	return txn;
}

bool path_scheduler_has_transaction(meshlink_handle_t *mesh, const node_t *node, path_transaction_type_t type) {
	return path_scheduler_find_txn(mesh, node, type) != NULL;
}

void path_scheduler_end_transaction(meshlink_handle_t *mesh, path_sched_txn_t *txn) {
	if(!mesh || !txn || !mesh->probe_txns) {
		return;
	}

	for list_each(path_sched_txn_t, cur, mesh->probe_txns) {
		if(cur == txn) {
			list_delete(mesh->probe_txns, cur);
			path_scheduler_sync_active(mesh);
			return;
		}
	}
}

void path_scheduler_end_type(meshlink_handle_t *mesh, node_t *node, path_transaction_type_t type) {
	path_scheduler_end_transaction(mesh, path_scheduler_find_txn(mesh, node, type));
}

static path_transaction_type_t path_scheduler_type_for_priority(path_transaction_priority_t priority, bool *have_type) {
	*have_type = true;

	switch(priority) {
	case PATH_TX_ACTIVE_ROUTE_RECOVERY:
		return PATH_TXN_SUSPECT;

	case PATH_TX_CHANNEL_PROMOTION:
		return PATH_TXN_PROMOTION;

	case PATH_TX_LIVENESS:
	case PATH_TX_PMTU_INCREASE:
		return PATH_TXN_PMTU_DISCOVERY;

	default:
		*have_type = false;
		return PATH_TXN_PROMOTION;
	}
}

void path_scheduler_cancel(meshlink_handle_t *mesh, node_t *node, path_transaction_priority_t priority) {
	bool have_type;
	path_transaction_type_t type;

	if(!mesh || !node) {
		return;
	}

	path_scheduler_cancel_packets(mesh, node, priority);

	type = path_scheduler_type_for_priority(priority, &have_type);

	if(have_type) {
		path_scheduler_end_type(mesh, node, type);
	}

	path_scheduler_sync_active(mesh);
}

void path_scheduler_cancel_node(meshlink_handle_t *mesh, node_t *node) {
	if(!mesh || !node) {
		return;
	}

	if(mesh->probe_queue) {
		for list_each(path_sched_item_t, item, mesh->probe_queue) {
			if(item->req.node == node) {
				list_delete(mesh->probe_queue, item);
			}
		}
	}

	if(mesh->probe_txns) {
		for list_each(path_sched_txn_t, txn, mesh->probe_txns) {
			if(txn->node == node) {
				list_delete(mesh->probe_txns, txn);
			}
		}
	}

	path_scheduler_sync_active(mesh);
}

path_sched_admit_t path_scheduler_emit_packet(meshlink_handle_t *mesh, path_sched_txn_t *txn, const path_probe_request_t *pkt) {
	path_probe_request_t req;

	if(!mesh || !pkt || !pkt->send) {
		return PATH_SCHED_DENIED;
	}

	req = *pkt;
	req.skip_minute = path_scheduler_skip_minute(txn);
	path_scheduler_init(mesh);

	if(path_scheduler_promotion_capped(&req)) {
		return PATH_SCHED_DENIED;
	}

	path_scheduler_refill(mesh);

	if(path_scheduler_can_send(mesh, &req)) {
		path_scheduler_dispatch(mesh, &req);
		path_scheduler_drain(mesh);
		return PATH_SCHED_SENT;
	}

	return path_scheduler_enqueue(mesh, &req);
}

void path_scheduler_set_budget(meshlink_handle_t *mesh, unsigned second, unsigned minute, unsigned txns) {
	if(!mesh) {
		return;
	}

	path_scheduler_init(mesh);
	mesh->probe_budget.second_tokens = second;
	mesh->probe_budget.minute_tokens = minute;
	mesh->probe_budget.second_refill_at = mesh->loop.now;
	mesh->probe_budget.second_refill_at.tv_sec += 3600;
	mesh->probe_budget.minute_refill_at = mesh->probe_budget.second_refill_at;
	mesh->probe_max_transactions = txns;
	path_scheduler_sync_active(mesh);
}
