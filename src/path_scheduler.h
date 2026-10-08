#ifndef MESHLINK_PATH_SCHEDULER_H
#define MESHLINK_PATH_SCHEDULER_H

/*
    path_scheduler.h -- mesh-wide probe admission
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct meshlink_handle;
struct node_t;

/* Fleet probe budget. active_transactions counts live validation
   state machines (promotion, suspect, PMTU discovery), not packets.
   PATH_SCHED_PARKED_PACKETS_PER_MIN is the parked-probe cap: liveness and
   PMTU-increase only.    Admitted validation (promotion, suspect, punch, PMTU discovery)
   shares PATH_SCHED_PACKETS_PER_SEC and skips the parked minute bucket so a
   search can finish (~18 PMTU probes) and a second admitted search does not
   wait 60s. Worst-case optional validation traffic is therefore
   4 pkt/s × 60s = 240 packets/minute while both slots stay admitted. Parked
   probes add at most 20/min when second tokens remain. Required backbone
   traffic uses a separate 1 pkt/s bucket (60/min). */
#define PATH_SCHED_MAX_TRANSACTIONS            2
#define PATH_SCHED_PACKETS_PER_SEC             4
#define PATH_SCHED_PARKED_PACKETS_PER_MIN     20
#define PATH_SCHED_PACKETS_PER_MIN PATH_SCHED_PARKED_PACKETS_PER_MIN
#define PATH_SCHED_BACKBONE_RESERVE_PPS        1
#define PATH_SCHED_KEEPALIVE_PPS              10
#define PATH_PROMOTION_MAX_REQUESTS         8

typedef enum path_transaction_priority_t {
	PATH_TX_BACKBONE_REQUIRED = 0,
	PATH_TX_ACTIVE_ROUTE_RECOVERY,
	PATH_TX_CHANNEL_PROMOTION,
	PATH_TX_PUNCH,
	PATH_TX_LIVENESS,
	PATH_TX_PLPMTU_PROBE,
	PATH_TX_KEEPALIVE,
	/* Same rank as active-route recovery, separate queue so a rebind probe
	   does not cancel a suspect probe (or the other way around). */
	PATH_TX_REBIND,
	PATH_TX_RELAY_HOP
} path_transaction_priority_t;

typedef enum path_transaction_type_t {
	PATH_TXN_PROMOTION = 0,
	PATH_TXN_SUSPECT,
	PATH_TXN_PLPMTU_SEARCH,
	PATH_TXN_META_UPGRADE,
	PATH_TXN_PUNCH,
	PATH_TXN_REBIND,
	PATH_TXN_RELAY_HOP
} path_transaction_type_t;

typedef enum path_sched_admit_t {
	PATH_SCHED_DENIED = 0,
	PATH_SCHED_QUEUED,
	PATH_SCHED_SENT
} path_sched_admit_t;

typedef struct path_sched_txn path_sched_txn_t;
typedef struct path_probe_request_t path_probe_request_t;
typedef void (*path_probe_send_fn)(struct meshlink_handle *mesh, const path_probe_request_t *req);
typedef void (*path_transaction_preempt_fn)(struct meshlink_handle *mesh, struct node_t *node, path_transaction_type_t type);

struct path_probe_request_t {
	struct node_t *node;
	uint16_t length;
	bool broadcast;
	bool skip_minute;                       /* admitted validation: 4/s only, not parked 20/min */
	path_transaction_priority_t priority;
	path_probe_send_fn send;
	uint8_t probe_kind;
	uint8_t probe_purpose;
	uint64_t probe_nonce;
};

typedef struct path_probe_budget_t {
	unsigned active_transactions;           /* live begin() slots, not queued packets */
	unsigned second_tokens;                 /* optional packet bucket */
	unsigned minute_tokens;                 /* parked liveness / PMTU-increase */
	unsigned backbone_second_tokens;        /* required-path packet bucket */
	unsigned keepalive_tokens;              /* idle UDP mapping refresh */
	uint64_t optional_packets_sent;         /* non-backbone emits; observe only */
	struct timespec second_refill_at;
	struct timespec minute_refill_at;
	struct timespec backbone_refill_at;
	struct timespec keepalive_refill_at;
} path_probe_budget_t;

/* Mesh-wide probe admission. Due-time stays on per-node timers; this is the gate.
   Validation state machines hold a slot from begin() until end(); keepalive
   packets only consume packet tokens. Promotion, suspect, punch, and rebind may preempt the
   globally lowest-priority live slot, including other nodes. Preemption drops
   that victim's queued packets and runs the owner callback so the state
   machine cannot keep emitting or committing outside the cap. */
void path_scheduler_init(struct meshlink_handle *mesh);
void path_scheduler_stop(struct meshlink_handle *mesh);
path_sched_txn_t *path_scheduler_begin_transaction(struct meshlink_handle *mesh, struct node_t *node, path_transaction_type_t type, path_transaction_priority_t priority, path_transaction_preempt_fn preempt);
bool path_scheduler_has_transaction(struct meshlink_handle *mesh, const struct node_t *node, path_transaction_type_t type);
void path_scheduler_end_transaction(struct meshlink_handle *mesh, path_sched_txn_t *txn);
void path_scheduler_end_type(struct meshlink_handle *mesh, struct node_t *node, path_transaction_type_t type);
path_sched_admit_t path_scheduler_emit_packet(struct meshlink_handle *mesh, path_sched_txn_t *txn, const path_probe_request_t *pkt);
void path_scheduler_cancel_packets(struct meshlink_handle *mesh, struct node_t *node, path_transaction_priority_t priority);
void path_scheduler_cancel(struct meshlink_handle *mesh, struct node_t *node, path_transaction_priority_t priority);
void path_scheduler_cancel_node(struct meshlink_handle *mesh, struct node_t *node);
void path_scheduler_drain(struct meshlink_handle *mesh);
void path_scheduler_refill(struct meshlink_handle *mesh);
void path_scheduler_set_budget(struct meshlink_handle *mesh, unsigned second, unsigned minute, unsigned txns);

/* Owner hook passed to begin(). Probing promotion discards; a validated
   candidate stays parked so tick can reacquire and commit. PMTU pauses. */
void path_transaction_preempt(struct meshlink_handle *mesh, struct node_t *node, path_transaction_type_t type);

#endif
