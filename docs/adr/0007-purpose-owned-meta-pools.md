# ADR 0007: Purpose-owned META connection pools

## Status

Accepted

## Context

Generic `min_connects`/`max_connects` autoconnect treated META TCP as a
device-class quota. A camera could fill every slot with LAN peers before
the unique backbone was reachable, and a backbone-class node initiated
outgoing META even though production topology is a star: the unique
backbone listens, every other node keeps exactly one persistent
connection to it.

ADR 0004 already dropped per-address health matrices. ADR 0005 stores
the unique backbone name and marks extras/`wrong-class` as
`conflict_backbone`. Neither owned how intents are created, retained, or
torn down.

A zero-initialized purpose must not look like a required backbone
intent. Persistence must not be a second flag that can disagree with
purpose.

## Decision

Replace generic autoconnect with purpose-owned logical intents on
`outgoing_t`. Device-class `min_connects`/`max_connects` are gone.

```c
typedef enum meta_connection_purpose_t {
	META_PURPOSE_NONE = 0,
	META_PURPOSE_BACKBONE_REQUIRED,
	META_PURPOSE_LAN_RESILIENCE,
	META_PURPOSE_HANDOVER_SPARE,
} meta_connection_purpose_t;

static inline bool meta_purpose_is_persistent(meta_connection_purpose_t purpose) {
	return purpose == META_PURPOSE_BACKBONE_REQUIRED;
}
```

`META_PURPOSE_NONE` is the unset value. Finding 5 does not create LAN or
handover intents. Finding 7 fills the reserved LAN pool. ADR 0003
upgrade probes stay in `net_upgrade.c` and are not a second outgoing.

`connection_policy_tick()` is the only balancer:

- A BACKBONE-class node, including a conflicted extra, initiates
  nothing.
- Every other node owns at most one `BACKBONE_REQUIRED` intent. The
  target is the stored backbone name, not conflicted, not blacklisted,
  and class `BACKBONE`. Missing key requests the key and keeps the
  intent. No known addresses retries; it does not delete a persistent
  intent.
- Incoming backbone META inherits that durable intent
  (`connection_policy_bind_connection` on ACK; `setup_outgoing_connection`
  attaches it; `transfer_outgoing` prefers the persistent purpose).
- `conflict_backbone` nodes are refused at ACK and skipped when
  selecting a pool target.

`BACKBONE_REQUIRED` has its own reconnect ladder, owned by
`connection_policy_schedule_backbone_retry()`:

```c
static const unsigned backbone_retry_seconds[] = {
	1, 2, 5, 10, 30, 60, 300, 900
};
```

Delays are jittered ±20% and clamped to at least one second.
`outgoing_t.retry_step` is the ladder index. `reset_outgoing()` does not
clear it. ACK does not clear it. An authenticated drop resets the step
only if that META socket stayed active for `BACKBONE_STABLE_RESET_SEC`
(direct or canonical). Hourly key renewal restamps `last_key_renewal`
and must not restamp `activated_at`. A refused or timed-out startup
socket continues the current epoch (direct then canonical) and only
then waits. Duplicate discovery/hint wakes a scheduled retry and must
not clear `retry_step`.

Each reconnect epoch keeps ADR 0003 startup: one best trusted direct
for 250 ms, then canonical. `BACKBONE_REQUIRED` does not walk
`OUTGOING_KNOWN_INDIRECT`. Leftover trusted directs are make-before-break
upgrade probes (`net_upgrade.c`), not a second outgoing. Discovery or a
hint while canonical META is already up does not zero the retry timer.
While a retry is armed, a duplicate discovery announcement fires the
timer immediately and leaves `retry_step` alone.

The intent is created before the peer key is known and is kept when no
endpoint is usable. Blacklist and `conflict_backbone` still drop it.

Retiring an intent closes its sockets. `drop_outgoing()`:

1. Cancels the pending startup socket.
2. Removes and frees the intent.
3. Terminates every active socket previously attached to it, or
   `shutdown(SHUT_RDWR)` if that socket's IO handler is on the stack.
4. Sets `retiring_outgoing` so `terminate_connection` does not redial
   and `connection_policy_on_connection_closed` does not re-enter tick.

## Consequences

- Production topology after finding 5 is a star. Camera-to-camera META
  waits for finding 7.
- A stored backbone that is reclassified or conflicted drops both the
  reserved intent and its live META.
- ADR 0004's route ranking is unchanged. ADR 0005 still owns identity
  and the conflict bit. ADR 0006 still owns who may invite.
- Finding 6 (retry ladder) is implemented on this same intent. Finding 10
  (relay-hop skip of `conflict_backbone`) remains separate.
