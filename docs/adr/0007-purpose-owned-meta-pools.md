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
  (`setup_outgoing_connection` attaches it; `transfer_outgoing` prefers
  the persistent purpose).
- `conflict_backbone` nodes are refused at ACK and skipped when
  selecting a pool target.

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
- Finding 6 (retry ladder) and finding 10 (relay-hop skip of
  `conflict_backbone`) are separate.
