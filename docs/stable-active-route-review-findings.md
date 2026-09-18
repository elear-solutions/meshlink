# Meshlink Topology and Stable Active-Route Findings

## Scope

This document covers Meshlink only. It combines:

- the stable active-route review;
- the intended one-backbone product topology;
- persistent META connection ownership;
- bounded local-network resilience;
- warm Network Middle Node UDP relay reachability;
- channel-driven peer hole punching;
- test and repository cleanup.

COCO and Network Management Node changes are intentionally excluded.

The target topology is:

1. Exactly one backbone node starts the network.
2. Stationary and portable nodes join through that backbone.
3. The backbone accepts connections but creates no outgoing META connections.
4. Every stationary and portable node owns one mandatory backbone META intent.
5. That intent prefers a trusted direct backbone address and uses canonical as
   fallback.
6. Each stationary or portable node maintains at most three authenticated local
   META adjacencies for internet-loss resilience.
7. Each stationary or portable node keeps authenticated UDP reachability to the
   backbone warm for relay traffic.
8. Direct peer UDP punching exists only while channels need that peer.
9. Channel traffic prefers local UDP, WAN UDP, local META, backbone UDP relay,
   backbone direct-META relay, then backbone canonical-META relay.

## How to use this document

Resolve findings in numerical order. Each open finding assumes the invariants
established by earlier findings.

- Findings 1-2 are completed foundations.
- Finding 3 persists backbone identity. Extra backbone-class nodes are
  marked `conflict_backbone`. Finding 5 skips them in META pools;
  finding 10 still owns relay-hop skip.
- Finding 4 gates production invitation create/serve to the unique
  backbone.
- Finding 5 replaced generic autoconnect with purpose-owned pools in
  `connection_policy`. Finding 6 added the telescopic retry ladder on
  the same `BACKBONE_REQUIRED` intent. Findings 7-8 extend that
  ownership.
- Findings 9-14 complete route correctness and traffic budgets.
- Findings 15-20 finish interfaces, verification, and cleanup.

Do not implement a later finding by adding a second competing state machine.
Move ownership to the module introduced by the earliest relevant finding.

---

## 1. Fallback traffic cleared UDP suspicion

**Priority:** P1  
**Status:** Completed and merged in `e3a818b0`

### Issue Summary

The first record sent over a temporary fallback used to overwrite the preferred
direct-UDP route and clear its suspect state. The following record immediately
returned to the failed endpoint, preventing timeout-based demotion.

The merged fix adds `temporary_fallback` to the send target, records application
activity without committing temporary fallback traffic, and commits the
fallback only after actual demotion.

### Example Real-world scenario failure

1. A camera streams over WAN UDP.
2. Its NAT mapping expires.
3. A reliable retransmission marks WAN UDP suspect.
4. One record uses the live backbone fallback.
5. The old implementation clears suspicion while recording that fallback.
6. The next record returns to dead WAN UDP.
7. Video oscillates between failed UDP and fallback.

### Suggested code change to fix

Completed. Preserve these invariants:

```c
if(target->temporary_fallback) {
	/* Traffic was carried, but the preferred route is still under test. */
	return;
}

path_commit_active_route(n, target, &mesh->loop.now);
```

Future route work must not remove the distinction between:

- the preferred active route;
- a temporary carrier used while that route is suspect;
- the committed fallback after demotion.

---

## 2. Production UDP promotion lacked an independent second round

**Priority:** P1  
**Status:** Completed and merged in `c9001bbe`

### Issue Summary

Candidate validation was coupled to the path-MTU timer. A settled path parked
that timer for the device-class ping interval after the first reply, while the
candidate deadline was ten seconds. The second validation round was therefore
never sent in production.

The merged fix gives promotion its own timer, sends authenticated 64-byte
candidate probes, retries the current nonce every second, rotates the nonce
after a matching reply, waits 500 milliseconds before round two, and leaves
hold/residency commitment to `path_route_tick()`.

Probe requests and replies use a scoped explicit destination override, so both
peers may remain configured with WAN active addresses while the local candidate
is validated. Path-MTU remains parked on the active endpoint.

### Example Real-world scenario failure

1. An app streams to a camera over working WAN UDP.
2. Discovery learns the camera's local address.
3. The first local candidate probe succeeds.
4. The old shared path-MTU timer parks for sixty seconds.
5. The ten-second candidate deadline expires before round two.
6. Local UDP never takes over.

### Suggested code change to fix

Completed. Preserve the ownership split:

```c
promotion_timer:
    validation rounds + validation deadline

path_route_tick:
    post-validation hold + active-route residency + commit

mtutimeout:
    PMTU and active-endpoint liveness only
```

The per-candidate timer must not grow request-count policy. The later global
probe scheduler owns aggregate packet and transaction limits.

---

## 3. Define and persist the unique backbone identity

**Priority:** P1  
**Status:** Partially completed

Identity is persisted. Conflicts are detected, not quarantined. Findings
5 and 10 must skip `conflict_backbone` nodes when filling META pools and
choosing the relay hop. See [ADR 0005](adr/0005-backbone-identity.md).

### Issue Summary

Meshlink knew device classes but had no explicit, persistent backbone
identity. Generic graph and autoconnect logic could not enforce a single
re-entry node: inferring "who the backbone is" from the live set of
`DEV_CLASS_BACKBONE` hosts elected a new identity whenever gossip
contained a second such node.

### Example Real-world scenario failure

A portable node receives graph data containing two nodes marked as backbone.
Autoconnect selects whichever sorts first, while relay routing later follows a
different graph nexthop. META recovery and relay traffic no longer agree on the
network's guaranteed re-entry node.

### Suggested code change to fix

Landed in `src/connection_policy.c`. The invariant is a **name**. The
cached `node_t *` is resolved while the host exists and cleared on
forget/delete; the name stays.

```c
typedef struct backbone_identity_t {
	char *name;
	node_t *node;
} backbone_identity_t;

bool connection_policy_set_backbone(meshlink_handle_t *mesh, const char *name);
node_t *connection_policy_backbone(meshlink_handle_t *mesh);
bool connection_policy_validate_topology(meshlink_handle_t *mesh);
```

Persist in sidecar `current/backbone` (packmsg `uint32 version=1` + name)
and `config_sync()` the directory after write. Do not bump
`MESHLINK_CONFIG_VERSION`. Gossip never calls `set_backbone`. First write
wins.

Bootstrap:

1. `open` leaves the identity unset on a new confbase.
2. `join` requires the inviter host config to be `DEV_CLASS_BACKBONE` and
   commits that name before return. Invitation v3 carries the name;
   v2 infers it from the first host blob. Join rebuilds `current/`, so it
   clears any identity a prior `start` committed.
3. `start` commits self only if the name is still unset and self is
   `DEV_CLASS_BACKBONE`.
4. Extra `DEV_CLASS_BACKBONE` nodes, and a stored name whose class is not
   `DEV_CLASS_BACKBONE`, set `conflict_backbone`. Detection only — they
   still participate in graph, gossip, and relay. Finding 5 skips them
   in META pools.
5. Missing sidecar on an existing confbase migrates only when unambiguous:
   self-only BACKBONE, or exactly one other BACKBONE host. Two or more:
   do not guess.

Still open under the original item 4: do not exclude `conflict_backbone`
from routing decisions here. META-pool skip is finding 5; relay-hop skip
is finding 10.

---

## 4. Enforce backbone-only production bootstrap

**Priority:** P1  
**Status:** Completed

### Issue Summary

Invitation creation and serving were ungated: any eligible node, including
a second backbone-class host, could issue a production invitation. Join
only required the inviter host to be `DEV_CLASS_BACKBONE`, so that extra
node became the joiner's stored identity.

### Example Real-world scenario failure

Camera B joins using an invitation produced by Camera A while both are on the
same LAN. The installation later moves Camera B to another network. Camera B
knows Camera A as its bootstrap peer but lacks a guaranteed canonical NMN route,
so it cannot reliably re-enter the network.

### Suggested code change to fix

Completed. Production invite/serve uses `connection_policy_can_invite()`.
Unset identity may invite only as an unambiguous creator (one BACKBONE-class
node, self not `conflict_backbone`). Join parses the whole invitation before
mutating `current/`. Tests use `devtool_set_allow_peer_bootstrap()` to plant
blobs; join stays strict. See [ADR 0006](adr/0006-backbone-only-bootstrap.md).

Preserve these invariants:

```c
if(!connection_policy_can_invite(mesh)) {
	meshlink_errno = MESHLINK_ENOTSUP;
	return NULL;
}

if(n->devclass != DEV_CLASS_BACKBONE
                || strcmp(invitation_backbone, n->name)) {
	meshlink_errno = MESHLINK_EPEER;
	return false;
}
```

---

## 5. Replace generic autoconnect with purpose-owned connection pools

**Priority:** P1  
**Status:** Completed

**Depends on:** finding 3 `conflict_backbone` (skip conflicted nodes when
filling META pools; they are detected, not yet excluded).

### Issue Summary

Current autoconnect balances a generic number of META connections using device
class and graph ordering. The defaults request three connections for backbone,
stationary, and portable nodes. This does not model the intended topology:

- backbone: zero outgoing META connections;
- stationary/portable: one mandatory backbone META connection;
- stationary/portable: at most three local-resilience META adjacencies;
- no other outgoing META connections.

One `min_connects`/`max_connects` pair cannot express reserved backbone
capacity plus a separate local cap.

### Example Real-world scenario failure

A portable node fills all three generic connection slots with cameras before
the backbone becomes reachable. Because it is already at its maximum, the
backbone does not get a reserved slot. The node remains locally connected but
has lost its only guaranteed internet re-entry path.

Conversely, the backbone's current `min_connects = 3` makes it initiate
connections even though the product design says it must accept only.

### Suggested code change to fix

Introduce explicit connection purposes:

```c
typedef enum meta_connection_purpose_t {
	META_PURPOSE_BACKBONE_REQUIRED,
	META_PURPOSE_LAN_RESILIENCE,
	META_PURPOSE_HANDOVER_SPARE,
} meta_connection_purpose_t;

typedef struct outgoing_t {
	/* Existing fields. */
	meta_connection_purpose_t purpose;
	bool persistent_intent;
} outgoing_t;
```

Move selection and balancing behind a connection-policy module:

```c
void connection_policy_tick(meshlink_handle_t *mesh);
void connection_policy_on_discovery(meshlink_handle_t *mesh, node_t *node,
                                    const sockaddr_t *address,
                                    address_source_t source);
void connection_policy_on_connection_closed(meshlink_handle_t *mesh,
                                            node_t *node,
                                            meta_connection_purpose_t purpose);
```

Required pool invariants:

```text
Backbone node:
  required backbone outgoing = 0
  LAN-resilience outgoing = 0
  accepts authenticated incoming connections

Stationary/portable node:
  required backbone logical intent = exactly 1
  active backbone META sockets = 1, except bounded handover overlap
  local META adjacencies = 0..3
  other outgoing META intents = 0
```

Remove backbone and LAN-resilience connections from generic
`min_connects`/`max_connects` balancing. The generic autoconnect loop should be
deleted or reduced to an adapter that calls the new module.

---

## 6. Make the backbone META intent durable with direct-first canonical fallback

**Priority:** P1  
**Status:** Completed

Finding 5 owns the persistent `BACKBONE_REQUIRED` intent in
`src/connection_policy.c`. This finding owns the telescopic retry ladder
and keep-alive on that same intent.

### Issue Summary

Direct-before-canonical address ordering and canonical-to-direct make-before-
break already exist, but they are attached to an ordinary outgoing entry.
There is no non-evictable backbone intent with its own retry lifecycle.

The current retry delay grows linearly and generic balancing may delete or fail
to recreate an outgoing entry when peer connections occupy the available
slots.

### Example Real-world scenario failure

An app has three local META peers when its NMN connection drops. Generic
autoconnect considers the minimum connection count satisfied and does not
restore NMN. Internet access returns, but the app stays in a LAN-only island.

### Suggested code change to fix

Keep one durable logical backbone outgoing object for every non-backbone node:

```c
typedef struct backbone_outgoing_t {
	node_t *node;
	outgoing_t *attempt;
	struct timespec retry_at;
	unsigned retry_step;
} backbone_outgoing_t;
```

Use a jittered telescopic ladder, for example:

```c
static const unsigned backbone_retry_seconds[] = {
	1, 2, 5, 10, 30, 60, 300, 900
};
```

Each retry epoch:

1. Tries the best trusted direct backbone endpoint.
2. Tries remaining trusted direct endpoints without cycling indefinitely.
3. Resolves and tries canonical.
4. Keeps the intent alive even if no endpoint is currently usable.

When canonical is active and a trusted direct address appears, reuse the
existing bounded make-before-break upgrade. A successful stable direct
connection resets the retry ladder.

Canonical and direct are two carriers for one logical mandatory connection, not
two steady-state sockets.

---

## 7. Implement a bounded deterministic local META resilience overlay

**Priority:** P1  
**Status:** Completed

Finding 5 reserved `META_PURPOSE_LAN_RESILIENCE` and
`META_LAN_RESILIENCE_MAX` on `src/connection_policy.c` and left LAN fill
empty. This finding owns selection, admission, and the inbound cap.

### Issue Summary

The intended local META behavior is not demand-only. Known stationary and
portable nodes should maintain a bounded local overlay so the network remains
usable when internet access or NMN is unavailable.

Current generic autoconnect:

- does not require a local address;
- does not require discovery/authenticated-local provenance;
- does not separate local peers from the backbone quota;
- limits outgoing attempts rather than total local adjacencies;
- can exceed the desired cap through inbound connections;
- does not guarantee that independently selected peers form a connected graph.

### Example Real-world scenario failure

Ten cameras discover one another. Each independently connects to three
arbitrary peers. The resulting graph can split into disconnected groups, or one
popular node can accept nine inbound connections despite the intended cap of
three. When internet fails, some cameras cannot reach the app or one another.

### Suggested code change to fix

Treat locality and authentication as admission requirements:

```c
bool connection_policy_local_candidate(const node_t *node,
                                       const sockaddr_t *address,
                                       address_source_t source,
                                       path_cap_t capability) {
	return (node->devclass == DEV_CLASS_STATIONARY
	        || node->devclass == DEV_CLASS_PORTABLE)
	    && path_address_is_local(address)
	    && (capability & PATH_CAP_META)
	    && (source == ADDR_SRC_DISCOVERY
	        || source == ADDR_SRC_AUTH_DIRECT);
}
```

Define "at most three" as total authenticated local adjacencies, including
incoming and outgoing sockets. Use deterministic topology selection rather
than first-seen ordering. A practical design is:

- predecessor by stable node ID;
- successor by stable node ID;
- one deterministic symmetric backup/chord;
- deterministic initiator ownership for each selected pair.

Before accepting or initiating a fourth local adjacency, compare the complete
desired set and retire the least preferred non-required adjacency.

Maintain one META connection per selected local peer. Existing simultaneous
connect tie-breaking may resolve duplicate sockets, but it must not choose the
topology itself.

This finding replaces the old demand-only local-META recommendation. Local META
is a persistent bounded resilience plane; direct peer UDP remains channel
demand-driven.

---

## 8. Maintain authenticated backbone UDP as a warm relay path

**Priority:** P1  
**Status:** Open

### Issue Summary

UDP has no connection object, so the required invariant is a maintained,
authenticated, endpoint-scoped UDP mapping to the backbone.

Current UDP probing is generic per node. Confirmed UDP may become idle when
there is no application traffic, while unreachable peer UDP can be probed
indefinitely. Neither behavior matches the intended roles:

- backbone UDP should stay warm because it is a relay carrier;
- ordinary peer UDP should be idle unless channels need it.

### Example Real-world scenario failure

An app has no active stream for several minutes. Its confirmed NMN UDP mapping
is not refreshed and expires in the NAT. When a camera stream starts, the route
policy selects UDP relay based on stale state, loses initial records, and only
then falls back to META.

### Suggested code change to fix

Add explicit backbone UDP state owned by the connection-policy/path-scheduler
module:

```c
typedef struct backbone_udp_path_t {
	sockaddr_t endpoint;
	address_source_t source;
	bool confirmed;
	uint64_t liveness_nonce;
	struct timespec last_authenticated_reply;
	struct timespec next_keepalive;
} backbone_udp_path_t;
```

Rules:

1. Start backbone UDP establishment after backbone META authentication.
2. Learn the direct UDP endpoint through authenticated control exchange.
3. Keep it warm with small authenticated liveness probes even with no channels.
4. Demote only the exact failed endpoint.
5. Re-establish through direct endpoint discovery; canonical TCP is not a UDP
   carrier.
6. Reserve scheduler capacity for this required relay path.

Make the interval configurable and shorter than the supported NAT idle window,
with jitter to prevent fleet synchronization.

---

## 9. Gate direct peer UDP punching on channel demand

**Priority:** P1  
**Status:** Open

### Issue Summary

Direct peer UDP probing currently begins after SPTPS key establishment and can
continue for reachable peers without any channel. `meshlink_channel_open_ex()`
creates UTCP state but does not tell path policy that peer UDP is now needed.

The desired behavior is the inverse:

- no direct peer UDP punching without channel demand;
- start on the first channel for that peer;
- share one peer path across all channels;
- stop after the last channel closes, with a short grace period.

### Example Real-world scenario failure

An app knows fifty cameras but watches only one. Key exchange and generic UDP
probing create hole-punch traffic for many idle cameras. NAT tables, radio
airtime, and logs grow with known-node count rather than active-stream count.

### Suggested code change to fix

Track demand per peer:

```c
typedef struct peer_path_demand_t {
	unsigned channel_count;
	struct timespec idle_until;
} peer_path_demand_t;
```

Expose a small internal interface:

```c
void path_channel_acquire(meshlink_handle_t *mesh, node_t *peer);
void path_channel_release(meshlink_handle_t *mesh, node_t *peer);
bool path_peer_udp_demanded(const meshlink_handle_t *mesh,
                           const node_t *peer);
```

Call `path_channel_acquire()`:

- before sending the first outgoing UTCP SYN;
- when an incoming channel SYN is accepted.

Call `path_channel_release()` on every terminal channel path, including abort,
remote close, timeout, rejection, and node teardown.

On `0 -> 1`, initiate key exchange and local/WAN UDP validation through the
existing META overlay. On `1 -> 0`, retain the selected peer route only for a
bounded grace period, then stop peer liveness and promotion timers.

Remove unconditional direct-peer `send_mtu_probe()` startup from generic key
completion. Keep a separate exception for the backbone UDP path from finding 8.

---

## 10. Make the active application route authoritative and pin relay to the backbone

**Priority:** P1  
**Status:** Open

**Depends on:** finding 3 `conflict_backbone` (relay hop is
`connection_policy_backbone()`, never a conflicted extra backbone-class
node).

### Issue Summary

`path_active_send_target()` still reconstructs a preferred route from live node
booleans on each send. The recorded route is descriptive rather than the
authoritative selected route.

The route also lacks an exact UDP endpoint and endpoint provenance. WAN-to-local
changes therefore cannot be represented as same-mechanism endpoint promotions.

Relay currently uses `n->nexthop`. The graph may choose a local peer, but the
product path order specifically requires relay through the configured backbone.

### Example Real-world scenario failure

Application data is stable over backbone direct META. A transient
`udp_confirmed` observation on the graph nexthop causes the next record to use
UDP relay immediately, without candidate validation or residency. When the flag
changes again, data returns to META.

In another topology, the graph selects a local camera as `nexthop`; traffic
logged as "relay" no longer means relay through NMN.

### Suggested code change to fix

Store exact route identity:

```c
typedef struct data_route_t {
	data_route_kind_t kind;
	relay_carrier_t relay_carrier;
	node_t *first_hop;
	sockaddr_t udp_endpoint;
	address_source_t endpoint_source;
	bool local;
	bool suspect;
	struct timespec selected_at;
	struct timespec healthy_since;
} data_route_t;
```

Split policy operations:

```c
bool path_resolve_active_route(meshlink_handle_t *, node_t *, path_target_t *);
bool path_select_fallback(meshlink_handle_t *, node_t *, path_target_t *);
void path_commit_candidate(meshlink_handle_t *, node_t *);
```

Normal sends resolve the recorded route. Reranking occurs only when:

- establishing the first route;
- committing a validated promotion;
- handling an exact active-route hard failure;
- completing suspect demotion.

For relay classes:

```c
node_t *hop = connection_policy_backbone(mesh);
```

Then choose backbone UDP, backbone direct META, or backbone canonical META.
Local META is valid only when the destination is one of the authenticated local
adjacencies from finding 7.

Include endpoint, source, locality, carrier, and first hop in route equality.
Same-class endpoint changes must restart residency only after explicit commit.

---

## 11. Correct cooldown escalation on long-lived routes

**Priority:** P1  
**Status:** Open

### Issue Summary

Candidate failure escalation is currently reset from the active route's
original `selected_at` time. Once a route is older than sixty seconds, a new
candidate failure can create a cooldown and have it cleared in the same tick.

Repeated stale local candidates therefore never progress through the intended
30, 60, 120, 300, and 600 second cooldown ladder.

### Example Real-world scenario failure

A camera has used WAN UDP for ten minutes. Discovery repeatedly reports a stale
local address. Every validation times out, but the old active-route timestamp
immediately resets failure history. The camera retries the stale address
continuously.

### Suggested code change to fix

Track health since the most recent failure:

```c
static void path_note_candidate_failure(meshlink_handle_t *mesh, node_t *n) {
	n->promotion_candidate.last_failure_at = mesh->loop.now;
	memset(&n->active_route.healthy_since, 0,
	       sizeof n->active_route.healthy_since);
}

static void path_note_authenticated_route_success(meshlink_handle_t *mesh,
                                                  node_t *n) {
	if(!n->active_route.healthy_since.tv_sec) {
		n->active_route.healthy_since = mesh->loop.now;
	}
}
```

Reset escalation once after sixty uninterrupted seconds of authenticated
service following the latest failure. Never clear a cooldown in the tick that
created it.

---

## 12. Separate suspect validation from PMTU and reject stale replies

**Priority:** P1  
**Status:** Open

### Issue Summary

`PATH_SUSPECT_PROBES` is defined but unused. Reliable retransmission currently
wakes the existing path-MTU timer, which sends a variable-size burst. Any
authenticated reply from the current address can clear suspicion without
matching a nonce generated after suspicion began.

This mixes PMTU, liveness, and reliable recovery, and lets a delayed reply from
an older probe clear a new failure epoch.

### Example Real-world scenario failure

1. A liveness reply is delayed in a mobile-network queue.
2. A reliable retransmission marks the route suspect.
3. The old reply arrives from the same endpoint.
4. Meshlink clears the new suspicion.
5. Future channel records remain on a route that has not answered either new
   suspect probe.

Large PMTU probes may also fail during congestion even when 64-byte liveness
would succeed, causing unnecessary demotion.

### Suggested code change to fix

Add one temporary suspect transaction for the exact active endpoint:

```c
typedef struct suspect_validation_t {
	bool active;
	sockaddr_t endpoint;
	uint64_t nonce;
	uint8_t probes_sent;
	uint8_t replies_received;
	struct timespec deadline;
	timeout_t timer;
} suspect_validation_t;
```

Send exactly two authenticated 64-byte probes across one second. Clear
suspicion only when endpoint and nonce match the current suspect epoch:

```c
if(suspect->active
                && !sockaddrcmp(from, &suspect->endpoint)
                && nonce == suspect->nonce) {
	suspect->replies_received++;
	path_clear_route_suspicion(mesh, node);
}
```

Do not modify `mtuprobes`, `minmtu`, or `maxmtu`. A stale promotion, PMTU, or
previous-suspect reply must not affect current suspicion.

---

## 13. Add role-aware global probe and transaction budgets

**Priority:** P1  
**Status:** Open

### Issue Summary

Each node owns independent timers, so a large set of peers can emit probe bursts
simultaneously. There is no mesh-wide enforcement for concurrent validation,
packets per second, or packets per minute.

The old blanket "idle peers produce zero probes" rule is incomplete for the
envisioned topology:

- idle ordinary peers should produce zero direct-UDP probes;
- the mandatory backbone UDP relay mapping must remain warm;
- active channel peers may validate or maintain direct UDP;
- PMTU increase probes remain low priority.

### Example Real-world scenario failure

Fifty known cameras sit behind unsupported NATs. Independent timers align and
emit bursts despite no active channels. At the same time, low-value peer PMTU
traffic can consume the opportunity to refresh the required backbone UDP relay
mapping.

### Suggested code change to fix

Use one mesh-wide scheduler with priority classes:

```c
typedef enum path_transaction_priority_t {
	PATH_TX_BACKBONE_REQUIRED,
	PATH_TX_ACTIVE_ROUTE_RECOVERY,
	PATH_TX_CHANNEL_PROMOTION,
	PATH_TX_LIVENESS,
	PATH_TX_PMTU_INCREASE,
} path_transaction_priority_t;

typedef struct path_probe_budget_t {
	unsigned active_transactions;
	unsigned second_tokens;
	unsigned minute_tokens;
	struct timespec second_refill_at;
	struct timespec minute_refill_at;
} path_probe_budget_t;
```

All promotion, suspect, liveness, PMTU, backbone UDP, and META upgrade work
requests admission through one interface:

```c
bool path_scheduler_submit(meshlink_handle_t *mesh,
                           path_transaction_priority_t priority,
                           node_t *node,
                           path_transaction_fn run);
```

Enforce the agreed fleet budgets, including the later eight-request promotion
cap, here rather than adding counters to each candidate implementation.

Reserve capacity for mandatory backbone recovery and UDP keepalive so optional
peer discovery cannot starve the guaranteed network path.

---

## 14. Clear candidate cooldown only for genuinely new network information

**Priority:** P2  
**Status:** Open

### Issue Summary

Production learning can start candidates, but cooldown reset semantics still
need an explicit network-information epoch. Clearing cooldown for every repeated
discovery announcement would bypass backoff; never clearing it would delay a
valid retry after an actual network change.

### Example Real-world scenario failure

An app leaves the camera's Wi-Fi and local validation fails repeatedly. It later
returns and learns a genuinely new local endpoint, but the old ten-minute
cooldown remains. Alternatively, duplicate mDNS announcements repeatedly clear
the cooldown and create continuous probes.

### Suggested code change to fix

Have address learning report material change and record which endpoint/network
generation consumed the one cooldown reset:

```c
typedef struct candidate_retry_epoch_t {
	uint64_t network_generation;
	sockaddr_t endpoint;
	bool cooldown_cleared;
} candidate_retry_epoch_t;
```

Only a new endpoint, interface generation, or authenticated network change may
clear cooldown:

```c
if(address_materially_changed
                && retry_epoch_is_new(mesh, node, endpoint)) {
	path_candidate_clear_cooldown(mesh, node);
}
```

Repeated identical hints or discovery packets must not clear it again.

---

## 15. Preserve endpoint provenance through candidate and route commitment

**Priority:** P2  
**Status:** Open

### Issue Summary

Local UDP candidate selection returns only an address, and candidate start
currently hardcodes discovery provenance. The endpoint may actually come from
an authenticated direct observation, a hint, or another allowed source.

The active route also lacks endpoint provenance. Logs, META eligibility, and
future trust decisions can therefore disagree with how the endpoint was
learned.

### Example Real-world scenario failure

An authenticated local endpoint is promoted but stored as ordinary discovery.
A later policy decision rejects a valid META use or emits misleading diagnostics
because the original trust class was lost.

### Suggested code change to fix

Pass complete endpoint descriptors:

```c
typedef struct path_endpoint_t {
	sockaddr_t address;
	address_source_t source;
	path_cap_t capability;
} path_endpoint_t;

bool path_pick_local_udp_candidate(meshlink_handle_t *mesh,
                                   const node_t *node,
                                   path_endpoint_t *out);
```

Copy provenance into `route_candidate_t`, then into `data_route_t` only after
successful validation and commitment.

---

## 16. Validate channel ownership in the fixed MSS getter

**Priority:** P2  
**Status:** Open

### Issue Summary

`meshlink_channel_get_mss()` locks the supplied mesh but does not verify that
the channel belongs to that mesh. Passing a channel from another Meshlink
instance locks the wrong mutex and reads the other instance's UTCP state without
serialization.

### Example Real-world scenario failure

An application manages two networks and accidentally calls
`meshlink_channel_get_mss(mesh_a, channel_from_mesh_b)`. Concurrent teardown on
Mesh B can race the getter despite the apparent lock in the function.

### Suggested code change to fix

Validate ownership under the supplied mesh lock:

```c
node_t *node = channel->node;

if(!node || node->mesh != mesh || !node->utcp) {
	meshlink_errno = MESHLINK_EINVAL;
	pthread_mutex_unlock(&mesh->mutex);
	return (size_t)-1;
}

size_t mss = utcp_get_mss(node->utcp);
```

Apply the same ownership rule to related channel getters touched by this work.

---

## 17. Add production-path topology, connection, and routing tests

**Priority:** P2  
**Status:** Open

### Issue Summary

Existing helper and devtool tests are useful for deterministic state coverage,
but the envisioned topology requires black-box tests through actual connection,
timer, channel, and packet paths.

Some previous tests passed while production promotion could not send round two.
The same mistake must not recur for connection ownership or channel demand.

### Example Real-world scenario failure

Unit tests prove that a selected candidate can transition when helpers are
called manually, but a portable device fills its connection quota with local
peers and never creates the mandatory NMN outgoing intent.

### Suggested code change to fix

Add tests in dependency order:

1. Backbone identity persists through invitation, join, close, and reopen.
   Done in `test/backbone-identity.c` (finding 3). Conflicted extra
   backbone-class nodes are detected, not blacklisted.
2. Non-backbone invitation is rejected in production mode. Join already
   rejects a non-backbone inviter host. Invite *creation* gating and
   "inviter must be the stored unique backbone" remain finding 4.
3. Backbone initiates zero outgoing META connections.
4. Stationary/portable maintains exactly one backbone logical intent.
5. Backbone late discovery preempts no required slot because its slot is
   reserved.
6. Backbone reconnect cycles direct endpoints then canonical with telescopic
   jittered retry.
7. Canonical-to-direct handover keeps one logical META intent and bounded socket
   overlap.
8. Local discovery forms at most three total authenticated META adjacencies.
9. A LAN of more than four nodes remains connected under deterministic peer
   selection.
10. Internet loss leaves the local overlay operational.
11. Backbone UDP remains warm without channels.
12. Ordinary peer UDP emits zero probes without channels.
13. First outgoing and incoming channel demand starts peer punching.
14. Last channel close stops peer punching after grace.
15. Two simultaneous channels share one peer path state.
16. Relay carrier is always the configured backbone.
17. All six route classes deliver through their intended mechanism.
18. Suspect, cooldown, stale-reply, same-class endpoint, and fixed-MSS
   transitions run through production paths.
19. Many peers remain inside global transaction and packet budgets.

Keep focused policy tests, but never let a devtool-only transition be the sole
acceptance test for a production invariant.

---

## 18. Stop reinitializing live synchronization objects in `canonical-migrate`

**Priority:** P3  
**Status:** Open

### Issue Summary

`stream_send()` repeatedly initializes `stream_writable` when the send buffer
stalls. Reinitializing an initialized pthread mutex or condition variable is
undefined, especially while a poll callback may still access it.

### Example Real-world scenario failure

Under a loaded sanitizer or continuous-integration host, the stream stalls
twice. The second initialization races the previous callback and the test hangs
or fails nondeterministically.

### Suggested code change to fix

Initialize once before streaming and reset before each wait:

```c
init_sync_flag(&stream_writable);

/* In stream_send(). */
reset_sync_flag(&stream_writable);
meshlink_set_channel_poll_cb(mesh, channel, writable_cb);
assert(wait_sync_flag(&stream_writable, 5));
```

Destroy it once during teardown if required by the synchronization helper.

---

## 19. Version the exported devtool status interface

**Priority:** P3  
**Status:** Open

### Issue Summary

`devtool_node_status_t` is caller-allocated and returned through an exported
symbol. Appending route and candidate fields changes how much memory the library
writes. An existing diagnostics binary built against an older header can pass a
smaller allocation.

### Example Real-world scenario failure

A deployed diagnostics utility is not rebuilt during a Meshlink library update.
The new library writes beyond the old status structure and corrupts adjacent
heap memory.

### Suggested code change to fix

Add a size-aware version:

```c
bool devtool_get_node_status_v2(meshlink_handle_t *mesh,
                                meshlink_node_t *node,
                                devtool_node_status_t *status,
                                size_t status_size);
```

Write only `min(status_size, sizeof(*status))`. Preserve the old symbol with its
old layout or deliberately bump the diagnostic ABI.

---

## 20. Remove generated artifacts and stale policy state

**Priority:** P3  
**Status:** Open

### Issue Summary

Generated test launchers can remain untracked in the source tree, and comments
or fields can outlive the behavior they originally described.

After the topology redesign, likely stale items include:

- generic `min_connects`/`max_connects` assumptions;
- `udp_local_probe_next` if all promotion scheduling is centralized;
- `PATH_SUSPECT_PROBES` unless consumed by finding 12;
- comments claiming `last_application_traffic` owns behavior that moved to
  explicit channel demand;
- any per-node timers superseded by the global scheduler.

`test/backbone-identity` is gitignored with the other generated test
launchers. Do not commit it.

### Example Real-world scenario failure

A generated `test/path-stability` launcher is accidentally committed with
build-machine-specific paths. Later, a maintainer reads a stale field comment
and adds behavior to a timer that no longer owns the transition.

### Suggested code change to fix

Before final commit:

1. Remove generated `test/path-stability` artifacts from the source tree.
2. Add exact generated paths to ignore rules or use out-of-tree builds.
3. Run a symbol/reference audit for retired fields and constants.
4. Update ADR 0004 to describe the final connection pools, channel demand, NMN
   UDP exception, scheduler ownership, and route commitment rules.
5. Remove compatibility shims once no production or test caller uses them.

Delete dead state rather than retaining it as speculative future policy.

---

## Final architecture invariants

The redesign is complete only when all of the following hold:

### Topology and META

- Exactly one persisted backbone identity exists.
- Production nodes join through that backbone.
- Backbone creates no outgoing META connections.
- Every running stationary/portable node owns one durable backbone META intent.
- Backbone META prefers trusted direct and falls back to canonical.
- Canonical-to-direct migration is make-before-break with bounded overlap.
- Each stationary/portable node has at most three authenticated local META
  adjacencies.
- No other generic peer META connections are created.

### UDP and channels

- Backbone UDP relay reachability remains warm without channels.
- Ordinary peer UDP punching starts only from channel demand.
- Multiple channels to one peer share one path state.
- Peer probing stops after the last channel and bounded grace period.
- PMTU, promotion, suspect recovery, and liveness have distinct ownership.

### Application routing

- One authoritative active application route exists per demanded peer.
- Temporary fallback cannot erase suspect state.
- Route identity includes exact endpoint, provenance, locality, carrier, and
  first hop.
- Relay first hop is the configured backbone.
- The preference order is:
  1. local peer UDP;
  2. WAN peer UDP;
  3. local peer META;
  4. backbone UDP relay;
  5. backbone direct-META relay;
  6. backbone canonical-META relay.
- Fixed MSS never changes because the active carrier changes.
- Carrier changes never restart end-to-end SPTPS or UTCP by themselves.

### Stability and budgets

- Promotion requires authenticated rounds, hold, and residency.
- Suspect recovery matches endpoint and current nonce epoch.
- Cooldown escalation survives on long-lived routes.
- Mandatory backbone work cannot be starved by optional peer work.
- All path transactions obey global packet and concurrency budgets.

### Verification

- Tests exercise production timers, sockets, channels, and callbacks.
- Large-network tests prove LAN connectivity and connection caps.
- Internet-loss tests prove local resilience.
- Live camera tests prove all six route classes and fallback behavior.
- Serial, concurrent, sanitizer, and live acceptance runs remain green.
