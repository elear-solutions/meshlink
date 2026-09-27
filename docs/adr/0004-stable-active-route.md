# ADR 0004: Stable active route

## Status

Accepted

## Context

ADR 0001 ranks validated paths, ADR 0002 scopes candidates by transport,
and ADR 0003 makes a canonical-to-direct META upgrade hitless. A later
attempt generalised that work into a per-address policy: every remembered
endpoint carried independent UDP and META health, every destination
carried a planned route with its own generation, and each route change
rewrote the UTCP maximum segment size.

Two camera runs and a sanitizer run showed that model is not safe or
stable:

1. `meshlink_channel_get_mss()` read UTCP without the mesh mutex while
   route commits mutated the same fields and could `realloc()` the UTCP
   packet buffer. That is a data race and, during a send, a use after
   free.
2. Even with a lock, an application reads a size, packetises, and then
   sends. A route change inside that window silently invalidates the size
   it already used.
3. Relay traffic rearmed a parked path-MTU timer on every send, so an
   active relay hop produced continuous full-size probe bursts.
4. Application data triggered a local META dial, and a failed attempt
   kept retrying, so a peer could hold an extra TCP connection it never
   used.
5. Observed state was reconstructed from live sockets on every
   evaluation, so a recorded failure could be overwritten by
   synchronisation.

## Decision

The preference order stays as ADR 0001 describes, extended with a direct
local META TCP class:

1. Direct local UDP
2. Direct WAN UDP
3. Direct local META TCP
4. UDP relay through a directly addressed backbone UDP endpoint
5. META relay through a directly addressed backbone TCP connection
6. META relay through the canonical backbone connection

Those six are labels for ranking and logs. Internally there are three
forwarding mechanisms: direct UDP to an endpoint, direct META on the
node's own connection, and relay through a first hop whose carrier is
UDP, direct META, or canonical META.

A destination keeps exactly one active data route and at most one
promotion candidate. Remembered addresses stay in `recent[]` with their
provenance and capability bits. Learning an address is not validation and
does not create per-address health state.

The active route never stores a `connection_t *`. META targets are
resolved from the node's current connection under the mesh mutex at send
time, so terminating a connection cannot leave a dangling route.

Channel size is fixed. UTCP receives one maximum transmission unit when
the node's UTCP instance is created, computed as the relay-safe floor for
that origin and destination name pair. Path-MTU discovery, relay budget
reports, and route changes never call `utcp_set_mtu()` afterwards.
`meshlink_channel_get_mss()` takes the mesh mutex and returns that fixed
budget.

One `utcp_send()` call uses one route. A soft or hard failure observed
while that call is unwinding is recorded and applied after it returns, so
a single unreliable datagram cannot be split across two carriers.

Promotion is make-before-break and deliberately slow. The active route
carries data while one higher-ranked candidate validates. Direct UDP
needs two authenticated probe rounds, separated in time, each answered
with the nonce that was sent. Direct local META needs a fully
authenticated connection to a local address whose provenance is discovery
or an authenticated local observation. A validated candidate then waits
for a short hold, and the active route must have served a minimum
residency, before traffic moves.

Demotion is honest. A hard socket error on the active endpoint moves
future records to an already live fallback immediately. A reliable-channel
retransmission marks the route suspect, moves subsequent records to a
live fallback, and probes the suspect endpoint with two 64-byte
nonce-epoch packets on a dedicated timer; the route is demoted only
if those probes go unanswered. PMTU and stale replies do not clear
the current epoch. Relay UDP probes the backbone hop with that hop's
SPTPS nonce path; a matching reply clears dependent destinations, and
a miss demotes backbone UDP and reranks them. With no live fallback
the suspect route keeps carrying data while it is probed, and the
node is not reported unreachable.

Probing is demand driven and globally bounded. An idle peer is not
probed. An active route is proven by traffic, or by one small liveness
exchange per interval. Full-size path-MTU discovery runs on a long
interval. Relay forwarding does not accelerate probing.

## Consequences

- Channel maximum segment size is stable for the lifetime of the node's
  UTCP instance, so an application may read it once. It is the relay-safe
  floor, not the best size the current path could carry.
- Promotion changes only future records. Node SPTPS, `validkey`, and UTCP
  channels survive it.
- Fallback is not hitless. Unreliable records already handed to a failed
  route may be lost. Reliable channels recover by retransmission, and
  recovery is immediate only when a fallback connection is already up.
- A peer has one META connection, except during the bounded ADR 0003
  handover window.
- Generic `min_connects`/`max_connects` autoconnect is gone. META
  intents are purpose-owned (ADR 0007): the unique backbone initiates
  nothing; every other node owns one persistent `BACKBONE_REQUIRED`
  intent and a bounded LAN-resilience overlay of at most three
  authenticated local META adjacencies. Direct peer UDP punching stays
  channel-demand-driven (finding 9). ADR 0008 exchanges the current
  WAN mapping on that same demand and lets a confirmed direct carrier
  supersede a pending lower-ranked relay candidate.
- Backbone UDP relay reachability stays warm with no channel. Ordinary
  peer UDP punching does not.
- The global scheduler admits probe packets and transactions. Due times
  stay on the per-node `promotion_timer`, `suspect_validation.timer`,
  and `mtutimeout`.
- `path_record_active_route()` records a temporary fallback and does
  not commit it as the active route.
- Per-address UDP and META health matrices, planned-route generations,
  and route-driven UTCP resizing are removed.
