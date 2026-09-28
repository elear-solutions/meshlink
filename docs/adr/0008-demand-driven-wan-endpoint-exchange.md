# ADR 0008: Demand-driven WAN endpoint exchange

## Status

Accepted

## Context

ADR 0004 ranks a confirmed direct WAN UDP path above UDP relay. Finding 9
stopped the backbone from originating probes to ordinary peers, so
`udp_confirmed` stays false for those peers: it is set only by a probe
reply. Forwarding an `ANS_KEY` still required that flag before it would
append an address. The backbone had already seen the peer's public UDP
source and then omitted it. Each side probed a stale `recent[0]` entry,
the punch missed, and the channel stayed on `relay-udp`.

A stored address is not the mapping the NAT will accept a punch on.
Restarting SPTPS to provoke another `ANS_KEY` would drop a live channel.
The backbone must not start probing ordinary peers again.

## Decision

An authenticated direct UDP datagram records a runtime observation on the
sender node: endpoint, `mesh->loop.now`, and `session_id`. It is not a
route, it is not persisted, and it does not set `udp_confirmed`.

The observation is fresh for three backbone keepalive intervals (75
seconds) and only while `session_id` still matches. A new session clears
it. Unbound, non-routable, unauthenticated, META-carried, and relayed
packets do not record one.

Ordinary peers ask for the mapping only while a channel demands UDP.
`REQ_PUNCH_ENDPOINT` is a routed `REQ_KEY` extension:

```text
REQ_KEY <requester> <backbone> REQ_PUNCH_ENDPOINT <target>
```

It is sent only when the live backbone META connection advertises protocol
minor 4 or newer. An older peer ignores the unknown extension and stays
connected. The unique backbone answers with the existing address-only
`ANS_KEY` shape, in both directions when both observations are fresh:

```text
ANS_KEY <observed> <recipient> . -1 -1 -1 0 <host> <port>
```

No observation means no hint. Relay UDP and META stay in place.

The same helper repairs opportunistic `ANS_KEY` forwarding. An empty
address is filled from the fresh observation, otherwise from a confirmed
active UDP endpoint. `recent[0]` is never the source of a forwarded hint.
A forwarder that is not the backbone leaves an address already on the message alone. The backbone does not. It replaces a member-filled address with the same helper: a fresh observation, otherwise a confirmed active endpoint. It drops the address only when that helper has nothing.

The receiver accepts a hint only while its own channel demand is live.
The hint is staged even when the peer key is not valid yet. Once the
SPTPS handshake completes, the staged hint is applied as a rendezvous
candidate. It is not written into `n->address`. An authenticated direct
source seen locally is a peer-reflexive candidate and outranks the hint,
including a hint that arrives while that challenge is in flight. A
locally authenticated source may be private or link-local; that source
is never stored as an NMN observation and never exported in `ANS_KEY`.

The node proves one endpoint at a time. It sends a 64-byte probe, nonce
at the existing probe offset, to that endpoint. Peers already echo probe
payload bytes, so this needs no wire-format or protocol-minor change.
Two sends, one promotion-round apart, then the challenge fails. A later
or moving hint does not restart an in-flight peer-reflexive challenge.
When that challenge fails, the latest hint is tried, then the existing
REQ_EXTERNAL and LAN rotation. A failed source is not pinned for the
observation freshness window.

Confirmation is still a reply whose nonce and UDP source match the
current challenge, and whose session, network, and demand epochs still
match. That reply is what sets `udp_confirmed`, installs `n->address`,
and starts PMTU. Receiving a request or an application datagram does not
confirm, and it does not stop the NMN request ladder. A confirmed peer
keeps the working endpoint and stores a newer hint for a later demotion.
Demotion does not restore the hint as a confirmed address; it may start
a new hint challenge. An identical hint does not restart the request
ladder. Session change, demand end, network-epoch change, key loss, and
freshness expiry drop a staged hint and the in-flight challenge.

One peer shares one request ladder across every channel to it: immediate
on the 0→1 transition, then 1, 2, 5, 10, and 30 seconds while direct UDP
is still unconfirmed. The route tick drives it. A new hint, a network
epoch change, or a new demand epoch restarts the ladder. Confirmation,
idle expiry, or a session change stops it. The request is META control
traffic, not a UDP probe, and it does not restart SPTPS.

A pending relay candidate does not block a strictly better live carrier.
Direct WAN UDP discards a lower relay candidate and its queued
transaction, and commit refuses to install relay when that direct carrier
is already live. A local-UDP candidate is never replaced by WAN UDP or
relay.

Two endpoint-dependent NATs still fail the punch when neither side
admits a bootstrap packet. The probes go out, no reply comes back, and
relay remains the route. One endpoint-dependent NAT opposite a cone
completes in both directions: the cone's stable mapping delivers the
first packet, and the endpoint-dependent side is proved by a reciprocal
probe to the source that packet arrived from.

## Consequences

- `udp_confirmed` still means a reply proved both directions.
- The backbone distributes hints and originates no ordinary-peer probes.
- Idle peers emit neither endpoint requests nor peer probes.
- Port-restricted cone NAT can move from relay to `direct-wan-udp` without
  a second 30-second residency behind a relay candidate.
- NMN hints only bootstrap. The preferred unconfirmed candidate is the authenticated peer-reflexive source, and only a matching reply from that endpoint confirms it.
- Two endpoint-dependent NATs stay on relay when no bootstrap packet lands. A cone opposite an endpoint-dependent NAT confirms both ways.
- Protocol minor 4 is required to emit `REQ_PUNCH_ENDPOINT`. Minor 3 keeps
  the old relay and opportunistic `ANS_KEY` behavior.
