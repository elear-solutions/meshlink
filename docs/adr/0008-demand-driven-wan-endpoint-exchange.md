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

The receiver installs a hint only while its own channel demand is live and
the peer key is valid. An unconfirmed peer adopts it as the probe
destination and arms `send_mtu_probe()`. A confirmed peer keeps the working
endpoint and stores the hint for a later demotion. The hint is not
confirmed until its own reply arrives.

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

Symmetric NAT still fails the punch. The probes go out, no reply comes
back, and relay remains the route.

## Consequences

- `udp_confirmed` still means a reply proved both directions.
- The backbone distributes hints and originates no ordinary-peer probes.
- Idle peers emit neither endpoint requests nor peer probes.
- Port-restricted cone NAT can move from relay to `direct-wan-udp` without
  a second 30-second residency behind a relay candidate.
- Symmetric NAT stays on relay.
- Protocol minor 4 is required to emit `REQ_PUNCH_ENDPOINT`. Minor 3 keeps
  the old relay and opportunistic `ANS_KEY` behavior.
