# ADR 0010: Validated UDP rebinding

## Status

Accepted

## Context

ADR 0008 confirms an ordinary-peer UDP endpoint only when that exact
source returns our nonce. After `udp_confirmed` is set, a later
authenticated datagram from a new source is stored as a lookup alias and
otherwise ignored. Sends, liveness probes, and suspect probes stay on
`n->address`.

That pin is wrong for an endpoint-dependent NAT that reallocates the
WAN port while the flow is still in use. Docker MASQUERADE `--random`
and some carrier-grade NATs do this under load, not only after an idle
timeout. The peer that still hears the sender keeps receiving. Its own
probes go to the previous port and die. Recovery today is a full
demotion: relay fallback, another 30-second residency, and PMTU
discovery from zero. One rediscovery in a field capture settled at 726
because only the small replies made it back during the dead window.
Each event costs 30 to 45 seconds instead of about one round trip.

A keepalive does not prevent the remap. The camera's public port
changed while it was still sending.

## Decision

A confirmed ordinary peer may migrate to a new authenticated source
without dropping the route.

- Detection runs only after SPTPS accepts the datagram. A replayed
  packet cannot open a candidate. Backbone and non-ordinary peers are
  unchanged.
- The current endpoint has to have been quiet for 500ms, or the route
  is already suspect, or a liveness probe is outstanding. A second live
  path does not migrate.
- One nonce-bearing 64-byte probe, inside a `PATH_TXN_REBIND` slot at
  recovery rank, proves the new source. The reply has to come from that
  source, with the session and network epoch unchanged. The wire format
  does not change.
- Commit replaces `n->address` and, when the active route is direct UDP,
  `active_route.udp_endpoint`. Kind, `selected_at`, `udp_confirmed`, and
  PMTU stay. A different IP is not a rebind. It stays on the promotion
  path, so a parked PMTU is not discarded while a local candidate is
  still proving itself.
- A failed challenge is held down for 5 seconds. Demotion (probe give-up
  or unanswered suspect probes) waits for an in-flight or fresh
  candidate, then proceeds as before if the challenge fails.
- Six migrations inside 60 seconds log `Unstable NAT binding`. That is
  an observation, not a policy change.

## Consequences

- NAT rebinding costs the quiet window plus one round trip, not a relay
  fallback and a new residency.
- `udp_confirmed` still means a reply proved the endpoint that we send to.
- Zero-RTT migration was rejected. Installing an unproven source would
  break the ADR 0008 rule and accept a reflection toward whatever
  address a captured datagram claimed, to save about one round trip.
- Keepalives were rejected. The mapping changes while outbound traffic
  is running, so a faster refresh would not hold the port.
- Cost is one address compare per authenticated datagram, one candidate
  per peer, and one probe per migration.
