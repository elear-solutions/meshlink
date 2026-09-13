# ADR 0001: Validated per-hop path preference

## Status

Accepted

## Context

Meshlink can reach a peer over several paths: local UDP, WAN UDP, UDP
relay through a neighbour, META TCP to that neighbour's direct address,
and META TCP through the neighbour's canonical NLB address.

A learned NLB address used to land in `recent[]` and look like a direct
endpoint. The next reconnect then dialled the load balancer first and
marked the session as non-canonical, which blocked the hitless upgrade
to the real node.

## Decision

Rank only **validated** paths. Learning an address starts validation; it
does not move traffic.

Preference, best first:

1. Direct local UDP (bidirectional probe reply)
2. Direct WAN UDP (bidirectional probe reply)
3. Per-hop UDP relay
4. Per-hop direct META TCP
5. Per-hop canonical NLB META TCP

The guarantee is **per hop**, not a single whole-route list. A record
that enters a relay over META stays on META on the way out
(Camera–UDP–NMN–TCP–App is allowed; META-in pins META-out).

The current lower tier stays active while a better candidate validates.
Promotion is hitless: no channel reset and no false unreachable
transition. Canonical NLB is the last validated META fallback.

Each `recent[]` entry carries provenance. Canonical-equivalent addresses
are never stored as direct candidates. Old host configs without
provenance load as unknown and are sanitized on read.

## Consequences

- META outbound order is recent (direct) → known edges → canonical →
  indirect edges. `via_canonical` is set from provenance or canonical
  equivalence, not only from the walk stage.
- A falsely “recent” NLB connection is still treated as canonical META
  and remains eligible for a direct upgrade probe.
- While WAN UDP is confirmed, local candidates are probed at a low rate
  and may replace WAN only after a probe reply.

## Live verification

1. Start through canonical NLB; learn the direct NMN endpoint; confirm
   hitless migration away from NLB (no channel reset, no unreachable flap).
2. Confirm local direct UDP, then WAN direct UDP, then mixed UDP/META
   relay, then both-hop UDP relay.
3. Fail the direct path and confirm fallback to canonical NLB META.
