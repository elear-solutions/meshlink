# ADR 0002: Transport-scoped address candidates

## Status

Accepted

## Context

ADR 0001 ranks validated paths and keeps canonical NLB endpoints out of
`recent[]`. Two production holes remained:

1. A hostname canonical that has not resolved yet still let invitation
   `HINT` and leftover `UNKNOWN` entries look like direct META
   candidates, so a fresh join through the NLB was classified
   `meta-direct`.
2. A UDP-reflexive NAT mapping (ANS_KEY, inbound remap, probe confirm)
   was written into `recent[]` with implicit TCP eligibility. The next
   outgoing walk then dialled those UDP-only ports.

Provenance (where an address came from) is not the same as transport
eligibility (which protocol may consume it).

## Decision

Provenance and transport capability are independent. Each `recent[]`
slot carries `recent_source[]` and `recent_cap[]` (`META`, `UDP`, or
both). One socket entry is shared; learning the same endpoint for the
other transport merges capability bits and keeps the highest-trust
source.

UDP-reflexive ports are UDP-only. They never appear in the META
outgoing walk or an upgrade probe.

A hostname canonical is resolved when it is loaded, set, or received
through `REQ_CANONICAL`, not only when the outgoing walk reaches its
canonical stage. Every resolved address is cached. On completion,
canonical-equivalent `recent[]` entries are removed, a live matching
META connection is reclassified as canonical, its graph edge is marked
indirect, and a direct META probe starts if a META-capable candidate
exists. DNS failure is non-destructive: the active connection stays up
and retry uses bounded backoff.

Lower tiers stay active while a better candidate validates. A META
migration does not change UDP route selection, relay budget, or the
META-in → META-out rule.

Invitation URLs may still list a canonical hostname. Resolved
canonical endpoints are not stored as `HINT`. A join through an
unresolved hostname canonical seeds the canonical cache from the
invitation peer and does not insert that peer into `recent[]`.

Legacy host configs without `recent_cap[]` are migrated conservatively:
known TCP-quality sources become META-capable; unmatched leftovers stay
UDP-only until TCP validates them.

## Consequences

- META consumers (`get_recent_addresses`, upgrade probe) require
  `PATH_CAP_META` and `path_is_direct_candidate`.
- UDP consumers require `PATH_CAP_UDP`.
- `HINT` and `UNKNOWN` are not direct META candidates while a hostname
  canonical has not been tried yet (`canonical_sa_count == 0` and
  backoff is still zero). After a DNS failure, backoff is set and a
  later application hint may fall through. Authenticated local
  discovery is not rejected for that reason.
- `INDIRECT` and `CANONICAL` slots are never META walk candidates,
  even if they carry `PATH_CAP_META`. A UDP-reflexive slot that later
  gains META (same endpoint independently authenticated over TCP)
  stays eligible.
- `EDGE_DIRECT` on the same IP as a cached canonical endpoint is
  rejected (NLB-IP + another port). Peer-advertised `AUTH_DIRECT` /
  `EXTERNAL` on that IP is allowed.
- Logs are split: `Path candidate`, `Path validation`, `Path META`,
  `Path route`.
