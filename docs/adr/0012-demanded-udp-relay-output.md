# ADR 0012: Demand-owned UDP relay output and directional budgets

## Status

Accepted for WS2. Field validation is pending.

## Context

An endpoint's backbone mapping only proves the endpoint's sending direction.
The NMN cannot infer a durable output path from an incoming application packet
or keepalive. Previously its output usually stayed on META, and oversized
records on a ready hop could be silently dropped. SPTPS also encrypts its type,
so a forwarding NMN cannot identify application data in legacy `REQ_SPTPS`.
The NMN cannot see end-to-end channel acknowledgements to detect every silent
reduction of its output path's MTU.

## Decision

Each NMN output peer has one runtime relay-hop owner, shared by every relayed
flow. A validated application envelope extends its demand for 30 seconds,
including records carried on META. Application channels and ordinary punching
remain endpoint-owned. Advertised addresses never establish relay readiness.

A fresh, authenticated UDP observation supplies a candidate. A 64-byte echo
with purpose `RELAY_HOP` challenges that exact endpoint. Only an authenticated
reply with the same nonce, peer session, network epoch, endpoint, purpose, and
unexpired demand commits readiness. There are two actual socket transmissions,
at least a second apart, and an absolute ten-second deadline. Admission denial
and socket failure consume no attempt. After failure, the same candidate waits
30 seconds; a different authenticated candidate can start sooner. A working
endpoint stays usable while a replacement is challenged. IP-scoped WS1 cache
knowledge survives port replacement.

This is a narrow exception to ADR 0008's prohibition on NMN-originated probes:
only demanded relay output hops may originate readiness, health, keepalive,
and size probes. Confirmation bypasses ordinary route promotion and does not
advertise addresses. Requests and backbone keepalives do not extend demand.
Expiry, key loss, peer reconnect, session change, network change, blacklist,
node deletion, and shutdown cancel owned work and require a fresh proof.

Protocol 17.8 appends `REQ_SPTPS_APP` without changing prior request numbers.
Its origin, destination, and base64 ciphertext have the legacy envelope shape.
Only application type 0 uses it, and only to a directly connected META hop
advertising minor 8. A destination authenticates the encrypted datagram and
applies replay protection using application-only receive handling; handshake
and probe records cannot execute through this envelope. A forwarding NMN
uses the same output decision for marked META ingress and UDP type-8 ingress.
Legacy unmarked envelopes continue on META. Fallback to an older META hop
translates to legacy `REQ_SPTPS`, preserving the original inner ciphertext.

An output sends only if the exact endpoint is proved and the fully wrapped
record fits. Oversize, absent socket, would-block, `EMSGSIZE`, and hard failure
attempt META once. `EMSGSIZE` also updates PLPMTU; a hard error at the proved
endpoint revokes readiness. A successful UDP socket send never has a META
fallback. Devtools distinguish these outcomes and count actual UDP sends.

`REQ_RELAY_MTU` reports only the NMN's outbound final-hop packet budget after
type-8 wrapping overhead. The origin computes:

```
overhead = 2 + len(origin) + len(destination) + 21
first = origin-to-NMN PLPMTU - overhead
final = valid NMN report, or MINMTU - overhead until one arrives
packet budget = min(first, final)
channel MTU = packet budget - sizeof(meshlink_packethdr_t)
```

Subtractions and name limits are checked. UTCP performs its existing header
deduction. The reverse NMN-to-origin PLPMTU is never substituted for the first
leg. Reports belong to the current nexthop and reporting connection. Both leg
changes refresh channels; reductions and readiness reacquisition refresh
reports for active flows.

Older origins do not clamp a final-hop report against their first hop. Until
the NMN's directly connected origin advertises 17.8, its offered output budget
therefore stays at the conservative legacy floor. This keeps NMN-first rollout
from growing legacy senders past their first-hop size. Oversized final-leg
records still have the normal META fallback.

While demand remains active, settled output paths verify their current usable
size nominally every 30 seconds, staggered by up to two seconds. This uses
WS1's fixed-size acknowledgement, three-attempt bound, recovery echo, and
size-reduction behavior. Verification coalesces with search and preserves
hostile holds and the existing raise deadline. Denied admission does not count
as loss. All probes use existing mesh-wide caps. Verification age, overdue
milliseconds, and admission delays expose scheduler-limited detection time.

## Consequences

No public MeshLink application API or persisted readiness format changes.
Mixed-version meshes retain connectivity, with limited META-ingress
optimization until the directly connected hops upgrade. Deploy the NMN first,
then endpoints. Match NMN, camera, and Android build identities in field logs;
measure each leg's actual carrier, directional budget, rebinding recovery,
and silent size-drop recovery. WS3 startup route delay remains a separate
acceptance question. No field deployment or capture is implied by passing the
local Docker tests.
