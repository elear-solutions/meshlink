# ADR 0013: WS3 route promotion after backbone proof, reachability, and rebind

## Status

Accepted; field validation pending

## Context

WS1 made a usable base MSS available as soon as UDP confirms, and WS2 made
UDP relay output usable for demanded channels. Route selection still left
application traffic on META relay for roughly 30–40 seconds in the C3
captures. A direct candidate could occupy the only promotion slot while
the same backbone first hop already had a proved UDP carrier. The old
30-second active-route residency also delayed an otherwise ready direct
route. L1 showed offline destinations starting and committing promotions.
C3 showed a validated same-IP rebind moving the confirmed endpoint while
a pending direct candidate retained the old port until its later commit
attempt failed.

## Decision

- Elective route promotions retain the one-second validation hold and use a
  ten-second minimum active-route residency. The existing approximately
  five-second route tick performs the eventual commit; no separate
  deadline timer is introduced.
- A demanded META relay through the configured backbone may replace its
  META carrier with that same hop's confirmed UDP carrier after one second
  of backbone proof. This carrier change keeps the destination's
  `selected_at` timestamp and does not consume its promotion slot. A
  pending higher-ranked direct or local candidate remains pending.
- Unreachable destinations cannot start, validate, or commit elective
  promotions. A pending candidate is retired when a route tick observes
  unreachability. Reachability recovery resumes normal selection while
  preserving the learned PLPMTU cache.
- A validated same-IP rebind updates a nonce-free direct candidate for the
  old endpoint to the newly confirmed endpoint and its authenticated
  source/capability. The candidate's one-second hold restarts at the
  rebind proof; the active route's residency does not. A candidate whose
  proof nonce belongs to the old endpoint is discarded and reconsidered
  immediately after the rebind completes. Unrelated candidates are kept.

## Consequences

The common META-to-backbone-UDP step can occur on the next route tick
after its one-second hold, even while direct UDP is proving. Direct UDP
still waits for two authenticated rounds, its hold, and ten seconds of
active-route residency. The shorter residency trades some route stability
for faster direct use; field captures must measure oscillation and
retransmits as well as time spent on META and UDP relay. No field result is
claimed by this ADR.

This refines ADR 0004's route-residency policy and ADR 0008's direct-over-
relay candidate rule without changing route preference order or the
one-candidate limit.
