# ADR 0003: Hitless path handover

## Status

Accepted

## Context

ADR 0001 ranks validated paths. ADR 0002 scopes `recent[]` by transport.
Production logs still showed three holes:

1. Promoting a direct META spare called `send_req_key()`, which stopped
   node SPTPS, cleared `validkey`, and dropped in-flight channel data.
2. A graph-derived NLB-IP with the peer's advertised NMN port was probed
   as UDP (`EDGE_DIRECT` / leftover `UNKNOWN`).
3. Startup walked every recent and known address before the canonical
   NLB, so a black-hole private endpoint delayed the first working path
   by the ordinary connection timeout.

## Decision

Startup is sequential and bounded. Try exactly one best META-capable
direct candidate for 250 ms (TCP connect plus Meshlink authentication).
If it has not authenticated, cancel it and dial the canonical NLB. If no
direct candidate exists, dial canonical immediately. Canonical DNS may
be pre-resolved while the direct socket is pending; two startup sockets
are never opened.

After any path is active, upgrades are make-before-break: validate a
better path in parallel, keep the current path carrying traffic, promote
only after authentication, then drain and close the old META. Already
queued encrypted META bytes may flush. A drain timeout is a cleanup
guard only.

An authenticated direct META upgrade preserves node SPTPS, `validkey`,
UTCP channels, UDP proof, and relay budgets when the old connection was
an active canonical META for the same node and the node has not been
marked as a new process. A first connection, missing key, interrupted
key exchange, or session-identifier change still bootstraps normally.

Graph-derived `EDGE_DIRECT` and leftover `UNKNOWN` endpoints that share
an IP with a resolved canonical endpoint but use another port are not
UDP or META candidates. Peer-vouched `EXTERNAL`, `AUTH_DIRECT`,
`UDP_REFLEXIVE`, discovery, and application hints on that IP remain
legal.

Selected-route logs are owned by `path_note_selected_route()`. UDP
validation and META socket migration use `Path UDP` and `Path META`.

## Consequences

- `ack_h()` snapshots `upgrade_probe` before the flag is cleared and
  skips `send_req_key()` only when `upgrade_should_preserve_node_session()`
  is true.
- `recent[]` sanitation drops untrusted hybrids and persists the result.
- The outgoing walk no longer serializes leftover direct candidates
  before NLB. Those candidates are validated after a lower path is
  active, or on a later fallback.
- `node_status_cb` does not fire across a META socket replacement.
  `meta_status_cb` may describe the replacement and must not be read as
  unreachability.
