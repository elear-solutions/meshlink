# ADR 0005: Persistent backbone identity

## Status

Accepted

## Context

Device class (`DEV_CLASS_BACKBONE`) is a weight and timeout hint. Treating
the live set of backbone-class nodes as "who the backbone is" elects a
new identity whenever graph data contains a second such node. META
recovery and relay then disagree on the re-entry node.

Finding 3 owns that identity. It does not own invitation-creation
gating or relay hop selection. Finding 5 owns META pool skip of
`conflict_backbone`.

## Decision

The invariant is a **name**. The cached `node_t *` is resolved while the
host exists and cleared on forget/delete; the name stays.

Persist it in sidecar `current/backbone` (packmsg `uint32 version=1` +
name) and `config_sync()` the containing directory after write. Do not
bump `MESHLINK_CONFIG_VERSION` and do not append a field to
`meshlink.conf` — that layout is shared with host configs, export/import,
and invitation blobs.

Do not stamp self in `meshlink_setup()`. Sequence:

1. `open` leaves the identity unset on a new confbase.
2. `join` requires invitation v3, the inviter host config to be
   `DEV_CLASS_BACKBONE`, and the v3 identity to match that host. It
   commits that name before return. Join rebuilds `current/`, so it
   clears any identity a prior `start` committed. Invitation *creation*
   and *serving* are finding 4 / ADR 0006.
3. `start` commits self only if the name is still unset and self is
   `DEV_CLASS_BACKBONE`.

Gossip (`ADD_EDGE` / ACK) never calls `set_backbone`. First write wins;
a different name is refused.

`conflict_backbone` is a **conflict detected** bit, not quarantine.
It is set when:

- a node is `DEV_CLASS_BACKBONE` but is not the stored identity, or
- the stored identity resolves to a node whose class is not
  `DEV_CLASS_BACKBONE`.

Finding 3 does not exclude those nodes from graph routing,
gossip, or relay. Finding 5 skips `conflict_backbone` nodes when
choosing META pools. Finding 10 must skip them as the relay hop.

Missing sidecar on an existing confbase migrates only when the answer is
unambiguous: self-only BACKBONE, or exactly one other BACKBONE host.
Two or more BACKBONE hosts: do not guess.

## Consequences

- Production joins fail (`MESHLINK_EPEER`) if the inviter is not
  backbone-class. Invitation create/serve gating is ADR 0006.
- Import does not elect. A second backbone-class host is marked
  `conflict_backbone`; finding 5 already skips it for META pools, and
  finding 10 still owns relay-hop skip.
- Forgetting the backbone node drops the pointer; reopen still knows
  the name.
- Ephemeral / `STORAGE_DISABLED` keep the name in memory only.
- Autoconnect is gone. Backbone META is a reserved
  `BACKBONE_REQUIRED` intent in `connection_policy` (ADR 0007); LAN fill
  is finding 7.
