# ADR 0005: Persistent backbone identity

## Status

Accepted

## Context

Device class (`DEV_CLASS_BACKBONE`) is a weight and timeout hint. Treating
the live set of backbone-class nodes as "who the backbone is" elects a
new identity whenever graph data contains a second such node. META
recovery and relay then disagree on the re-entry node.

Finding 3 owns that identity. It does not own invitation-creation
gating, autoconnect pools, or relay hop selection.

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
2. `join` requires the inviter host config to be `DEV_CLASS_BACKBONE`
   and commits that name before return. Invitation v3 carries the name
   explicitly; v2 infers it from the first host blob. Join rebuilds
   `current/`, so it clears any identity a prior `start` committed.
3. `start` commits self only if the name is still unset and self is
   `DEV_CLASS_BACKBONE`.

Gossip (`ADD_EDGE` / ACK) never calls `set_backbone`. First write wins;
a different name is refused.

`conflict_backbone` is a **conflict detected** bit, not quarantine.
It is set when:

- a node is `DEV_CLASS_BACKBONE` but is not the stored identity, or
- the stored identity resolves to a node whose class is not
  `DEV_CLASS_BACKBONE`.

Finding 3 does not exclude those nodes from autoconnect, graph routing,
gossip, or relay. Findings 5 and 10 must skip `conflict_backbone` nodes
when choosing META pools and the relay hop.

Missing sidecar on an existing confbase migrates only when the answer is
unambiguous: self-only BACKBONE, or exactly one other BACKBONE host.
Two or more BACKBONE hosts: do not guess.

## Consequences

- Production joins fail (`MESHLINK_EPEER`) if the inviter is not
  backbone-class. Invite *creation* stays ungated until finding 4.
- Import does not elect. A second backbone-class host is marked
  `conflict_backbone`; it still participates in the mesh until
  findings 5 and 10 exclude it.
- Forgetting the backbone node drops the pointer; reopen still knows
  the name.
- Ephemeral / `STORAGE_DISABLED` keep the name in memory only.
- Autoconnect and `path_active_send_target()` are unchanged in this
  finding.
