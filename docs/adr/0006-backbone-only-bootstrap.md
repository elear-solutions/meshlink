# ADR 0006: Backbone-only production bootstrap

## Status

Accepted

## Context

Finding 3 stores a unique backbone name. Invitation *creation* and
*serving* stayed ungated, so a stationary node or a conflicted extra
backbone-class node could still mint a URL. Join only checked that the
first host blob was `DEV_CLASS_BACKBONE`, so that extra node became the
joiner's stored identity.

Finding 3 already persists identity through join, close, and reopen.
This finding owns who may create and serve production invitations.

## Decision

Only the unique backbone creates and serves production invitations.

`connection_policy_can_invite()` is internal and name-based:

- device class of self is `DEV_CLASS_BACKBONE`
- identity is unset only when this node is an unambiguous creator:
  self is not `conflict_backbone` and exactly one BACKBONE-class node
  exists (a pristine network is just self; invite-before-start still
  works). Ambiguous legacy topologies with a missing sidecar cannot
  elect themselves by inviting.
- otherwise `connection_policy_is_backbone(self)`

Do not compare `backbone.node == self`; the pointer is cleared on forget.

Invite commits self as backbone when the name is still unset, using the
same helper as `start()`. That helper also refuses to guess when more than
one BACKBONE-class node is present. `start()` commits before `init_outgoings()`.

The invitation v3 field is the stored backbone name, not raw `self`.
Join requires version 3, that field present, and it equal to the first
host name. First host must still be `DEV_CLASS_BACKBONE`. Failures stay
`MESHLINK_EPEER`. A prior `start` that stamped self is still cleared on
join (ADR 0005). Join parses and validates the whole invitation into
temporary objects (including `packmsg_done()`) before mutating the handle
or replacing `current/`. The replacement is built under `new/` and
renamed into place.

Create/serve refusal is `MESHLINK_ENOTSUP`.

Tests may call `devtool_set_allow_peer_bootstrap()` so a non-backbone
handle can plant an invitation file. That flag does not weaken
`meshlink_join()`. A bypass invitation from a joined extra backbone-class
node stamps the stored name while the first host blob is still self, so
join fails the identity match.

## Consequences

- Cameras cannot become bootstrap authorities.
- A second backbone-class node that joined through the unique backbone
  cannot invite.
- Leftover invitation files on a non-backbone node are not served.
- v2 invitation blobs are rejected.
- Autoconnect pools are replaced by purpose-owned intents (ADR 0007).
  Relay hop selection is unchanged (finding 10).
