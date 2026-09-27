# Demand-driven WAN hole punch

A camera and an app with a live channel punch a direct WAN UDP path when
the NAT is a port-restricted cone. The backbone tells each side the
other's current public UDP source. Neither side uses a stored
`recent[0]` address, and the backbone does not originate the punch.

`udp_confirmed` means a probe reply proved both directions. An inbound
authenticated UDP datagram is only a runtime observation: endpoint,
time, and session id. It is not persisted and it is not a route.

## Wire

Peers send this only while a channel is open, and only when the backbone
META connection speaks protocol minor 4 or newer:

```text
REQ_KEY <requester> <backbone> REQ_PUNCH_ENDPOINT <target>
```

The backbone answers with the existing address-only `ANS_KEY`, once in
each direction when both observations are fresh:

```text
ANS_KEY <observed> <recipient> . -1 -1 -1 0 <host> <port>
```

An empty forwarded `ANS_KEY` is filled the same way. A fresh observation
wins. A confirmed active endpoint is the fallback. `recent[0]` is not
copied onto the message. A forwarder that is not the backbone keeps an address already present. The backbone replaces a member-filled address with its observation, or drops it when it has none.

An observation older than 75 seconds, or one whose session id no longer
matches, is not sent. No observation leaves the peers on relay.

## What each side does

The receiver installs the hint only while it has channel demand and a
valid peer key. If its UDP to that peer is unconfirmed, the hint becomes
the probe destination and `send_mtu_probe()` runs. If some other UDP
endpoint is already confirmed, that endpoint stays and the hint is only
remembered. Confirmation still waits for a reply.

Requests share one ladder per peer: immediate on the first channel, then
1, 2, 5, 10, and 30 seconds until direct UDP confirms. A new hint, a
network change, or a new demand epoch starts the ladder over. Idle peers
send nothing. Opening a channel does not restart SPTPS when the key is
already valid.

Once direct WAN UDP is confirmed, it replaces a pending relay candidate
instead of waiting through that candidate's residency.

## Logs

Backbone:

- `Punch endpoint request for <target> from <requester>`
- `Fresh UDP observation for <node>`
- `No UDP observation for <node>`
- `Sending punch hint for <node> to <peer>: <host> port <port>`
- `Appending fresh UDP observation to ANS_KEY from <node> to <peer>`

Peers:

- `Requesting punch endpoint for <peer> via <backbone>`
- `Using punch hint from <peer>: <host> port <port>`
- `Keeping confirmed UDP endpoint of <peer>; punch hint stored` when a
  working endpoint must not be replaced

Nothing in these lines means the observation itself is confirmed.

## Symmetric NAT

The exchange still happens and both sides still probe. The port the
backbone saw is not the port that will accept the peer, so there is no
reply. `relay-udp` (or META relay) stays the route. That is the expected
result, not another punch attempt with a stored address.
