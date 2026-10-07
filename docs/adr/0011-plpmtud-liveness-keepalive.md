# ADR 0011: PLPMTUD, path liveness and adaptive keepalive

## Status

Accepted

## Context

One counter, `mtuprobes`, used to mean three things: discovery, a parked
path, and a liveness probe in flight. The discovery echoed full-size
datagrams. Those echoes, and the `maxmtu + 8` raise that replaced a
liveness probe, are what re-mapped the camera's NAT (F3, F5). A single
lost reply demoted the path and wiped the measured size. Idle mappings
expired between pings (F6). ADR 0010 is right that a keepalive does not
stop a remap that happens while the path is still sending. It does not
follow that an idle path should send nothing.

There is no public deployment of the old wire format. Initial WS1 uses
protocol 17.6; the C3 recovery/expiry-attribution follow-up uses 17.7 for
observed-endpoint metadata and recovery echoes. All endpoints and the NMN
are deployed together.

## Decision

Three machines per path, plus a small cache.

**PLPMTU.** Usable payload starts at 1211 (a 1232-byte UDP datagram after
the 21-byte SPTPS overhead) as soon as UDP is confirmed. The search
walks a fixed ladder: 1259, 1339, 1379, 1399, 1419, 1431, 1451. One
size is in flight. Three losses mark it failed and the search stops
there until the raise timer. The peer answers a size probe with a
64-byte ack that carries the received length. An echo request longer
than 64 bytes is dropped, so a peer can never be forced to send an
oversized reply.

After a size request times out, a timer-owned 64-byte recovery echo goes
out before another size attempt, separated by the health/size pacing
guard. It exposes a new NAT port even while application traffic remains
relayed during direct promotion. Admission denial consumes no size try
and queues no packet; a late size ACK remains valid until the retry is
actually sent. The echo carries a separate nonce and cannot confirm a
larger size.

Echo replies and size ACKs carry the request sender's observed endpoint
in bytes 12–31: marker `0xa7`, address family tag (4 or 6), a network-order
port and sixteen address bytes (IPv4 uses the first four). Rebind requests
carry the endpoint being challenged in the same layout. Observations are
used only from the confirmed peer endpoint, with reply nonces validated
by their owning machine. Backbone exchanges use the same observation;
they do not need ordinary-peer rebind support.

`EMSGSIZE` lowers the size immediately. A local remap within two
seconds of an oversized probe marks the path hostile and stretches the
raise interval, from 10 minutes, doubling, capped at a day. Two large
sends on a suspected route, followed by the suspect clearing, verify
the current size; three losses drop it to the base.

A liveness give-up pauses the search and keeps the size. Session change
and blacklist save it and disable the machine.

**Liveness.** Ordinary demanded peers only. The backbone node keeps its
own UDP timer. Up to three tries share one nonce. Any authenticated
reply from the confirmed endpoint counts. The greater name parks when
it sees the peer's request. Give-up tries a rebind rescue first, then
demotes the route. It does not start a new search.
Timer-owned liveness sends are immediate or denied, never queued: the
owner counts actual admitted attempts and retries denials itself. A
reply parks the window and cancels any remaining scheduler work.

**Keepalive.** Both ends of a direct path. A 64-byte keepalive goes out
only after that end has been idle for the interval, and only while the
path is in demand locally or the peer has been heard within 60 seconds.
It is not answered. The interval starts at 15 seconds for ordinary peers
and 25 seconds for the backbone. Select that default on confirmation,
when the role is known; a restored interval takes precedence. Record this
sender's outbound idle
gap only when it is at least the configured interval. An authenticated
observation of its own same-IP source port changing within 30 seconds of
that gap confirms a probable idle expiry, unless a recent oversized send
could explain the remap. A local liveness give-up and same-IP recovery
alone do not identify whose mapping expired. Unchanged mappings, public-IP
changes, another remote path and local network-epoch changes cannot teach
an expiry. A confirmed expiry shrinks the interval to 60 percent of the
gap that died, with a 5 second floor. It grows
20 percent an hour back to the cap.

Every successful UDP send to the confirmed endpoint refreshes this
sender's activity, including probe replies, rebind challenges and backbone
probes that use a destination override. Sends to another candidate do not
refresh the confirmed mapping. A failed nonblocking send is not outbound
activity. This accounting is covered through the actual probe-send callback,
as well as the keepalive state machine.

**Cache.** Four entries per node, keyed by remote IP with the port
zeroed. Each holds the size, the largest failure, the hostile flag, the
raise backoff, the keepalive interval, a timestamp and a fingerprint of
the local external address. Fresh entries restore without a probe.
Older ones are checked once. The array is a trailer on the host config.
Disabled and keys-only storage keep it in memory.
Cache flag `0x02` marks intervals written by the corrected sender-owned
algorithm. Legacy 17.6 intervals are ignored on restoration, since they
may reflect remote-side or oversize failures. Their MTU and hostility
information remains usable; the serialized tuple layout is unchanged.

Channel MSS uses the current PLPMTU as soon as UDP is confirmed.
Promotion to direct is not gated on the search.

## Rejected

- Patching the old echo search. The echo itself is the packet that
  re-maps the NAT.
- A fixed 1280 for every path. The field path carries more, and the
  relay budget wants that.
- Binary search between the base and the failure. The ladder is short,
  and a binary step is just another oversized datagram.

## Consequences

- ADR 0004's parked-PMTU liveness note is replaced by the liveness
  machine above.
- ADR 0010 still owns under-load rebinding. The keepalive here is only
  for idle expiry.
- `meshlink_get_pmtu()` returns the confirmed PLPMTU, or the minimum
  MTU when the node is reachable but UDP is not.
