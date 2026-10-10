# ADR 0015: Backbone private-endpoint exchange

## Status

Accepted

## Context

A cloud-hosted stationary device such as a video storage node must use a
private unicast path to its network management node. Those nodes stay on
separate backbone machines. They may be on different workers and subnets in
the same VPC. Co-location and multicast discovery are not available, and the
application must not fetch a placement-specific address.

A private address range is not evidence that an address is on-link. Graph
edges, restored `recent[]` entries and unknown provenance must not be dialed
off-subnet. A working public direct carrier must still be able to move to a
private carrier. The public punch exchange (ADR 0008) stays public-only.

## Decision

### Provenance

`ADDR_SRC_BACKBONE_PRIVATE` is the only provenance that may leave the local
prefix. It is runtime evidence. `path_sanitize_recent()` rewrites a stored
copy to `ADDR_SRC_UNKNOWN` on load. Restart does not restore authority,
freshness or confirmation.

`ADDR_SRC_HINT`, `ADDR_SRC_AUTH_DIRECT` and `ADDR_SRC_CANONICAL` keep their
existing dial rules, with one exception: an `AUTH_DIRECT` entry for the
backbone that is off the local prefix is dialable only while the exchange
vouches for it. Authenticating there once, including before a restart, does
not outlive the backbone withdrawing the address. A hint is not granted this
exception. Loopback stays a
same-host case. IPv6 link-local requires a non-zero scope that matches an
interface index.

### Wire contract

Protocol minor 9. Older peers never receive these requests and keep current
behavior. The messages are `REQ_KEY` extensions, addressed to the peer that
must handle them. A forwarder cannot grant provenance: `from->connection`
must be the socket the message arrived on, and that socket's node must be
the named backbone (member side) or the requesting member (backbone side).

```text
REQ_KEY <member> <backbone> REQ_BACKBONE_PRIVATE <query_id>
REQ_KEY <backbone> <member> ANS_BACKBONE_PRIVATE <query_id> <session_id> <revision> <lifetime_s> <n> [<host> <port> <cap>]*n
REQ_KEY <backbone> <member> REQ_BACKBONE_PRIVATE_CHANGED <session_id> <revision>
```

`cap` is `PATH_CAP_META | PATH_CAP_UDP`. At most 8 endpoints. The reply line
must fit in `MAXBUFSIZE`. Lifetime is 300 seconds. The backbone answers at
most once per 2 seconds per connection; extra requests are dropped.

The published set is the cached local-network inventory crossed with the
mesh listen sockets: wildcard binds publish every private address of that
family, specific binds publish only themselves, with the bound port.
Loopback, unspecified, multicast, broadcast and link-local addresses are
not published. The NLB source, the canonical address and the external-IP
service are not sources.

### Freshness

One member-side owner per backbone. Query ladder: 1, 2, 5, 10, 30, 120
seconds with ±20% jitter. An empty set uses the 120 second step. Duplicate
replies and scheduler denial do not reset or advance the ladder.

A reply is accepted only when `query_id` matches the in-flight query,
`session_id` matches the backbone node, and `revision` is not older than
the revision already accepted for that session. A new session clears the
revision namespace. The member stores the local network epoch with the set.
`path_backbone_private_vouches()` is true only while the address is in that
unexpired set and the session and epoch still match.

The member re-queries on authenticated reconnect, session change, a
`CHANGED` notice, local network epoch change, expiry when a candidate needs
reuse, and private-path failure. A set from another session or network
vouches for nothing, so that query goes out at once rather than at the set's
expiry; only an in-flight query holds it back. A healthy proven private
carrier does not keep querying.

### Promotion

For the backbone link only, in order: proven private UDP, proven private
META, public UDP, canonical META. Ordinary peer ranking is unchanged.

META uses the ordered cutover (ADR 0009), including public-direct to
private. The standby must authenticate as the backbone and the session must
still match before commit. UDP validates a candidate beside a confirmed
public endpoint. The live endpoint and its keepalive are not overwritten
until the nonce, source, session, revision and network epoch all match.
TCP success does not prove UDP, or the reverse. Failure leaves the working
carrier in place and cools the candidate down (30 seconds, doubling, cap
10 minutes). SPTPS and UTCP are not restarted to discover or promote an
endpoint.

Authority is checked again when evidence lands, not only when validation
starts. A UDP reply that arrives after the set expired or stopped naming the
endpoint is dropped with its candidate. A META probe dialed from the set
carries that provenance, so a withdrawn endpoint still needs authority even
though it is no longer in the set: the probe is refused at authentication,
the barrier refuses to start, and READY does not lead to COMMIT. If the
endpoint is withdrawn after COMMIT went out, the peer has already committed,
so ACK completes the barrier and the connection is then closed rather than
kept as primary. Only candidate probes that actually leave count as
unanswered. The scheduler does not queue them, and denial just retries on the
next tick, so an exhausted budget cannot fail a candidate that sent nothing.

Once private carriers are selected, superseded public UDP keepalives and
speculative public probes stop. Proven private META unconfirms public
backbone UDP rather than leaving a confirmed mapping without liveness, so a
later fallback revalidates it instead of sending into a stale endpoint.
Private evidence does not enable mDNS or LAN broadcast.

Each transport validates on its own schedule. A healthy private carrier
stops endpoint queries, not validation of the other transport. An endpoint
counts as proven only while its carrier is up; once that carrier is lost it
is validated again (subject to failure cooldown), so a transient private
outage does not end private use for the session.

A regular backbone UDP probe that confirms an endpoint in the vouched set is
recorded as private, the same as the candidate proof. While private META is
proven, public destinations are not opened for backbone UDP, and data rides
private META rather than public UDP. Private-range destinations stay
eligible.

A private META carrier stays put while its address is still vouched. It
cuts over to another vouched listener only when its own address has left the
current set, so a multi-homed backbone does not churn between listeners.

### Outage policy

`MESHLINK_BACKBONE_PATH_PREFER_PRIVATE` is the default. Ranking puts proven
private carriers first; when none is up, public UDP and canonical META carry
data immediately. There is no hold-down: withholding public here would only
turn a private outage into a data outage. The member keeps re-querying and
promotes back once private is proven again.

`MESHLINK_BACKBONE_PATH_PRIVATE_ONLY` is opt-in and runtime-only. Until a
private carrier has been proven in the current backbone session, public
carriers carry data (bootstrap, and recovery after a new session). After
that, every send resolution, including an already recorded route and the
temporary fallback for a suspect private route, is limited to private
carriers. Data to the backbone is reported unavailable until private works
again. META control traffic may still use the canonical anchor. The setting
is not written to host config.

### Relocation

A graceful change keeps the session, bumps the revision, and sends
`CHANGED`. The member validates replacements before retiring a working
carrier. A new session invalidates private evidence and in-flight
validation. Recovery uses the canonical anchor when nothing else works,
then queries the new instance. A delayed reply from the old session cannot
commit. This does not promise hitless channels across a process restart.

## Consequences

- Protocol minor becomes 9. Public punch messages are unchanged.
- Off-subnet RFC1918 and ULA graph, unknown and restored entries are not
  dialed unless the exchange vouches for them. Tests that used an invented
  private address need a matching interface snapshot.
- Deployment placement and cross-AZ charges stay an infrastructure concern.
  Meshlink does not infer them from the address class.
