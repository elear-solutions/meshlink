# WS4 implementation scope

Analysis date: 2026-10-08. Baseline: `ws3-route-selection` at
`e6e02e9caa793f35db6f522f5e40348b884f268f`.
M2 design revised: 2026-10-09, for separate NMN/VSN BBNMs and automatic
backbone private-path discovery.

This is a proposed implementation scope, based on source inspection, existing
tests, ADRs, and targeted reads of C2 and the supplied WS2 Android capture.
It does not change production code or establish new test/field acceptance.
The active WS3 review may change this baseline; recheck the touched functions
against its final head before implementation.

## Assessment

The remaining work is **M2, M3, M4, M5 and F10**. M1 and M8 already exist in
the current branch and should retain their review, full-suite and field gates.
M6 is expected NAT behavior and M7 belongs to the application layer.

The largest change is F10. It touches the channel contract, UTCP lifecycle,
callback reentrancy, AIO ownership, public C/C++ interfaces and SDK adoption.
M2 is also more than a predicate: it needs a local-interface inventory,
authenticated backbone private-endpoint exchange and carrier migration.
M4 and M5 have concrete causes; changing only log frequency would leave the
duplicate control traffic and retry accounting in place. M3's historical
PMTU behavior has largely been removed by WS1, so its remaining scope is
explicit discovery eligibility and regression coverage.

Recommended delivery order:

1. Fix M4/M5 control-request ownership and add deterministic coverage.
2. Implement M2 private-endpoint discovery/promotion and subnet eligibility;
   use its separate on-link evidence to finish M3 discovery guards.
3. Repair F10 terminal notification/reason handling under the existing contract.
4. Add F10 availability feedback and an opt-in sustained-offline close policy.
5. Complete consumer adoption and Hemanth-path acceptance.

Each increment should be independently reviewable and pass the serial Docker
suite. The F10 contract can be settled while the smaller changes are built.

## M1 and M8: implemented prerequisites

M1's rolling six-migration threshold and 60-second warning suppression are in
`path_rebind_note_flap()` (`src/path_policy.c:4227`). The suppression deadline
is separate from endpoint challenge state; preserve that separation.

M8 closes the failed netlink descriptor in `discovery_start()`, logs interface
index plus system error for multicast-interface failures, and rescans from
`meshlink_hint_network_change()` while discovery is enabled. ADR 0014 and
`test/discovery-failure.c` cover the intended fallback. That test checks 16
failure/start/stop cycles, descriptor stability, address refresh, IPv4/IPv6
diagnostics and a plain OS unicast UDP exchange. The latter is a limited
environment check, not an end-to-end Meshlink-channel test.

The tracker records targeted success and a follow-up full run stopped after
25 passing tests. Do not inherit the earlier WS3 58-test result as validation
of the later M1/M8 commit. Their final full-suite result remains owned by the
active review. Field validation is still required.

## M2: private candidate eligibility and backbone private-path discovery

### Required behavior

Cloud-hosted stationary devices such as the video storage node (VSN) must be
able to use private unicast paths to their network management node (NMN).
NMNs and VSNs remain on dedicated BBNMs with independent placement and scaling.
They may be on different workers and subnets within the same VPC; co-location
and multicast discovery are not prerequisites.

A VSN joins normally through the canonical/NLB endpoint. Meshlink then queries
its authenticated backbone for that backbone's current private listening
endpoints, validates them and promotes successful private carriers for both
META control traffic and clusterprotocol channel traffic. The SDK/application
does not fetch an NMN address from TrustCenter or inject a placement-specific
hint. Endpoint discovery, validation, retry and promotion belong to Meshlink.

Defrag may move the logical NMN to another BBNM and change its private addresses
and ports. Keep the canonical endpoint as the stable bootstrap/recovery anchor;
refresh private candidates from the authenticated NMN instance rather than
treating an old endpoint as permanent identity.

Private unicast reachability is distinct from on-link LAN membership. A routed
private endpoint may be eligible for validation without permitting broadcast
or mDNS. This scope does not infer AWS billing or AZ placement from address
class: private traffic can still incur cross-AZ charges. It establishes the
transport behavior; deployment placement remains an infrastructure concern.

### What the code does

[`path_address_is_local()`](/Users/ashish/coco-project/third-party/meshlink/src/path_policy.c:376)
classifies loopback, RFC1918, IPv4 link-local, IPv6 link/site-local and ULA by
address range. It does not determine whether an address is on a local subnet.

`sssp_bfs()` (`src/graph.c:135`) learns direct graph addresses as
`ADDR_SRC_EDGE_DIRECT` with `PATH_CAP_BOTH`. `graph_may_seed_udp()`
(`src/node.c:316`) refuses RFC1918/ULA as the initial graph-seeded UDP address,
but this does **not** remove them from `recent[]` or all later pickers.

[`path_is_direct_candidate()`](/Users/ashish/coco-project/third-party/meshlink/src/path_policy.c:290)
and `path_is_udp_candidate()` check provenance, canonical-equivalence,
transport capability and untrusted canonical-IP hybrids. Neither checks
local subnets. Consequences include:

- META startup: `path_best_startup_meta()` walks recent entries and raw reverse
  graph edges, then `get_next_outgoing_address()` dials the selected address.
- META upgrade: `pick_probe_address()` in `net_upgrade.c` uses the same
  candidate policy; startup-only filtering would miss upgrades.
- LAN META: `path_best_local_meta()` prefers discovery/authenticated sources
  but treats private address class as locality.
- UDP bootstrap: `choose_udp_address()` tries recent, catta, reverse-edge and
  current-node addresses. `lan_candidate()` only checks family, self endpoint
  and the WAN address to skip.
- Local UDP promotion: `path_pick_local_udp_candidate()` explicitly ignores
  its `mesh` argument and treats private range/source as sufficient evidence.
- Private authenticated ingress can separately start a nonce challenge;
  active proved paths must be distinguished from speculative candidates.

Two existing mechanisms are useful but do not fulfill this requirement:

- ADR 0008's `REQ_PUNCH_ENDPOINT` exchanges fresh observed public NAT mappings
  for ordinary peers, not the backbone's own private listening endpoints.
  Its private-address export restrictions must remain intact.
- ADR 0009 provides ordered canonical-to-direct META cutover. The current
  `path_upgrade_ineligible_reason()` rejects an already-direct META primary,
  and `path_backbone_udp_note_direct()` ignores new candidates while backbone
  UDP is confirmed. A working public direct carrier therefore needs explicit
  support for promotion to private; learning another address is insufficient.

The current interface inventory cannot implement a correct prefix check.
`discovery_address_t` (`src/discovery.c:89`) stores index, up flag and address,
but no netmask/prefix. `scan_ifaddrs()` discards `ifa_netmask`; Linux netlink
parsing discards `ifa_prefixlen`; PF_ROUTE parsing consumes only `RTA_IFA`.
The discovery fingerprint also omits prefixes. A mask-only change currently
cannot invalidate eligibility through that fingerprint.

### Proposed implementation

Introduce one internal **local-network inventory module** with a cached snapshot
of local interface address/prefix/scope/flags and small, separate query interfaces
for on-link eligibility and private endpoint publication.
Use the cached query in candidate selection; never call `getifaddrs()` per
packet, per graph edge, or per retry.

A concrete placement is `src/local_network.c/.h`, with snapshot refresh,
eligibility query and teardown behind that interface, plus `src/Makefile.am`
registration. Share the query between META/UDP policy and local discovery;
keep platform enumeration details inside the inventory implementation.

The snapshot must work with discovery disabled, notification socket failure,
and platforms using different discovery backends. The mDNS address set is
not enough: it excludes point-to-point interfaces and marks interfaces down
when they lack multicast support. VPN/private unicast eligibility must not
depend on multicast membership. Prefer an inventory that discovery can refresh
without making discovery sockets its lifetime owner.

Refresh at start, network-change hints and supported native notifications.
Include prefix and relevant interface state in change detection. On scan
failure, define snapshot freshness and a conservative speculative-address
policy; retain already authenticated working carriers. A network change must
make cached candidates re-evaluable, including candidates loaded from storage.

Apply eligibility at **use time**, rather than erasing off-subnet addresses
from persisted `recent[]`. This preserves useful addresses when the device
returns to that network. Keep provenance and capability independent per ADR
0002. Put the rule in shared candidate policy and audit raw picker fallbacks;
filtering only the learning function misses reverse-edge reads, catta and
legacy stored entries.

Candidate rules:

- Unsolicited graph-derived/unknown RFC1918 and ULA speculative destinations
  must match an active local prefix. Raw reverse-edge and persisted fallbacks
  must not bypass this rule.
- A private endpoint supplied by the backbone itself through the authenticated
  exchange below permits bounded unicast validation even outside the local
  prefix. Give this evidence distinct provenance and runtime freshness; do not
  inherit the exception from generic `HINT`, `EDGE_DIRECT` or restored storage.
- IPv6 link-local requires a usable matching interface scope; zero scope is
  insufficient. Loopback is a separate same-host case, not an ordinary LAN.
- Keep required canonical/backbone META dialing out of the speculative
  direct-address filter. Explicit private deployments must still bootstrap.
- Preserve authenticated working sockets and nonce-proved ingress. Application
  hints for other routed private/VPN peers remain a separate policy decision;
  the backbone exchange does not grant all hints an off-subnet exception.
- A matching subnet is permission to attempt validation, not proof of a peer.
  Likewise, an authenticated advertisement is not proof of endpoint reachability
  or identity. Overlapping private ranges must never select a different peer.

#### Authenticated backbone private-endpoint exchange

Add a capability-negotiated request/reply exchange for the backbone's own
private endpoints over its live authenticated META connection. It is separate
from the public punch exchange, although scheduler ownership, bounded retries,
nonce validation and freshness conventions should be reused where appropriate.
Do not repurpose the public address-only `ANS_KEY` hint as private evidence.

After backbone META authentication, a supporting member automatically requests
the private endpoint set even if public UDP already works. The reply must come
from the expected unique backbone on the current authenticated connection.
Forwarded graph messages or another member's assertion cannot grant this
provenance. Rate-limit requests and replies and bound endpoint count/message
size. Unsupported peers retain existing behavior; an empty endpoint set is an
explicit result that backs off rather than causing a rapid request loop.

Publish active RFC1918/ULA addresses on which the backbone's mesh listeners
are reachable, with their actual ports and independent META/UDP capabilities.
Use the cached inventory and socket binding context, not the TCP source seen
through NLB/Demux, the public canonical address, or the external-IP service.
Do not publish remote-unusable loopback, unspecified, multicast, broadcast or
unscoped link-local addresses. Multi-interface inventory must be bounded and
respect the Meshlink network namespace. Never enumerate interfaces per query.

Bind each reply/candidate to a query ID, backbone identity/session, endpoint-set
revision and a bounded runtime lifetime. A revision changes when the published
address/port/capability set changes, including within a surviving session;
session change invalidates the prior revision namespace. Reject stale replies
and invalidate in-flight validation on session or local network-epoch changes.
Persisted addresses may remain hints, but cannot restore freshness, provenance
authority or confirmation for this exception after restart.

One member-side request owner per backbone is shared across all channels and
the required backbone connection. Retry on a bounded schedule with backoff/jitter; duplicate
replies and scheduler denial must not reset it or spin. An ordinary field device
that cannot reach the NMN's private endpoints records bounded failures and backs
off. Refresh on authenticated reconnect/session change, endpoint-set change,
local network change, expiry when a candidate needs reuse, and private-path
failure. A failed-write delay is scoped to its authenticated META connection
generation, backbone session and full local network epoch; reconnect/cutover or
network change retires that delay through the existing query owner. Unchanged
failed writes remain paced, accepted queries retain their in-flight deadlines,
and timeout plus failed resend advances once. Hold retirement does not erase
endpoint cooldowns or backbone publication revision/hash. Deterministic lifecycle
regressions cover these contracts; field acceptance still requires the evidence
below. A healthy private carrier does not require continuous endpoint queries.

#### Validation and carrier promotion

Keep the current working primary while validating private candidates. TCP must
authenticate the expected NMN identity and become a standby before ordered META
cutover. UDP requires an authenticated nonce/source-matched challenge tied to
the current candidate/session/network epoch; the reply advertisement alone
never confirms UDP. TCP success does not prove UDP capability, or vice versa.

Extend ordered META cutover to support public-direct-to-private transitions as
well as canonical-to-private. Extend the backbone UDP owner to validate a better
private candidate while a public endpoint is already confirmed, with separate
candidate state so validation does not overwrite the live endpoint or keepalive.
Commit only after proof and applicable migration guards; failed candidates leave
the working carrier usable and receive bounded cooldowns. Do not restart SPTPS
or UTCP merely to discover or promote an endpoint.

For the backbone link, prefer proved private carriers over public carriers.
Private UDP supplies the preferred direct private/local data path; proved private
META supplies the fallback before public UDP or canonical META. This preference
must use private-path evidence, not turn every RFC1918 graph entry into a usable
route. Keep ordinary peer ranking unchanged unless separately justified. Once
the private carriers are selected, retire superseded public carrier keepalives
and speculative probes; moving application payload alone is insufficient for
private steady-state traffic. Private unicast evidence never enables mDNS or
LAN broadcast by itself.

#### Backbone relocation and recovery

The logical backbone identity survives placement changes; endpoint authority
belongs to its current authenticated session/revision. On a graceful address
change with a surviving session, announce an endpoint-set revision change and
refresh/validate replacements before retiring a working carrier where possible.
On restart or abrupt relocation, invalidate old session evidence and reconnect
through the canonical anchor when no working path remains. Query the replacement
instance's private endpoints and promote them after fresh validation. Address or
port reuse by another node must fail identity/nonce validation; delayed replies
from the old instance cannot roll back the endpoint set or commit a stale path.

Canonical/public traffic is allowed during initial bootstrap and recovery.
This does not promise zero public traffic during defrag, or hitless channel and
subscription continuity across an NMN process restart. Use existing session and
application recovery semantics for that case. Settle whether prolonged private
failure permits public steady-state fallback or reports unavailable under an
opt-in private-only policy; automatic discovery does not itself settle that
availability/cost trade-off.

Expected edits: local-network inventory owner, `discovery.c/.h`,
`meshlink_internal.h`, lifecycle/hint paths in `meshlink.c`, shared predicates
and pickers in `path_policy.c/.h`, `net_packet.c`, and affected META consumers
in `net_socket.c`, `net_upgrade.c`, `connection_policy.c`; backbone candidate
ownership in `path_backbone_udp.c/.h`; and capability/request dispatch plus
private-endpoint exchange in `protocol.h`, `protocol_key.c` and authentication
paths as needed. Record the wire contract and provenance/promotion rules in an
ADR before implementation. Prefer using
`n->mesh` where the existing node-scoped predicate already provides context;
change signatures only where necessary. `graph.c`/`node.c` need an audit,
not deletion of graph topology.

### Acceptance coverage

Use fake interface snapshots to verify real masks, not assumed /24 or /64:
same/off-subnet IPv4, multiple interfaces, down/removal, IPv6 ULA, scoped
link-local, loopback, private VPN interfaces, mask-only changes, scan failure,
discovery disabled, and native-notification fallback. Test a stored candidate
becoming eligible after a network change.

Plant `10.20.1.181` with `EDGE_DIRECT` provenance against a different local
prefix and verify zero META dials and UDP candidate emissions through startup,
upgrade, promotion and bootstrap. Separately supply a real off-subnet private
endpoint through the authenticated backbone exchange and verify bounded unicast
validation is allowed. Keep public, canonical, authenticated,
same-subnet LAN and hairpin cases working. Cover both IPv4 and IPv6.

Add end-to-end backbone cases with discovery disabled and NMN/VSN in separate
network namespaces connected through routed private subnets:

- Join via canonical META, establish public direct META/UDP first, then query
  and prove the private set. Assert META and UDP both migrate, the existing
  channel delivers ordered data without promotion-induced reset, and healthy
  steady state emits no NMN traffic on superseded public carriers.
- Private UDP fails but private META works: channel traffic uses private META
  before public carriers. Cover TCP-only and UDP-only endpoint capabilities and
  the explicitly chosen outage fallback policy.
- Multiple channels issue one shared query ladder; empty sets, unreachable
  private addresses on field devices, duplicate replies, query timeout,
  scheduler denial and cooldowns remain bounded. New hints do not restart an
  in-flight challenge or erase proof for the working carrier.
- Forged/forwarded replies, wrong backbone/peer identity, expired advertisements,
  restored candidates without current authority, and mismatched query ID,
  session, revision, nonce or UDP source cannot commit a route.
- Graceful endpoint change within one session and abrupt NMN move to another
  BBNM with changed private IP/port. Recover through canonical when necessary,
  query the new session, and return to private steady state. Cover old/new
  reply reordering, interface removal, IP/port reuse by another peer, and
  same-IP port-only change. Do not require hitless channels across process restart.
- Older peers without exchange capability retain connectivity; private-path
  success never schedules mDNS/broadcast for a routed-only destination.

Extend `path-policy-coverage`, `transport-recent`, outgoing/canonical tests,
`discovery-failure`, backbone UDP, ordered META cutover, protocol negotiation,
LAN discovery and NAT integration as appropriate. Tests
that currently assume any invented private address is usable need an explicit
matching test subnet rather than weakened assertions.

The NMN load-balancer client-IP/proxy-protocol correction remains infrastructure
work. Meshlink-side filtering cannot repair a bogus same-subnet address.

## M3: broadcasts for WAN-only peers

### Baseline differs from the original capture

WS1's size search emits `SIZE_REQUEST` to a confirmed path. The remaining
broadcast producer is
[`path_local_discovery_tick()`](/Users/ashish/coco-project/third-party/meshlink/src/path_liveness.c:754),
which emits a 64-byte echo with `PROBE_PURPOSE_LOCAL_DISCOVERY`, not a padded
PMTU size search. Before this change its first few tries broadcast whenever
`n->prevedge` existed; that condition alone says nothing about LAN presence.

The only production caller of `path_local_discovery_start()` found in this
baseline is `path_channel_acquire()` (`src/path_policy.c:3337`). Devtools and
unit coverage can start it directly. Thus the old WAN-only broadcast behavior
is not established as a still-active normal path. Avoid rebuilding old PMTU
logic to fix a historical symptom.

### Remaining change

Make broadcast eligibility explicit inside the discovery owner and recheck
before emission. Use current LAN/on-subnet evidence from M2, peer demand,
reachability, key validity, interface/family availability and network epoch.
`prevedge` supplies topology/port information, not sufficient locality.
The authenticated routed-private exception in M2 permits unicast validation,
not broadcast. Include a proved routed-private backbone case with no on-link
LAN evidence and assert zero broadcast/mDNS attempts for that destination.

WAN-only peers should keep punch/bootstrap and relay fallback. A discovery
attempt with an unsuitable broadcast carrier must not spin indefinitely or
consume a finite ladder as though the peer failed to reply. Preserve WS1's
scheduler-admission accounting and keep family/interface choice explicit in
`choose_broadcast_address()` (`src/net_packet.c:997`).

Add a WAN-only case with a non-null graph edge, a local case that still
discovers, a network change during an armed discovery, no usable multicast
family, and scheduler denial. Existing `src/path_plpmtu_cover.c:904` coverage
checks nonce/purpose/local replies and first-tries broadcast behavior; extend
it to eligibility and assert the actual scheduled probe kind/length/destination.
Field logs should show no WAN-only LAN-probe attempts; missing log lines alone
do not prove no packet was scheduled.

### Implemented

Eligibility lives in `path_local_discovery_plan()`. `prevedge` supplies the
listen port only. On-link `EDGE_DIRECT` without current LAN evidence gets
unicast tries and never a broadcast. Broadcast destinations are directed:
IPv4 `addr | ~mask`, IPv6 `ff02::1` with `sin6_scope_id` set to the interface
index. There is no wall-clock arm deadline.

A ladder is tied to the interface snapshot (`local_network_epoch()`), not only
to `lan_network_epoch`. A hint that leaves the interfaces unchanged retires the
nonce but keeps the ladder's tries, so repeated hints cannot extend it. A new
snapshot starts a fresh ladder. An idle peer runs another ladder only after an
interface change, or once when broadcast becomes possible for a ladder that
could not broadcast. LAN evidence arriving during a unicast ladder adds the
broadcast prefix once, capping that ladder at ten tries plus three broadcasts.

Node key readiness rechecks eligibility. A peer refused for "no valid key"
starts when the handshake completes; a ladder cut off by a rekey resumes with
its spent tries. A reply is accepted only while the ladder's network epoch is
current, so a reply that lands after a network change but before the next
tick cannot confirm UDP. The nonce-zero confirm path in
`path_try_confirm_udp_probe_reply()` uses the same on-link rule.

Broadcast evidence is a current local META adjacency or a current-epoch mDNS
sighting with an on-link discovered address. A broadcast `sendto` that returns
no socket or a hard error blocks broadcast for that network epoch and does not
consume a ladder try; with no unicast target the ladder ends exhausted.
Scheduler denial and `WOULD_BLOCK` also leave the try count unchanged. Unicast
discovery destinations are speculative and are not aliased into the node UDP
cache. Counters on the devtool node status (`runs`, `broadcasts`, `unicasts`,
`skips`, `carrier_failures`, `confirms`), not missing log lines, are what the
coverage asserts.

## M4: coalesce punch endpoint requests

### Confirmed mechanism

The code already shares one demand count and ladder per peer.
`path_channel_acquire()` sends on the first 0→1 channel transition; subsequent
channels return without restarting it. Existing
`test_punch_demand_keeps_key()` (`test/path-stability.c:2002`) explicitly
checks that a second channel produces no new request or SPTPS restart.

The remaining reset is
[`path_punch_note_hint()`](/Users/ashish/coco-project/third-party/meshlink/src/path_policy.c:2401):
a different/first hint sets `last_hint`, clears the request schedule and calls
`path_punch_endpoint_tick()` immediately. A response can therefore trigger
another endpoint request milliseconds after the preceding request. Identical
hints are already suppressed; newly received hints are the important case.

Direct capture evidence, not inferred channel multiplicity:

- C2 camera `hemanth-camera-meshlink-004.txt:5671` requests at epoch-ms
  `1791183264878`; hint arrives at `4916`, and line 5679 immediately requests
  again at `4916` (38ms later).
- Supplied WS2 Android `android-meshlink-ws2-001.txt:389` requests at
  `10:59:07.815`; first hint at line 395 arrives at `.832`; line 397 requests
  again at `.832` (17ms later).

These logs match the current request-on-new-hint control flow. Their exact
build identities were not established by this analysis.

### Change and invariants

Keep the endpoint request ladder owned by the peer's demand/network/session
state. Receiving a usable hint should update/validate the candidate immediately
without automatically issuing another request for the answer just received.
Separate request cadence from candidate challenge cadence.

Recommended behavior: immediate request for a genuine new demand/network
epoch; preserve an already scheduled next request on a new hint; reset backoff
after useful new information without moving the next request inside the minimum
request interval. A changed hint after a long quiet period may make a request
eligible, but admission belongs to the same owner. Preserve identical-hint
suppression, direct confirmation, staged hints during KEX, peer-reflexive
priority, session invalidation and the two-endpoint-dependent-NAT fallback.

Only a successfully accepted META request advances send counters/deadline.
Do not introduce a second timer or scheduler for this control message.
Make the low-level sending helper internal to the owner if practical; retain
protocol-minor-4 checks and no-SPTPS-restart behavior. Update ADR 0008's explicit
new-hint-restarts-ladder decision when this policy changes.

Expected edits: `path_policy.c`, peer request state in `node.h` if a last-send
timestamp is needed, protocol helper declarations/visibility and focused
coverage. Devtool status already exposes actual request count and step.

Tests: two simultaneous channels, request followed by first hint within 20ms,
moving/identical hints, hint before key completion, request failure, backbone
reconnect, confirmation stopping requests, demand grace/reopen, session and
network changes. Assert both actual request writes and counts; preserve prompt
challenge emission for a new valid candidate.

## M5: startup KEX retry accounting

### Confirmed C2 cause

[`send_req_key()`](/Users/ashish/coco-project/third-party/meshlink/src/protocol_key.c:113)
has two different operations behind one name: public-key acquisition and
SPTPS session start/restart. When the ECDSA key is unknown, it sends
`REQ_PUBKEY`, advances `key_retry_step`, but does not set `waitingforkey`.
It also advances the schedule when no META nexthop exists, and ignores the
return value of the public-key request write.

Opening a channel first calls `path_peer_ensure_udp_key()` from demand
acquisition. Its initial UTCP SYN then reaches `send_sptps_packet()`; because
`waitingforkey` is still false, it calls `send_req_key()` again. The missing-key
request and ladder advancement are duplicated without waiting for a deadline.

C2 Android `android-meshlink-003.txt` confirms this sequence:

- Lines 131–135: no ECDSA key, public-key request, `step=1 epoch=0`.
- Lines 141–145: initial 56-byte SYN, no ECDSA key, second public-key request,
  `step=2 epoch=0`, in the same millisecond (`12:24:21.623`).
- Lines 245–254: key learned; the SYN is retried and SPTPS begins at
  `12:24:21.708`, yielding `step=3 epoch=1`.
- SPTPS succeeds at `12:24:21.749`.

The ladder did not actually wait through three retries. It counted two key
acquisition sends and a fresh handshake together. This is more precise than
the tracker's description of a harmless unexplained startup step jump.

The general ladder is `{2,5,10,30,60}`. `node_kex_arm()` also advances it on
an accepted responder start (`protocol_key.c:562`). Audit simultaneous starts
and role changes as well as missing keys. The current jitter calculation adds
only 0–1, 0–2, …, 0–30 **milliseconds**, despite delays being in seconds;
record this in diagnostics, but widening jitter is a separate policy change.

### Proposed implementation

Give node-level key acquisition/recovery one owner with an explicit phase
such as public-key request pending versus handshake pending. Keep
`waitingforkey`'s SPTPS meaning; do not overload it just to suppress public-key
requests. All ordinary demand, initial SYN, connection-policy ticks and inbound
triggers should ask this owner to ensure progress.

Coalesce requests until their deadline. Advance retry accounting on a genuine
attempt, with explicit failure behavior for absent/failed META writes. Reset
or separate the public-key phase's backoff when a newly learned ECDSA key allows
the first handshake. Arm the first responder handshake without pretending it
was another timeout retry. Preserve the name-based simultaneous-start tie-break.

Keep an explicit force/restart operation for real listen-port changes,
devtool force-KEX and session resets. Preserve ordered-cutover uncertainty's
intentional prompt retry and warm session preservation. A blanket rate limit
inside `send_req_key()` would risk suppressing these legitimate actions.

Call-site audit: `protocol_auth.c:343,722,726`, `net_packet.c:614,649`,
`connection_policy.c:1141,1339`, `path_policy.c:3211`, watchdog and responder
handling in `protocol_key.c`, cutover uncertainty in `net_upgrade.c`, and
devtool force-KEX. Expected edits are this ownership cluster plus `node.h`,
`protocol.h` and focused coverage. A small internal key-owner interface is
preferable to unrelated boolean guards at every caller.

`node_kex_cover_unit()` currently checks only that the watchdog does not climb
before its deadline and advances at the deadline. Add: unknown key plus initial
SYN, multiple channels, repeated policy ticks, key response starting a prompt
first handshake, lost public-key response, absent/send-failed META, simultaneous
starts, responder role changes, lost handshake, session reset, uncertain
cutover, success cancelling retries and idle ordinary peers. Count real wire
requests and SPTPS restarts, and include deadline/phase/trigger in scheduling
diagnostics so step changes can be interpreted.

## F10: channel availability and terminal lifecycle

### Existing behavior traced end to end

[`check_reachability()`](/Users/ashish/coco-project/third-party/meshlink/src/graph.c:154)
changes node status, tears down path activity, calls `update_node_status()`,
and then calls `utcp_offline()`. The node callback currently runs **before**
UTCP offline reconciliation. A new availability notification needs committed
channel state before application code is invoked.

[`utcp_offline()`](/Users/ashish/coco-project/third-party/meshlink/src/utcp.c:2751)
does not store an offline gate. It calls `utcp_expect_data()` on eligible
established/FIN_WAIT channels to arm their connection timer; recovery moves
pending retransmission deadlines to now and lowers RTO. A channel can continue
to accept writes while the node is unreachable.

`meshlink_channel_send()` calls `utcp_send()`. Reliable sends enter the bounded
UTCP buffer, even if the packet cannot reach the peer. UTCP's default maximum
send and receive buffer sizes are 131072 bytes each. `channel_send()` routes
through Meshlink; unreachable traffic cannot resolve an active route, but
local buffering and retry state remain. A positive send result means queued
locally, not delivered. Full buffers return short/zero writes; negative UTCP
results become the broad `MESHLINK_ENETWORK` error.

Unreliable sends need separate guarantees: after establishment UTCP discards
their send buffer after emission, regardless of eventual network delivery.
An accepted unreliable write is not a promise of storage across an outage.

Poll means buffer capacity, not peer availability. `utcp_set_poll_cb()` arms
polling based on free space. Reusing `poll(len=0)` to report temporary
unavailability would collide with the existing error convention and abort AIO
work in `channel_poll()`.

AIO is a second buffering layer. `meshlink_channel_aio_send()` and its FD
variant append descriptors to an uncapped linked queue. The UTCP 128KiB bound
does **not** bound total AIO submissions or the amount of application memory
held by Meshlink. AIO completion reports how much was consumed/queued, not
proof that the peer acknowledged delivery. A claim of bounded buffering must
explicitly address both layers.

Per-node default timeout is 60s. Positive `meshlink_set_channel_timeout()` is
also an **idle-RX** timeout, including ACK-only input; it can close a healthy
silent channel while the node is still reachable. It is not an equivalent
implementation of a sustained-node-offline close policy.

### Notification defects and audit scope

[`channel_recv()`](/Users/ashish/coco-project/third-party/meshlink/src/meshlink.c:4517)
and `channel_poll()` do not translate system `errno` to `meshlink_errno` before
application callbacks. This violates the receive callback's documented reason
contract. The thread-local Meshlink error intentionally persists between API
calls, so it can be stale even on a graceful EOF.

UTCP sources currently set:

- Timeout: `ETIMEDOUT` in `close_timed_out()`.
- Refused SYN: `ECONNREFUSED`; remote reset: `ECONNRESET` in `utcp_recv()`.
- Remote FIN: zero, leaving `CLOSE_WAIT` and a potentially usable send half.
- `utcp_reset_all_connections()`: zero even for session replacement or
  blacklisting. Those callers need explicit terminal reasons.
- `utcp_exit()`: invokes callbacks without establishing a reason.

Timeout/reset receive callbacks run before poll callbacks. An AIO completion
or receive callback can change both error globals through nested API calls;
setting the reason only once at the beginning is insufficient. Capture/store
it and restore the intended reason immediately before **each** callback.

Terminal notifications are spread across refused/reset/FIN handling,
reset-all, timeout and exit. State `CLOSED` prevents routine subsequent timeout
delivery, but there is no shared terminal-reason/notification owner. Audit
cross-path delivery and late registration rather than claiming C3 proves a
missing or duplicate callback.

`channel->in_callback` only protects AIO completion today. Receive and poll
callbacks can close/abort their own channel; new availability fanout can also
close a sibling or create another channel. Add disciplined callback lifetime
and traversal handling before adding fanout. A boolean alone can be inadequate
under nested callbacks; use a depth/deferred-free scheme or equally explicit
ownership. Preserve the existing ability to close/abort in callbacks.

There is no Meshlink list of channels: they live behind UTCP's private
connection array. Choose either a Meshlink-owned live-channel registry with
safe iteration or an internal UTCP event/iteration seam that hides the array.
Do not expose `utcp_priv.h` to general Meshlink callers to implement fanout.

Terminal receive/poll bridges currently do not release channel UDP demand;
`channel_demand_drop()` runs at explicit application close/abort. Evaluate
releasing demand when a channel becomes terminal even if its handle remains
valid. Do not release it merely on temporary unavailability or read-side EOF.

### Recommended contract, pending design acceptance

Keep default reliable channels recoverable through transient reachability loss.
Add explicit per-channel availability feedback, separate from read EOF and
terminal failure. Tentative interface: a status/availability callback and a
query for current state, with an explicit reason argument or stored reason.
Exact names and enum representation should be agreed in an ADR before coding.

The contract should state:

1. Availability tracks **Meshlink's observed node reachability** for a live
   channel; it is not a guarantee of packet delivery, handshake completion or
   writability. Direct-path loss with a live relay is not node unavailability.
2. On unreachable/recovered transitions, update all relevant channel state
   before notifying. Deliver each transition once, with specified ordering
   relative to node callbacks. A new channel opened while offline starts
   unavailable. Query plus registration behavior must avoid missed-state races.
3. Default reliable sends can queue up to their configured UTCP bound while
   unavailable. Poll advertises this local capacity. Recovery sends retained
   bytes in order. State the separate AIO descriptor/byte admission limit or
   explicitly expose and document application-owned bounds; silently promising
   all buffering is bounded is incorrect.
4. An optional per-channel offline-close grace uses a distinct monotonic
   deadline. Zero/default disables it; positive grace starts at actual node
   unavailability and cancels on recovery. It should not close idle reachable
   channels, extend because of continued send attempts, or reuse idle-RX timing.
5. Terminal closure is irreversible for the old channel. Reconnect never
   produces recovered on that handle. The handle survives terminal notification
   until explicit close/abort; those calls invalidate it.
6. Remote FIN is read EOF/half-close, not automatically a terminal event.
   Preserve sending from `CLOSE_WAIT`. Exactly once applies to terminal events
   and each outstanding AIO cleanup; do not suppress a legitimate terminal
   error after a prior read EOF.
7. Each registered terminal receive/poll observer gets its applicable final
   notification once, unless the application invalidates the channel in an
   earlier callback. Specify late callback registration and callbacks replaced
   during dispatch. Local close/abort should not create callbacks after handle
   invalidation. AIO buffers return ownership once, including partial progress.
8. Store terminal reason before draining AIO/dispatching callbacks. Graceful
   EOF maps to `MESHLINK_OK`; network timeout to at least `MESHLINK_ENETWORK`;
   peer reset/refusal/session replacement to a documented peer reason;
   blacklist to `MESHLINK_EBLACKLISTED`. If timeout/reset precision is required,
   use an explicit reason enum or appended error codes and update strerror;
   existing enums cannot distinguish all these cases.

Default send compatibility is the recommended first implementation. If media
needs immediate rejection of writes or suspension of AIO consumption while
unavailable, define a separate opt-in admission policy with a distinguishable
would-block/unavailable result. Reusing terminal `-1` or poll-zero feedback
would make transient recovery ambiguous. Existing queued reliable data cannot
be discarded without an explicit stream-integrity policy.

For AIO bounds, prefer an explicit per-channel outstanding-byte/descriptor
limit with admission failure before ownership transfers. Distinguish default
compatibility from an opt-in hard cap; impose no unannounced small global
limit. Specify FD submissions, subtraction on partial progress, completion,
abort and callback-enqueued work.

### Implementation surface

- `graph.c`: reconcile availability/offline state, session-reset ordering and
  notification fanout after state is committed.
- `meshlink.c`: callback registration/query/policy, channel registry or internal
  iteration, creation/acceptance, AIO admission, send/poll contract, terminal
  reason translation, safe callbacks and demand release.
- `meshlink_internal.h`, possibly `node.h`: live state, terminal reason,
  notification guards, registry links, callback depth and offline deadline.
- `utcp.c`, `utcp.h`, `utcp_priv.h`: one internal terminal event/reason owner;
  preserve FIN semantics and expose the narrow event/iteration seam required
  by Meshlink. Audit timeout, reset, exit and closed-handle sends.
- Blacklist/whitelist and stop/start paths in `meshlink.c`, destruction in
  `node.c`: classify terminal versus recoverable lifecycle explicitly.
- `meshlink.h`, `meshlink++.h`, `meshlink.sym`: public contract, wrappers,
  trampolines and exported symbols. Preserve the public channel prefix
  (`node`, `priv`); append private state internally.
- `test/Makefile.am`, channel failure/timeout/AIO/corner-case suites and a
  focused new availability test. Internal deterministic UTCP coverage may be
  needed to avoid sleeping through repeated 60-second timers.
- ADR and finding tracker: approved semantics and evidence, without marking
  field acceptance from unit tests.

### Consumer integration found locally

COCO's transport layer already forwards node reachability into its own event
loop and node lifecycle controller (`ct_meshlink_node_status_cb()`,
`meshlink_node_status_event_handler()`). It separately interprets a zero-length
data-stream receive as `CP_DATA_STREAM_CLOSED`, then clears `statusCb`:

[`data_stream_channel_receive_cb()`](/Users/ashish/coco-project/platform/coco/src/clusterprotocol/src/clustertransport/ct_common_utilities.c:1202).

Reusing this close path for unavailable would prevent a later recovered/open
notification. `ct_meshlink_channel_poll_cb()` also ignores zero-length polls
and deregisters after the initial successful poll. Generic receive callbacks
read `meshlink_errno`, so fixing reason propagation has immediate diagnostic
value.

A Meshlink callback alone will not stop the existing media send loop. Plan
COCO transport adoption: register availability on opened and accepted media
channels, carry state/reason safely through its event queue, pause/resume
producers, and reserve CLOSED for irreversible termination. Map new statuses
through stream interfaces and mobile/camera bindings as needed. This was a
targeted consumer inspection, not a full audit of those downstream repositories.

### Acceptance coverage

Exercise public interfaces and real callback behavior; flags recording only
that some callback occurred are insufficient. Count events and capture reasons,
buffer lengths, byte order and ownership returns.

- Sending and idle channels lose one node: each sees unavailable once,
  alongside the existing node callback. No immediate terminal close by default.
- Recover before timeout: recovered once, retained reliable bytes arrive in
  order, no lost AIO ownership, no spurious EOF; a healthy relay change produces
  no unavailable event.
- Continue a C3-style 540-byte/64ms send loop while offline: bounded UTCP
  queue, predictable partial/zero writes, no timer extension from writes and
  eventual terminal result. Include unreliable-channel differences.
- Multiple AIO buffer/FD submissions: specified admission cap, partial
  progress, outage/recovery and terminal cleanup exactly once.
- Timeout, refusal, peer reset, session restart, blacklist, local close/abort
  and mesh destruction: correct reason and applicable terminal notifications,
  no stale TLS reason and no recovery after terminal closure.
- Remote FIN followed by continued local send and later termination: EOF
  remains distinct from terminal close.
- Receive callback changes errno via another API; multiple AIO completions do
  likewise: every subsequent observer sees the original terminal reason.
- Abort/close inside availability, receive, poll and AIO callbacks; close a
  sibling or open a new channel during fanout; no use-after-free, skipped live
  sibling, duplicate cleanup or recursion corruption.
- Register/replace callbacks while offline or after terminal closure; opening
  before peer reachability and reopening after a real session change.
- Opt-in offline grace: just-before/at/after deadline, recovery cancellation,
  independent policies on two channels, healthy silent peer stays open,
  inherited timeout interactions and no demand retained by terminal handles.

Run focused channel tests, C++ compile coverage, path-demand and NAT/relay
regressions, then the full serial suite in the ARM64 container. Where supported,
use memory instrumentation for callback/reentrancy cases.

## Decisions required before F10 implementation

These are proposed design choices, not requests to stop the current analysis:

- Exact availability interface, initial/query/registration behavior and callback
  ordering; observed reachability versus a broader route-readiness definition.
- Keep existing offline buffering by default; decide whether a fail-fast media
  admission policy is also required for WS4.
- AIO bounds, defaults and ownership/admission failure contract.
- Offline-close grace interface and how it composes with existing timeouts.
- Precise reason representation, half-close versus terminal notifications and
  behavior when observers are added after termination.
- M2 wire/capability contract, endpoint publication/freshness bounds, and outage
  policy for private-only versus public fallback; generic application hints for
  other routed private/VPN peers remain separate from backbone self-advertisement.

## Verification and completion gates

Build/test only inside `meshlink-arm64`, from
`/mnt/host/coco-project/third-party/meshlink`, following the tracker. Every
implementation PR runs `make -j1 check` independently. This analysis did not
run builds/tests or alter the active review's container/build artifacts.

For field acceptance, record exact Meshlink/SDK builds for NMN, Android and
camera, with a new Hemanth-path capture. Collect:

- No off-subnet unsolicited graph/unknown private attempts; authenticated
  backbone private endpoints can be validated across subnets, with continued
  same-subnet discovery, public punching, hairpin and relay delivery.
- Separate NMN/VSN BBNMs: public bootstrap followed by proved private META/data
  steady state, including promotion from working public direct carriers. Capture
  destinations for payload, keepalives and probes, then repeat after NMN defrag
  with changed private IP/port. Assert no routed-private-induced broadcasts.
- Endpoint request timestamps showing no hint-induced duplicate request;
  changed endpoints still challenged promptly.
- KEX request counts/phase/deadline evidence showing one pending public-key
  acquisition, a prompt first handshake and actual timeout retries thereafter.
- Per-channel unavailable/recovered/terminal events, send/AIO admission and
  queues during a short outage, long outage, restart and stream pause.
- Correct SDK producer pause/resume and irreversible terminal-close behavior.
- M1 warning-window behavior and M8 fallback/diagnostics on Android/Docker.

Keep WS1/WS2/WS3 performance and field gates separate. WS4 does not imply
the infrastructure address correction, broader NAT support, or general changes
to ordinary peer ranking. M2 does include backbone private-carrier promotion.
Completion requires code, public contract, consumer integration
where needed, independent suite success and the recorded field evidence.

M2 adds a capability-negotiated private-endpoint request/reply contract and must
allocate an appropriate protocol minor/capability before implementation. Keep
public punch messages compatible and older peers functional. Public symbols/
wrappers also change for F10; any added versioned devtool fields must follow the
existing status-version convention. Local-network inventory, private endpoint
authority/challenges and channel availability/grace state should be runtime
state, with no host-config format change required by this scope.
