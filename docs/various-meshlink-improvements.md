# Meshlink field findings tracker

This document tracks what field captures have shown about meshlink connection stability, what we did about each finding, and the workstreams (WS1–WS4) that group the remaining fixes. Plans should reference findings by ID (F1, F2, …, M1, …) and workstreams by ID (WS1, …). When a capture confirms or changes a finding, update its **Status** and **Seen in** fields rather than adding a new section.

Status values:
- **Fixed**: code landed and a later capture confirms it.
- **Fix ready**: code exists but no field capture has confirmed it yet.
- **Open**: understood, no fix yet.
- **By design**: expected behaviour; listed so nobody re-investigates it.
- **Not meshlink**: belongs to another layer.

## Status summary

| ID | Finding | Status | Workstream |
|----|---------|--------|------------|
| F0 | Confirmed peers pinned to a dead NAT port | Fixed (PR #125) | — |
| F1 | Suspect fallback silently drops retransmits, so channels stall | Fixed | — |
| F2 | The `maxmtu + 8` raise replaces liveness, causing false give-ups | Fixed | — (follow-up in WS1) |
| F3 | Oversized datagrams make the camera's NAT re-map; PMTU discovery causes most of it | Fix ready | WS1 |
| F4 | Slow climb to direct at startup and after restarts | Partly fixed (MSS); route choice still open | WS1 (MSS), WS3 (route choice) |
| F5 | Liveness is one probe per window; one lost reply demotes the path | Fix ready | WS1 |
| F6 | The camera's NAT expires idle mappings faster than our ping cadence | Fix ready | WS1 |
| F7 | The NMN delivers relayed records over META, never UDP | Open | WS2 |
| F8 | Route promotion continues while the destination is unreachable | Open | WS3 |
| M1–M8 | Minor items | Open / By design / Not meshlink | WS4 |

Order: WS1 → WS2 → WS3, with WS4 whenever convenient.

## Captures

| ID | When | Nodes | Builds | Files |
|----|------|-------|--------|-------|
| C1 | 2026-10-04 22:17–22:38 IST | phone = node 1, Hemanth's camera = node 4, Ashish's camera = node 2, NMN = node 0 | nodes on `validated-udp-rebind` (PR #125); NMN on `elear-develop` | `android-meshlink-001.txt`, `hemanth-camera-meshlink-00{1,2,3}.txt`, `ashish-camera-meshlink-001.txt` |
| C2 | 2026-10-05 12:24–12:42 IST | phone = node 5, Hemanth's camera = node 4, NMN = node 0 | nodes with the F1 and F2 fixes on top of PR #125; NMN on `elear-develop` | `android-meshlink-003.txt`, `hemanth-camera-meshlink-00{4,5,6}.txt` |
| L1 (local) | 2026-10-06 22:34:09–22:37:53 IST; camera log covers 22:36:51–22:37:45 | Android emulator = node 6, local camera simulator = node 2, NMN = node 0 | WS1 endpoint builds; NMN advertises protocol 17.6; exact build SHAs not recorded | `android-meshlink-ws1-001.txt`, `camera-meshlink-ws1-001.txt` |

For C1 and C2, the only difference between `elear-develop` and PR #125 is rebind, and rebind is switched off on any pair that includes the backbone (`path_is_ordinary_peer_pair`). So the stale NMN build behaves the same as the new code for the findings from those captures.

L1 is a local check with the endpoints on the same host, using the Ubuntu Docker container and QEMU. It does not exercise Hemanth's Jio path or replace the pending WS1 field capture C3. The camera clock appears roughly 0.8s ahead of Android; cross-endpoint timings need that adjustment. The camera uses `KEYS_ONLY` storage, so L1 cannot confirm its PLPMTU persistence across process restarts.

### Environment
- **Phone:** home network, public `183.83.170.151`, endpoint-independent NAT. The public port is stable (`11390` in C1, `10066` in C2).
- **Hemanth's camera:** simulator in Docker on a laptop, listening on `22558`, behind Jio (`152.57.183.89`), with an endpoint-dependent NAT. The camera's public port toward the phone changes often (F3).
- **Ashish's camera (C1 only):** Docker Desktop on the same home network as the phone; reaches the phone over hairpin UDP.
- **NMN:** `16.113.46.107:21828`, behind a load balancer (see M2).
- **Clock offsets:** the camera ran about 55ms behind the phone in C1 and about 105ms ahead in C2. Both were estimated from rebind and suspect probe round trips.
- **Ping settings in the app:** `pinginterval` 10s, `pingtimeout` 5s.

---

## F0: Confirmed peers pinned to a dead NAT port
**Status:** Fixed (PR #125, `validated-udp-rebind`). **Seen in:** before C1; verified in C1 and C2.

- **Problem:** after a peer was confirmed, authenticated traffic from a new source port was only cached as an alias. Probes kept going to the dead port until the route demoted to relay, which cost a 30s residency and a PMTU reset.
- **Fix:** challenge a quiet same-IP source with a nonce probe, then commit it in place. Route kind, residency and PMTU are kept. A different IP is not a rebind. Decision recorded in ADR 0010.
- **Verified:**
  - C1: 150 migrations, 8 failed challenges, no flip-backs, and no route change caused by a migration.
  - C2: 113 migrations, mostly committed in under 100ms or around 500ms.

## F1: Suspect fallback silently drops retransmits, so channels stall
**Status:** Fixed (plan `suspect_fallback_and_pmtu_liveness`, branch `suspect-fallback-pmtu-liveness`). **Seen in:** C1; verified in C2.

**Symptom (C1):**
- 681 short writes from `meshlink_channel_send` (no errno; the UTCP send buffer was full), in 7 bursts of 4–10s.
- All on the phone→camera channel: 540-byte writes every 64ms, probably talkback audio (a guess).
- Four bursts ended with the app aborting the channel: 22:20:10, 22:23:51, 22:26:06 and 22:37:33.

**Mechanism:**
- A UTCP retransmit coalesces to the full direct MSS (1430 bytes) and marks the route suspect (`route-suspect … reliable retransmit`).
- `path_resolve_active_route` then sends it on the temporary fallback, which is the UDP relay via the NMN.
- `send_relay_outer` silently drops anything over the hop `minmtu`. Here that's a 1455-byte payload against a phone→NMN `minmtu` of 1442/1443; the relay can carry at most 1418 bytes of inner data.
- A 64-byte probe clears suspicion, the next RTO re-suspects, and it loops until the app aborts.
- The mirror case also happened (C1 run 1): relay MSS 1418 against a direct PMTU of 1411.
- Root cause: the temporary fallback ignored the fallback carrier's MTU.

**Fix:** `path_send_target_for_record`. A record goes on the temporary fallback only if it fits that carrier. Otherwise it goes on the suspected primary, then on META, and is never silently dropped. Redirects and oversize drops are counted and rate-limit logged. Covered by test T22.

**Verified (C2):**
- Zero `meshlink_channel_send failed`.
- 3 redirects (`Suspect fallback for 4 cannot carry 1451 bytes; sending on direct-wan-udp`). The camera received full-size packets right after each one, and suspicion cleared within about 400ms.

## F2: The `maxmtu + 8` raise replaces liveness, causing false give-ups
**Status:** Fixed (same plan and branch as F1). **Seen in:** C1; verified in C2.

**Symptom (C1):**
- 3 give-ups ("did not respond to UDP ping"), 2 of them false: 22:25:33 and 22:36:14.
- The endpoint was answering suspect probes the whole time, and the punch re-confirmed on the same port a second later.

**Mechanism:**
- At `mtuprobes == 32`, when a raise was due, only the `maxmtu + 8` probe was sent.
- On a path that really is at `maxmtu`, that reply is lost by design.
- Nonce replies were barred from resetting `mtuprobes`.
- With the app's ping settings, the give-up landed exactly 15s after "Fixing MTU" whenever a raise was due, and the first raise after every session is always due.

**Fix:**
- The 64-byte liveness probe always goes out; the raise rides beside it and is matched by `pmtu_raise_pending`.
- A nonce reply from the parked endpoint counts as liveness.
- Covered by test T23.

**Verified (C2):**
- No give-up within 15s of a fix.
- The raise succeeds (phone `raising MTU to 1426`, camera `1425`).

**Follow-ups:**
- Sending the raise in the same tick as the liveness probe still trips the camera's NAT (see F3 and F5). WS1 replaces the raise with the new search and never pairs a size probe with liveness.

---

## F3: Oversized datagrams make the camera's NAT re-map; PMTU discovery causes most of it
**Status:** Fix ready (WS1 on `ws1-plpmtud-liveness`, not yet field-confirmed). **Priority:** 1. **Seen in:** C1, C2.

This is now the root of nearly every oscillation. F4, F5 and the length of each relay episode all follow from it.

**Evidence:**
- **C1 correlation:** 167 of 168 camera port changes came within 1.2s of a datagram over 1430 bytes in either direction. The single exception followed 21s of quiet (an idle expiry; see F6).
- **C2 timing:** churn bursts line up with PMTU discovery on either side and stop once both sides settle. Isolated migrations follow the phone's `+8` raise (12:35:08) and the camera's (12:36:11).
- **PMTU black hole:** DF is set (`IP_PMTUDISC_DO`, `net_setup.c` line 523), yet the camera never logs `EMSGSIZE`, so no ICMP Frag-Needed reaches the container.
- **The path MTU differs by direction:** phone→camera carries at least 1451; camera→phone tops out around 1430–1431.
- **Discovery is mostly oversized (C2):** every cycle, on both sides and toward both peers, sends 40–70 probes larger than the MTU it finally settles on, about 80% of all probes, over 31–39s.
- **The search never converges:** `maxmtu` only drops on `EMSGSIZE`, which never comes here. The camera re-sends its midpoint probe (1434/1436) every round for the whole cycle.
- **Settled values drift low:** 1416–1418 against a real ~1430, because probes that would have fit get lost to dead mappings.
- **During the camera's discovery the phone can't reach it:**
  - C2 run 2: the camera received nothing from the phone from 12:32:17 to 12:32:27, and three rebind challenges failed.
  - C2 run 3: nine punches failed between 12:36:22 and 12:36:47.

**Mechanism (speculation, but it fits every case):**
- At 12:36:20.897 (C2) the camera sent a 1434-byte probe and then a 1425-byte one. The 1425 still arrived, but inbound to that port was dead about 20ms later, and the camera's next packets came from a new port.
- That matches a NAT (the Jio CGNAT or a tethering NAT) that removes the mapping when the ICMP for an oversized packet comes back.
- We can't tell which hop does it from these logs.
- Optional A/B test: run the simulator with `--network host` to separate Docker's NAT from the carrier's.

**Contributors:**
- The phone's large probes make the camera echo oversized replies.
- The camera's own discovery toward the phone and toward the NMN (the NMN leg is unconfirmed without NMN logs).
- The periodic `+8` raise.
- Every give-up resets PMTU and re-runs the full discovery (F5, F6).
- Every camera restart re-runs discovery from scratch, even though the NAT kept the same port (C2: reconfirmed on `57065` within 1.2s of the restart).

**Fix:** WS1. The current PMTU code can't be patched into something robust, for four reasons:
- one counter (`mtuprobes`) drives liveness, discovery and the raise;
- the search only shrinks on `EMSGSIZE`, which a black hole never produces;
- every probe is echoed at full size, so the peer is forced to send oversized packets;
- data waits for discovery before the route can go direct.

Options considered and folded into WS1: converge on loss, keep PMTU on give-up, separate the raise from liveness, remember PMTU per remote IP, and measure one direction only.

**Verification:** see the WS1 test matrix. The field check is no churn bursts at session start, and 3 or fewer migrations per session on Hemanth's path.

## F4: Slow climb to direct at startup and after restarts
**Status:** Partly fixed. **Priority:** 4. **Seen in:** C1, C2.

MSS is what waited on PMTU. Promotion to direct is not gated on it. WS1 publishes the 1211-byte base as soon as UDP is confirmed, so `channel_compute_mtu` can use it before the search finishes. The route-choice leftovers stay in WS3.

**Evidence:**
- **Startup choice depends on start order:**
  - When the phone starts after the camera, it commits `meta-direct` about 0.9s before backbone UDP confirms (C1 runs 2 and 3, C2 run 1).
  - All phone→camera data then goes as `REQ_KEY … 21` over TCP through the NMN, for 70s and 100s in C1 and 71s in C2.
  - When the phone starts first, it commits `relay-udp` (C2 run 3: 74s before direct).
- **No step down to relay-udp:** the backbone-UDP candidate is pre-empted by the direct-UDP candidate, so `meta-direct` never moves to `relay-udp`.
- **MSS was gated on PMTU:** the channel stayed on the floor until "Fixing MTU", about 5s after the candidate had already started. Promotion itself was not waiting on that log. WS1 removes the MSS wait by publishing the base immediately.
- **After a camera restart (C2 run 1, 12:30:48):** the phone never got back to direct before the app was closed at about 12:31:53. That is where the restart cycle in C2 started.

**Fix:**
- **WS1** removes the PMTU gate: direct is promoted at the 1232-byte base right away, and the search only raises it later.
- **WS3** covers the rest:
  - re-rank `meta-direct` → `relay-udp` once backbone UDP confirms;
  - don't let a direct-UDP candidate pre-empt the backbone-UDP step down.

**Coming risk:** once the phone goes direct earlier, any remaining churn costs about 500ms of phone→camera data per rebind (the quiet window). WS1 removes the churn, so this should not show up; check for it in the first field capture after WS1.

## F5: Liveness is one probe per window; one lost reply demotes the path
**Status:** Fix ready (WS1, not yet field-confirmed). **Priority:** 2. **Seen in:** C2.

**Evidence (C2, 12:36:11–12:37:05):**
- At 12:36:11.596 the camera sent its 64-byte liveness probe and its 1439-byte raise in the same millisecond.
- The phone answered the 64-byte probe within about 70ms, but the reply never reached the camera. The camera gave up at 12:36:16.610.
- The camera had been receiving authenticated direct UDP from the phone throughout (suspect probes at 12:36:12.5 and 12:36:14.8), but only probe replies count as liveness.
- The give-up restarted the camera's discovery, which churned its NAT (F3). The phone demoted at 12:36:21 and then failed nine punches. Result: 44s on relay.

**Root cause:** a single 64-byte probe per `pingtimeout` window, no retry, and the give-up resets PMTU.

**Fix:** WS1. Liveness becomes its own state machine with 3 tries per window. A give-up demotes the route but never touches PLPMTU, and liveness is never sent in the same tick as a size probe.

## F6: The camera's NAT expires idle mappings faster than our ping cadence
**Status:** Fix ready (WS1 adaptive keepalive, not yet field-confirmed). **Priority:** 2. **Seen in:** C1 (one case), C2.

**Evidence (C2, 12:38:15–12:39:32):**
- The stream stopped at about 12:38:15. After that, the camera's only packet toward the phone was its reply to the phone's 12:38:25 ping.
- The next ping at 12:38:43.999, about 19s later, went unanswered, and the phone gave up at 12:38:49.
- The camera's next outbound packet (12:38:52) came from the same port, and the punch confirmed 4s after the give-up.
- But the give-up had reset PMTU, so another 30 probes ran, 20 more migrations followed, and the phone spent 43s on relay.
- A 10s idle earlier in the same run survived. So the timeout looks like 10–19s (speculative).
- At idle the camera sends nothing on its own, and the phone's ping cadence works out to about 19–20s.

**Fix:** WS1 adds an adaptive idle keepalive (see "Keepalive design" under WS1).

This revises the ADR 0010 position that keepalives don't help. That position still holds for the under-load re-mapping (F3), but not for idle expiry. WS1 records the change in a new ADR.

## F7: The NMN delivers relayed records over META, never UDP
**Status:** Open. **Priority:** 3. **Seen in:** C1, C2.

**Evidence:**
- C2: the phone received 30,530 of its 89,410 packets (34%) as `REQ_KEY … 21` from the NMN, while the camera was sending them `via UDP to 0`.
- In early C2 run 3 the camera's video (about 1,700 packets per 5s) went through the NMN over TCP.
- C1: the camera received 291 of 312 relayed records over META.

**Mechanism:**
- `relay_handle_record` forwards over UDP only when `relay_hop_udp_ready(out)` holds, which needs `udp_confirmed` on the NMN's side (`relay.c` lines 552–560). Otherwise it uses base64 `REQ_SPTPS` over META.
- Every place that sets `udp_confirmed` starts from the peer's side: a punch challenge reply, or the camera-originated backbone UDP mapping. The NMN only answers.
- So an ordinary peer is never UDP-ready from the NMN's point of view.
- This is code-level and the same on every branch; the stale NMN build has nothing to do with it.

**Impact:** "relay-udp" is UDP only on the first leg. The last leg adds TCP head-of-line blocking and latency, and base64 encoding plus `REQ_KEY` parsing on the NMN for every relayed packet.

**Fix:** WS2.

**Verification:** a relay test asserts that the last leg is UDP (no `REQ_KEY … 21` at the destination) once both peers have confirmed backbone UDP.

## F8: Route promotion continues while the destination is unreachable
**Status:** Open. **Workstream:** WS3. **Seen in:** L1.

**Evidence (Android, all timestamps on the same clock):**
- At 22:36:08.972, node 2 becomes unreachable after `DEL_EDGE` from the NMN (`android-meshlink-ws1-001.txt`, line 102845).
- At 22:36:12.947, Android starts a backbone-UDP route candidate for node 2 (line 102856).
- At 22:36:18.008, it promotes that candidate and logs `Path route: 2 none -> relay-udp (commit)` (line 102858).
- Node 2 remains unreachable until 22:36:51.600 (line 102894).

**Mechanism:** `path_route_tick()` runs for offline peers too. `path_consider_route_promotion()` and `path_commit_candidate()` do not check destination reachability. A retained route and channel demand let the live backbone carrier qualify even though the destination is offline. Committing it writes `active_route.selected_at`, restarting route residency.

**Impact:** incorrect route-state transitions and promotion admission while the destination is offline. `path_active_send_target()` checks reachability, so this capture is not evidence of packets being sent to the offline camera. The residency change can affect later recovery; an added recovery delay was not demonstrated in L1.

**Fix:** prevent candidate creation and commitment for unreachable destinations, and retire any pending promotion when reachability is lost. Keep the learned PLPMTU cache intact.

**Verification:** disconnect a peer while retaining channel demand, run route ticks and backbone-readiness callbacks, and assert that no promotion starts or commits and the residency timestamp does not advance. Reconnect the peer and verify normal route selection and data delivery.

---

## Minor

| ID | Finding | Status | Seen in |
|----|---------|--------|---------|
| M1 | `Unstable NAT binding` is level-triggered: 130 lines in C1, 84 in C2. It should fire once per window. | Open | C1, C2 |
| M2 | The NMN originates `ADD_EDGE` with `10.20.1.181` (very likely its load balancer's VPC IP) for every camera. Peers keep validating that bogus `edge-direct` candidate with cooldowns of 30–139s. Fix on the infra side (client-IP preservation or proxy protocol), and/or have meshlink skip private candidates that aren't on our own subnet. | Open | C1, C2 |
| M3 | PMTU probes go to `ff02::1` and `255.255.255.255` for WAN peers. That causes `Network is unreachable` errors inside Docker. It's harmless, since `relay_on_hard_send_error` ignores non-confirmed destinations. | Open | C1, C2 |
| M4 | `Requesting punch endpoint` is sent twice about 14ms apart, probably once per opened channel. | Open | C1, C2 |
| M5 | At startup the node KEX retry steps from 1 to 3 within 85ms. Harmless: KEX completes 40ms later. | Open | C2 |
| M6 | Ashish's camera ↔ Hemanth's camera stay on relay: both NATs are endpoint-dependent (Docker Desktop and Jio). | By design | C1 |
| M7 | Stream-open failures ("Tunnel Open resource command status failed", "Media streaming is not ready") happen only within a few seconds of a camera restart. | Not meshlink | C1, C2 |
| M8 | Android's AF_NETLINK bind-failure fallback leaves the socket open. Discovery also degrades in the local Docker/QEMU setup; details below. | Open | L1 |

### M8: Netlink bind-failure socket leak and discovery limitations
**Status:** Open. **Workstream:** WS4. **Seen in:** L1.

**Evidence:** all three Android app starts log `Could not bind AF_NETLINK socket: Permission denied` (`android-meshlink-ws1-001.txt`, lines 34, 59794 and 76439).

**Mechanism:** in `discovery_start()` (`src/discovery.c`), socket creation succeeds but binding the netlink notification groups fails. The fallback calls `scan_ifaddrs()` without closing the failed socket or registering it with the event loop. That leaks one descriptor per failed discovery start. The three starts in L1 are separate app processes, so the capture does not demonstrate accumulated descriptor pressure.

**Related environment limitations:**
- The netlink fallback discovers the initial interfaces but does not subscribe to subsequent interface/address notifications. Android does call `meshlink_hint_network_change()` in L1, providing an application-driven fallback.
- The camera logs `Could not set outgoing multicast interface on IPv4 socket` twice (`camera-meshlink-ws1-001.txt`, lines 56 and 130). Those mDNS sends return early. The log omits errno, so the cause is not established.
- These are discovery limitations, not evidence that ordinary UDP is broken. They are distinct from M3's broadcast/multicast PMTU probes.

**Fix:** close the netlink socket on bind failure. Include errno and interface context in multicast-interface failure logs, and verify the application network-change fallback when native notifications are unavailable.

**Verification:** force netlink bind failure, repeat discovery start/stop, and assert that the open-descriptor count remains stable. Verify that a network-change hint refreshes the address set and advances the network epoch. Exercise multicast-interface failure and check that its diagnostic identifies the interface and error without disrupting ordinary UDP.

---

## Workstreams

The remaining findings are grouped by the code they touch, so that each piece of delicate code is redesigned once instead of being patched finding by finding.

Rules for every workstream:
- Build and test only inside the `meshlink-arm64` container, from `/mnt/host/coco-project/third-party/meshlink`. Run the full suite serially with `make -j1 check`.
- Each PR passes the full suite on its own.
- Each workstream ends with a field capture on Hemanth's path, recorded here as a new capture (C3, …).

| ID | Scope | Findings | Depends on | Status |
|----|-------|----------|------------|--------|
| WS1 | Path MTU and liveness rework | F3, F5, F6, F4 (PMTU gate), F2 follow-up | — | Designed; plan next |
| WS2 | Relay data plane | F7, relay MTU | WS1 PR A; NMN deployed first | Not started |
| WS3 | Route selection at startup and after reachability changes | F4 (route choice), F8 | WS1 | Not started |
| WS4 | Hygiene | M1, M2 (meshlink side), M3, M4, M5, M8 | — | Not started |

### WS1: Path MTU and liveness rework

**Goal:** a path's correctness never depends on discovering its MTU. Data flows immediately at a size that works on essentially every path in the world. Discovery only ever raises that size; it never sends oversized echoes, gives up quickly, and remembers which paths punish oversized packets.

**Decisions:**

| Topic | Decision |
|-------|----------|
| Backward compatibility | Not required (internal development only, no public launch). The wire format may change without negotiation, and every node and the NMN are deployed together. A full-size echo from a peer is still accepted as proof of a size, since that costs nothing extra. |
| Base size | 1232 bytes of UDP payload, which is meshlink MTU 1211 (1232 − 21 bytes of SPTPS overhead). It fits IPv6's 1280 minimum, 464XLAT/NAT64, PPPoE, most VPNs and mobile carriers. |
| Persistence scope | Per node, per remote IP. |
| Keepalive owner | Both ends of a direct path, sent only when that end has been idle on the path, and only while the path is in demand. The interval adapts per path. Details below. |

**Why the current design can't be patched:**
- **One counter, three jobs:** `mtuprobes` drives liveness, discovery and the raise. That's why F2 and F5 happened, and why a liveness give-up wipes PMTU.
- **No convergence without ICMP:** `maxmtu` only drops on `EMSGSIZE`, which a black hole never produces.
- **Full-size echoes:** an L-byte request gets an L-byte reply, so the peer is forced to send oversized packets into its own uplink.
- **Data waits for discovery:** the route can't go direct until PMTU settles (F4).

**Design:**
1. **Two state machines per path.**
   - **Liveness:** is the endpoint alive?
   - **PLPMTU:** how big can our datagrams to it be? PLPMTU state is keyed by local address family and remote IP, not by port, so it survives rebind (F0), liveness give-up, and session restarts.
2. **Base first.** Every path starts at base (1232 / MTU 1211), and the route can go direct at base right away; there is no PMTU gate on promotion. Channel MSS follows the PLPMTU, and every change goes through `channel_refresh_mtu`.
3. **Bounded search** (datagram PLPMTUD, RFC 8899).
   - **States:** `BASE → SEARCHING → COMPLETE`, plus `ERROR` (black-hole fallback to base).
   - **Ladder:** probe a short ladder of UDP payload sizes (for example 1280, 1360, 1400, 1420, 1440, 1452, 1472), then refine between the largest confirmed size and the smallest failed one.
   - **Failure:** at most 3 tries per size. Three losses at size S set `largest_failed = S`, and nothing at or above S is probed again until the raise timer.
   - **Pacing:** one size probe in flight per path, never in the same tick as a liveness probe or a keepalive, and rate-limited per peer.
   - **Raise timer:** 600s, with exponential backoff while probes keep failing.
4. **One-direction measurement.**
   - A size probe is a padded request. The receiver answers with a 64-byte acknowledgement that carries the nonce and the number of bytes it received.
   - Each node learns only its own send direction (on Hemanth's path: phone→camera 1451, camera→phone ~1430). That is the size UTCP needs.
   - No node ever sends an oversized reply.
   - It is a new probe subtype inside SPTPS (authenticated); bump `PROT_MINOR` for visibility.
5. **Hostile-path detection.**
   - If a rebind is seen within about 1s of an oversized size probe we sent, mark that remote IP hostile.
   - On a hostile path: stop probing above the confirmed size, and back the raise timer off exponentially from 10 min to a cap of 24h.
6. **Data-plane black-hole detection.**
   - Signal: full-MSS records keep being lost while 64-byte probes are answered (the signal the F1 suspect logic already sees).
   - Response: re-probe at the current PLPMTU. After 3 losses, drop to base and search again slowly.
   - This covers mid-session MTU drops, such as a VPN coming up or a carrier change on the same IP.
7. **Liveness (F5).**
   - 64-byte probes while the path is in demand, with up to 3 tries inside `pingtimeout` (for example at 0s, 1.5s and 3s).
   - A give-up only happens after all tries go unanswered. It demotes the route and leaves PLPMTU untouched.
   - A nonce reply from the confirmed endpoint keeps counting as liveness (the F2 fix).
8. **Idle keepalive (F6).** See "Keepalive design" below.
9. **Persistence.**
   - Per node, per remote IP: PLPMTU, `largest_failed`, the hostile flag, the learned keepalive interval, a timestamp and the local network epoch.
   - Reuse an entry when the remote IP and local network epoch match and it's under 24h old.
   - In memory first (survives sessions); on disk in PR C (survives restarts).
10. **Observability.** New devtool status fields and counters:
    - PLPMTU state, current size, `largest_failed`, and the hostile flag;
    - size probes sent and lost, and how many were above the confirmed size;
    - liveness tries and give-ups;
    - keepalives sent, the current keepalive interval, and idle expiries detected.

    These are what let fleet data tune the ladder and the keepalive interval.

**Keepalive design (F6):**
- **Who sends:** both ends of a direct UDP path.
  - Neither end can reliably tell whether it is behind a NAT. Phones and cameras often both are, and the mapping is often several NATs deep.
  - RFC 4787 only guarantees that outbound traffic refreshes a mapping, so each end has to keep its own mappings alive.
- **When:**
  - Only after that end has sent nothing on the path for the keepalive interval. Any outbound packet resets the timer: data, liveness, or probes.
  - So the cost is zero while streaming, and at most one 64-byte packet per interval per idle side.
- **Only while the path is in demand:** the route is direct and a channel needs the peer.
  - An idle, unwanted path is allowed to expire.
  - On the next demand it is re-punched through the NMN. PLPMTU and the learned interval come from the cache, so recovery is one punch round trip.
- **No reply:** the keepalive is fire-and-forget, so there is no amplification. Liveness stays separate.
- **Adaptive interval, per path:**
  - Start at 15s for ordinary peers. The observed timeout on Hemanth's path was 10–19s; RFC 4787 asks for at least 2 minutes, but mobile CGNATs routinely use 30s or less.
  - When an idle expiry is detected, shrink the interval to 60% of the longest idle gap that survived, with a floor of 5s. Detection: liveness fails after an idle gap longer than the interval, or a rebind shows up right after such a gap.
  - After an hour without an expiry, grow it by 20%, up to the starting value.
  - The learned value is persisted with the PLPMTU entry.
- **Backbone UDP:** keeps its required keepalive (currently 25s), but uses the same adaptive rule. Only peers whose NATs expire faster pay for a shorter interval, which keeps the load on the NMN proportional across a global fleet.

**Delivery:** implemented together on `ws1-plpmtud-liveness` (not split into three PRs in the tree). `PROT_MINOR` is 6. ADR 0011 records the decisions. Field capture C3 is still to be run.

- Liveness, PLPMTU and keepalive are separate machines. `mtuprobes` is gone.
- A liveness give-up keeps the learned size.
- Search starts at payload 1211 (UDP 1232) and walks a fixed ladder. There is no binary refine.
- Size probes are one-direction `SIZE_REQUEST` / 64-byte `SIZE_ACK`. An echo longer than 64 bytes is dropped.
- Hostile paths and data-plane black holes hold or drop the size without a full rediscovery.
- Both ends send an adaptive idle keepalive. The interval shrinks after a confirmed idle expiry and grows back toward the cap.
- The per-node per-remote-IP cache is in the host config trailer. `MESHLINK_STORAGE_DISABLED` and `KEYS_ONLY` keep it in memory only.
- Devtool node status is version 6.

**WS1 test matrix (netns, in the `meshlink-arm64` container):**
- **Black hole:** DF packets above N are dropped with no ICMP. Data flows at base from the first second, and the search settles with at most 3 tries per size.
- **ICMP present:** `EMSGSIZE` still lowers the size immediately.
- **Asymmetric MTU:** each side's MSS matches its own send direction.
- **Oversize-punishing NAT** (emulated, speculative):
  - Drop packets over N.
  - Have a `conntrack -E` watcher delete the flow's entry on that drop, so the next packet gets a new port under `MASQUERADE --random`.
  - Assert that the hostile flag is set, there are 3 or fewer migrations per session, and there's no relay fallback.
- **IPv6 at 1280, and PPPoE at 1492.**
- **Mid-session MTU drop:** black-hole detection falls back to base and recovers without the channel stalling.
- **Idle expiry:** a 15s UDP conntrack timeout on the camera side. The keepalive holds the mapping, and after a forced expiry the interval shrinks and stays shrunk.
- **Single lost liveness reply:** drop one reply; there is no give-up.
- **Restart:** a camera restart reuses the cached PLPMTU, with no search if the entry is fresh.
- **Regression:** T1, T18a, T21, T22, T23, the udp-relay NAT matrix including rebind, and path-policy-coverage all still pass.

**Done when:**
- The full suite passes.
- A field capture on Hemanth's path shows:
  - no churn bursts at session start;
  - 3 or fewer oversized-probe losses per discovery;
  - no relay episode after a stream pause;
  - direct within a few seconds of startup.

### WS2: Relay data plane (F7)
- **Goal:** "relay-udp" is UDP on both legs.
- **NMN-side relay readiness:** the NMN marks a peer's endpoint relay-ready after an authenticated exchange from that exact endpoint. That can be the peer's backbone keepalive, or a nonce exchange the NMN initiates. The mark expires on silence, using WS1's keepalive and liveness rules.
- **Relay MTU from both legs:** `relay_budget` becomes the minimum of the origin→NMN and NMN→destination PLPMTUs (WS1 machinery running on the NMN), replacing the current `minmtu`-based budget.
- **Keep the META fallback** for destinations without a ready UDP endpoint, and count it, so fleet data shows how often it happens.
- **Rollout:** deploy the NMN first.
- **Tests:** a relay test asserts that the last leg is UDP; a test asserts the relay budget follows the smaller leg.

### WS3: Route selection at startup and after reachability changes (F4 leftovers, F8)
- Once backbone UDP confirms, re-rank `meta-direct` → `relay-udp`, so data never stays on TCP through the NMN just because of start order.
- Don't let a direct-UDP candidate pre-empt the backbone-UDP step down.
- **F8:** prevent offline destinations from starting or committing promotions; test disconnect, background route ticks and reconnect with retained channel demand.
- Re-measure after WS1, because promoting direct at base may already remove most of F4.

### WS4: Hygiene
- **M1:** edge-trigger `Unstable NAT binding`, so it fires once per window.
- **M2 (meshlink side):** skip private-address candidates that aren't on any of our own subnets. The infra fix (client-IP preservation or proxy protocol at the NMN load balancer) is tracked with infra.
- **M3:** don't send broadcast or multicast PMTU probes to peers we only know by WAN address.
- **M4:** coalesce `Requesting punch endpoint` per peer.
- **M5:** review the KEX retry ladder stepping at startup.
- **M8:** close the netlink socket on bind failure, improve multicast-interface diagnostics, and verify network-change hints when native discovery notifications are unavailable.

## Appendix: how the captures were analysed
The logs are large (C2's phone log is 175 MB), so each analysis first builds compact extracts:
- **Phone:** keep only `ct_meshlink_logger_cb` lines, strip CR, and reduce each line to `<epoch_ms> <pid> <message>`. Each pid is one app run.
- **Camera:** keep only `ct_meshlink_logger_cb` lines and reduce each to `<epoch_ms> <message>`. Each file is one camera run.
- **Key-event timeline:** filter on `Path route`, `Path UDP`, `UDP rebind`, `Punch`, `PLPMTU of`, `UDP keepalive interval`, `did not respond`, `Suspect fallback`, `became (un)reachable`, `meshlink_open_ex` and `Error sending`, and print readable IST times.
- **Per-direction traffic in 5s buckets:** count `Sending packet of … to N` (direct, or followed by `Relaying type-8 via UDP`), `Received packet of … from N`, and `REQ_KEY from 0: 15 <src> <dst> 21` (delivered over META).
- **PMTU cycles:** group `Sending MTU probe length L to N at <non-broadcast>` lines until `PLPMTU of N settled`, and count probes larger than the settled size. `PLPMTU of N raised` is a step up. `PLPMTU of N: path is hostile` and `black hole detected` are the phase-B holds.
- **App-layer symptoms:** `meshlink_channel_send failed`, `MediaStreamChannel: onStatusChanged`, and `meshlink_channel_abort`.
