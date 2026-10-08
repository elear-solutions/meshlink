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
| F4 | Slow climb to direct at startup and after restarts | WS3 implemented; field validation pending | WS1 (MSS), WS3 (route choice) |
| F5 | Liveness is one probe per window; one lost reply demotes the path | Fix ready | WS1 |
| F6 | The camera's NAT expires idle mappings faster than our ping cadence | Fix ready | WS1 |
| F7 | The NMN delivers relayed records over META, never UDP | Implemented; field validation pending | WS2 |
| F8 | Route promotion continues while the destination is unreachable | Implemented; field validation pending | WS3 |
| F9 | A pending direct promotion keeps the old port after a validated rebind | Implemented; field validation pending | WS3 |
| F10 | Channels expose no immediate availability change when the peer becomes unreachable | Open (API/policy review) | WS4 |
| M1–M8 | Minor items | Open / By design / Not meshlink | WS4 |

Order: WS1 → WS2 → WS3, with WS4 whenever convenient.

## Captures

| ID | When | Nodes | Builds | Files |
|----|------|-------|--------|-------|
| C1 | 2026-10-04 22:17–22:38 IST | phone = node 1, Hemanth's camera = node 4, Ashish's camera = node 2, NMN = node 0 | nodes on `validated-udp-rebind` (PR #125); NMN on `elear-develop` | `android-meshlink-001.txt`, `hemanth-camera-meshlink-00{1,2,3}.txt`, `ashish-camera-meshlink-001.txt` |
| C2 | 2026-10-05 12:24–12:42 IST | phone = node 5, Hemanth's camera = node 4, NMN = node 0 | nodes with the F1 and F2 fixes on top of PR #125; NMN on `elear-develop` | `android-meshlink-003.txt`, `hemanth-camera-meshlink-00{4,5,6}.txt` |
| L1 (local) | 2026-10-06 22:34:09–22:37:53 IST; camera log covers 22:36:51–22:37:45 | Android emulator = node 6, local camera simulator = node 2, NMN = node 0 | WS1 endpoint builds; NMN advertises protocol 17.6; exact build SHAs not recorded | `android-meshlink-ws1-001.txt`, `camera-meshlink-ws1-001.txt` |
| C3 | 2026-10-07 09:16:28–09:35:04 IST | Android = node 6, Hemanth's camera = node 4, NMN = node 0 | All advertise protocol 17.6; exact build SHAs not recorded | `android-meshlink-ws1-00{2,3}.txt`, `camera-meshlink-ws1-00{2,3,4,5,6,7}.txt` |

For C1 and C2, the only difference between `elear-develop` and PR #125 is rebind, and rebind is switched off on any pair that includes the backbone (`path_is_ordinary_peer_pair`). So the stale NMN build behaves the same as the new code for the findings from those captures.

L1 is a local check with the endpoints on the same host, using the Ubuntu Docker container and QEMU. C3 exercises Hemanth's Jio path (`152.57.155.226`). The camera clock appears roughly 0.8s ahead of Android in L1 and 0.91–0.95s ahead in C3; cross-endpoint timings need that adjustment. Android captures 002 and 003 overlap: deduplicate their shared records when counting events. All supplied camera captures use `KEYS_ONLY` storage, so they cannot confirm PLPMTU persistence across process restarts. Its memory-only cache is intentional under this policy; a full-storage run is still needed to verify disk reuse.

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
**Status:** Fix ready (bounded search confirmed in C3; startup recovery follow-up awaiting a new field capture). **Priority:** 1. **Seen in:** C1, C2, C3.

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

**C3 follow-up:** camera→phone and camera→NMN searches settle at payload 1431, while phone→camera reaches 1451. All replies are 64 bytes. The six camera sessions send 107 size requests across those two legs; 35 are at the failed 1451 size. The bounded directional search works, but startup recovery still has a blind spot: application traffic remains on META/relay during promotion residency, so no small direct packet exposes the new NAT port after an oversized request. The next scheduled small packet can be 15s later, outside the 2s hostile-detection window.

- Android gives up UDP at 09:16:55.821 (`android-meshlink-ws1-002.txt:3600`) and recovers at 09:17:05.773 (line 17428): 9.952s. Camera 002's next 64-byte request is exactly 15s after its last failed size request (`camera-meshlink-ws1-002.txt:9607`). Further give-ups occur at 09:22:44.687, 09:25:05.540 and 09:33:16.194 in Android 003. The camera 006 startup also demotes through the suspect path at 09:33:42.989.
- Camera 007 shows the successful case: a prompt rebind challenge arrives after two oversized attempts, the path becomes hostile, and the phone commits the port change in 30ms. Earlier sessions usually exhaust all three attempts without learning hostility.
- The original hostile-NAT integration test sent application packets every 500ms after forcing direct promotion. That hid this gap.

**WS1 follow-up fix:** after a missed size request, send a timer-owned 64-byte recovery echo before another size attempt, with the normal health/size pacing guard and scheduler limits. Authenticated probe replies report the sender's observed endpoint, allowing its own remap to be detected on ordinary and backbone paths without application UDP. Preserve the size nonce for a late ACK. Regression coverage includes denied recovery admission, wrong nonce/source, backbone recovery, and an oversize-punishing NAT while direct promotion is held and the application sends no data.

## F4: Slow climb to direct at startup and after restarts
**Status:** WS3 implemented; field validation pending. **Priority:** 4. **Seen in:** C1, C2, C3.

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
- **WS1** publishes the 1232-byte base immediately after UDP confirmation; the search raises MSS later. Direct is eligible at base, but existing route residency and promotion holds still apply.
- **WS3** covers the rest:
  - re-rank a META relay to the same first hop's proved UDP carrier after a one-second hold, preserving destination residency even with a pending direct candidate;
  - reduce elective active-route residency from 30 to 10 seconds, with the existing route tick making the eventual commit. See ADR 0013.

**C3:** the MSS wait is removed, but direct selection still commonly takes 30–40s. The final session takes about 39s despite cached phone→camera PLPMTU 1451; F9 records the additional stale-port promotion cycle. WS3 owns these remaining delays. Earlier promotion should also be checked against any remaining rebind quiet-window cost.

## F5: Liveness is one probe per window; one lost reply demotes the path
**Status:** Fix ready (three-attempt behavior confirmed in C3; scheduler-accounting follow-up awaiting a new field capture). **Priority:** 2. **Seen in:** C2, C3.

**Evidence (C2, 12:36:11–12:37:05):**
- At 12:36:11.596 the camera sent its 64-byte liveness probe and its 1439-byte raise in the same millisecond.
- The phone answered the 64-byte probe within about 70ms, but the reply never reached the camera. The camera gave up at 12:36:16.610.
- The camera had been receiving authenticated direct UDP from the phone throughout (suspect probes at 12:36:12.5 and 12:36:14.8), but only probe replies count as liveness.
- The give-up restarted the camera's discovery, which churned its NAT (F3). The phone demoted at 12:36:21 and then failed nine punches. Result: 44s on relay.

**Root cause:** a single 64-byte probe per `pingtimeout` window, no retry, and the give-up resets PMTU.

**Fix:** WS1. Liveness becomes its own state machine with 3 tries per window. A give-up demotes the route but never touches PLPMTU, and liveness is never sent in the same tick as a size probe.

**C3/code-review follow-up:** C3 has three small liveness attempts per failed window and retains PLPMTU after demotion. A separate code-level gap remained under scheduler starvation: liveness could queue even though its owner only counted immediate sends. Repeated timer retries could enqueue extra attempts, and a successful reply did not cancel them. This was not established as a cause of the C3 outages. WS1 now denies timer-owned liveness requests when they cannot send immediately; the owner retries without counting a denial as peer silence. Local discovery shares that priority and likewise advances its finite probe ladder only on admission. Unit coverage exhausts the budget, refills and drains it, verifies exactly three counted/emitted liveness attempts, checks that a reply leaves no stale sends, and verifies that denied local discovery does not exhaust its ladder.

## F6: The camera's NAT expires idle mappings faster than our ping cadence
**Status:** Fix ready (C3 exposed expiry-attribution and owner-learning gaps; follow-up awaiting a new field capture). **Priority:** 2. **Seen in:** C1 (one case), C2, C3.

**Evidence (C2, 12:38:15–12:39:32):**
- The stream stopped at about 12:38:15. After that, the camera's only packet toward the phone was its reply to the phone's 12:38:25 ping.
- The next ping at 12:38:43.999, about 19s later, went unanswered, and the phone gave up at 12:38:49.
- The camera's next outbound packet (12:38:52) came from the same port, and the punch confirmed 4s after the give-up.
- But the give-up had reset PMTU, so another 30 probes ran, 20 more migrations followed, and the phone spent 43s on relay.
- A 10s idle earlier in the same run survived. So the timeout looks like 10–19s (speculative).
- At idle the camera sends nothing on its own, and the phone's ping cadence works out to about 19–20s.

**Fix:** WS1 adds an adaptive idle keepalive (see "Keepalive design" under WS1).

**C3 follow-up:** the phone shortens its interval to 5000ms after four startup recoveries, but the camera never shortens its 15s interval. The first phone liveness window starts after only a 6.357s local outbound gap, below the 15s interval; recovery follows the camera's oversized-send phase. A same-remote-IP re-punch does not establish whose NAT expired or whether the cause was idle expiry. Shortening the phone's interval cannot keep the camera's outbound-only mapping alive.

**WS1 follow-up fix:** learn on the endpoint whose source port changed, using an authenticated observed endpoint and its own preceding outbound gap of at least the configured interval. A local give-up/reconfirmation alone is insufficient. Reject stale evidence, another remote endpoint, public-IP/network changes, and recent oversized-send correlation. Keepalives can expose and repair the mapping while the application is quiet. Unit tests cover these exclusions and both peer/backbone learning; the idle-NAT integration case uses the normal 15s starting interval against a 12s camera mapping, verifies camera-side shortening and no phone-side false expiry, then checks stable delivery through further idle periods.

**Additional accounting gap found during verification:** probe replies, rebind challenges and backbone probes sent through the destination-override callback bypassed outbound-activity accounting. That could leave a fictitious idle gap despite actual traffic, or omit the sender-owned gap needed to learn an expiry. Both UDP send paths now record successful sends to the confirmed endpoint; sends to another candidate and unsuccessful sends cannot refresh that mapping. Unit coverage exercises the real probe-send callback and checks that a different candidate leaves the confirmed path's activity unchanged.

Fresh nodes also initialized the ordinary 15s interval before their backbone role was known, overriding the intended 25s backbone default. Choose the default on UDP confirmation, preserve restored intervals, and bound the initial outbound gap from confirmation when the first probe preceded endpoint assignment. Unit coverage checks both fresh roles and restored intervals.

**Upgrade behavior:** 17.6 may have persisted falsely shortened intervals in the phone's full-storage cache. New entries mark the corrected keepalive generation with flag `0x02`. Restore an interval only from that generation; legacy entries still supply their MTU, failure bound and hostility state. Unit coverage checks legacy versus current restoration and serialization of the marker, so the false 5s lesson cannot survive an upgrade silently.

This revises the ADR 0010 position that keepalives don't help. That position still holds for the under-load re-mapping (F3), but not for idle expiry. WS1 records the change in a new ADR.

## F7: The NMN delivers relayed records over META, never UDP
**Status:** Open. **Priority:** 3. **Seen in:** C1, C2, C3.

**Evidence:**
- C2: the phone received 30,530 of its 89,410 packets (34%) as `REQ_KEY … 21` from the NMN, while the camera was sending them `via UDP to 0`.
- In early C2 run 3 the camera's video (about 1,700 packets per 5s) went through the NMN over TCP.
- C1: the camera received 291 of 312 relayed records over META.
- C3: after removing the overlapping Android records, 23,659 camera→phone relayed `REQ_KEY … 21` records still arrive from the NMN over META. Protocol 17.6 did not resolve last-leg relay readiness.

**Mechanism:**
- `relay_handle_record` forwards over UDP only when `relay_hop_udp_ready(out)` holds, which needs `udp_confirmed` on the NMN's side (`relay.c` lines 552–560). Otherwise it uses base64 `REQ_SPTPS` over META.
- Every place that sets `udp_confirmed` starts from the peer's side: a punch challenge reply, or the camera-originated backbone UDP mapping. The NMN only answers.
- So an ordinary peer is never UDP-ready from the NMN's point of view.
- This is code-level and the same on every branch; the stale NMN build has nothing to do with it.

**Impact:** "relay-udp" is UDP only on the first leg. The last leg adds TCP head-of-line blocking and latency, and base64 encoding plus `REQ_KEY` parsing on the NMN for every relayed packet.

**Fix:** WS2.

**Verification:** a relay test asserts that the last leg is UDP (no `REQ_KEY … 21` at the destination) once both peers have confirmed backbone UDP.

## F8: Route promotion continues while the destination is unreachable
**Status:** Implemented; field validation pending. **Workstream:** WS3. **Seen in:** L1.

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

## F9: Pending direct promotion retains the old port after rebind
**Status:** Implemented; field validation pending. **Workstream:** WS3. **Seen in:** C3.

**Evidence (Android 003, one clock):**
- At 09:34:19.853 a direct candidate targets camera port 60808 (`android-meshlink-ws1-003.txt:239009`).
- The validated rebind to port 53583 commits at 09:34:25.230 (line 241058), 30ms after discovery.
- A replacement direct candidate for 53583 starts only at 09:34:53.758 (line 276321), 28.528s after the successful rebind. Direct finally commits at 09:34:58.829 (line 279777), about 39s after the original confirmation.

**Mechanism:** `path_rebind_commit()` moves `n->address` and an already-active direct route's endpoint, but leaves `promotion_candidate` pointing to the previous port. `path_consider_route_promotion()` retains an existing equal-ranked candidate even when the endpoint differs. When residency eventually allows commitment, the already-live-carrier check rejects the stale endpoint and discards the candidate; a later route tick starts another candidate and hold period. This is distinct from F8's offline-destination admission and F4's general residency delay.

**Fix:** reconcile a pending direct candidate when a validated same-IP rebind commits. Retarget using the new endpoint's authenticated evidence, or discard and replace promptly. Preserve active-route residency; do not carry old-port nonce validation into the new candidate or wait until the stale candidate's eventual commit attempt to notice the change.

**Verification:** start a pending direct promotion while the channel is relayed and inside residency, commit a validated rebind, and assert that the pending endpoint immediately follows the confirmed endpoint or is promptly replaced. Check nonce/evidence validity, unchanged route residency, continued relayed delivery, and direct commitment without an extra discard/retry cycle once residency permits it.

## F10: Channel availability is not immediately reported on peer unreachability
**Status:** Open (API/policy review). **Workstream:** WS4. **Seen in:** C3.

**Evidence:** camera 002 reports node 6 unreachable at 09:19:33.049 (`camera-meshlink-ws1-002.txt:57571`), then logs 4,157 route drops from 09:19:33.079 to 09:19:45.817 while application channel sends continue. Android 003 reports node 4 unreachable at 09:23:13.004 (line 61811), but continues 540-byte writes every 64ms and records 126 zero-byte partial writes between 09:23:14.894 and 09:23:22.897 (lines 61861–62126). This is evidence of missing immediate channel availability feedback, not proof that a terminal-close callback was lost.

**Current semantics:** reachability loss calls the node-status callback and `utcp_offline()`. UTCP keeps established reliable connections open for recovery and arms their connection timeout. It does not invoke the channel's zero-length receive callback immediately. Remote closure, session reset, or terminal timeout does invoke that callback; the default UTCP timeout is 60s and can be overridden per node/channel. Consequently, an application watching only channel closure can still reasonably believe the channel is open while Meshlink accepts/buffers sends to an unreachable destination. The application issue should not be classified solely as teardown misuse without accounting for this Meshlink behavior.

**Potential Meshlink improvement:** provide explicit per-channel unavailable/recovered notifications, or an opt-in policy that promptly terminates channels on sustained node unreachability. Define what `meshlink_channel_send()` and the poll callback guarantee while unavailable, including buffering/backpressure and the error reported on terminal closure. Keep recovery of transient outages possible under the default reliable-channel contract; do not report a terminal close and later resume the same channel. Audit terminal-close notification delivery separately to ensure it happens exactly once for receive, poll and AIO users.

**Additional code-level detail:** `meshlink.h` promises that the zero-length receive callback has `meshlink_errno` set. UTCP's timeout path sets system `errno = ETIMEDOUT`, but the `channel_recv()` and `channel_poll()` bridges do not translate that reason into `meshlink_errno` before invoking application callbacks. That is a separate notification-diagnostics gap, not proof that a callback was omitted in C3. Define and test reason propagation, preserving it across AIO completion and callbacks that call other APIs.

**Verification:** disconnect a node with established sending and idle channels; verify node and channel availability notifications, bounded buffering/backpressure, timeout-close notifications and errno, and callback safety when the application aborts in a callback. Reconnect before timeout to verify recovery semantics; reconnect after terminal closure to verify the old channel remains closed. Include session restart and unreachable-destination send loops matching C3.

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
| WS1 | Path MTU and liveness rework | F3, F5, F6, F4 (PMTU gate), F2 follow-up | — | Implemented in PR #127; C3 follow-up fixes awaiting field validation |
| WS2 | Relay data plane | F7, relay MTU | WS1 PR A; NMN deployed first | Implemented; Docker and field validation tracked below |
| WS3 | Route selection at startup and after reachability changes | F4 (route choice), F8, F9 | WS1 | Implemented in PR #129; all 58 Docker tests pass; field validation pending |
| WS4 | Hygiene and channel availability | M1, M2 (meshlink side), M3, M4, M5, M8, F10 | — | Not started |

### WS1: Path MTU and liveness rework

**Goal:** a path's correctness never depends on discovering its MTU. Data flows immediately at a size that works on essentially every path in the world. Discovery only ever raises that size; it never sends oversized echoes, gives up quickly, and remembers which paths punish oversized packets.

**Decisions:**

| Topic | Decision |
|-------|----------|
| Backward compatibility | Not required (internal development only, no public launch). The wire format may change without negotiation, and every node and the NMN are deployed together. Size requests use a fixed 64-byte ACK; echo requests longer than 64 bytes are dropped. |
| Base size | 1232 bytes of UDP payload, which is meshlink MTU 1211 (1232 − 21 bytes of SPTPS overhead). It fits IPv6's 1280 minimum, 464XLAT/NAT64, PPPoE, most VPNs and mobile carriers. |
| Persistence scope | Per node, per remote IP. |
| Keepalive owner | Both ends of a direct path, sent only when that end has been idle on the path, and only while the path is in demand. The interval adapts per path. Details below. |

**Why the current design can't be patched:**
- **One counter, three jobs:** `mtuprobes` drives liveness, discovery and the raise. That's why F2 and F5 happened, and why a liveness give-up wipes PMTU.
- **No convergence without ICMP:** `maxmtu` only drops on `EMSGSIZE`, which a black hole never produces.
- **Full-size echoes:** an L-byte request gets an L-byte reply, so the peer is forced to send oversized packets into its own uplink.
- **MSS waits for discovery:** the channel remains at the minimum MSS before usable PMTU is published (F4); direct-route promotion itself is not gated on PMTU settlement.

**Design:**
1. **Three state machines per path.**
   - **Liveness:** is the endpoint alive?
   - **PLPMTU:** how big can our datagrams to it be? PLPMTU state is keyed by local address family and remote IP, not by port, so it survives rebind (F0), liveness give-up, and session restarts.
   - **Keepalive:** does this sender need outbound traffic to preserve its own idle mapping?
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
   - A missed size request triggers a 64-byte recovery echo before retrying the size. This works before direct promotion and on the backbone.
   - Replies carry the sender's observed endpoint. If its same-IP source port changes within 2s of an oversized size probe, mark that path hostile. Authenticated rebind challenges also carry their observed candidate endpoint.
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
   - In memory across sessions; the host-config trailer survives process restarts with full storage. `KEYS_ONLY` and disabled storage intentionally do not persist path metadata.
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
  - When the peer observes this sender's source port changing after its own outbound idle gap of at least the interval, shrink to 60% of that gap, with a floor of 5s. Confirm the endpoint observation from authenticated, nonce-validated replies or a rebind challenge from the confirmed peer. Require a same-IP local remap on the same remote path/network epoch within 30s of the outbound gap; exclude recent oversized sends. Local give-up and same-IP recovery alone do not identify idle expiry or its owner.
  - After an hour without an expiry, grow it by 20%, up to the starting value.
  - The learned value is persisted with the PLPMTU entry.
- **Backbone UDP:** keeps its required keepalive (currently 25s), but uses the same adaptive rule. Only peers whose NATs expire faster pay for a shorter interval, which keeps the load on the NMN proportional across a global fleet.

**Delivery:** implemented together on `ws1-plpmtud-liveness` ([PR #127](https://github.com/elear-solutions/meshlink/pull/127)). C3 validates the directional ladder, bounded attempts, small replies and retained size, but exposes the F3/F6 startup and attribution gaps described above. The follow-up uses protocol 17.7 for observed-endpoint metadata and recovery probes. ADR 0011 records the decisions. A fresh field capture with the follow-up on all endpoints and the NMN is still required.

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
  - Repeat before direct promotion, with residency held and no application sends; recovery must come from Meshlink control traffic. Verify backbone recovery and wrong-nonce/source rejection in unit coverage.
- **IPv6 at 1280, and PPPoE at 1492.**
- **Mid-session MTU drop:** black-hole detection falls back to base and recovers without the channel stalling.
- **Idle expiry:** a 12s camera UDP conntrack timeout against the normal 15s initial interval. The camera learns its outbound refresh interval, the phone records no false expiry, and subsequent idle periods keep delivery working. Unit coverage rejects short gaps, unchanged mappings, stale evidence, network/IP changes and oversize-induced remaps.
- **Liveness admission:** exhaust/refill/drain scheduler budgets; denials consume no attempts, successful replies leave no stale queued probes, and no window emits more than three counted attempts.
- **Single lost liveness reply:** drop one reply; there is no give-up.
- **Restart:** a camera restart reuses the cached PLPMTU, with no search if the entry is fresh.
- **Regression:** T1, T18a, T21, T22, T23, the udp-relay NAT matrix including rebind, and path-policy-coverage all still pass.

**Done when:**
- The full suite passes.
- A field capture on Hemanth's path shows:
  - no churn bursts at session start;
  - 3 or fewer oversized-probe losses per discovery;
  - no relay episode after a stream pause;
  - the base MSS is usable immediately after UDP confirmation. Direct-selection delays remain tracked in WS3 (F4, F9).

### WS2: Relay data plane (F7)

Implemented on top of WS1; Docker validation and field acceptance are tracked
separately. [ADR 0012](adr/0012-demanded-udp-relay-output.md) records ownership,
protocol compatibility, budgets, and the narrow NMN probing exception.

- One runtime owner per NMN output peer shares demand across relayed flows.
  Authenticated ingress supplies a candidate; a matching nonce reply from the
  exact endpoint proves readiness. Two actual transmissions, one second apart,
  have a ten-second deadline. Same-candidate failure retries wait 30 seconds.
  Working output remains usable during replacement validation.
- Relayed application traffic, including META fallback, retains demand for
  30 seconds. Backbone keepalives cannot retain it. Expiry and lifecycle
  invalidation stop owned probes and readiness while preserving eligible cache
  knowledge. Relay proof neither promotes ordinary routes nor exports addresses.
- Protocol 17.8 adds application-only `REQ_SPTPS_APP`. Marked META and UDP
  ingress share the output decision; legacy envelopes and handshake/control
  traffic retain META. An older next hop receives legacy fallback.
- Records that fit a proved output hop use UDP. Oversize, absent socket,
  would-block, `EMSGSIZE`, and hard failure attempt META once; successful UDP
  transmission never also falls back. Counters expose readiness, actual UDP
  sends, and each fallback reason.
- The origin's packet budget is `min(origin→NMN PLPMTU − overhead, final report)`.
  Overhead is `2 + origin-name length + destination-name length + 21`.
  Until a valid report arrives, the final budget is `MINMTU − overhead`.
  Reports are tied to the current nexthop and META connection. Both leg changes
  refresh channel MTUs; UTCP keeps its existing header deduction.
  Reports to legacy origins retain the conservative floor because those builds
  cannot clamp the reported budget against the first leg themselves.
- Demanded, settled NMN output hops verify the current size about every
  30 seconds using WS1 acknowledgements, recovery echoes, and bounded retries.
  Verification preserves hostile holds and coalesces with search. Mesh-wide
  scheduler caps still apply. Devtools status version 7 exposes verification
  age, overdue time, and admission delays alongside readiness and send outcomes.
- Regression coverage uses separately linked internal support without new
  production compile switches, natural proof and delivery in both directions,
  marked META ingress, application-only authentication/replay checks, explicit
  send failures, smaller-leg arithmetic, and silent output-size reduction.
  A symmetric-NAT stream test drops actual final-leg UDP packets after natural
  settlement and confirms periodic checking reduces the budget and resumes
  the unacknowledged stream. Scheduler coverage verifies shared demand,
  preemption accounting, the two-slot cap, and eventual admission.
- Docker validation completed on 2026-10-08 in `meshlink-arm64`, based on
  WS1 `57ee0cd7`. Targeted `relay-hop`, `relay-coverage`,
  `path-policy-coverage`, and `backbone-udp` checks passed, followed by the
  full serial `make -j1 check`. That full run passed 57 of 58 tests and had
  one `channels-aio-cornercases` timeout. Three consecutive serial rechecks
  with `make -j1 check RECHECK_LOGS="channels-aio-cornercases.log"` passed
  without implementation changes; the final suite summary is 58 passed,
  zero failed, skipped, or errored. The observed intermittent timeout
  remains undiagnosed.
  The demand-expiry/reopen case also passed five focused
  `./path-stability --peer-demand` repetitions and the final full run; its
  earlier timeout on the preceding WS1 base did not recur. All compilation
  and tests ran in Docker; field acceptance remains separate.
- Rollout and field acceptance are deferred at the user's request: deploy
  NMN first, then camera and Android builds when deployment resumes. Capture
  matching build identities, proved output followed
  by actual UDP sends, explained META fallback, smaller directional budgets,
  rebinding and silent-MTU recovery, and probes confined to demanded outputs.
  Track WS3 startup route delay separately.

### WS3: Route selection at startup and after reachability changes (F4 leftovers, F8, F9)
- Once backbone UDP confirms and its proof has held one second, move the same relay first hop from META to UDP on the next route tick without restarting destination residency.
- Keep a pending higher-ranked direct candidate while the relay carrier upgrades; commit it after its own hold and ten seconds of active-route residency.
- **F8:** prevent offline destinations from starting or committing promotions; test disconnect, background route ticks and reconnect with retained channel demand.
- **F9:** reconcile pending direct promotions immediately after a validated rebind; test a relayed channel inside residency whose pending endpoint still points to the old port. Preserve residency and replace endpoint validation safely.
- Docker unit coverage exercises the one-second backbone hold, ten-second residency, offline admission and resumed selection, and a pending direct candidate retargeted by rebind. Existing relay and NAT integration tests exercise packet delivery. Record a new Hemanth-path capture before marking field validation complete; compare META/relay durations, direct time, rebind recovery, route changes, retransmits and packet loss with C3. No field timing is inferred from unit tests.

**Delivery:** implemented on `ws3-route-selection` ([PR #129](https://github.com/elear-solutions/meshlink/pull/129)); ADR 0013 records the policy. The full serial Docker `make -j1 check` rerun passed all 58 tests with no skips. The first run passed 57 tests and hit a T18a direct-UDP setup timeout in `path-stability`; that timeout did not reproduce in six isolated runs, a complete `path-stability` rerun, or the successful full-suite rerun. Temporary diagnostic changes were reverted before the successful full run. Hemanth-path field validation is still pending.

### WS4: Hygiene
- **M1:** edge-trigger `Unstable NAT binding`, so it fires once per window.
- **M2 (meshlink side):** skip private-address candidates that aren't on any of our own subnets. The infra fix (client-IP preservation or proxy protocol at the NMN load balancer) is tracked with infra.
- **M3:** don't send broadcast or multicast PMTU probes to peers we only know by WAN address.
- **M4:** coalesce `Requesting punch endpoint` per peer.
- **M5:** review the KEX retry ladder stepping at startup.
- **M8:** close the netlink socket on bind failure, improve multicast-interface diagnostics, and verify network-change hints when native discovery notifications are unavailable.
- **F10:** define per-channel availability feedback on node unreachability, buffering/backpressure guarantees, and optional prompt-close policy; verify transient recovery and exactly-once terminal-close notifications.

## Appendix: how the captures were analysed
The logs are large (C2's phone log is 175 MB), so each analysis first builds compact extracts:
- **Phone:** keep only `ct_meshlink_logger_cb` lines, strip CR, and reduce each line to `<epoch_ms> <pid> <message>`. Each pid is one app run.
- **Camera:** keep only `ct_meshlink_logger_cb` lines and reduce each to `<epoch_ms> <message>`. Each file is one camera run.
- **Key-event timeline:** filter on `Path route`, `Path UDP`, `UDP rebind`, `Punch`, `PLPMTU of`, `UDP keepalive interval`, `did not respond`, `Suspect fallback`, `became (un)reachable`, `meshlink_open_ex` and `Error sending`, and print readable IST times.
- **Per-direction traffic in 5s buckets:** count `Sending packet of … to N` (direct, or followed by `Relaying type-8 via UDP`), `Received packet of … from N`, and `REQ_KEY from 0: 15 <src> <dst> 21` (delivered over META).
- **PMTU cycles:** group `Sending MTU probe length L to N at <non-broadcast>` lines until `PLPMTU of N settled`, and count probes larger than the settled size. `PLPMTU of N raised` is a step up. `PLPMTU of N: path is hostile` and `black hole detected` are the phase-B holds.
- **App-layer symptoms:** `meshlink_channel_send failed`, `MediaStreamChannel: onStatusChanged`, and `meshlink_channel_abort`.
