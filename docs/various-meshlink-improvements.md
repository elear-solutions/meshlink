# Meshlink field findings tracker

This document tracks what field captures have shown about meshlink connection stability, and what we did about each finding. Plans should reference findings by ID (F1, F2, …, M1, …). When a capture confirms or changes a finding, update its **Status** and **Seen in** fields rather than adding a new section.

Status values:
- **Fixed**: code landed and a later capture confirms it.
- **Fix ready**: code exists but no field capture has confirmed it yet.
- **Open**: understood, no fix yet.
- **By design**: expected behaviour; listed so nobody re-investigates it.
- **Not meshlink**: belongs to another layer.

## Status summary

| ID | Finding | Status | Priority |
|----|---------|--------|----------|
| F0 | Confirmed peers pinned to a dead NAT port | Fixed (PR #125) | — |
| F1 | Suspect fallback silently drops retransmits, so channels stall | Fixed | — |
| F2 | The `maxmtu + 8` raise replaces liveness, causing false give-ups | Fixed | — |
| F3 | Oversized datagrams make the camera's NAT re-map; PMTU discovery causes most of it | Open | 1 |
| F4 | Slow climb to direct at startup and after restarts | Open | 4 |
| F5 | Liveness is one probe per window; one lost reply demotes the path | Open | 2 |
| F6 | The camera's NAT expires idle mappings faster than our ping cadence | Open | 2 |
| F7 | The NMN delivers relayed records over META, never UDP | Open | 3 |
| M1–M7 | Minor items | Open / By design / Not meshlink | 5 |

## Captures

| ID | When | Nodes | Builds | Files |
|----|------|-------|--------|-------|
| C1 | 2026-10-04 22:17–22:38 IST | phone = node 1, Hemanth's camera = node 4, Ashish's camera = node 2, NMN = node 0 | nodes on `validated-udp-rebind` (PR #125); NMN on `elear-develop` | `android-meshlink-001.txt`, `hemanth-camera-meshlink-00{1,2,3}.txt`, `ashish-camera-meshlink-001.txt` |
| C2 | 2026-10-05 12:24–12:42 IST | phone = node 5, Hemanth's camera = node 4, NMN = node 0 | nodes with the F1 and F2 fixes on top of PR #125; NMN on `elear-develop` | `android-meshlink-003.txt`, `hemanth-camera-meshlink-00{4,5,6}.txt` |

The only difference between `elear-develop` and PR #125 is rebind, and rebind is switched off on any pair that includes the backbone (`path_is_ordinary_peer_pair`). So the stale NMN build behaves the same as the new code for every finding below.

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
- Sending the raise in the same tick as the liveness probe still trips the camera's NAT (see F3 and F5).

---

## F3: Oversized datagrams make the camera's NAT re-map; PMTU discovery causes most of it
**Status:** Open. **Priority:** 1. **Seen in:** C1, C2.

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

**Fix options, cheapest first:**
1. **Converge on loss:** after 2–3 lost probes at size L, set `maxmtu = L - 1`. That cuts about 30 rounds of oversized probes to 3–5.
2. **Keep PMTU on give-up** when the IP is the same: re-confirm at `minmtu` instead of resetting `minmtu`/`maxmtu`. This alone would have shortened the 12:38:49 C2 episode from 43s to about 4s.
3. **Separate the raise from the liveness probe:** send the raise only after the liveness reply arrives, not in the same tick.
4. **Remember PMTU per peer IP** across sessions and restarts.
5. **Measure one direction only (bigger change):** the receiver answers with a 64-byte "got L bytes" message instead of echoing L bytes back. Nobody sends oversized replies, and each direction gets its real MTU (phone→camera 1451, camera→phone ~1430). This changes the wire format, so it needs a protocol minor bump.

**Verification:**
- A netns test with a NAT that drops oversized packets with DF set and sends no ICMP (black hole) asserts that discovery settles in 5 rounds or fewer.
- A field capture shows no churn bursts at session start.

## F4: Slow climb to direct at startup and after restarts
**Status:** Open. **Priority:** 4. **Seen in:** C1, C2.

**Evidence:**
- **Startup choice depends on start order:**
  - When the phone starts after the camera, it commits `meta-direct` about 0.9s before backbone UDP confirms (C1 runs 2 and 3, C2 run 1).
  - All phone→camera data then goes as `REQ_KEY … 21` over TCP through the NMN, for 70s and 100s in C1 and 71s in C2.
  - When the phone starts first, it commits `relay-udp` (C2 run 3: 74s before direct).
- **No step down to relay-udp:** the backbone-UDP candidate is pre-empted by the direct-UDP candidate, so `meta-direct` never moves to `relay-udp`.
- **Direct is gated on PMTU:** promotion only happens about 5s after "Fixing MTU". Candidate starts before that (every ~10s, each on the camera's then-current port) all go nowhere.
- **After a camera restart (C2 run 1, 12:30:48):** the phone never got back to direct before the app was closed at about 12:31:53. That is where the restart cycle in C2 started.

**Fix direction:**
- Most of this disappears with F3: PMTU settles sooner, so promotion happens sooner.
- Separately:
  - Re-rank `meta-direct` → `relay-udp` once backbone UDP confirms.
  - Don't let a direct-UDP candidate pre-empt the backbone-UDP step down.
  - Consider promoting direct at a provisional MSS before PMTU settles.

**Coming risk:** once the phone is on direct during churn, the 500ms rebind quiet window means about 500ms of phone→camera data goes to a dead port per rebind. F3 fixes this by removing the churn.

## F5: Liveness is one probe per window; one lost reply demotes the path
**Status:** Open. **Priority:** 2. **Seen in:** C2.

**Evidence (C2, 12:36:11–12:37:05):**
- At 12:36:11.596 the camera sent its 64-byte liveness probe and its 1439-byte raise in the same millisecond.
- The phone answered the 64-byte probe within about 70ms, but the reply never reached the camera. The camera gave up at 12:36:16.610.
- The camera had been receiving authenticated direct UDP from the phone throughout (suspect probes at 12:36:12.5 and 12:36:14.8), but only probe replies count as liveness.
- The give-up restarted the camera's discovery, which churned its NAT (F3). The phone demoted at 12:36:21 and then failed nine punches. Result: 44s on relay.

**Root cause:** a single 64-byte probe per `pingtimeout` window, no retry, and the give-up resets PMTU.

**Fix direction:**
- Retry the liveness probe 2–3 times inside `pingtimeout`.
- Keep PMTU on give-up (F3 option 2).
- Optionally, if the confirmed endpoint has delivered authenticated UDP within the window, re-confirm before demoting.

## F6: The camera's NAT expires idle mappings faster than our ping cadence
**Status:** Open. **Priority:** 2. **Seen in:** C1 (one case), C2.

**Evidence (C2, 12:38:15–12:39:32):**
- The stream stopped at about 12:38:15. After that, the camera's only packet toward the phone was its reply to the phone's 12:38:25 ping.
- The next ping at 12:38:43.999, about 19s later, went unanswered, and the phone gave up at 12:38:49.
- The camera's next outbound packet (12:38:52) came from the same port, and the punch confirmed 4s after the give-up.
- But the give-up had reset PMTU, so another 30 probes ran, 20 more migrations followed, and the phone spent 43s on relay.
- A 10s idle earlier in the same run survived. So the timeout looks like 10–19s (speculative).
- At idle the camera sends nothing on its own, and the phone's ping cadence works out to about 19–20s.

**Fix direction:**
- While a peer is in demand, keep a 64-byte UDP packet going about every 8s from the NATed side, or shorten `pinginterval` for that device class.
- This revises the ADR 0010 position that keepalives don't help. That still holds for the under-load re-mapping (F3), but not for idle expiry.
- Pair with F3 option 2 so that a real expiry costs one punch round trip, not a rediscovery.

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

**Fix direction:** let the NMN mark a peer's endpoint as relay-ready after an authenticated backbone keepalive or nonce exchange from that exact endpoint. Gate it on the peer's own backbone UDP confirmation, and expire it on silence.

**Verification:** a relay test asserts that the last leg is UDP (no `REQ_KEY … 21` at the destination) once both peers have confirmed backbone UDP.

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

## Next plans
1. **F3 options 1–3 together with F5:** converge on loss, keep PMTU on give-up, separate the raise from liveness, add a liveness retry. Expected to remove nearly all churn and to shorten F4.
2. **F6:** idle keepalive from the NATed side while the peer is in demand.
3. **F7:** NMN-side relay readiness so the last leg goes over UDP.
4. **F4 leftovers:** startup re-ranking, and the backbone-UDP step down.
5. **F3 options 4–5:** per-peer PMTU memory and one-direction measurement (protocol minor bump).
6. **Minor items**, opportunistically.

Every plan builds and tests only inside the `meshlink-arm64` container, from `/mnt/host/coco-project/third-party/meshlink`, running `make -j1 check` serially.

## Appendix: how the captures were analysed
The logs are large (C2's phone log is 175 MB), so each analysis first builds compact extracts:
- **Phone:** keep only `ct_meshlink_logger_cb` lines, strip CR, and reduce each line to `<epoch_ms> <pid> <message>`. Each pid is one app run.
- **Camera:** keep only `ct_meshlink_logger_cb` lines and reduce each to `<epoch_ms> <message>`. Each file is one camera run.
- **Key-event timeline:** filter on `Path route`, `Path UDP`, `UDP rebind`, `Punch`, `Fixing MTU`, `Increase in PMTU`, `did not respond`, `Suspect fallback`, `became (un)reachable`, `meshlink_open_ex` and `Error sending`, and print readable IST times.
- **Per-direction traffic in 5s buckets:** count `Sending packet of … to N` (direct, or followed by `Relaying type-8 via UDP`), `Received packet of … from N`, and `REQ_KEY from 0: 15 <src> <dst> 21` (delivered over META).
- **PMTU cycles:** group `Sending MTU probe length L to N at <non-broadcast>` lines until `Fixing MTU of N`, and count probes larger than the settled MTU.
- **App-layer symptoms:** `meshlink_channel_send failed`, `MediaStreamChannel: onStatusChanged`, and `meshlink_channel_abort`.
