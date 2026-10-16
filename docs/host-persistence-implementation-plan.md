# Role-aware Meshlink persistence: implementation contract

This is the implementation handoff and validation contract for the reset demo environment. It supersedes the original proposal to rewrite every host file once a minute. No old host-file reader, migration, dual format, compatibility mode, or rollout cleanup belongs in this change. The network wire format remains unchanged.

## Product decisions

Every production member retains its named NMN NLB canonical hostname and externally reachable port. Backend NMN addresses and ports can change. Numeric backend addresses are not an additional configured bootstrap mechanism. Generic Meshlink numeric-address APIs and fixtures remain supported.

All peers, regardless of device class, have in-memory last-observation timestamps at 60-second resolution. Every full-storage owner checkpoints ongoing observation history on a stable 23–24-hour deadline. This deliberately permits roughly one day of understated history after a crash, plus observation resolution, scheduling, and storage delay. The consumer's 30-day retention threshold and grace policy do not change. The user accepts this precision for the reset demo.

A local BACKBONE owner omits remote recent endpoints on disk. Its in-memory endpoint behavior remains unchanged. It retains useful MTU/NAT path history. PORTABLE, STATIONARY, and UNKNOWN local owners preserve bounded recent endpoint hints, ordering, provenance, and capability, plus MTU/NAT history. There is no self path-cache file. Fresh local interfaces are still gathered for discovery and wire advertisements.

## On-disk records

`current/hosts/<name>` is an authoritative record. It is a strict MessagePack array with exactly ten fields:

1. Local host format version, initially 1.
2. Node name, equal to the filename.
3. Random nonzero local 128-bit record incarnation.
4. Existing submesh name.
5. Device class.
6. Blacklist policy.
7. Public key, zero or 32 bytes; self requires exactly 32 matching the main private identity.
8. Existing canonical string, hostname/address followed by port, or empty.
9. Last observation (`last_reachable`), signed 64-bit epoch seconds.
10. Last unreachable edge, signed 64-bit epoch seconds.

This record contains no endpoints, MTU history, private keys, routing/session state, counters, or live proof. Its corruption is a storage error that fails startup; it must never silently remove a roster member. Configured local class precedence remains as before.

Disk strings reject embedded NUL bytes, and timestamps must be nonnegative and representable in the platform's `time_t`. Partial authoritative-directory enumeration errors fail startup too.

`current/path-cache/<name>` is optional and independently replaceable. It is a strict MessagePack array with exactly seven fields:

1. Local cache format version, initially 1.
2. Peer name.
3. Matching local record incarnation.
4. Local public key, 32 bytes.
5. Peer public key, zero or 32 bytes.
6. At most five recent tuples, each `[sockaddr_ext, source, capability]`.
7. At most four MTU tuples, each `[IP_bytes, size, largest_failed, flags, raise_backoff, keepalive_ms, updated_at, network_fingerprint]`.

IP bytes contain four or sixteen bytes and no port. Recent tuples preserve aligned ordering. Missing, malformed, unsupported, identity-mismatched, or undecryptable caches are cache misses. They cannot erase observation history or prevent authoritative recovery. Recreated names receive fresh incarnations even if the public key is unchanged. Established public-key replacement invalidates previously bound cache history.

The same layout exists under staged `new/`. Main mesh configuration, invitations, and backbone identity retain their existing formats. Local host/cache versions are independent of main/wire versions.

## Disk/wire separation

The wire encoder retains the existing host-advertisement layout and version. Export and invitation creation share it. Invitation creation must not embed raw local host bytes. Advertisements can contain fresh bounded endpoint hints, but always carry zero observation timestamps and no local incarnation or MTU cache. Import and join create fresh local record incarnations and zero local observation history. Lazy public-key lookup reads trust only; full startup explicitly restores authoritative records and optional cache data.

## Runtime semantics preserved

Routing, topology election, direct/local/WAN/hairpin/relay ranking, session recovery, retry clocks, and `mesh->last_unreachable` are unchanged. `last_unreachable` continues to record the down edge. No live UDP confirmation, LAN presence, private opt-in authority, relay readiness, live NAT mapping, SPTPS proof, or session state is restored from cache.

Existing path validation remains authoritative: MTU entries older than 24 hours expire; recent entries inside the existing 600-second trust window follow existing rules; older entries require verification; local-network fingerprints and keepalive generation flags retain their checks. Canonical assignment/precedence is not redesigned in this delivery. Material MTU/NAT changes persist, while timestamp-only cache refreshes do not.

## Mutation classification and scheduling

`node_storage` owns local projections and generations. Call sites classify KEY_POLICY, CONFIG, EDGE, OBSERVATION, ENDPOINTS, PATH_HISTORY, and PROFILE changes. Core and cache generations are independent. Updating cache data never acknowledges observation history. A core commit piggybacks the latest observation.

Handled requests on active META sockets refresh observations after `last_ping_time`. LAN quiet timer resets do not. The existing five-second node walk also refreshes graph-reachable peers without local sockets. Null, self, and blacklisted nodes are ignored. Epoch time failures and backwards/future timestamps do not move observations backwards. One wall-clock sample serves the node walk; deadlines use the event loop's monotonic clock.

The reachable edge is the first observation. First positive observation uses a native synchronous durable core commit. Subsequent edges become eligible within the existing five-second walk. In-memory observations are gated at 60 seconds. Ongoing checkpoints use `86400 - stable_incarnation_phase` seconds, where phase is 0–3600 seconds; unchanged offline records generate no timer writes. Loading or durably committing core history resets the monotonic deadline from durable observation age. Future-clock records are clamped to avoid busy loops.

Cache changes coalesce for five seconds independently of writer completion notifications. Member LRU-only reorder is material. BACKBONE endpoint-only changes have an identical disk projection and cause no write. Cache `updated_at` alone is excluded from the material projection. Plaintext projections are compared before encryption, so random nonces cannot create false differences. Identical ACK class, canonical values, empty clears, and self open state do not generate writes.

A failed native write marks the visible disk projection uncertain: a rename may have succeeded before directory sync failed. A later reversion must commit again even if it equals the last acknowledged bytes. The last durable observation remains separate and unchanged on failure.

A successful immutable snapshot acknowledges only its captured generation. Newer mutations remain pending. An old completion cannot replace a newer durable projection. Reverting to bytes already on disk must account for older pending work: background paths enqueue/coalesce the current projection and never wait for filesystem I/O; synchronous explicit operations use a per-record barrier.

Each mutation reason records its latest owning projection generation. A completion clears reasons covered by its snapshot even when newer observation-only mutations exist; it retains genuinely newer configuration/edge mutations. This prevents slow storage from turning daily observation checkpoints into urgent writes. Mutations remain classified while persistence is suppressed, so re-enabling full storage can project current configuration and newly imported peers. Identical explicit retries repair failed configuration writes without flushing observation-only work. Failed main-port writes retain a retry marker scoped to the active storage epoch, and failed self-canonical writes retain deferred advertisement independently of background acknowledgment.

## Writer and durability

`storage_writer` provides one lazy process-wide thread shared by handles. Limits count queued, running, and completed-but-uncollected work: 256 jobs globally, 2 MiB serialized payload globally, and 32 jobs per handle. Owners are serviced round-robin. A queued owner/path job is replaced by its latest immutable snapshot. Admission failure leaves generation pending for later retry and never falls back to synchronous network-loop I/O.

Snapshots own their payload, path, encryption key, generation, and sequence. The worker never dereferences `node_t`, takes the mesh mutex, invokes application callbacks, or updates owner state. It performs native file commits and triggers only the dedicated loop signal. Completions are collected under the mesh mutex or synchronously with the loop stopped. Signal IDs 0 and 1 retain their existing uses; storage uses 2.

Internal headers state the mesh-mutex or exclusive stopped-lifecycle requirement, caller ownership of encoded outputs, backend/clock context lifetime, and flush-versus-cancel barrier behavior. Same-owner lifecycle/native-commit serialization is a caller contract; the worker remains independent of mesh/node lifetime. Raw encrypted storage keys are the full `CHACHA_POLY1305_KEYLEN` bytes, distinct from 32-byte public keys.

Explicit trust/config changes and first positive observations use a native synchronous commit: cancel older queued work for that path, wait for an already-running same-path write, commit the newest snapshot, then acknowledge success. Queue capacity does not constrain this native path. Queue locks are never held across filesystem I/O or per-record waits. The worker can always make progress while a caller holds the mesh mutex.

Each native commit writes a temporary file in the same parent directory, completes encryption/plaintext and final metadata, flushes, file-syncs, closes, renames atomically, and directory-syncs the parent. Both encrypted and plaintext paths obey this contract. A rename followed by directory-sync failure is still a failed durable acknowledgment. New directory metadata and durable deletion also synchronize parents. No group transaction or group-directory-sync optimization is included.

Background errors retain pending generations and the last durable observation. Retries use monotonic delays 1, 2, 5, 10, 30, 60, and then 300 seconds capped. Owner counters record core/cache writes, no-ops, cache hits/misses, admission failure, and storage errors. Native fault seams exercise write, file sync, rename, and directory sync without real failures or sleeps.

## Lifecycle barriers

- Stop: after graph teardown, cancel obsolete queued snapshots, wait owned running work, and commit the latest permitted pending projections natively. Unrelated queued-owner I/O does not delay current snapshots. Collect completions before returning.
- Close: retire/cancel/drain owner work before freeing nodes, loop signals, paths, or keys. The final owner joins the process-wide thread. A later owner can restart it.
- Forget: retire the incarnation, cancel queued jobs, wait for running same-record jobs, durably unlink the authoritative record, and best-effort delete optional cache. Old completions and orphan caches cannot attach to a new incarnation. Failed durable deletion synchronously compensates with the previous persisted authoritative snapshot under every policy, returns a storage error, and retains pending newer state. If compensation also fails, invalidate the claimed durable projection and report the failure.
- Join: freeze/cancel/drain old storage before self-name/class mutation and staged `new/` creation. No old worker can recreate `current/` during the swap. Preserve rollback bookkeeping and existing commit ordering.
- Encryption-key rotation: drain and collect old-key work before copying/switching epochs. Jobs own key copies. Invalid optional cache cannot block rotation of authoritative records. Adopt an installed new key before cleanup or an early exit.
- Port changes: flush and barrier before closing/recreating the node roster; no worker or uncollected old completion survives the reload.
- Policy changes: cancel newly disallowed queued work and wait running work before setter returns. Re-enabling full storage persists current memory, without reloading stale disk cache. Preserve existing initial identity creation semantics.
- Profile changes: prevent older jobs from restoring excluded endpoints and reproject under the new local class.

Join and rotation share directory activation that reports actual active namespace separately from durable success. A failed sync attempts rollback. If the new namespace remains active after a failed rollback, memory adopts its matching identity/key even though the API returns a storage failure. If no current namespace can be restored, reject further persistence, join, rotation, and port mutations until reopen, preserving recovery trees. Recovery prefers readable current, then old, then new using the supplied key; plaintext failed joins recover old too. A missing main file with an existing authoritative host roster is an error, never an empty store. Optional path-cache absence does not block core operations; recreate only that directory under an already-existing current/new epoch.

Live-handle fork support is not added. Existing fork fixtures close all handles before forking; final-owner worker shutdown preserves that pattern.

## Clusterprotocol

After node lookup, `ct_get_node_last_seen_timestamp` returns Meshlink's `last_reachable` verbatim, including zero. Missing node/handle returns -1. EINVAL from reachability remains fatal. Remove wall-clock substitution, skew rewriting, and comparison with `last_unreachable`. The network event handler remains an unchanged forwarder. Mock parameters expose a last-reachable knob; fixed timestamps prove passthrough without timing assertions. No NMN sidecar or retention grace is introduced.

## Implementation order

1. Add strict authoritative/cache codecs, optional directories, incarnation binding, separate wire encoder, trust-only lookup, fatal authoritative startup handling.
2. Replace monolithic dirty state and direct node writes with classified storage calls; preserve endpoint order and runtime path guards.
3. Add bounded writer, native durability and fault seam, immutable completion generations, lifecycle/policy/profile barriers.
4. Add runtime observations and daily scheduling; document query-window semantics.
5. Preserve Coco passthrough and fixed mock coverage; build/link real Coco transport against revised Meshlink.
6. Finish deterministic tests and review, then run required complete serial suites.

## Validation contract

No new permanent test binaries and no added sleeps. Extend existing internal/static-link test targets with controlled clocks and condition barriers.

Required cases: strict valid/corrupt core and cache records; cache-only corruption preserves authoritative identity/history; incarnation/name/key mismatch; local role projection and member ordering; no self cache; KEYS_ONLY/DISABLED and switching; no-op and cache timestamp-only suppression; core/cache checkpoint independence; all native failure phases in plaintext and encrypted mode; queue limits/coalescing/fairness/ownership; stale completions/reversion; close/forget/policy/join/rotation barriers; 60-second observation gate and graph-only observations; first/drop stamps, daily phase/deadlines, offline no-op, reopen/stop/failure. Preserve transport-recent warm recovery, direct-candidate order, stale fallback, crypto reuse, MTU/NAT trust/verify behavior, private authority, LAN discovery, and relocation regressions.

Use a synthetic scheduler projection for 3,000 owners × 10 peers rather than 30,000 real filesystem commits, and demonstrate one ongoing first-day checkpoint per peer independent of cache traffic. Test worker concurrency/lifecycle with ASan/UBSan and TSan where supported. Do not replace actual network regressions with white-box arithmetic.

All Meshlink builds and tests run in `meshlink-arm64`; full command is `make -j1 check`. Run the existing black-box reachability case 04 without permanent harness changes. All Coco tests run serially in `toolchain_ubuntu_container`, full `ctest -L clusterprotocol --output-on-failure`; do not substitute a fast-only suite. Rebuild real revised Meshlink for the Coco toolchain and prove the real transport link, beyond mock-only unit tests. Suite generators must preserve combined registrations.

Only verified disposable generated test configurations may be removed. No deployment/PVC cleanup, package publication, push, or compatibility work is authorized by this document. Record commands, versions, results, and logs. Production PVC latency and deployment-scale write benchmarks require the actual demo environment and must not be claimed from these tests.

## Implementation status

The split codecs, classified storage module, bounded writer, native durability, lifecycle integration, and Coco passthrough are implemented and reviewed. Candidate14 is frozen. The ARM suite has a green aggregate with preserved full-run provenance, affected lifecycle/channel regressions are green, ASan/UBSan and TSan checks are green, black-box reachability case 04 is green, and the rebuilt production transport/Meshlink link probe is green. The complete 106-test Coco suite passed with actual exit 0. Required validation is complete; earlier draft, stopped, and failed runs are retained separately below. Both repositories remain uncommitted for final review; no package, deployment, or push was performed.

## Final validation evidence

Candidate14 is the frozen reviewed and validated source. The Meshlink results, sanitizer checks, black-box case, real transport link probe, and complete Coco suite are green. The 470-file build-input manifest is `/tmp/meshlink-persistence-sanitizers-candidate14/manifest.json`, SHA256 `ad29240a25ec69231b91ac7efeea49ce7b5fa12eb5482b4a90aebebf2645b869`. The independent 426-file source/header/build-input review manifest is `/tmp/meshlink-persistence-parent-review-candidate14.sha256`, SHA256 `25982f4c9e928f39f5f10a2ecc0c7d101165a7810a3d4b855d81c287e66b7a39`. These cover different inventories, so their hashes intentionally differ. Documentation and generated test data are excluded.

Final builds/checks ran serially. ARM used `meshlink-arm64` (aarch64, GCC 13.3.0, GNU Make 4.3); Coco used `toolchain_ubuntu_container` (x86_64, GCC 12.3.0, CTest 3.22.1). No permanent test binary or added sleep was introduced.

The complete ARM `make -j1 check` run on candidate10 finished with 66/67 passing, exit 2. Its sole failure was an existing discovery fixture assumption: it required a local-discovery timer to send before direct punching could confirm UDP. The timer has a minimum 1 ms delay, so that ordering is not guaranteed. The corrected existing restart devtool attempts the first discovery tick under its existing lock, with genuine scheduler admission; the controlled fixture supplies 30/30 tokens and the normal transaction limit 2. Natural startup still uses default budgets. Three bounded serial runs passed, including natural startup with zero discovery sends followed by a controlled real unicast. Later sanitizer evidence exposed close-time lifetime and fixture ownership defects, corrected separately.

After the final close guard, eight affected ARM regressions passed: peer-control, path-policy-coverage, local-discovery-eligibility, channels, channels-aio, channels-aio-abort, channels-fork, and lifecycle-start-stop. The final fixture-only memory cleanup was followed by another successful local-discovery check. Native Automake regenerated an aggregate 67/67 summary from 59 unchanged full-run result pairs and these 8 fresh affected cases. It did not rerun the unchanged metering/throughput benchmarks. Provenance includes hashes of every reused log/TRS; the original failing full-run log is retained.

- Full ARM command/log: `make -j1 check`, `/tmp/meshlink-persistence-final-candidate10/full-arm.log` (actual 66 pass/1 fail; not presented as a successful final full rerun).
- Fresh affected checks: `make -j1 -C test check TESTS="peer-control path-policy-coverage local-discovery-eligibility channels channels-aio channels-fork lifecycle-start-stop" check_PROGRAMS="peer-control path-policy-coverage local-discovery-eligibility channels channels-aio channels-fork lifecycle-start-stop" dist_check_SCRIPTS= SUBDIRS=`, plus the same single-target command for channels-aio-abort and final local-discovery. Logs `/tmp/persistence-candidate13-focused.log`, `/tmp/persistence-candidate13-aio-abort.log`, `/tmp/persistence-candidate14-discovery-focused.log`.
- Final aggregate: `/tmp/meshlink-persistence-final-candidate14/{aggregate-arm.log,aggregate-provenance.json,test-suite.log}`. The exact native summary command and reused-result hashes are in the provenance file.
- ASan/UBSan 8/8, exit 0, including leak detection: storage-policy, encrypted, import-export, port, lifecycle-start-stop, channels-fork, path-policy-coverage, local-discovery-eligibility. Flags `-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined`; runtime `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Checks used serial `make -j1 -C test check`, selecting only those existing targets. Logs and individual TRS are under `/tmp/meshlink-persistence-sanitizers-candidate14/asan-ubsan/`.
- TSan 3/3, exit 0: storage-policy, lifecycle-start-stop, local-discovery-eligibility. Flags `-O1 -g -fno-omit-frame-pointer -fsanitize=thread`; runtime `TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1:history_size=7`, no suppressions. Logs/TRS under `/tmp/meshlink-persistence-sanitizers-candidate14/tsan/`.
- Existing black-box `test_case_get_node_reachability_04`: 1/1, exit 0. The temporary selection restored the normal main object and relinked the standard harness through an EXIT trap. Original/restored main-object SHA256 both `4811befe9ba72786813f34a83faeeb9720f1a9bcd6192362f6e443c753820044`. Build/run/restoration logs under `/tmp/meshlink-persistence-final-candidate14/blackbox-artifacts/`.

The only UBSan validation exception is the demonstrated signed-shift-base operation in unchanged bundled Ed25519 `fe.c`, `ge.c`, and `sc.c`. A validation-only compiler wrapper adds `-fno-sanitize=shift-base` for those three translation units. ASan and every other UBSan category remain enabled there; every new persistence module retains full UBSan. No crypto source, repository build default, discovery check, or persistence check is suppressed. Exact compiler evidence is `/tmp/meshlink-persistence-sanitizers-candidate14/sanitizer-exclusions.log`.

All ten production clustertransport translation units compiled into a fresh archive against the revised Meshlink headers, and the executable linked that archive with a freshly built real x86 Meshlink static library. The probe executed the production getter and actual Meshlink persistence: unknown timestamp zero, missing peer -1, fixed nonzero timestamp, a later unreachable timestamp ignored, current reachable status ignored, and the same history after reopen. It does not claim to execute all transport paths. Build/link map, symbols, dynamic-library inspection, artifact hashes, and run logs are under `/tmp/meshlink-coco-validation-candidate14/`; the exact build command is in `build-real.log`, and `run-real.log` records exit-zero execution. The Meshlink archive hash is `431bda440556c72b774bae19643d6ab290d6486c258eb72f3d7cc87c091c9533`; the production CT archive hash is `409ddd25e2fddd398869b0d78db53f90fa9d88334e1fafe3edb7082d876f5bb7`.

The unit target was rebuilt with `cmake --build /mnt/host/coco-project/platform/coco/src/clusterprotocol/utest/build-fixes-20261013 --parallel 1`. The complete `ctest -j1 -L clusterprotocol --output-on-failure` run in that directory passed **106/106, zero failures, exit 0**, in **3951.09 seconds**. No fast-only filter was used. Its raw log is `/tmp/meshlink-coco-validation-candidate14/run-unit.log`; the full CTest log is copied to `/tmp/meshlink-persistence-final-candidate14/coco-artifacts/LastTest.log`. The durable serial controller completed all ten phases with actual exit 0; `/tmp/meshlink-persistence-final-candidate14/status.json` records exact per-phase commands, durations, and logs.

Final checks confirmed all 470 frozen inputs, the independent 426-file review inventory, and all eight changed Coco inputs still match their manifests; both scoped whitespace checks passed, no added sleep calls were found, all 67 aggregate TRS results pass, and the standard black-box main object remains restored. Evidence is `/tmp/meshlink-persistence-final-candidate14/final-source-checks.json`. Individual ARM logs/TRS are collected under `arm-results/`; bounded fixture and affected-check logs are under `focused-artifacts/` in the same directory.

## Failures resolved during validation

Failed/stopped revisions remain separate from final passing evidence. The candidate2 full run was explicitly stopped for known same-value retry defects. Candidate4 completed 66/67 and a debugger traced its path-policy crash to an uninitialized synthetic cutover node, corrected with normal storage lifetime and an established-peer observation. Sanitizers then found the new immutable encrypted-key snapshot was 32 bytes instead of the 64 bytes required by ChaCha-Poly1305; all storage-key copies and fixtures now use the full contract, with an owned 64-byte snapshot regression.

Further sanitizer checks exposed existing empty-array bsearch calls, signed hash-byte shift, and stale outgoing-address ownership; small defined-arithmetic/empty-count/ownership fixes preserve existing policy and retry state. A live TSan debugger inspection proved the existing DNS condition could already be satisfied before an unconditional wait; the predicate loop now preserves the same absolute deadline and ownership. No crypto arithmetic source was changed.

The expanded discovery sanitizer case then exposed an existing teardown use-after-free: self could be freed before a peer's UTCP channel callbacks asked path policy about self. Dying-peer channel release now balances its count and returns before consulting self or arming idle work. Its real close path and existing live/dying-demand cases are covered. Finally the fixture now frees open-parameter owned strings through the public destructor and releases its bridge command; final leak detection stays enabled.

Synthetic scheduling covers 3,000 logical owners × 10 peers using the actual checkpoint admission/acknowledgment seam and a fake backend. It is not a PVC throughput benchmark. Production PVC latency/IOPS, multi-pod behavior, and deployment sizing require the reset demo environment; no performance claim or deployment validation is inferred from unit workloads. Explicit state/trust and first-observation commits intentionally retain synchronous durability.
