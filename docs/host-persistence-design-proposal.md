# Meshlink role-aware persistence

The reviewed design separates authoritative identity/configuration and observation history from optional performance cache. It keeps the NLB canonical bootstrap address, preserves guarded MTU/NAT recovery, removes persistent remote endpoint hints only for BACKBONE owners, and checkpoints every peer's ongoing last observation once per stable 23–24-hour interval.

The detailed contract, rationale, schemas, lifecycle rules, implementation sequence, and validation requirements are maintained in [the implementation plan](host-persistence-implementation-plan.md). That document supersedes earlier discussions of minute-level durable writes, shorter checkpoint intervals, and a mixed host/cache format.

The central scale improvement is independent write cadence: authoritative history changes about once a day per observed peer, while optional path cache changes only when its material projected content changes. A bounded process-wide worker isolates background filesystem latency from established network traffic. Explicit trust/configuration changes and the first positive observation retain synchronous durable acknowledgment.

A crash restores the last successful daily checkpoint from the PVC. It no longer restores only the original session-start timestamp. With the accepted daily precision, a peer close to the 30-day retention threshold may be retired roughly one day early; the consumer threshold and grace policy remain unchanged. Storage failures can extend the checkpoint delay and remain visible as errors/pending work.

Nothing cached confers current authority or reachability. Existing session, path, MTU trust, network fingerprint, keepalive generation, LAN presence, private opt-in, and relay validation rules still run after restart. Missing or invalid optional cache affects recovery speed; invalid authoritative records fail startup.

The implementation follows this contract in both repositories. The detailed plan records frozen source identities and validation evidence, including reused full-suite results and fresh affected regressions. The complete Coco suite passed 106/106; final Meshlink, sanitizer, black-box, and real transport-link evidence is recorded there. No deployment or PVC throughput claim is made.
