# ADR 0009: Ordered META cutover and node KEX recovery

## Status

Accepted. Supersedes the cutover section of ADR 0003. All-at-once rollout: every deployed peer speaks protocol minor 5 before direct META upgrades are enabled.

## Context

A live camera/app pair stayed on UDP relay. The camera log showed:

- canonical META upgraded to a direct META socket;
- the camera sent SPTPS KEX on the canonical socket;
- the app's answering SIG (`ANS_KEY` / SPTPS handshake) arrived on that same socket during the swap;
- `receive_meta()` / `receive_request()` treated the retired socket as `drain_only` and discarded the bytes;
- the camera stayed `validkey=false`, `waitingforkey=true`;
- later `REQ_SPTPS` was dropped with "don't have a valid key yet";
- a punch hint that arrived before `validkey` was ignored;
- the KEX retry in `timeout_handler()` only looked at `c->node` on the NMN connection, so the peer exchange never restarted.

ADR 0003 said queued outbound bytes plus a drain timeout were enough for a hitless migration. That only covers data this side already encrypted. It does not cover the peer's in-flight records, and it does not keep a single ordered stream across two sockets.

## Decision

`PROT_MINOR` is 5. Five direct META requests carry a random nonzero 64-bit cutover id:

- `META_CUTOVER_PREPARE` on the old primary
- `META_CUTOVER_READY` on the old primary
- `META_CUTOVER_COMMIT` on the new standby
- `META_CUTOVER_ACK` on the new standby
- `META_CUTOVER_EMERGENCY` on the standby when the old primary dies before the barrier is proven

`upgrade_probe_eligible()` refuses a direct META upgrade when the active canonical peer reports a protocol minor below 5. The node stays on canonical META. A peer that speaks minor 4 or older and still sets `PROTOCOL_UPGRADE` is refused the same way.

### Invariants

- `node->connection` is the only connection used for ordinary META sends.
- The old canonical connection remains `node->connection` until an ordered barrier proves both directions are drained.
- A newly authenticated direct connection is a standby on both peers until cutover commits.
- No authenticated META bytes are read and discarded.
- Normal META records never use the standby before commit.
- During the barrier, newly generated normal META records are queued as plaintext records with preserved boundaries and FIFO order.
- The queue is bounded (256 records, 256 KiB). Overflow aborts the cutover and replays the queue on the still-live old primary. It never drops records and never switches anyway.
- Graph edge ownership and `outgoing_t` ownership move exactly once, at commit.
- Graceful cutover preserves node SPTPS, `validkey`, UTCP, punch state, UDP state, and relay state.
- Failure before commit keeps canonical primary whenever it is alive.
- If the old primary dies before ordering is proven, direct META may be promoted for reachability, but node KEX recovery treats delivery as uncertain.
- Punch endpoint exchange stays channel-demand-driven and never causes the backbone to originate peer probes.

### Sequence

1. Both sides authenticate the direct socket and hold it as standby (`status.spare`). Canonical stays primary. The initiator logs validation, not migration.
2. The initiator freezes ordinary META and sends `PREPARE` on the old primary, after every record already queued on that socket.
3. `PREPARE` proves every earlier initiator-to-responder record was processed. The responder freezes and sends `READY` on the old primary.
4. `READY` proves every earlier responder-to-initiator record was processed. The initiator sends `COMMIT` as the first cutover record on the standby.
5. The responder swaps graph and `outgoing_t`, makes the standby primary, sends `ACK` before any queued ordinary records, flushes the FIFO, and closes the old socket without a node-down callback.
6. The initiator does the same swap on `ACK`, flushes, and closes the old socket.
7. Migration is logged once, at commit.

Duplicate messages are idempotent only when the id and socket match the current attempt. Anything else is a stale no-op. It never promotes a second time.

### Failure

One timer on the cutover object bounds the barrier.

- Standby dies before commit: abort, unfreeze, replay the outbound FIFO on the old primary, then replay held inbound requests onto that same primary when it is still `node->connection`. Keep the old graph and outgoing, apply upgrade backoff. The standby timer is re-armed when the abort leaves that socket up and the replay succeeded.
- Replay never calls `terminate_connection()`. A handler failure returns false to the `receive_request()` that is already on that connection. A failure from a timer, a closing socket, or queue overflow shuts the dispatch socket down and leaves the `connection_t` allocated until the META I/O path frees it. `send_meta()` fails closed once that deferred teardown is set. Held records are dropped only when the node is deleted, the mesh stops, the peer is blacklisted or retiring, or no live primary remains to receive them. A replay-handler failure retires the standby as well as the canonical socket. Neither can be promoted: `find_spare()` and the no-cutover primary-close path ignore a socket marked for teardown. An overflow trigger is sent only after that replay succeeds; a failed replay reports the trigger as undelivered.
- A READY send that fails, including the release of a withheld READY, aborts immediately onto the live canonical primary. It does not wait for the barrier timer.
- Old primary dies before the barrier is proven, including after READY (`INIT_WAIT_ACK`), while the standby is up and the mesh is running: install the standby for reachability, keep the FIFO frozen, and send `META_CUTOVER_EMERGENCY`. The peer echoes EMERGENCY and promotes with uncertain delivery. Ordinary META is flushed only after that exchange, or when the barrier timer expires. Records that arrive on a standby before promotion are held and replayed, not dropped. A full hold forces that sync; if there is no barrier to join, the socket fails closed. Delivery is uncertain for that peer only. No node down/up callback.
- A peer that never saw PREPARE accepts EMERGENCY on its standby, adopts the id, and answers before either side flushes.
- Timeout while the old primary is alive: abort and stay canonical. Never switch on timeout.
- Timeout during emergency sync: flush the FIFO and schedule KEX recovery for that peer.
- Mesh stop, blacklist, intent retirement, LAN epoch retirement, or node deletion: cancel the timer, drop the FIFO, close both sockets without promotion, and clear every pointer.

### Node KEX recovery

One node-owned watchdog replaces the META-connection retry in `timeout_handler()` and the independent 10-second restart in `send_sptps_packet()`. Endpoint punch retries stay separate.

The ladder is 2, 5, 10, 30, 60 seconds with jitter.

- `send_req_key()` starts a new epoch, sets `waitingforkey`, and arms the deadline. If the public key is missing it sends `REQ_PUBKEY` and reschedules the same ladder without clearing the demand bit.
- SPTPS handshake success clears waiting state, retry step, deadline, and uncertainty.
- A session-id change clears the epoch. A fresh `send_req_key()` happens only when backbone UDP or channel demand still needs the key.
- `REQ_SPTPS` while `validkey` is false sets a node-owned retry-demand bit and schedules one retry. The bit is what makes the deadline fire when nothing else wants the key. It does not restart once per record.
- An inbound `REQ_KEY` that starts the responder handshake arms the same watchdog.
- Old-primary failure during cutover sets `key_delivery_uncertain` and pulls the deadline forward.
- A periodic node scan, not a META-connection scan, runs the watchdog for every reachable demanded peer.

### Punch hints

A valid address-only hint is staged even when `validkey` is false. It becomes the active unconfirmed probe destination, and `send_mtu_probe()` runs, only after the key is valid. An identical hint does not restart the ladder. A repeated identical hint while `validkey` is false refreshes the 75-second freshness timestamp. A hint never sets `udp_confirmed`. Staged hints are dropped on session change, demand-epoch end, network-epoch invalidation, node deletion, or freshness expiry.

## Consequences

- The camera/app SIG race cannot discard the answering handshake on a retired META socket.
- Graceful cutover does not restart node SPTPS and does not reset UTCP.
- A wedged `waitingforkey` is retried on a bounded ladder.
- A punch hint that arrives before the key is applied after the handshake.
- Exactly one logical META primary exists. Overlap is one primary plus one standby.
- Peers older than protocol minor 5 stay on canonical META.
