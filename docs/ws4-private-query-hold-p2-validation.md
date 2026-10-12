# WS4 P2 implementation and verification

Baseline: `elear-develop`, commit `608370993bc9b6dd5c1772b359795c4717ff1513`.
Verification date: 2026-10-11 UTC (2026-10-12 IST). Implementation is an uncommitted working-tree
patch against that commit. The existing private-path default/API is unchanged;
this does not include WS4 change 1 or SDK/VSN adoption. No field acceptance is
claimed.
Implementation fingerprint (SHA-256 of `git diff --binary -- . ':(exclude)docs'`
followed by the new `test/event-signal.c` contents):
`07ddec9d0455a1b81287e21c8d20ceba50a753a1b2382ce78cca0540429be345`.

## Resulting behavior

A failed private-query write followed by authenticated reconnect or local
network change previously inherited the obsolete retry delay (96–144 seconds
at the last rung). The query owner now retires that failed attempt's deadline
when its connection generation, backbone session or full network epoch changes.
Connection registration assigns a generation to both accepted and outgoing
sockets; termination and destruction retire owned failed holds. No connection
pointer is retained in the hold. Ordered cutover preserves subscriptions and
the warm-session clock without transferring failed-write ownership.

An unchanged failed first write remains paced even with `bb_private_asked`
false. Accepted queries retain their pending-query deadlines, timeout plus
failed resend climbs once, and synchronous replies retain their own deadline.
Hold retirement preserves endpoint cooldowns. Session reset preserves backbone
publication revision/hash. ADR 0015 and the M2 scope paragraph describe the
retry ownership.

## Additional repairs

Compiler diagnostics were addressed at their source: mutable arrays for
mutable string fields in cover fixtures; removal of unused helpers/fixtures;
complete designated peer initializers; checked namespace command results;
and interrupted/failed signal-pipe write handling with caller errno preserved.
C-only warning options moved from shared CPPFLAGS to CFLAGS, retaining those
checks for C without passing unsupported options to C++. No warning suppression
was added.

The event timer now normalizes exactly one billion nanoseconds and clears both
time fields when disabled. Metering tests reset their synchronization flag
rather than reinitializing live pthread objects. The NAT punishment worker's
stop request is protected by a mutex, with an explicit running flag instead of
treating pthread_t as an integer sentinel. The namespace helper's inverted
NDEBUG guard was corrected so release test builds retain setup operations and
assertions. Same-host join fixtures request local invitations when no canonical
address is configured, avoiding extra public address discovery; explicitly
configured canonical endpoints and their provenance remain included. Backbone
creation retains its existing external-address lookup, so that source of
network variability remains. These are concrete code defects or harness
dependencies; they are not claimed to explain
every historically intermittent test failure.

## Reproduction and commands

Every Meshlink build/test below runs in `meshlink-arm64`, with working directory
`/mnt/host/coco-project/third-party/meshlink`. GCC is Ubuntu 13.3.0 on AArch64. Dates in this record use UTC.
The checkout initially had no generated Makefile, so setup required
`autoreconf -fsi` and `./configure`.

Before changing the private owner, the real lifecycle regressions both aborted
with exit 134 at the assertion requiring one prompt private query:

```sh
make -C test -j1 peer-control
MESHLINK_PRIVATE_QUERY_REGRESSION=reconnect ./test/peer-control
MESHLINK_PRIVATE_QUERY_REGRESSION=network ./test/peer-control
```

The event timer boundary test also aborted against the pre-normalization code
at the assertion requiring `{101, 0}` from `{100, 500000000}` plus half a second.
The first event-signal test fixture had an uninitialized local event loop;
that test-only error was diagnosed with GDB and fixed by zero-initializing it.
An additional regression then caught an overly broad context check in the first
implementation: an accepted write whose send callback advanced the network
would lose its in-flight ID. Context invalidation is now restricted to failed
writes; the accepted-query ID/deadline survives this reentrant epoch change.
The final peer-control repetition includes that regression.

Build and gates:

```sh
autoreconf -fsi
./configure
make clean
make -j1
make -C test -j1 check TESTS="peer-control backbone-private-path backbone-private-relocate connection-policy path-policy-coverage"
make -j1 check
```

A focused five-test gate passed before the final additional event/harness
repairs. The baseline build emitted 7 compiler warnings and baseline test
compilation emitted 17. The final clean build and check-program compilation emitted zero
compiler warnings. Subsequent incremental builds also emitted zero compiler
warnings. Final gate results are recorded below.
Autotools setup retains upstream obsolescence notices for `AC_PROG_CC_C99`
and `$as_echo`, and notes that optional Doxygen is unavailable; these are
configuration-tool notices, not compiler diagnostics.

Direct repetitions use the test binaries, preserving Automake log timestamps
so the independent serial gate executes its tests separately:

```sh
for run in $(seq 1 100); do
    ./test/peer-control
    ./test/event-signal
done
for run in $(seq 1 10); do
    ./test/backbone-private-path
    ./test/backbone-private-relocate
done
for run in $(seq 1 5); do
    ./test/connection-policy
done
for run in $(seq 1 5); do
    for testname in backbone-private-path backbone-private-relocate connection-policy path-policy-coverage; do
        ./test/$testname
    done
done
```

The final peer-control fixture passed 100 repetitions, including counted failed
writes, synchronous answers and accepted-send network reentrancy. The final
event-signal fixture passed 100 repetitions,
covering EINTR retry, failed-write recovery, coalescing, errno preservation,
timer carry and timer retirement. The same event fixture also passed against
a separately compiled event module with HAVE_STDATOMIC_H undefined, using
-Wall -Wextra -pedantic -Werror; production configuration was unchanged. The namespace helper additionally compiled
successfully with assertions enabled by its guard despite -DNDEBUG:

```sh
gcc -DHAVE_CONFIG_H -I. -Isrc -Itest -Wall -Wextra -pedantic -Werror \
    -std=c11 -DNDEBUG -c test/netns_utils.c -o /tmp/ws4-netns-ndebug.o
```

## Final gate record

Final connection-policy repetitions: 5/5 passed. Outgoing-order,
canonical-migrate and join-canonical-nlb additionally passed with the final
invitation helper. Private path and relocation repetitions: 10/10 cycles passed
before that last helper change (these private fixtures use their own explicit
invitations). After the final accepted-send reentrancy correction, another 5/5
serial cycles of private path, private relocation, connection policy and
path-policy coverage passed.

The independent full serial `make -j1 check` completed with exit 0 on the final
implementation: 66 total, 66 passed, 0 skipped, 0 failed, 0 errors, and no
expected/unexpected failures. Its complete build-and-test log contained zero
compiler warnings. All four long metering variants, UDP relay's NAT/MTU and
keepalive scenarios, path stability, both private lifecycle tests and the new
event-signal regression passed in that gate. No enabled test failed during this
final run, and no failure was hidden by rerunning it.

The plan's exact five-test focused command also completed against the final
implementation after the full gate: 5 total, 5 passed, 0 skipped, 0 failed,
0 errors and exit 0, with zero compiler warnings. This invocation reran the
five tests; it did not substitute cached repetition results for the gate.

The earlier exploratory suite runs were stopped to finish the implementation
and restart against the final production changes; they are not full-suite
passes. cmocka and LXC development packages are unavailable, so configure does
not enable the separate blackbox suite; it was not run and is outside the
66-test result above.

Baseline reproduction logs, final build logs, full/focused gate logs and final repetition logs are
preserved under `test/tmp/ws4-private-query-hold-p2-logs/` (ignored test artifacts).
