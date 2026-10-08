# ADR 0014: NAT warning windows and discovery failure fallback

## Status

Accepted; local build and targeted coverage passed. Full-suite verification
delegated to the repository owner; field validation pending.

## Context

ADR 0010 logs unstable NAT binding after six validated migrations within
60 seconds. Once the threshold is reached, every further migration logs
the same warning, obscuring recovery events in field captures.

Android can create an AF_NETLINK socket but lack permission to bind its
notification groups. Discovery falls back to scanning interfaces, but
leaves the unregistered descriptor open. Multicast-interface selection
failures also omit the interface and system error from their diagnostics.

## Decision

- Keep the six-migration, rolling 60-second detection threshold. After a
  warning, suppress further warnings for that peer for 60 seconds from
  the warning's timestamp. At or after expiry, another validated
  migration may warn if the rolling threshold still holds. A new burst
  after a quiet interval may also warn. Suppression survives challenge
  cancellation, and does not change endpoint validation or migration.
- On AF_NETLINK bind failure, close the socket before scanning interfaces.
  The failed socket is never registered with the event loop. The initial
  scan remains available even without native interface notifications.
- Retain application-driven network-change hints as the notification
  fallback. With discovery enabled, a hint scans the current interface
  addresses and advances the network epoch.
- Include the interface index and system error in IPv4 and IPv6
  multicast-interface selection failures. A failed selection stops that
  mDNS send; it does not disable ordinary UDP traffic.

## Consequences

Repeated NAT migrations remain visible through existing migration logs
and counters, with at most one instability warning per peer per warning
window. Sustained instability can warn again after each window.

Discovery start/stop does not accumulate descriptors when netlink binding
is denied. This does not restore native notifications on restricted
Android devices; applications still need to provide network-change hints.
Interface-index diagnostics identify the failing local interface without
claiming a cause beyond the reported system error.

Local coverage forces netlink binding and multicast-interface selection
failures, repeats discovery start/stop, and changes the scanned addresses
before a network-change hint. Route-policy coverage exercises NAT bursts,
ring wrap, suppression just before expiry, and renewed warnings at expiry
and after a quiet interval. Both targeted tests passed in the ARM64 Docker
environment. The serial full-suite rerun was stopped at the owner's request
after 25 passing tests, with no failures reported before interruption.
The owner will run the full suite with code review. Field validation remains
required.
