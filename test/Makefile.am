TESTS = \
	basic \
	basicpp \
	blacklist \
	channels \
	channels-aio \
	channels-aio-abort \
	channels-aio-cornercases \
	channels-aio-fd \
	channels-buffer-storage \
	channels-cornercases \
	channels-failure \
	channels-timeout \
	channels-fork \
	channels-no-partial \
	channels-udp \
	channels-udp-cornercases \
	datagram-channel-mix \
	discovery \
	discovery-learn \
	duplicate \
	encrypted \
	ephemeral \
	get-all-nodes \
	import-export \
	invite-join \
	join-canonical-nlb \
	metering \
	metering-relayed \
	metering-slowping \
	metering-tcponly \
	meta-connections \
	get-external-address \
	mtu-probe-log \
	outgoing-order \
	outgoing-bounded \
	canonical-migrate \
	hybrid-udp-probe \
	req-external-recent \
	port \
	port-range \
	reconnect-backoff \
	req-external-port \
	sign-verify \
	storage-policy \
	simultaneous-connect \
	trio \
	trio2 \
	udp-relay \
	relay-coverage \
	path-policy-coverage \
	local-network \
	peer-control \
	backbone-identity \
	connection-policy \
	backbone-udp \
	path-stability \
	transport-recent \
	utcp-closed-syn \
	utcp-random \
	channels-session-restart \
	channels-utcp-prng \
	utcp-benchmark \
	utcp-benchmark-stream

TESTS += \
	api_set_node_status_cb

if BLACKBOX_TESTS
SUBDIRS = blackbox
endif

dist_check_SCRIPTS = $(TESTS)

# utcp-benchmark scripts invoke src/utcp-test (EXTRA_PROGRAMS — not built by default).
utcp-benchmark.log utcp-benchmark-stream.log: $(top_builddir)/src/utcp-test$(EXEEXT)
$(top_builddir)/src/utcp-test$(EXEEXT):
	$(MAKE) $(AM_MAKEFLAGS) -C $(top_builddir)/src utcp-test

AM_CPPFLAGS = $(PTHREAD_CFLAGS) -I${top_srcdir}/src -iquote. -Wall
AM_LDFLAGS = $(PTHREAD_LIBS)

check_PROGRAMS = \
	api_set_node_status_cb \
	basic \
	basicpp \
	blacklist \
	channels \
	channels-aio \
	channels-aio-abort \
	channels-aio-cornercases \
	channels-aio-fd \
	channels-buffer-storage \
	channels-cornercases \
	channels-failure \
	channels-timeout \
	channels-fork \
	channels-no-partial \
	channels-udp \
	channels-udp-cornercases \
	datagram-channel-mix \
	discovery \
	discovery-learn \
	duplicate \
	echo-fork \
	encrypted \
	ephemeral \
	get-all-nodes \
	import-export \
	invite-join \
	join-canonical-nlb \
	metering \
	metering-relayed \
	metering-slowping \
	metering-tcponly \
	meta-connections \
	get-external-address \
	mtu-probe-log \
	outgoing-order \
	outgoing-bounded \
	canonical-migrate \
	hybrid-udp-probe \
	req-external-recent \
	port \
	port-range \
	reconnect-backoff \
	req-external-port \
	sign-verify \
	storage-policy \
	simultaneous-connect \
	stream \
	trio \
	trio2 \
	udp-relay \
	relay-coverage \
	path-policy-coverage \
	local-network \
	peer-control \
	backbone-identity \
	connection-policy \
	backbone-udp \
	path-stability \
	transport-recent \
	utcp-closed-syn \
	utcp-random \
	channels-session-restart \
	channels-utcp-prng

if INSTALL_TESTS
bin_PROGRAMS = $(check_PROGRAMS)
endif

api_set_node_status_cb_SOURCES = api_set_node_status_cb.c utils.c utils.h
api_set_node_status_cb_LDADD = $(top_builddir)/src/libmeshlink.la

basic_SOURCES = basic.c utils.c utils.h
basic_LDADD = $(top_builddir)/src/libmeshlink.la

basicpp_SOURCES = basicpp.cpp utils.c utils.h
basicpp_LDADD = $(top_builddir)/src/libmeshlink.la

blacklist_SOURCES = blacklist.c utils.c utils.h
blacklist_LDADD = $(top_builddir)/src/libmeshlink.la

channels_SOURCES = channels.c utils.c utils.h
channels_LDADD = $(top_builddir)/src/libmeshlink.la

channels_aio_SOURCES = channels-aio.c utils.c utils.h
channels_aio_LDADD = $(top_builddir)/src/libmeshlink.la

channels_aio_abort_SOURCES = channels-aio-abort.c utils.c utils.h
channels_aio_abort_LDADD = $(top_builddir)/src/libmeshlink.la

channels_aio_cornercases_SOURCES = channels-aio-cornercases.c utils.c utils.h
channels_aio_cornercases_LDADD = $(top_builddir)/src/libmeshlink.la

channels_aio_fd_SOURCES = channels-aio-fd.c utils.c utils.h
channels_aio_fd_LDADD = $(top_builddir)/src/libmeshlink.la

channels_buffer_storage_SOURCES = channels-buffer-storage.c utils.c utils.h
channels_buffer_storage_LDADD = $(top_builddir)/src/libmeshlink.la

channels_no_partial_SOURCES = channels-no-partial.c utils.c utils.h
channels_no_partial_LDADD = $(top_builddir)/src/libmeshlink.la

channels_failure_SOURCES = channels-failure.c utils.c utils.h
channels_failure_LDADD = $(top_builddir)/src/libmeshlink.la

datagram_channel_mix_SOURCES = datagram-channel-mix.c utils.c utils.h
datagram_channel_mix_LDADD = $(top_builddir)/src/libmeshlink.la

channels_timeout_SOURCES = channels-timeout.c utils.c utils.h
channels_timeout_LDADD = $(top_builddir)/src/libmeshlink.la

channels_fork_SOURCES = channels-fork.c utils.c utils.h
channels_fork_LDADD = $(top_builddir)/src/libmeshlink.la

channels_cornercases_SOURCES = channels-cornercases.c utils.c utils.h
channels_cornercases_LDADD = $(top_builddir)/src/libmeshlink.la

channels_udp_SOURCES = channels-udp.c utils.c utils.h
channels_udp_LDADD = $(top_builddir)/src/libmeshlink.la

channels_udp_cornercases_SOURCES = channels-udp-cornercases.c utils.c utils.h
channels_udp_cornercases_LDADD = $(top_builddir)/src/libmeshlink.la

discovery_SOURCES = discovery.c utils.c utils.h
discovery_LDADD = $(top_builddir)/src/libmeshlink.la

discovery_learn_SOURCES = discovery-learn.c utils.c utils.h
discovery_learn_LDADD = $(top_builddir)/src/libmeshlink.la

duplicate_SOURCES = duplicate.c utils.c utils.h
duplicate_LDADD = $(top_builddir)/src/libmeshlink.la

echo_fork_SOURCES = echo-fork.c utils.c utils.h
echo_fork_LDADD = $(top_builddir)/src/libmeshlink.la

encrypted_SOURCES = encrypted.c utils.c utils.h
encrypted_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

ephemeral_SOURCES = ephemeral.c utils.c utils.h
ephemeral_LDADD = $(top_builddir)/src/libmeshlink.la

get_all_nodes_SOURCES = get-all-nodes.c utils.c utils.h
get_all_nodes_LDADD = $(top_builddir)/src/libmeshlink.la

import_export_SOURCES = import-export.c utils.c utils.h
# Internal observation checks use the static library, preserving the public symbol set.
import_export_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

invite_join_SOURCES = invite-join.c utils.c utils.h
invite_join_LDADD = $(top_builddir)/src/libmeshlink.la

join_canonical_nlb_SOURCES = join-canonical-nlb.c utils.c utils.h
join_canonical_nlb_LDADD = $(top_builddir)/src/libmeshlink.la

metering_SOURCES = metering.c netns_utils.c netns_utils.h utils.c utils.h
metering_LDADD = $(top_builddir)/src/libmeshlink.la

metering_relayed_SOURCES = metering-relayed.c netns_utils.c netns_utils.h utils.c utils.h
metering_relayed_LDADD = $(top_builddir)/src/libmeshlink.la

metering_slowping_SOURCES = metering-slowping.c netns_utils.c netns_utils.h utils.c utils.h
metering_slowping_LDADD = $(top_builddir)/src/libmeshlink.la

metering_tcponly_SOURCES = metering-tcponly.c netns_utils.c netns_utils.h utils.c utils.h
metering_tcponly_LDADD = $(top_builddir)/src/libmeshlink.la

meta_connections_SOURCES = meta-connections.c netns_utils.c netns_utils.h utils.c utils.h
meta_connections_LDADD = $(top_builddir)/src/libmeshlink.la

get_external_address_SOURCES = get-external-address.c utils.c utils.h
get_external_address_LDADD = $(top_builddir)/src/libmeshlink.la

mtu_probe_log_SOURCES = mtu-probe-log.c utils.c utils.h
mtu_probe_log_LDADD = $(top_builddir)/src/libmeshlink.la

outgoing_order_SOURCES = outgoing-order.c utils.c utils.h
outgoing_order_LDADD = $(top_builddir)/src/libmeshlink.la

outgoing_bounded_SOURCES = outgoing-bounded.c utils.c utils.h
outgoing_bounded_LDADD = $(top_builddir)/src/libmeshlink.la

canonical_migrate_SOURCES = canonical-migrate.c utils.c utils.h
canonical_migrate_LDADD = $(top_builddir)/src/libmeshlink.la

hybrid_udp_probe_SOURCES = hybrid-udp-probe.c utils.c utils.h
hybrid_udp_probe_LDADD = $(top_builddir)/src/libmeshlink.la

req_external_recent_SOURCES = req-external-recent.c utils.c utils.h
req_external_recent_LDADD = $(top_builddir)/src/libmeshlink.la

port_SOURCES = port.c utils.c utils.h
port_LDADD = $(top_builddir)/src/libmeshlink.la

port_range_SOURCES = port-range.c utils.c utils.h
port_range_LDADD = $(top_builddir)/src/libmeshlink.la

reconnect_backoff_SOURCES = reconnect-backoff.c utils.c utils.h
reconnect_backoff_LDADD = $(top_builddir)/src/libmeshlink.la

req_external_port_SOURCES = req-external-port.c utils.c utils.h
req_external_port_LDADD = $(top_builddir)/src/libmeshlink.la

sign_verify_SOURCES = sign-verify.c utils.c utils.h
sign_verify_LDADD = $(top_builddir)/src/libmeshlink.la

storage_policy_SOURCES = storage-policy.c node-storage.c node-storage-lifecycle.c node-observation.c node-storage-tests.h utils.c utils.h
storage_policy_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

simultaneous_connect_SOURCES = simultaneous-connect.c utils.c utils.h
simultaneous_connect_LDADD = $(top_builddir)/src/libmeshlink.la

trio_SOURCES = trio.c utils.c utils.h
trio_LDADD = $(top_builddir)/src/libmeshlink.la

trio2_SOURCES = trio2.c utils.c utils.h
trio2_LDADD = $(top_builddir)/src/libmeshlink.la

udp_relay_SOURCES = udp-relay.c netns_utils.c netns_utils.h utils.c utils.h
udp_relay_LDADD = $(top_builddir)/src/libmeshlink.la

relay_coverage_SOURCES = relay-coverage.c utils.c utils.h
relay_coverage_LDADD = $(top_builddir)/src/libmeshlink.la

path_policy_coverage_SOURCES = path-policy-coverage.c utils.c utils.h
path_policy_coverage_LDADD = $(top_builddir)/src/libmeshlink.la

local_network_SOURCES = local-network.c
local_network_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

backbone_identity_SOURCES = backbone-identity.c utils.c utils.h
backbone_identity_LDADD = $(top_builddir)/src/libmeshlink.la

connection_policy_SOURCES = connection-policy.c utils.c utils.h
connection_policy_LDADD = $(top_builddir)/src/libmeshlink.la

backbone_udp_SOURCES = backbone-udp.c utils.c utils.h
backbone_udp_LDADD = $(top_builddir)/src/libmeshlink.la

path_stability_SOURCES = path-stability.c netns_utils.c netns_utils.h utils.c utils.h
path_stability_LDADD = $(top_builddir)/src/libmeshlink.la

transport_recent_SOURCES = transport-recent.c utils.c utils.h
transport_recent_LDADD = $(top_builddir)/src/libmeshlink.la

utcp_closed_syn_SOURCES = utcp-closed-syn.c
utcp_closed_syn_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

utcp_random_SOURCES = utcp-random.c
utcp_random_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

channels_session_restart_SOURCES = channels-session-restart.c utcp-peek.c utcp-peek.h utils.c utils.h
channels_session_restart_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

channels_utcp_prng_SOURCES = channels-utcp-prng.c utcp-peek.c utcp-peek.h utils.c utils.h
channels_utcp_prng_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

relay_hop_SOURCES = relay-hop.c relay-hop-support.c utils.c utils.h
relay_hop_LDADD = $(top_builddir)/src/.libs/libmeshlink.a

relay_hop_LDFLAGS = $(AM_LDFLAGS) -Wl,--wrap=sendto

if LINUX
TESTS += lifecycle-start-stop
check_PROGRAMS += lifecycle-start-stop

lifecycle_start_stop_SOURCES = lifecycle-start-stop.c
lifecycle_start_stop_LDADD = $(top_builddir)/src/.libs/libmeshlink.a
lifecycle_start_stop_LDFLAGS = $(AM_LDFLAGS) -Wl,--wrap=setns -Wl,--wrap=pthread_cond_wait -Wl,--wrap=pthread_join

TESTS += utcp-no-rand
check_PROGRAMS += utcp-no-rand

utcp_no_rand_SOURCES = utcp-no-rand.c
utcp_no_rand_LDADD = $(top_builddir)/src/.libs/libmeshlink.a
utcp_no_rand_LDFLAGS = $(AM_LDFLAGS) -Wl,--wrap=rand

TESTS += event-signal
check_PROGRAMS += event-signal

event_signal_SOURCES = event-signal.c
event_signal_LDADD = $(top_builddir)/src/.libs/libmeshlink.a
event_signal_LDFLAGS = $(AM_LDFLAGS) -Wl,--wrap=write
TESTS += relay-hop
check_PROGRAMS += relay-hop
TESTS += discovery-failure
check_PROGRAMS += discovery-failure
TESTS += backbone-private-path
check_PROGRAMS += backbone-private-path
TESTS += backbone-private-relocate
check_PROGRAMS += backbone-private-relocate
TESTS += local-discovery-eligibility
check_PROGRAMS += local-discovery-eligibility

backbone_private_path_SOURCES = backbone-private-path.c netns_utils.c netns_utils.h utils.c utils.h
backbone_private_path_LDADD = $(top_builddir)/src/libmeshlink.la

backbone_private_relocate_SOURCES = backbone-private-relocate.c netns_utils.c netns_utils.h utils.c utils.h
backbone_private_relocate_LDADD = $(top_builddir)/src/libmeshlink.la

local_discovery_eligibility_SOURCES = local-discovery-eligibility.c netns_utils.c netns_utils.h utils.c utils.h
local_discovery_eligibility_LDADD = $(top_builddir)/src/libmeshlink.la

discovery_failure_SOURCES = discovery-failure.c
discovery_failure_LDADD = $(top_builddir)/src/.libs/libmeshlink.a
discovery_failure_LDFLAGS = $(AM_LDFLAGS) -Wl,--wrap=bind -Wl,--wrap=setsockopt -Wl,--wrap=getifaddrs -Wl,--wrap=freeifaddrs
endif

peer_control_SOURCES = peer-control.c utils.c utils.h
peer_control_LDADD = $(top_builddir)/src/.libs/libmeshlink.a
