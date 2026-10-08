/* Separately linked internal tests: no production compile switches. */
#include "system.h"
#include "meshlink_internal.h"
#include "connection_policy.h"
#include "connection.h"
#include "protocol.h"
#include "../src/utils.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "path_liveness.h"
#include "path_plpmtu.h"
#include "path_policy.h"
#include "path_probe.h"
#include "path_scheduler.h"
#include "relay.h"
#include <assert.h>

void relay_hop_tests(meshlink_handle_t *mesh);

static sockaddr_t endpoint(unsigned port) {
	sockaddr_t sa = {0};
	sa.in.sin_family = AF_INET;
	sa.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.in.sin_port = htons(port);
	return sa;
}

static void setup_peer(meshlink_handle_t *mesh, node_t *n) {
	memset(n, 0, sizeof *n);
	static char name[] = "camera";
	n->name = name;
	n->mesh = mesh;
	n->session_id = 123;
	n->devclass = DEV_CLASS_STATIONARY;
	n->status.reachable = n->status.validkey = true;
	n->address = endpoint(32000);
	n->sock = 0;
	n->sptps.state = SPTPS_SECONDARY_KEX;
	n->sptps.datagram = n->sptps.outstate = true;
	n->sptps.handle = n;
	n->sptps.send_data = send_sptps_data;
	n->sptps.outcipher = chacha_poly1305_init();
	uint8_t key[CHACHA_POLY1305_KEYLEN] = {0};
	assert(chacha_poly1305_set_key(n->sptps.outcipher, key));
}

static void advance(meshlink_handle_t *mesh, unsigned seconds) {
	mesh->loop.now.tv_sec += seconds;
}

void relay_hop_tests(meshlink_handle_t *mesh) {
	node_t n;
	setup_peer(mesh, &n);
	struct timespec saved_now = mesh->loop.now;
	mesh->loop.now.tv_sec = time(NULL);
	assert(connection_policy_set_backbone(mesh, mesh->self->name));
	assert(connection_policy_backbone(mesh) == mesh->self);

	/* Authenticated ingress alone, including an echo request, proves nothing. */
	path_note_authenticated_udp_observation(mesh, &n, &n.address);
	assert(!n.status.udp_confirmed && !n.relay_hop.timer.cb);
	path_scheduler_set_budget(mesh, 0, 0, 2);
	relay_hop_note_demand(mesh, &n);
	uint64_t nonce = n.relay_hop.nonce;
	assert(nonce && !n.relay_hop.attempts && !n.relay_hop.confirmed);
	relay_hop_note_demand(mesh, &n);
	path_note_authenticated_udp_observation(mesh, &n, &n.address);
	assert(n.relay_hop.nonce == nonce && !n.peer_udp.channel_count);
	assert(!relay_hop_reply(mesh, &n, &n.address, nonce));

	/* Failed socket sends do not count; a subsequent actual transmission does. */
	int sockets = mesh->listen_sockets;
	mesh->listen_sockets = 0;
	path_scheduler_set_budget(mesh, 4, 20, 2);
	relay_hop_tick(mesh, &n);
	assert(!n.relay_hop.attempts);
	mesh->listen_sockets = sockets;
	path_scheduler_set_budget(mesh, 4, 20, 2);
	relay_hop_tick(mesh, &n);
	assert(n.relay_hop.attempts == 1);
	assert(!relay_hop_reply(mesh, &n, &n.address, nonce ^ 1));
	sockaddr_t wrong = endpoint(32001);
	assert(!relay_hop_reply(mesh, &n, &wrong, nonce));
	wrong = n.address;
	wrong.in.sin_addr.s_addr ^= htonl(1);
	assert(!relay_hop_reply(mesh, &n, &wrong, nonce));
	n.session_id++;
	assert(!relay_hop_reply(mesh, &n, &n.address, nonce));
	n.session_id--;
	mesh->lan_network_epoch++;
	assert(!relay_hop_reply(mesh, &n, &n.address, nonce));
	mesh->lan_network_epoch--;
	vpn_packet_t reply = {0};
	reply.data[0] = PROBE_KIND_ECHO_REPLY;
	reply.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_PUNCH;
	memcpy(reply.data + PROBE_NONCE_OFFSET, &nonce, sizeof nonce);
	n.last_udp_from = n.address;
	probe_record_h(mesh, &n, &reply, PROBE_FIXED_LEN);
	assert(!n.relay_hop.confirmed && !n.status.udp_confirmed);
	assert(relay_hop_reply(mesh, &n, &n.address, nonce));
	assert(n.relay_hop.confirmed && n.status.udp_confirmed);
	assert(n.active_route.kind == DATA_ROUTE_NONE);
	assert(n.plpmtu.state != PLPMTU_DISABLED && n.liveness.timer.cb);

	/* Replacement is challenged without overwriting the working endpoint. */
	uint16_t old_size = n.plpmtu.size;
	wrong = endpoint(32001);
	path_scheduler_set_budget(mesh, 4, 20, 2);
	path_note_authenticated_udp_observation(mesh, &n, &wrong);
	nonce = n.relay_hop.nonce;
	assert(nonce && n.relay_hop.confirmed && !sockaddrcmp(&n.address, &n.relay_hop.confirmed_endpoint));
	advance(mesh, 10);
	relay_hop_note_demand(mesh, &n);
	assert(!n.relay_hop.nonce && n.relay_hop.confirmed);
	path_note_authenticated_udp_observation(mesh, &n, &wrong);
	assert(!n.relay_hop.nonce);
	wrong = endpoint(32002);
	path_scheduler_set_budget(mesh, 4, 20, 2);
	path_note_authenticated_udp_observation(mesh, &n, &wrong);
	assert(n.relay_hop.nonce && n.relay_hop.attempts == 1);
	assert(relay_hop_reply(mesh, &n, &wrong, n.relay_hop.nonce));
	assert(!sockaddrcmp(&n.address, &wrong) && n.plpmtu.size == old_size);

	/* New traffic cannot revive expired proof before its timer runs. */
	advance(mesh, 30);
	path_note_authenticated_udp_observation(mesh, &n, &wrong);
	path_scheduler_set_budget(mesh, 4, 20, 2);
	relay_hop_note_demand(mesh, &n);
	assert(!n.relay_hop.confirmed && !n.status.udp_confirmed && n.relay_hop.nonce);
	assert(relay_hop_reply(mesh, &n, &wrong, n.relay_hop.nonce));

	/* Expired demand rejects a late reply and releases every owned timer. */
	advance(mesh, 30);
	assert(!relay_hop_reply(mesh, &n, &wrong, nonce));
	relay_hop_tick(mesh, &n);
	assert(!n.relay_hop.timer.cb && !n.relay_hop.confirmed && !n.status.udp_confirmed);
	assert(!n.plpmtu.timer.cb && !n.liveness.timer.cb && !n.keepalive.timer.cb);
	path_keepalive_note_rx(mesh, &n);
	assert(!n.keepalive.timer.cb);

	/* Key invalidation and network change require a fresh authenticated source. */
	path_note_authenticated_udp_observation(mesh, &n, &wrong);
	path_scheduler_set_budget(mesh, 4, 20, 2);
	relay_hop_note_demand(mesh, &n);
	node_set_validkey(mesh, &n, false);
	assert(!n.relay_hop.nonce && !n.relay_hop.timer.cb && !n.udp_observation.session_id);
	node_set_validkey(mesh, &n, true);
	relay_hop_note_demand(mesh, &n);
	assert(!n.relay_hop.nonce);
	relay_hop_stop(mesh, &n);
	path_scheduler_cancel_node(mesh, &n);
	path_plpmtu_stop(mesh, &n);
	path_liveness_stop(mesh, &n);
	path_keepalive_stop(mesh, &n);
	update_node_udp_from(mesh, &n, NULL, ADDR_SRC_UNKNOWN);
	sptps_stop(&n.sptps);

	/* Multiple demanded outputs share the two-slot cap and eventually enter.
	   Preemption retains actual-send accounting and the absolute deadline. */
	node_t peers[4];
	path_scheduler_set_budget(mesh, 4, 20, 2);
	for(unsigned i = 0; i < 4; i++) {
		setup_peer(mesh, &peers[i]);
		peers[i].address = endpoint(32100 + i);
		path_note_authenticated_udp_observation(mesh, &peers[i], &peers[i].address);
		relay_hop_note_demand(mesh, &peers[i]);
	}
	assert(peers[0].relay_hop.attempts == 1 && peers[1].relay_hop.attempts == 1);
	assert(!peers[2].relay_hop.attempts && !peers[3].relay_hop.attempts);
	path_sched_txn_t *recovery = path_scheduler_begin_transaction(mesh, &n, PATH_TXN_SUSPECT, PATH_TX_ACTIVE_ROUTE_RECOVERY, NULL);
	assert(recovery);
	assert(peers[0].relay_hop.attempts == 1 && peers[1].relay_hop.attempts == 1);
	path_scheduler_end_transaction(mesh, recovery);
	for(unsigned i = 0; i < 4; i++) {
		path_scheduler_set_budget(mesh, 4, 20, 2);
		relay_hop_tick(mesh, &peers[i]);
		assert(peers[i].relay_hop.attempts == 1);
		assert(relay_hop_reply(mesh, &peers[i], &peers[i].address, peers[i].relay_hop.nonce));
		assert(peers[i].relay_hop.challenges_sent == 1 && !peers[i].peer_udp.channel_count);
		relay_hop_stop(mesh, &peers[i]);
		path_scheduler_cancel_node(mesh, &peers[i]);
		update_node_udp_from(mesh, &peers[i], NULL, ADDR_SRC_UNKNOWN);
		sptps_stop(&peers[i].sptps);
	}
	mesh->loop.now = saved_now;
}

static unsigned envelope_request, received_records, reported_budget;
static uint8_t encrypted_record[MAXSIZE];
static size_t encrypted_len;

static void envelope_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	(void)level;
	const char *wire = strstr(text, "Sending REQ_KEY to next: ");
	if(wire) {
		assert(sscanf(wire, "Sending REQ_KEY to next: %*u %*s %*s %u", &envelope_request) == 1);
		if(envelope_request == REQ_RELAY_MTU) {
			assert(sscanf(wire, "Sending REQ_KEY to next: %*u %*s %*s %*u %*s %u", &reported_budget) == 1);
		}
	}
}

static bool capture_record(void *handle, uint8_t type, const void *data, size_t len) {
	(void)handle;
	(void)type;
	assert(len <= sizeof encrypted_record);
	memcpy(encrypted_record, data, len);
	encrypted_len = len;
	return true;
}

static bool receive_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	(void)handle;
	assert(type == 0 && len == 5 && !memcmp(data, "Hello", len));
	received_records++;
	return true;
}

void relay_envelope_tests(meshlink_handle_t *mesh);
void relay_envelope_tests(meshlink_handle_t *mesh) {
	connection_t c = {0};
	static char next_name[] = "next";
	c.name = next_name;
	c.mesh = mesh;
	c.socket = -1;
	c.protocol_minor = PROT_MINOR_SPTPS_APP;
	meshlink_log_cb_t saved_cb = mesh->log_cb;
	meshlink_log_level_t saved_level = mesh->log_level;
	mesh->log_cb = envelope_log;
	mesh->log_level = MESHLINK_DEBUG;
	uint8_t data[21] = {0};
	assert(relay_meta_app(mesh, &c, "origin", "dest", data, sizeof data));
	assert(envelope_request == REQ_SPTPS_APP);
	c.protocol_minor--;
	assert(relay_meta_app(mesh, &c, "origin", "dest", data, sizeof data));
	assert(envelope_request == REQ_SPTPS);
	c.protocol_minor++;
	assert(relay_meta_req_sptps(mesh, &c, "origin", "dest", data, sizeof data));
	assert(envelope_request == REQ_SPTPS);

	node_t *origin = new_node();
	splay_tree_t *edges = origin->edge_tree;
	setup_peer(mesh, origin);
	origin->edge_tree = edges;
	origin->name = strdup("origin");
	origin->sptps.send_data = capture_record;
	origin->sptps.receive_record = receive_record;
	origin->sptps.instate = true;
	origin->sptps.incipher = chacha_poly1305_init();
	uint8_t key[CHACHA_POLY1305_KEYLEN] = {0};
	assert(chacha_poly1305_set_key(origin->sptps.incipher, key));
	origin->sptps.replaywin = 16;
	origin->sptps.late = calloc(16, 1);
	/* Do not add synthetic graph edges: envelope receive needs only identity. */
	char buf[1024], encoded[512];
	assert(sptps_send_record(&origin->sptps, 0, "Hello", 5));
	b64encode(encrypted_record, encoded, encrypted_len);
	snprintf(buf, sizeof buf, "%d origin nmn %d %s", REQ_KEY, REQ_SPTPS_APP, encoded);
	assert(relay_handle_meta_app(mesh, &c, origin, mesh->self, buf));
	assert(received_records == 1);
	assert(relay_handle_meta_app(mesh, &c, origin, mesh->self, buf));
	assert(received_records == 1); /* replay rejected */

	const uint8_t control_types[] = {SPTPS_HANDSHAKE, PKT_PROBE, PKT_RELAY_SPTPS};
	for(size_t i = 0; i < sizeof control_types; i++) {
		assert(sptps_send_record_raw(&origin->sptps, control_types[i], "Hello", 5));
		b64encode(encrypted_record, encoded, encrypted_len);
		snprintf(buf, sizeof buf, "%d origin nmn %d %s", REQ_KEY, REQ_SPTPS_APP, encoded);
		int state = origin->sptps.state;
		assert(relay_handle_meta_app(mesh, &c, origin, mesh->self, buf));
		assert(received_records == 1 && origin->sptps.state == state);
	}
	assert(relay_handle_meta_app(mesh, &c, origin, mesh->self, "15 origin nmn 31 !!!"));
	assert(received_records == 1);
	/* An older hop cannot introduce the new application envelope. */
	c.protocol_minor--;
	assert(sptps_send_record(&origin->sptps, 0, "Hello", 5));
	b64encode(encrypted_record, encoded, encrypted_len);
	snprintf(buf, sizeof buf, "%d origin nmn %d %s", REQ_KEY, REQ_SPTPS_APP, encoded);
	assert(relay_handle_meta_app(mesh, &c, origin, mesh->self, buf));
	assert(received_records == 1);
	free_node(origin);
	mesh->log_cb = saved_cb;
	mesh->log_level = saved_level;
}

void relay_mtu_tests(meshlink_handle_t *mesh);
void relay_mtu_tests(meshlink_handle_t *mesh) {
	node_t hop, dest = {0};
	connection_t c = {0}, replacement = {0};
	setup_peer(mesh, &hop);
	static char name[] = "destination";
	dest.name = name;
	dest.nexthop = &hop;
	dest.active_route.kind = DATA_ROUTE_RELAY;
	dest.active_route.relay_carrier = RELAY_CARRIER_UDP;
	dest.active_route.first_hop = &hop;
	hop.connection = &c;
	hop.status.udp_confirmed = true;
	hop.plpmtu.size = MTU;
	uint32_t overhead = 0;
	assert(relay_prefix21(mesh->self->name, name, &overhead));
	assert(relay_effective_budget(mesh, &dest) == MINMTU - overhead);
	dest.relay_budget = 900;
	dest.relay_budget_connection = &c;
	assert(channel_compute_mtu(mesh, &dest) == 900 - sizeof(meshlink_packethdr_t));
	hop.plpmtu.size = 700;
	assert(channel_compute_mtu(mesh, &dest) == 700 - overhead - sizeof(meshlink_packethdr_t));
	dest.relay_budget = 600;
	assert(channel_compute_mtu(mesh, &dest) == 600 - sizeof(meshlink_packethdr_t));
	/* The reverse origin path and end-to-end peer's size cannot replace leg 1. */
	dest.plpmtu.size = MINMTU;
	assert(relay_effective_budget(mesh, &dest) == 600);
	hop.connection = &replacement;
	assert(relay_effective_budget(mesh, &dest) == MINMTU - overhead);
	hop.connection = &c;
	dest.nexthop = mesh->self;
	assert(relay_effective_budget(mesh, &dest) == MINMTU - overhead);

	/* Periodic verification checks the current size and retains hostile holds. */
	struct timespec saved_now = mesh->loop.now;
	mesh->loop.now.tv_sec = time(NULL);
	hop.plpmtu.state = PLPMTU_COMPLETE;
	hop.plpmtu.size = 1399;
	hop.plpmtu.hostile = true;
	hop.plpmtu.raise_at = mesh->loop.now;
	hop.plpmtu.raise_at.tv_sec += 3600;
	hop.plpmtu.relay_verify_at = mesh->loop.now;
	hop.relay_hop.confirmed = true;
	hop.relay_hop.confirmed_endpoint = hop.address;
	hop.relay_hop.demand_until = mesh->loop.now;
	hop.relay_hop.demand_until.tv_sec += 300;
	path_scheduler_set_budget(mesh, 0, 0, 2);
	path_plpmtu_verify_relay_due(mesh, &hop);
	assert(hop.plpmtu.relay_verifying && hop.plpmtu.pending_size == 1399 && !hop.plpmtu.probe_size);
	assert(hop.plpmtu.relay_verify_admission_delays && !hop.plpmtu.probes_lost);
	path_scheduler_set_budget(mesh, 4, 20, 2);
	path_plpmtu_tick(mesh, &hop);
	assert(hop.plpmtu.probe_size == 1399);
	uint64_t nonce = hop.plpmtu.probe_nonce;
	sockaddr_t wrong = endpoint(32001);
	path_plpmtu_observe_ack(mesh, &hop, &wrong, nonce, 1399);
	assert(hop.plpmtu.relay_verifying);
	path_plpmtu_observe_ack(mesh, &hop, &hop.address, nonce, 1399);
	assert(hop.plpmtu.state == PLPMTU_COMPLETE && !hop.plpmtu.relay_verifying);
	assert(hop.plpmtu.size == 1399 && hop.plpmtu.hostile);
	assert(hop.plpmtu.raise_at.tv_sec == mesh->loop.now.tv_sec + 3600);
	assert(hop.plpmtu.relay_verifications == 1);

	/* Small recovery echoes remain admitted while the current size disappears. */
	hop.plpmtu.relay_verify_at = mesh->loop.now;
	path_plpmtu_verify_relay_due(mesh, &hop);
	for(unsigned i = 0; i < PATH_PLPMTU_MAX_PROBES; i++) {
		advance(mesh, 2);
		path_scheduler_set_budget(mesh, 4, 20, 2);
		path_plpmtu_tick(mesh, &hop);
		advance(mesh, 1);
		path_scheduler_set_budget(mesh, 4, 20, 2);
		path_plpmtu_tick(mesh, &hop);
	}
	assert(hop.plpmtu.size < 1399 && hop.plpmtu.relay_verify_failures == 1);
	assert(hop.plpmtu.probes_lost == PATH_PLPMTU_MAX_PROBES);

	/* Stopping after a network change must not retag old size knowledge. */
	path_plpmtu_stop(mesh, &hop);
	char *saved_ip = mesh->self->external_ip_address;
	mesh->self->external_ip_address = strdup("198.51.100.10");
	path_plpmtu_on_confirmed(mesh, &hop);
	uint32_t old_fp = path_local_network_fp(mesh);
	assert(hop.plpmtu.path_net_fp == old_fp);
	hop.plpmtu.size = 1399;
	hop.plpmtu.state = PLPMTU_COMPLETE;
	free(mesh->self->external_ip_address);
	mesh->self->external_ip_address = strdup("198.51.100.11");
	path_plpmtu_stop(mesh, &hop);
	assert(hop.mtu_cache[0].net_fp == old_fp);
	path_plpmtu_on_confirmed(mesh, &hop);
	assert(!hop.plpmtu.cache_hits && hop.plpmtu.size == PATH_PLPMTU_BASE);
	free(mesh->self->external_ip_address);
	mesh->self->external_ip_address = saved_ip;
	relay_hop_stop(mesh, &hop);
	path_plpmtu_stop(mesh, &hop);
	path_scheduler_cancel_node(mesh, &hop);
	update_node_udp_from(mesh, &hop, NULL, ADDR_SRC_UNKNOWN);
	sptps_stop(&hop.sptps);
	mesh->loop.now = saved_now;
}

/* The linker wraps only this test executable's socket sends. Production has
   no error-injection switch. Other sends use the real kernel datagram path. */
static int injected_send_errno;
ssize_t __real_sendto(int fd, const void *data, size_t len, int flags, const struct sockaddr *sa, socklen_t salen);
ssize_t __wrap_sendto(int fd, const void *data, size_t len, int flags, const struct sockaddr *sa, socklen_t salen);
ssize_t __wrap_sendto(int fd, const void *data, size_t len, int flags, const struct sockaddr *sa, socklen_t salen) {
	if(injected_send_errno) {
		errno = injected_send_errno;
		injected_send_errno = 0;
		return -1;
	}
	return __real_sendto(fd, data, len, flags, sa, salen);
}

static node_t *test_peer(meshlink_handle_t *mesh, const char *name) {
	node_t *n = new_node();
	splay_tree_t *edges = n->edge_tree;
	setup_peer(mesh, n);
	n->edge_tree = edges;
	n->name = strdup(name);
	node_add(mesh, n);
	return n;
}

void relay_send_tests(meshlink_handle_t *mesh);
void relay_send_tests(meshlink_handle_t *mesh) {
	node_t *origin = test_peer(mesh, "origin"), *dest = test_peer(mesh, "destination");
	connection_t c = {0};
	static char name[] = "next";
	c.name = name;
	c.mesh = mesh;
	c.socket = -1;
	c.protocol_minor = PROT_MINOR_SPTPS_APP;
	c.node = dest;
	dest->connection = &c;
	dest->nexthop = dest;
	origin->nexthop = origin;
	meshlink_log_cb_t saved_cb = mesh->log_cb;
	meshlink_log_level_t saved_level = mesh->log_level;
	mesh->log_cb = envelope_log;
	mesh->log_level = MESHLINK_DEBUG;
	uint8_t inner[700] = {0}, wrapped[800];
	size_t len = sizeof wrapped;
	assert(relay_encode(origin->name, dest->name, inner, 21, wrapped, &len));

	/* Unready and missing-socket paths use exactly one META attempt. */
	assert(relay_handle_record(mesh, origin, wrapped, len));
	assert(dest->relay_hop.meta_fallbacks == 1 && dest->relay_hop.fallback_reason[RELAY_UDP_UNREADY] == 1);
	dest->status.udp_confirmed = true;
	assert(!relay_hop_udp_ready(dest)); /* Generic UDP confirmation cannot bypass proof. */
	dest->relay_hop.confirmed = true;
	dest->relay_hop.confirmed_endpoint = endpoint(32001);
	assert(!relay_hop_udp_ready(dest)); /* Nor can a different proved port. */
	dest->relay_hop.confirmed_endpoint = dest->address;
	dest->plpmtu.size = MTU;
	int sockets = mesh->listen_sockets;
	mesh->listen_sockets = 0;
	assert(relay_handle_record(mesh, origin, wrapped, len));
	assert(dest->relay_hop.meta_fallbacks == 2 && dest->relay_hop.fallback_reason[RELAY_UDP_NO_SOCKET] == 1);
	mesh->listen_sockets = sockets;

	const int errors[] = {EAGAIN, EMSGSIZE, EHOSTUNREACH};
	const unsigned reasons[] = {RELAY_UDP_WOULD_BLOCK, RELAY_UDP_EMSGSIZE, RELAY_UDP_HARD_ERROR};
	for(unsigned i = 0; i < 3; i++) {
		dest->status.udp_confirmed = true;
		dest->relay_hop.confirmed = true;
		dest->plpmtu.size = MTU;
		injected_send_errno = errors[i];
		assert(relay_handle_record(mesh, origin, wrapped, len));
		assert(!injected_send_errno && dest->relay_hop.udp_sent == 0);
		assert(dest->relay_hop.meta_fallbacks == 3 + i && dest->relay_hop.fallback_reason[reasons[i]] == 1);
	}
	assert(!dest->status.udp_confirmed && !dest->relay_hop.confirmed);
	assert(dest->plpmtu.emsgsize == 1);

	dest->status.udp_confirmed = true;
	dest->relay_hop.confirmed = true;
	dest->plpmtu.size = MINMTU;
	len = sizeof wrapped;
	assert(relay_encode(origin->name, dest->name, inner, sizeof inner, wrapped, &len));
	assert(relay_handle_record(mesh, origin, wrapped, len));
	assert(dest->relay_hop.fallback_reason[RELAY_UDP_OVERSIZE] == 1 && dest->relay_hop.meta_fallbacks == 6);

	/* Exact wrapped boundary is sent once; success never follows with META. */
	len = sizeof wrapped;
	size_t prefix = 2 + strlen(origin->name) + strlen(dest->name);
	assert(relay_encode(origin->name, dest->name, inner, MINMTU - prefix, wrapped, &len));
	assert(len == MINMTU);
	assert(relay_handle_record(mesh, origin, wrapped, len));
	assert(dest->relay_hop.udp_sent == 1 && dest->relay_hop.meta_fallbacks == 6);

	/* A marked META record can exceed the wrapper capacity and still fall back. */
	uint8_t large[MAXSIZE] = {0};
	char encoded[MAXSIZE * 4 / 3 + 5], request[MAXSIZE * 4 / 3 + 128];
	b64encode(large, encoded, sizeof large);
	snprintf(request, sizeof request, "%d %s %s %d %s", REQ_KEY, origin->name, dest->name, REQ_SPTPS_APP, encoded);
	c.node = origin;
	assert(relay_handle_meta_app(mesh, &c, origin, dest, request));
	assert(dest->relay_hop.meta_fallbacks == 7 && dest->relay_hop.udp_sent == 1);
	assert(envelope_request == REQ_SPTPS_APP);

	/* NMN-first rollout must not raise a legacy origin past its smaller leg 1. */
	origin->connection = &c;
	dest->plpmtu.size = MTU;
	c.protocol_minor = PROT_MINOR_SPTPS_APP - 1;
	relay_maybe_report(mesh, origin->name, dest, false);
	uint32_t overhead;
	assert(relay_prefix21(origin->name, dest->name, &overhead));
	assert(reported_budget == MINMTU - overhead);
	c.protocol_minor = PROT_MINOR_SPTPS_APP;
	relay_maybe_report(mesh, origin->name, dest, false);
	assert(reported_budget == MTU - overhead);

	/* A hard error on a replacement probe leaves the working output intact;
	   the same error on its proved endpoint revokes it immediately. */
	vpn_packet_t probe = {0};
	probe.probe = true;
	probe.len = PROBE_FIXED_LEN;
	probe.data[0] = PROBE_KIND_ECHO_REQUEST;
	probe.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_LIVENESS;
	dest->probe_dest_override = endpoint(32001);
	dest->probe_dest_override_active = true;
	injected_send_errno = EHOSTUNREACH;
	assert(!sptps_send_record(&dest->sptps, PKT_PROBE, probe.data, probe.len));
	assert(!injected_send_errno && relay_hop_udp_ready(dest));
	dest->probe_dest_override = dest->address;
	injected_send_errno = EHOSTUNREACH;
	assert(!sptps_send_record(&dest->sptps, PKT_PROBE, probe.data, probe.len));
	dest->probe_dest_override_active = false;
	assert(!injected_send_errno && !dest->status.udp_confirmed && !dest->relay_hop.confirmed);

	/* Reply-only temporary confirmation cannot restore readiness following
	   a hard error sending to the already proved endpoint. */
	dest->status.udp_confirmed = dest->relay_hop.confirmed = true;
	dest->last_udp_from = dest->address;
	injected_send_errno = EHOSTUNREACH;
	probe_record_h(mesh, dest, &probe, probe.len);
	assert(!injected_send_errno && !dest->status.temp_udp_confirmed);
	assert(!dest->status.udp_confirmed && !dest->relay_hop.confirmed);
	assert(dest->relay_hop.meta_fallbacks == 7); /* probes never use application META */
	origin->connection = NULL;
	dest->connection = NULL;
	node_del(mesh, origin);
	node_del(mesh, dest);
	mesh->log_cb = saved_cb;
	mesh->log_level = saved_level;
}
