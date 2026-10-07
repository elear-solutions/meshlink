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
	sptps_stop(&n.sptps);
	mesh->loop.now = saved_now;
}

static unsigned envelope_request, received_records;
static uint8_t encrypted_record[MAXSIZE];
static size_t encrypted_len;

static void envelope_log(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;
	(void)level;
	const char *wire = strstr(text, "Sending REQ_KEY to next: ");
	if(wire) {
		assert(sscanf(wire, "Sending REQ_KEY to next: %*u %*s %*s %u", &envelope_request) == 1);
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
