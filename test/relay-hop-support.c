/* Separately linked internal tests: no production compile switches. */
#include "system.h"
#include "meshlink_internal.h"
#include "connection_policy.h"
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
