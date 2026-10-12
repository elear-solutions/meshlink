/*
    net_packet.c -- Handles in- and outgoing VPN packets
    Copyright (C) 2014-2017 Guus Sliepen <guus@meshlink.io>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include "conf.h"
#include "connection.h"
#include "crypto.h"
#include "graph.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "net_upgrade.h"
#include "netutl.h"
#include "node.h"
#include "path_liveness.h"
#include "path_plpmtu.h"
#include "path_policy.h"
#include "path_probe.h"
#include "path_scheduler.h"
#include "protocol.h"
#include "relay.h"
#include "relay_devtool.h"
#include "route.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

int keylifetime = 0;

static void send_udppacket(meshlink_handle_t *mesh, node_t *, vpn_packet_t *);

#define MAX_SEQNO 1073741824
#define PROBE_OVERHEAD (SPTPS_DATAGRAM_OVERHEAD + 40)

void path_probe_write_endpoint(uint8_t *data, const sockaddr_t *endpoint) {
	uint8_t *out = data + PROBE_ENDPOINT_OFFSET;

	memset(out, 0, PROBE_ENDPOINT_LEN);

	if(endpoint->sa.sa_family == AF_INET) {
		out[1] = PROBE_ADDR_FAMILY_IPV4;
		memcpy(out + 2, &endpoint->in.sin_port, 2);
		memcpy(out + 4, &endpoint->in.sin_addr, 4);
	} else if(endpoint->sa.sa_family == AF_INET6) {
		out[1] = PROBE_ADDR_FAMILY_IPV6;
		memcpy(out + 2, &endpoint->in6.sin6_port, 2);
		memcpy(out + 4, &endpoint->in6.sin6_addr, 16);
	} else {
		return;
	}

	out[0] = PROBE_ENDPOINT_MARKER;
}

bool path_probe_read_endpoint(const uint8_t *data, sockaddr_t *endpoint) {
	const uint8_t *in = data + PROBE_ENDPOINT_OFFSET;

	memset(endpoint, 0, sizeof *endpoint);

	if(in[0] != PROBE_ENDPOINT_MARKER || (!in[2] && !in[3])) {
		return false;
	}

	if(in[1] == PROBE_ADDR_FAMILY_IPV4) {
		endpoint->in.sin_family = AF_INET;
		memcpy(&endpoint->in.sin_port, in + 2, 2);
		memcpy(&endpoint->in.sin_addr, in + 4, 4);
	} else if(in[1] == PROBE_ADDR_FAMILY_IPV6) {
		endpoint->in6.sin6_family = AF_INET6;
		memcpy(&endpoint->in6.sin6_port, in + 2, 2);
		memcpy(&endpoint->in6.sin6_addr, in + 4, 16);
	} else {
		return false;
	}

	return true;
}

void net_probe_sched_send(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	node_t *n;
	vpn_packet_t packet;
	bool saved_broadcast;
	uint16_t saved_len;
	int len;
	const sockaddr_t *dest = NULL;

	if(!mesh || !req || !req->node) {
		return;
	}

	n = req->node;
	len = req->length < PROBE_FIXED_LEN ? PROBE_FIXED_LEN : req->length;

	if(n->devtool_force_meta && req->probe_kind != PROBE_KIND_ECHO_REQUEST) {
		return;
	}

	if(n->devtool_force_meta && req->probe_purpose != PROBE_PURPOSE_PUNCH
	                && req->probe_purpose != PROBE_PURPOSE_REBIND
	                && req->probe_purpose != PROBE_PURPOSE_PROMOTION
	                && req->probe_purpose != PROBE_PURPOSE_SUSPECT
	                && req->probe_purpose != PROBE_PURPOSE_BACKBONE
	                && req->probe_purpose != PROBE_PURPOSE_RELAY_HOP) {
		return;
	}

	saved_broadcast = n->status.broadcast;
	saved_len = n->mtu_probe_request_len;
	n->status.broadcast = req->broadcast;
	n->mtu_probe_request_len = (uint16_t)len;

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = req->probe_kind;
	packet.data[PROBE_PURPOSE_OFFSET] = req->probe_purpose;
	memcpy(packet.data + PROBE_NONCE_OFFSET, &req->probe_nonce, sizeof req->probe_nonce);
	if((size_t)len > PROBE_PAD_OFFSET) {
		randomize(packet.data + PROBE_PAD_OFFSET, (size_t)len - PROBE_PAD_OFFSET);
	}
	packet.len = (uint16_t)len;
	n->out_meta += packet.len + PROBE_OVERHEAD;

	if(req->probe_kind == PROBE_KIND_SIZE_ACK || req->probe_kind == PROBE_KIND_ECHO_REPLY) {
		dest = &n->last_udp_from;
	} else if(!req->broadcast && req->dest.sa.sa_family) {
		dest = &req->dest;
	}

	if(dest && dest->sa.sa_family) {
		path_copy_sockaddr(&n->probe_dest_override, dest);
		n->probe_dest_override_active = true;
		n->probe_dest_speculative = dest == &req->dest;
	}

	if(req->broadcast) {
		path_copy_sockaddr(&n->broadcast_dest, &req->dest);
	}

	send_udppacket(mesh, n, &packet);
	n->probe_dest_override_active = false;
	n->probe_dest_speculative = false;
	memset(&n->broadcast_dest, 0, sizeof n->broadcast_dest);
	n->status.broadcast = saved_broadcast;
	n->mtu_probe_request_len = saved_len;
}

static void send_probe_to(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet, const sockaddr_t *destination) {
	if(!destination || destination->sa.sa_family == AF_UNSPEC) {
		send_udppacket(mesh, n, packet);
		return;
	}

	path_copy_sockaddr(&n->probe_dest_override, destination);
	n->probe_dest_override_active = true;
	send_udppacket(mesh, n, packet);
	n->probe_dest_override_active = false;
}

void send_candidate_probe(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || !n->promotion_candidate.active || !n->promotion_candidate.nonce) {
		return;
	}

	if(!n->status.reachable || !n->status.validkey) {
		return;
	}

	vpn_packet_t packet;
	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = PROBE_KIND_ECHO_REQUEST;
	packet.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_PROMOTION;
	memcpy(packet.data + PROBE_NONCE_OFFSET, &n->promotion_candidate.nonce, sizeof n->promotion_candidate.nonce);
	randomize(packet.data + 14, PATH_PROMOTION_PROBE_LEN - 14);
	packet.len = PATH_PROMOTION_PROBE_LEN;
	n->out_meta += packet.len + PROBE_OVERHEAD;
	send_probe_to(mesh, n, &packet, &n->promotion_candidate.endpoint);
}

bool send_punch_probe(meshlink_handle_t *mesh, node_t *n) {
	vpn_packet_t packet;
	char *host = NULL;
	char *port = NULL;

	if(!mesh || !n || !n->status.reachable || !n->status.validkey || n->devtool_force_meta) {
		return false;
	}

	if(!n->peer_udp.challenge.active || !n->peer_udp.challenge.nonce) {
		return false;
	}

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = PROBE_KIND_ECHO_REQUEST;
	packet.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_PUNCH;
	memcpy(packet.data + PROBE_NONCE_OFFSET, &n->peer_udp.challenge.nonce, sizeof n->peer_udp.challenge.nonce);
	packet.len = PATH_PROMOTION_PROBE_LEN;
	n->out_meta += packet.len + PROBE_OVERHEAD;

	if(mesh->log_level <= MESHLINK_INFO) {
		sockaddr_t logged;

		path_copy_sockaddr(&logged, &n->peer_udp.challenge.endpoint);
		sockaddr2str(&logged, &host, &port);
		logger(mesh, MESHLINK_INFO, "Sending punch probe to %s at %s port %s source=%s",
		       n->name, host ? host : "?", port ? port : "?",
		       n->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS ? "peer-reflexive" : "rendezvous");
		free(host);
		free(port);
	}

	send_probe_to(mesh, n, &packet, &n->peer_udp.challenge.endpoint);
	return true;
}

bool send_rebind_probe(meshlink_handle_t *mesh, node_t *n) {
	vpn_packet_t packet;
	char *host = NULL;
	char *port = NULL;

	if(!mesh || !n || !n->status.reachable || !n->status.validkey || n->devtool_force_meta) {
		return false;
	}

	if(!n->udp_rebind.challenge_active || !n->udp_rebind.challenge_nonce) {
		return false;
	}

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = PROBE_KIND_ECHO_REQUEST;
	packet.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_REBIND;
	memcpy(packet.data + PROBE_NONCE_OFFSET, &n->udp_rebind.challenge_nonce, sizeof n->udp_rebind.challenge_nonce);
	randomize(packet.data + 14, PATH_PROMOTION_PROBE_LEN - 14);
	path_probe_write_endpoint(packet.data, &n->udp_rebind.challenge_endpoint);
	packet.len = PATH_PROMOTION_PROBE_LEN;
	n->out_meta += packet.len + PROBE_OVERHEAD;

	if(mesh->log_level <= MESHLINK_INFO) {
		sockaddr_t logged;

		path_copy_sockaddr(&logged, &n->udp_rebind.challenge_endpoint);
		sockaddr2str(&logged, &host, &port);
		logger(mesh, MESHLINK_INFO, "Sending rebind probe to %s at %s port %s",
		       n->name, host ? host : "?", port ? port : "?");
		free(host);
		free(port);
	}

	send_probe_to(mesh, n, &packet, &n->udp_rebind.challenge_endpoint);
	return true;
}

/* Pre-confirmation only. A live challenge already has a destination. This walks
   the same unconfirmed rotation as choose_udp_address() and does not start PMTU. */
void send_punch_bootstrap(meshlink_handle_t *mesh, node_t *n) {
	sockaddr_t scratch;
	sockaddr_t sa_buf;
	const sockaddr_t *sa = NULL;
	int sock = -1;
	vpn_packet_t packet;

	if(!mesh || !n || !n->status.reachable || !n->status.validkey || n->devtool_force_meta || n->status.udp_confirmed) {
		return;
	}

	if(!path_peer_udp_punching_allowed(mesh, n)) {
		return;
	}

	if(path_unconfirmed_punch_dest(mesh, n, &scratch)) {
		return;
	}

	/* choose_udp_address() walks the edge tree. A node that has not joined
	   the graph yet has nothing to rotate through. */
	if(!n->edge_tree || !mesh->listen_sockets || n->sock < 0 || n->sock >= mesh->listen_sockets) {
		return;
	}

	choose_udp_address(mesh, n, &sa, &sock, &sa_buf);

	if(!sa) {
		return;
	}

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = PROBE_KIND_ECHO_REQUEST;
	packet.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_PUNCH;
	packet.len = PATH_PROMOTION_PROBE_LEN;
	n->out_meta += packet.len + PROBE_OVERHEAD;
	send_probe_to(mesh, n, &packet, sa);
}

void send_suspect_probe(meshlink_handle_t *mesh, node_t *n) {
	suspect_validation_t *s;

	if(!mesh || !n) {
		return;
	}

	s = &n->suspect_validation;

	if(!s->active || !s->nonce) {
		return;
	}

	if(!n->status.reachable || !n->status.validkey) {
		return;
	}

	vpn_packet_t packet;
	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = PROBE_KIND_ECHO_REQUEST;
	packet.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_SUSPECT;
	memcpy(packet.data + PROBE_NONCE_OFFSET, &s->nonce, sizeof s->nonce);
	randomize(packet.data + 14, PATH_PROMOTION_PROBE_LEN - 14);
	packet.len = PATH_PROMOTION_PROBE_LEN;
	n->out_meta += packet.len + PROBE_OVERHEAD;
	send_probe_to(mesh, n, &packet, &s->endpoint);
	s->probes_sent++;
}

void send_backbone_udp_probe_at(meshlink_handle_t *mesh, const sockaddr_t *dest, uint64_t nonce) {
	node_t *n;
	vpn_packet_t packet;

	if(!mesh || !mesh->backbone_udp.node || !nonce || !dest) {
		return;
	}

	n = mesh->backbone_udp.node;

	if(!n->status.reachable || !n->status.validkey) {
		return;
	}

	if(dest->sa.sa_family == AF_UNSPEC || dest->sa.sa_family == AF_UNKNOWN) {
		return;
	}

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = PROBE_KIND_ECHO_REQUEST;
	packet.data[PROBE_PURPOSE_OFFSET] = PROBE_PURPOSE_BACKBONE;
	memcpy(packet.data + PROBE_NONCE_OFFSET, &nonce, sizeof nonce);
	randomize(packet.data + 14, PATH_PROMOTION_PROBE_LEN - 14);
	packet.len = PATH_PROMOTION_PROBE_LEN;
	n->out_meta += packet.len + PROBE_OVERHEAD;
	send_probe_to(mesh, n, &packet, dest);
}

void send_backbone_udp_probe(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->backbone_udp.node || !mesh->backbone_udp.liveness_nonce) {
		return;
	}

	if(!mesh->backbone_udp.node->status.reachable || !mesh->backbone_udp.node->status.validkey) {
		return;
	}

	if(mesh->backbone_udp.endpoint.sa.sa_family == AF_UNSPEC
	                || mesh->backbone_udp.endpoint.sa.sa_family == AF_UNKNOWN) {
		return;
	}

	send_backbone_udp_probe_at(mesh, &mesh->backbone_udp.endpoint, mesh->backbone_udp.liveness_nonce);
}

/* Higher name's next liveness sits past the lower name's next probe. */
#define GREATER_NAME_PARK_SLACK_SEC 1

static void send_probe_reply(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet) {
	bool udp_confirmed = n->status.udp_confirmed;

	n->status.temp_udp_confirmed = true;
	n->status.udp_confirmed = true;
	logger(mesh, MESHLINK_DEBUG, "Sending MTU probe reply %d to %s", packet->len, n->name);
	n->out_meta += packet->len + PROBE_OVERHEAD;
	send_probe_to(mesh, n, packet, &n->last_udp_from);

	if(n->status.udp_confirmed) {
		n->status.udp_confirmed = udp_confirmed;
	}

	n->status.temp_udp_confirmed = false;
	if(udp_confirmed && n->udp_send_result == RELAY_UDP_SENT) {
		/* A reply is outbound NAT activity on an already proved path. It
		   must still feed sender-owned idle learning without proving a new one. */
		path_keepalive_note_tx(mesh, n, &n->last_udp_from);
	} else if(udp_confirmed && n->relay_hop.confirmed && n->udp_send_result == RELAY_UDP_HARD_ERROR) {
		/* Restore temporary reply status before revoking a proved output. */
		relay_on_hard_send_error(mesh, n, &n->last_udp_from, n->sock);
	}
}

static void probe_handle_echo_request(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet, uint16_t len, uint8_t purpose, uint64_t nonce) {
	sockaddr_t observed;

	if(len > PROBE_FIXED_LEN) {
		return;
	}

	if(purpose == PROBE_PURPOSE_LIVENESS) {
		path_liveness_observe_peer_request(mesh, n, &n->last_udp_from);
	}

	if(purpose == PROBE_PURPOSE_REBIND && nonce && path_probe_read_endpoint(packet->data, &observed)) {
		path_keepalive_observe_local_endpoint(mesh, n, &n->last_udp_from, &observed);
	}

	packet->data[0] = PROBE_KIND_ECHO_REPLY;
	path_probe_write_endpoint(packet->data, &n->last_udp_from);
	send_probe_reply(mesh, n, packet);
}

static void probe_handle_size_request(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet, uint16_t len, uint8_t purpose, uint64_t nonce) {
	uint16_t ack_len;

	if(n->devtool_drop_size_probes_above && len > n->devtool_drop_size_probes_above) {
		return;
	}

	ack_len = len;
	memset(packet->data, 0, PROBE_FIXED_LEN);
	packet->data[0] = PROBE_KIND_SIZE_ACK;
	packet->data[PROBE_PURPOSE_OFFSET] = purpose;
	memcpy(packet->data + PROBE_NONCE_OFFSET, &nonce, sizeof nonce);
	packet->data[PROBE_ACKLEN_OFFSET] = (uint8_t)(ack_len >> 8);
	packet->data[PROBE_ACKLEN_OFFSET + 1] = (uint8_t)ack_len;
	path_probe_write_endpoint(packet->data, &n->last_udp_from);
	packet->len = PROBE_FIXED_LEN;
	send_probe_reply(mesh, n, packet);
}

static void probe_handle_echo_reply(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet, uint8_t purpose, uint64_t nonce, const sockaddr_t *from_snap) {
	sockaddr_t observed;

	if(purpose == PROBE_PURPOSE_RELAY_HOP) {
		if(relay_hop_reply(mesh, n, from_snap, nonce) && path_probe_read_endpoint(packet->data, &observed)) {
			path_keepalive_observe_local_endpoint(mesh, n, from_snap, &observed);
		}
		return;
	}

	if(purpose == PROBE_PURPOSE_LIVENESS && n->devtool_drop_liveness_replies) {
		n->devtool_drop_liveness_replies--;
		return;
	}

	if(n == mesh->backbone_udp.node) {
		uint64_t want = mesh->backbone_udp.liveness_nonce;

		if(want && nonce == want && !sockaddrcmp(from_snap, &mesh->backbone_udp.endpoint)) {
			bool have_observed = path_probe_read_endpoint(packet->data, &observed);
			path_backbone_udp_observe_reply(mesh, n, from_snap, nonce, have_observed ? &observed : NULL);
			return;
		}

		if(!mesh->backbone_udp.confirmed) {
			return;
		}
	}

	if(purpose == PROBE_PURPOSE_PLPMTU_RECOVERY) {
		if(nonce && nonce == n->plpmtu.recovery_nonce && !sockaddrcmp(from_snap, &n->address)) {
			path_liveness_observe_reply(mesh, n, from_snap, nonce, PROBE_PURPOSE_NONE);
			if(path_probe_read_endpoint(packet->data, &observed)) {
				path_keepalive_observe_local_endpoint(mesh, n, from_snap, &observed);
			}
		}
		return;
	}

	if(!n->status.udp_confirmed) {
		if(path_local_discovery_accept(mesh, n, from_snap, nonce, purpose)) {
			if(path_probe_read_endpoint(packet->data, &observed)) {
				path_keepalive_observe_local_endpoint(mesh, n, from_snap, &observed);
			}
			return;
		}

		if(path_try_confirm_udp_probe_reply(mesh, n, from_snap, nonce)) {
			if(path_probe_read_endpoint(packet->data, &observed)) {
				path_keepalive_observe_local_endpoint(mesh, n, from_snap, &observed);
			}
		}

		return;
	}

	{
		bool mine = purpose == PROBE_PURPOSE_LIVENESS && nonce && nonce == n->liveness.nonce
		            && !sockaddrcmp(from_snap, &n->address);
		path_observe_probe_reply(mesh, n, from_snap, nonce);
		path_liveness_observe_reply(mesh, n, from_snap, nonce, purpose);
		if(mine && path_probe_read_endpoint(packet->data, &observed)) {
			path_keepalive_observe_local_endpoint(mesh, n, from_snap, &observed);
		}
	}
}

static void probe_handle_size_ack(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet, uint64_t nonce, const sockaddr_t *from_snap) {
	sockaddr_t observed;
	uint16_t got = (uint16_t)((packet->data[PROBE_ACKLEN_OFFSET] << 8) | packet->data[PROBE_ACKLEN_OFFSET + 1]);
	bool valid = nonce && nonce == n->plpmtu.probe_nonce && got == n->plpmtu.probe_size
	             && !sockaddrcmp(from_snap, &n->address);

	path_plpmtu_observe_ack(mesh, n, from_snap, nonce, got);

	if(valid && path_probe_read_endpoint(packet->data, &observed)) {
		path_keepalive_observe_local_endpoint(mesh, n, from_snap, &observed);
	}
}

void probe_record_h(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet, uint16_t len) {
	uint8_t kind;
	uint8_t purpose;
	uint64_t nonce = 0;
	sockaddr_t from_snap;

	n->in_meta += len + PROBE_OVERHEAD;

	if(len < PROBE_FIXED_LEN || !packet) {
		logger(mesh, MESHLINK_WARNING, "Got too short MTU probe length %d from %s", packet ? packet->len : 0, n->name);
		return;
	}

	kind = packet->data[0];
	purpose = packet->data[PROBE_PURPOSE_OFFSET];
	memcpy(&nonce, packet->data + PROBE_NONCE_OFFSET, sizeof nonce);
	logger(mesh, MESHLINK_DEBUG, "Got MTU probe length %d from %s", packet->len, n->name);

	if(kind == PROBE_KIND_ECHO_REQUEST) {
		probe_handle_echo_request(mesh, n, packet, len, purpose, nonce);
		return;
	}

	if(kind == PROBE_KIND_SIZE_REQUEST) {
		probe_handle_size_request(mesh, n, packet, len, purpose, nonce);
		return;
	}

	if(kind == PROBE_KIND_KEEPALIVE) {
		path_keepalive_note_rx(mesh, n);
		return;
	}

	if(kind != PROBE_KIND_ECHO_REPLY && kind != PROBE_KIND_SIZE_ACK) {
		logger(mesh, MESHLINK_DEBUG, "Dropping unknown probe kind %u from %s", kind, n->name);
		return;
	}

	if(n->devtool_force_meta) {
		return;
	}

	path_copy_sockaddr(&from_snap, &n->last_udp_from);

	if(kind == PROBE_KIND_ECHO_REPLY) {
		probe_handle_echo_reply(mesh, n, packet, purpose, nonce, &from_snap);
		return;
	}

	probe_handle_size_ack(mesh, n, packet, nonce, &from_snap);
}

/* VPN packet I/O */

static void receive_packet(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet) {
	logger(mesh, MESHLINK_DEBUG, "Received packet of %d bytes from %s", packet->len, n->name);

	if(n->status.blacklisted) {
		logger(mesh, MESHLINK_WARNING, "Dropping packet from blacklisted node %s", n->name);
	} else {
		route(mesh, n, packet);
	}
}

static bool try_mac(meshlink_handle_t *mesh, node_t *n, const vpn_packet_t *inpkt) {
	(void)mesh;
	return sptps_verify_datagram(&n->sptps, inpkt->data, inpkt->len);
}

static void receive_udppacket(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *inpkt) {
	if(!n->status.reachable) {
		logger(mesh, MESHLINK_ERROR, "Got SPTPS data from unreachable node %s", n->name);
		return;
	}

	if(!n->sptps.state) {
		if(!n->status.waitingforkey) {
			logger(mesh, MESHLINK_DEBUG, "Got packet from %s but we haven't exchanged keys yet", n->name);
			node_kex_ensure(mesh, n);
		} else {
			logger(mesh, MESHLINK_DEBUG, "Got packet from %s but he hasn't got our key yet", n->name);
		}

		return;
	}

	if(!sptps_receive_data(&n->sptps, inpkt->data, inpkt->len)) {
		logger(mesh, MESHLINK_ERROR, "Could not process SPTPS data from %s: %s", n->name, strerror(errno));
		return;
	}

	/* Direct, authenticated UDP only. META-carried and relayed SPTPS do not land here. */
	path_note_authenticated_udp_observation(mesh, n, &n->last_udp_from);
	path_observe_punch_ingress(mesh, n, &n->last_udp_from);
	path_rebind_observe_rx(mesh, n, &n->last_udp_from);
	path_keepalive_note_rx(mesh, n);
}

static void send_sptps_packet(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.reachable) {
		logger(mesh, MESHLINK_ERROR, "Trying to send SPTPS data to unreachable node %s", n->name);
		return;
	}

	if(!n->status.validkey) {
		if(n->connection && (n->connection->flags & PROTOCOL_TINY) & n->connection->status.active) {
			send_raw_packet(mesh, n->connection, origpkt);
			return;
		}

		logger(mesh, MESHLINK_INFO, "No valid key known yet for %s", n->name);

		if(!n->status.waitingforkey) {
			node_kex_ensure(mesh, n);
		} else {
			node_kex_consider(mesh, n);
		}

		return;
	}

	uint8_t type = 0;

	// If it's a probe, send it immediately without trying to compress it.
	if(origpkt->probe) {
		if(!origpkt->data[0]) {
			n->mtu_probe_request_len = origpkt->len;
		}

		sptps_send_record(&n->sptps, PKT_PROBE, origpkt->data, origpkt->len);
		n->mtu_probe_request_len = 0;
		return;
	}

	sptps_send_record(&n->sptps, type, origpkt->data, origpkt->len);
	return;
}

static bool select_listen_socket(meshlink_handle_t *mesh, const sockaddr_t *sa, int *sock) {
	if(*sock >= 0 && *sock < mesh->listen_sockets
	                && mesh->listen_socket[*sock].sa.sa.sa_family == sa->sa.sa_family) {
		return true;
	}

	for(int i = 0; i < mesh->listen_sockets; i++) {
		if(mesh->listen_socket[i].sa.sa.sa_family == sa->sa.sa_family) {
			*sock = i;
			return true;
		}
	}

	return false;
}

/* Numeric host/port only — no getaddrinfo, no AF_UNKNOWN heap. */
bool host_port_to_sockaddr(const char *host, const char *port, sockaddr_t *out) {
	memset(out, 0, sizeof(*out));

	if(!host || !port || !*host || !*port) {
		return false;
	}

	char *end = NULL;
	long p = strtol(port, &end, 10);

	if(!end || *end || p <= 0 || p > 65535) {
		return false;
	}

	if(inet_pton(AF_INET, host, &out->in.sin_addr) == 1) {
		out->in.sin_family = AF_INET;
		out->in.sin_port = htons((uint16_t)p);
		return true;
	}

	if(inet_pton(AF_INET6, host, &out->in6.sin6_addr) == 1) {
		out->in6.sin6_family = AF_INET6;
		out->in6.sin6_port = htons((uint16_t)p);
		return true;
	}

	return false;
}

/* Split "host port" into host and port. With default_port, a bare "host" is
   accepted too and gets that port. *host_out must be freed by the caller;
   *port_out points into *host_out (or at default_port) and dies with it, so
   use the port before freeing the host. */
static bool parse_host_port_field(const char *field, const char *default_port, char **host_out, const char **port_out) {
	if(!field) {
		return false;
	}

	char *copy = xstrdup(field);
	char *port = strchr(copy, ' ');

	if(port && port[1]) {
		*port++ = 0;
		*port_out = port;
	} else if(!port && default_port) {
		*port_out = default_port;
	} else {
		free(copy);
		return false;
	}

	*host_out = copy;
	return true;
}

/* Our own findmyip dest. self->external_ip_address is "IP" (the port is
   myport) when learned, or "IP PORT" when pinned through devtools. */
bool self_external_sockaddr(meshlink_handle_t *mesh, sockaddr_t *out) {
	char *host = NULL;
	const char *port = NULL;

	if(!mesh->self || !parse_host_port_field(mesh->self->external_ip_address, mesh->myport, &host, &port)) {
		return false;
	}

	bool ok = host_port_to_sockaddr(host, port, out);
	free(host);
	return ok;
}

static bool is_self_external(const sockaddr_t *self_ext, const sockaddr_t *sa) {
	return self_ext && !sockaddrcmp(sa, self_ext);
}

/* Peer REQ_EXTERNAL as a public dest. Only our own exact IP:port is refused;
   the same IP on another port is a NAT hairpin candidate, not ourselves. */
static bool req_external_dest(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *self_ext, sockaddr_t *out) {
	char *host = NULL;
	const char *port = NULL;

	if(!parse_host_port_field(n->external_ip_address, NULL, &host, &port)) {
		logger(mesh, MESHLINK_DEBUG, "Couldn't find port, so skipping external IP address...");
		return false;
	}

	bool ok = host_port_to_sockaddr(host, port, out) && udp_address_usable(out);
	free(host);

	if(!ok) {
		logger(mesh, MESHLINK_DEBUG, "Couldn't create usable sockaddr, so skipping external IP address...");
		return false;
	}

	if(is_self_external(self_ext, out)) {
		logger(mesh, MESHLINK_DEBUG, "Skipping external UDP dest for %s: it is our own IP and port", n->name);
		return false;
	}

	return true;
}

static bool finish_udp_dest(meshlink_handle_t *mesh, const sockaddr_t **sa, int *sock) {
	if(!*sa) {
		return false;
	}

	if(!select_listen_socket(mesh, *sa, sock)) {
		*sa = NULL;
		return false;
	}

	return true;
}

/* The peer's REQ_EXTERNAL dest. ext was built from n->external_ip_address,
   so that string is what we log. */
static bool try_ext(meshlink_handle_t *mesh, node_t *n, const sockaddr_t **sa, int *sock, sockaddr_t *sa_buf, const sockaddr_t *ext, const char *why) {
	*sa_buf = *ext;
	*sa = sa_buf;

	if(!finish_udp_dest(mesh, sa, sock)) {
		return false;
	}

	logger(mesh, MESHLINK_DEBUG, "UDP dest for %s: external %s (%s)", n->name, n->external_ip_address, why);
	return true;
}

/* A dest a LAN turn may use: bound, not ourselves, and not the WAN dest the
   WAN turns already probe (skip), wherever that address was learned from. */
static bool lan_candidate(const sockaddr_t *sa, const sockaddr_t *self_ext, const sockaddr_t *skip) {
	if(!udp_address_bound(sa) || is_self_external(self_ext, sa)) {
		return false;
	}

	return !skip || sockaddrcmp(sa, skip);
}

static bool try_recent(meshlink_handle_t *mesh, node_t *n, const sockaddr_t **sa, int *sock, const sockaddr_t *self_ext, const sockaddr_t *skip) {
	for(int i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		const sockaddr_t *candidate = &n->recent[i];

		if(!path_is_udp_candidate(n, candidate, n->recent_source[i], n->recent_cap[i])) {
			continue;
		}

		if(!lan_candidate(candidate, self_ext, skip)) {
			continue;
		}

		*sa = candidate;

		if(finish_udp_dest(mesh, sa, sock)) {
			logger(mesh, MESHLINK_DEBUG, "UDP dest for %s: recent[%d]", n->name, i);
			return true;
		}
	}

	*sa = NULL;
	return false;
}

/* LAN dest sources for an unconfirmed peer, one per rotation turn. */
enum {
	UDP_LAN_SLOT_RECENT,    /* n->recent[] */
	UDP_LAN_SLOT_CATTA,     /* n->catta_address */
	UDP_LAN_SLOT_EDGE,      /* a random edge address, then n->address */
	UDP_LAN_SLOTS
};

void choose_udp_address(meshlink_handle_t *mesh, node_t *n, const sockaddr_t **sa, int *sock, sockaddr_t *sa_buf) {
	*sa = NULL;
	*sock = n->sock;

	if(n->status.udp_confirmed) {
		*sa = &n->address;
		finish_udp_dest(mesh, sa, sock);
		return;
	}

	/* Unconfirmed. A punch hint is the observed NAT port. It wins over
	   REQ_EXTERNAL's listen port, which is a different socket once the
	   public IPs differ. */
	{
		sockaddr_t punch;

		if(path_unconfirmed_punch_dest(mesh, n, &punch)) {
			path_copy_sockaddr(sa_buf, &punch);
			*sa = sa_buf;

			if(finish_udp_dest(mesh, sa, sock)) {
				logger(mesh, MESHLINK_DEBUG, "UDP dest for %s: punch dest", n->name);
				return;
			}
		}
	}

	sockaddr_t self_ext_buf;
	const sockaddr_t *self_ext = self_external_sockaddr(mesh, &self_ext_buf) ? &self_ext_buf : NULL;

	sockaddr_t ext;
	bool have_ext = n->external_ip_address && req_external_dest(mesh, n, self_ext, &ext);

	/* A REQ_EXTERNAL behind a public IP that is provably not ours is the only
	   dest worth probing: any LAN address we remember is stale once the peer
	   sits on another network. Provable needs both addresses in the same
	   family; a v4/v6 mismatch says nothing about the NAT, so it rotates. */
	bool other_nat = have_ext && self_ext && ext.sa.sa_family == self_ext->sa.sa_family && sockaddrcmp_noport(&ext, self_ext);

	if(other_nat && try_ext(mesh, n, sa, sock, sa_buf, &ext, "different public IP")) {
		return;
	}

	/* The peer may share our NAT or our host: same public IP, or we do not know
	   our own (only backbone nodes resolve it). Alternate the WAN hairpin with
	   the LAN candidates so whichever path the router supports gets a chance to
	   confirm: odd turns go WAN, even turns walk one LAN slot. With no WAN dest
	   (none reported, or no listen socket for its family) every turn is a LAN
	   slot. */
	bool rotate_wan = have_ext && !other_nat;
	n->udp_choice = (n->udp_choice + 1) % (rotate_wan ? 2 * UDP_LAN_SLOTS : UDP_LAN_SLOTS);
	bool wan_turn = rotate_wan && (n->udp_choice & 1);
	int lan_slot = rotate_wan ? n->udp_choice / 2 : n->udp_choice;

	if(wan_turn && try_ext(mesh, n, sa, sock, sa_buf, &ext, "hairpin turn")) {
		return;
	}

	/* The WAN dest may also sit in recent[], n->address (seeded from a public
	   graph edge) or an edge address; it must not consume a LAN turn. */
	const sockaddr_t *skip = rotate_wan ? &ext : NULL;

	if(lan_slot == UDP_LAN_SLOT_RECENT) {
		if(try_recent(mesh, n, sa, sock, self_ext, skip)) {
			return;
		}
	} else if(lan_slot == UDP_LAN_SLOT_CATTA && lan_candidate(&n->catta_address, self_ext, skip)
	                && path_is_udp_candidate(n, &n->catta_address, ADDR_SRC_DISCOVERY, PATH_CAP_BOTH)) {
		*sa = &n->catta_address;
	}

	if(!*sa) {
		/* UDP_LAN_SLOT_EDGE, or the slot's own source was empty: a random edge
		   address, then what the graph or a peer told us, then anything recent
		   (unless that was the slot that just came up empty), then canonical. */
		edge_t *candidate = NULL;
		int usable = 0;

		for splay_each(edge_t, e, n->edge_tree) {
			if(!e->reverse || (e->reverse->options & OPTION_INDIRECT)) {
				continue;
			}

			if(!path_is_udp_candidate(n, &e->reverse->address, ADDR_SRC_EDGE_DIRECT, PATH_CAP_BOTH)) {
				continue;
			}

			if(lan_candidate(&e->reverse->address, self_ext, skip)) {
				if(prng(mesh, ++usable) == 0) {
					candidate = e->reverse;
				}
			}
		}

		if(candidate) {
			*sa = &candidate->address;
		} else if(lan_candidate(&n->address, self_ext, skip)
		                && path_is_udp_candidate(n, &n->address, n->address_source, n->address_cap)) {
			*sa = &n->address;
		} else if(lan_slot != UDP_LAN_SLOT_RECENT && try_recent(mesh, n, sa, sock, self_ext, skip)) {
			return;
		}
	}

	if(!*sa && rotate_wan && try_ext(mesh, n, sa, sock, sa_buf, &ext, "no LAN candidate")) {
		return;
	}

	finish_udp_dest(mesh, sa, sock);
}

/* The caller resolved the interface-scoped target. Never fall back to a
   limited broadcast or a socket of another family. */
static void choose_broadcast_address(meshlink_handle_t *mesh, const node_t *n, const sockaddr_t **sa, int *sock) {
	*sa = NULL;
	*sock = -1;

	if(!n->broadcast_dest.sa.sa_family || !select_listen_socket(mesh, &n->broadcast_dest, sock)) {
		return;
	}

	*sa = &n->broadcast_dest;
}

static void send_udppacket(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.reachable) {
		logger(mesh, MESHLINK_INFO, "Trying to send UDP packet to unreachable node %s", n->name);
		return;
	}

	send_sptps_packet(mesh, n, origpkt);
}

/* Hop META first. Direct dest META if the hop has no TCP — #113 may have
   dropped the hop session after a direct edge came up, and a forced pin
   must not black-hole when that happens. */
static connection_t *meta_connection_for(node_t *to) {
	if(to->nexthop && to->nexthop->connection) {
		return to->nexthop->connection;
	}

	return to->connection;
}

static bool send_sptps_via_meta_conn(meshlink_handle_t *mesh, node_t *to, connection_t *c, const void *data, size_t len) {
	if(!c) {
		logger(mesh, MESHLINK_WARNING, "Unable to forward SPTPS packet to %s via %s", to->name, to->nexthop ? to->nexthop->name : to->name);
		return false;
	}

	if(!to->status.validkey) {
		char buf[len * 4 / 3 + 5];
		b64encode(data, buf, len);
		return send_request(mesh, c, NULL, "%d %s %s %s -1 -1 -1 %d", ANS_KEY, mesh->self->name, to->name, buf, 0);
	}

	return relay_meta_req_sptps(mesh, c, mesh->self->name, to->name, data, len);
}

static bool send_sptps_via_meta(meshlink_handle_t *mesh, node_t *to, const void *data, size_t len) {
	return send_sptps_via_meta_conn(mesh, to, meta_connection_for(to), data, len);
}

static bool send_sptps_via_udp(meshlink_handle_t *mesh, node_t *to, const void *data, size_t len) {
	to->udp_send_result = RELAY_UDP_NO_SOCKET;
	sockaddr_t sa_buf;
	const sockaddr_t *sa = NULL;
	int sock = -1;

	if(to->status.broadcast) {
		choose_broadcast_address(mesh, to, &sa, &sock);
	} else if(to->app_udp_override_active) {
		path_copy_sockaddr(&sa_buf, &to->app_udp_override);
		sa = &sa_buf;
		sock = to->sock;
		finish_udp_dest(mesh, &sa, &sock);
	} else {
		choose_udp_address(mesh, to, &sa, &sock, &sa_buf);
	}

	if(!sa || sock < 0 || sock >= mesh->listen_sockets) {
		return false;
	}

	if(to->mtu_probe_request_len && mesh->log_level <= MESHLINK_DEBUG) {
		char *address, *port;
		sockaddr2str(sa, &address, &port);
		logger(mesh, MESHLINK_DEBUG, "Sending MTU probe length %d to %s at %s port %s", to->mtu_probe_request_len, to->name, address, port);
		free(address);
		free(port);
	}

	if(mesh->relay_devtool && mesh->relay_devtool->inject_hard_send_error) {
		mesh->relay_devtool->inject_hard_send_error = false;
		to->udp_send_result = RELAY_UDP_HARD_ERROR;
		logger(mesh, MESHLINK_WARNING, "Error sending UDP SPTPS packet to %s: %s", to->name, "injected hard send error");
		relay_on_hard_send_error(mesh, to, sa, sock);
		return false;
	}

	ssize_t sent = sendto(mesh->listen_socket[sock].udp.fd, data, len, 0, &sa->sa, SALEN(sa->sa));
	if(sent < 0) {
		if(sockwouldblock(sockerrno)) {
			to->udp_send_result = RELAY_UDP_WOULD_BLOCK;
		} else if(sockmsgsize(sockerrno)) {
			to->udp_send_result = RELAY_UDP_EMSGSIZE;
			uint16_t payload = len > SPTPS_DATAGRAM_OVERHEAD ? (uint16_t)(len - SPTPS_DATAGRAM_OVERHEAD) : 0;
			path_plpmtu_note_emsgsize(mesh, to, payload);
		} else {
			to->udp_send_result = RELAY_UDP_HARD_ERROR;
			logger(mesh, MESHLINK_WARNING, "Error sending UDP SPTPS packet to %s: %s", to->name, sockstrerror(sockerrno));
			relay_on_hard_send_error(mesh, to, sa, sock);
		}
		return false;
	}
	to->udp_send_result = RELAY_UDP_SENT;
	if(!to->status.broadcast) {
		path_keepalive_note_tx(mesh, to, sa);
	}
	return true;
}

static bool send_relay_outer(meshlink_handle_t *mesh, node_t *hop, const void *data, size_t len) {
	size_t payload = len - RELAY_INNER_MIN;
	uint16_t hop_plp = path_plpmtu_size(hop);
	uint16_t limit = hop_plp ? hop_plp : MINMTU;

	/* Returning false leaves the original inner ciphertext available for META. */
	if(payload > limit) {
		if(hop->relay_oversize_drops < UINT32_MAX) {
			hop->relay_oversize_drops++;
		}

		if(mesh->loop.now.tv_sec >= hop->relay_oversize_logged_at + 10) {
			hop->relay_oversize_logged_at = mesh->loop.now.tv_sec;
			logger(mesh, MESHLINK_INFO, "META fallback for %zu-byte relay record via %s: hop limit %u",
			       len, hop->name, (unsigned)limit);
		}

		hop->udp_send_result = RELAY_UDP_OVERSIZE;
		return false;
	}

	if(!send_sptps_via_udp(mesh, hop, data, len)) {
		return false;
	}

	hop->relay_hop.udp_sent++;
	/* Hop scratch is set around sptps_send_record by relay_send_outer_record, then cleared. */
	const char *dest_name = hop->relay_send_dest;
	const char *origin_name = hop->relay_send_origin;

	/* Dest falls back to hop (first hop / dest==hop). Origin is unknown if not stashed. */
	/* Forwarding does not accelerate probing: a parked path-MTU timer stays
	   parked, otherwise a busy relay hop produces a continuous probe burst. */
	logger(mesh, MESHLINK_DEBUG, "Relaying type-8 via UDP to %s for %s from %s",
	       hop->name,
	       dest_name && dest_name[0] ? dest_name : hop->name,
	       origin_name && origin_name[0] ? origin_name : "?");
	return true;
}

static bool send_application_record(meshlink_handle_t *mesh, node_t *to, const void *data, size_t len) {
	path_target_t target;
	bool ok;

	if(!path_send_target_for_record(mesh, to, len, &target)) {
		return false;
	}

	path_record_active_route(mesh, to, &target);

	if(target.kind == DATA_ROUTE_DIRECT_UDP) {
		if(to->active_route.suspect && len > (size_t)SPTPS_DATAGRAM_OVERHEAD + PATH_PLPMTU_BASE) {
			path_plpmtu_note_large_suspect_send(mesh, to, (uint16_t)(len - SPTPS_DATAGRAM_OVERHEAD));
		}

		if(to->devtool_drop_direct_udp_records > 0) {
			to->devtool_drop_direct_udp_records--;
			return true;
		}

		path_copy_sockaddr(&to->app_udp_override, &target.udp_endpoint);
		to->app_udp_override_active = true;
		ok = send_sptps_via_udp(mesh, to, data, len);
		to->app_udp_override_active = false;
		return ok || relay_meta_app(mesh, meta_connection_for(to), mesh->self->name, to->name, data, len);
	}

	if(target.kind == DATA_ROUTE_RELAY && target.relay_carrier == RELAY_CARRIER_UDP && target.first_hop) {
		uint8_t wrapped[MAXSIZE];
		size_t wlen = sizeof(wrapped);

		if(relay_encode(mesh->self->name, to->name, data, len, wrapped, &wlen)) {
			path_copy_sockaddr(&target.first_hop->app_udp_override, &target.udp_endpoint);
			target.first_hop->app_udp_override_active = true;
			ok = relay_send_outer_record(mesh, target.first_hop, mesh->self->name, to->name, wrapped, wlen);
			target.first_hop->app_udp_override_active = false;
			return ok || relay_meta_app(mesh, target.first_hop->connection, mesh->self->name, to->name, data, len);
		}
	}

	if(target.kind == DATA_ROUTE_RELAY && target.first_hop) {
		return relay_meta_app(mesh, target.first_hop->connection, mesh->self->name, to->name, data, len);
	}

	return relay_meta_app(mesh, to->connection, mesh->self->name, to->name, data, len);
}

bool send_sptps_data(void *handle, uint8_t type, const void *data, size_t len) {
	assert(handle);
	assert(data);
	assert(len);

	node_t *to = handle;
	meshlink_handle_t *mesh = to->mesh;

	if(!to->status.reachable) {
		logger(mesh, MESHLINK_ERROR, "Trying to send SPTPS data to unreachable node %s", to->name);
		return false;
	}

	if(type >= SPTPS_HANDSHAKE) {
		return send_sptps_via_meta(mesh, to, data, len);
	}

	if(type == PKT_PROBE) {
		/* Dest override is armed around send_udppacket and cleared by the
		   caller even if SPTPS never reaches us. Do not consume it here. */
		if(to->probe_dest_override_active) {
			sockaddr_t dest = to->probe_dest_override;
			int sock = to->sock;

			to->udp_send_result = RELAY_UDP_NO_SOCKET;
			if(!select_listen_socket(mesh, &dest, &sock)) {
				return false;
			}

			if(!to->probe_dest_speculative) {
				node_udp_cache_alias(mesh, to, &dest);
			}

			ssize_t sent = sendto(mesh->listen_socket[sock].udp.fd, data, len, 0, &dest.sa, SALEN(dest.sa));
			to->udp_send_result = sent >= 0 ? RELAY_UDP_SENT : sockwouldblock(sockerrno) ? RELAY_UDP_WOULD_BLOCK : sockmsgsize(sockerrno) ? RELAY_UDP_EMSGSIZE : RELAY_UDP_HARD_ERROR;
			if(to->udp_send_result == RELAY_UDP_HARD_ERROR) {
				logger(mesh, MESHLINK_WARNING, "Error sending local UDP probe to %s: %s", to->name, sockstrerror(sockerrno));
				if(to->relay_hop.confirmed && !to->status.temp_udp_confirmed) {
					relay_on_hard_send_error(mesh, to, &dest, sock);
				}
			}
			if(sent >= 0) {
				path_keepalive_note_tx(mesh, to, &dest);
			}

			return sent >= 0;
		}

		return send_sptps_via_udp(mesh, to, data, len);
	}

	if(type == PKT_RELAY_SPTPS) {
		return send_relay_outer(mesh, to, data, len);
	}

	if(type != 0) {
		return send_sptps_via_meta(mesh, to, data, len);
	}
	return send_application_record(mesh, to, data, len);
}

bool receive_sptps_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	assert(handle);
	assert(!data || len);

	node_t *from = handle;
	meshlink_handle_t *mesh = from->mesh;

	if(type == SPTPS_HANDSHAKE) {
		if(!from->status.validkey) {
			logger(mesh, MESHLINK_INFO, "SPTPS key exchange with %s successful", from->name);
			node_set_validkey(mesh, from, true);
			node_kex_clear(mesh, from);

			if(from->utcp) {
				utcp_reset_timers(from->utcp);
			}

			path_apply_pending_punch_hint(mesh, from);
			path_punch_arm_ingress(mesh, from);
			path_local_discovery_on_key_ready(mesh, from);
		}

		return true;
	}

	if(len > MAXSIZE) {
		logger(mesh, MESHLINK_ERROR, "Packet from %s larger than maximum supported size (%d > %d)", from->name, len, MAXSIZE);
		return false;
	}

	if(from->status.in_req_sptps && type != 0) {
		return true;
	}

	if(type == PKT_RELAY_SPTPS) {
		return relay_handle_record(mesh, from, data, len);
	}

	vpn_packet_t inpkt;

	if(type == PKT_PROBE) {
		inpkt.len = len;
		inpkt.probe = true;
		memcpy(inpkt.data, data, len);
		probe_record_h(mesh, from, &inpkt, len);
		return true;
	} else {
		inpkt.probe = false;
	}

	if(type & ~(PKT_COMPRESSED)) {
		logger(mesh, MESHLINK_ERROR, "Unexpected SPTPS record type %d len %d from %s", type, len, from->name);
		return from->status.in_req_sptps;
	}

	if(type & PKT_COMPRESSED) {
		if(from->status.in_req_sptps) {
			return true;
		}

		logger(mesh, MESHLINK_ERROR, "Error while decompressing packet from %s", from->name);
		return false;
	}

	memcpy(inpkt.data, data, len); // TODO: get rid of memcpy
	inpkt.len = len;

	if(from->active_route.kind != DATA_ROUTE_DIRECT_UDP
	                || (from->last_udp_from.sa.sa_family
	                    && !sockaddrcmp(&from->last_udp_from, &from->active_route.udp_endpoint))) {
		path_note_authenticated_route_success(mesh, from);
	}

	receive_packet(mesh, from, &inpkt);
	return true;
}

/*
  send a packet to the given vpn ip.
*/
void send_packet(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet) {
	if(n == mesh->self) {
		// TODO: send to application
		return;
	}

	logger(mesh, MESHLINK_DEBUG, "Sending packet of %d bytes to %s", packet->len, n->name);

	if(!n->status.reachable) {
		logger(mesh, MESHLINK_WARNING, "Node %s is not reachable", n->name);
		return;
	}

	n->status.want_udp = true;

	send_sptps_packet(mesh, n, packet);
	return;
}

static node_t *try_harder(meshlink_handle_t *mesh, const sockaddr_t *from, const vpn_packet_t *pkt) {
	node_t *n = NULL;
	bool hard = false;

	for splay_each(edge_t, e, mesh->edges) {
		if(!e->to->status.reachable || e->to == mesh->self) {
			continue;
		}

		if(sockaddrcmp_noport(from, &e->address)) {
			if(mesh->last_hard_try == mesh->loop.now.tv_sec) {
				continue;
			}

			hard = true;
		}

		if(!try_mac(mesh, e->to, pkt)) {
			continue;
		}

		n = e->to;
		break;
	}

	if(hard) {
		mesh->last_hard_try = mesh->loop.now.tv_sec;
	}

	return n;
}

void handle_incoming_vpn_data(event_loop_t *loop, void *data, int flags) {
	(void)flags;
	meshlink_handle_t *mesh = loop->data;
	listen_socket_t *ls = data;
	vpn_packet_t pkt;
	char *hostname;
	sockaddr_t from;
	socklen_t fromlen = sizeof(from);
	node_t *n;
	int len;

	memset(&from, 0, sizeof(from));

	len = recvfrom(ls->udp.fd, pkt.data, MAXSIZE, 0, &from.sa, &fromlen);

	if(len <= 0 || len > MAXSIZE) {
		if(!sockwouldblock(sockerrno)) {
			logger(mesh, MESHLINK_ERROR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		}

		return;
	}

	pkt.len = len;

	sockaddrunmap(&from); /* Some braindead IPv6 implementations do stupid things. */

	n = lookup_node_udp(mesh, &from);

	if(!n) {
		n = try_harder(mesh, &from, &pkt);

		if(n) {
			/* An unconfirmed source is only an alias. n->address changes
			   when a challenge reply proves that exact endpoint. */
			if(n->status.udp_confirmed) {
				if(sockaddrcmp(&from, &n->address)) {
					node_udp_cache_alias(mesh, n, &from);
				}
			} else {
				node_udp_cache_alias(mesh, n, &from);
				path_learn_address_cap(mesh, n, &from, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP);
			}
		} else if(mesh->log_level <= MESHLINK_WARNING) {
			hostname = sockaddr2hostname(&from);
			logger(mesh, MESHLINK_WARNING, "Received UDP packet from unknown source %s", hostname);
			free(hostname);
			return;
		} else {
			return;
		}
	}

	if(n->status.blacklisted) {
		logger(mesh, MESHLINK_WARNING, "Dropping packet from blacklisted node %s", n->name);
		return;
	}

	n->sock = ls - mesh->listen_socket;
	path_copy_sockaddr(&n->last_udp_from, &from);

	receive_udppacket(mesh, n, &pkt);
}
