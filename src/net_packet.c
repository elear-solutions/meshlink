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
#include "path_policy.h"
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

/* mtuprobes == 1..30: initial discovery, send bursts with 1 second interval
   mtuprobes ==    31: sleep pinginterval seconds
   mtuprobes ==    32: send 1 burst, sleep pingtimeout second
   mtuprobes ==    33: no response from other side, restart PMTU discovery process

   Probes are sent in batches of at least three, with random sizes between the
   lower and upper boundaries for the MTU thus far discovered.

   After the initial discovery, a fourth packet is added to each batch with a
   size larger than the currently known PMTU, to test if the PMTU has increased.

   In case local discovery is enabled, another packet is added to each batch,
   which will be broadcast to the local network.

*/

static void send_mtu_probe_handler(event_loop_t *loop, void *data) {
	meshlink_handle_t *mesh = loop->data;
	node_t *n = data;
	int timeout = 1;

	n->mtuprobes++;

	if(!n->status.reachable || !n->status.validkey) {
		logger(mesh, MESHLINK_INFO, "Trying to send MTU probe to unreachable or rekeying node %s", n->name);
		n->mtuprobes = 0;
		return;
	}

	if(n->mtuprobes > 32) {
		if(!n->minmtu) {
			n->mtuprobes = 31;
			timeout = mesh->dev_class_traits[n->devclass].pinginterval;
			goto end;
		}

		logger(mesh, MESHLINK_INFO, "%s did not respond to UDP ping, restarting PMTU discovery", n->name);
		n->status.udp_confirmed = false;
		n->udp_tier = PATH_TIER_NONE;
		n->mtuprobes = 1;
		n->minmtu = 0;
		n->maxmtu = MTU;

		update_node_pmtu(mesh, n);
		relay_recompute_dependents(mesh, n);
		relay_update_destination_transport(mesh, n);
	}

	if(n->mtuprobes >= 10 && n->mtuprobes < 32 && !n->minmtu) {
		logger(mesh, MESHLINK_INFO, "No response to MTU probes from %s", n->name);
		n->mtuprobes = 31;
	}

	if(n->status.udp_confirmed && (n->mtuprobes == 30 || (n->mtuprobes < 30 && n->minmtu >= n->maxmtu))) {
		if(n->minmtu > n->maxmtu) {
			n->minmtu = n->maxmtu;
			update_node_pmtu(mesh, n);
		} else {
			n->maxmtu = n->minmtu;
		}

		n->mtu = n->minmtu;
		logger(mesh, MESHLINK_INFO, "Fixing MTU of %s to %d after %d probes", n->name, n->mtu, n->mtuprobes);
		n->mtuprobes = 31;
	}

	if(n->mtuprobes == 31) {
		if(!n->minmtu && n->status.want_udp && n->nexthop && n->nexthop->connection) {
			/* Send a dummy ANS_KEY to try to update the reflexive UDP address */
			send_request(mesh, n->nexthop->connection, NULL, "%d %s %s . -1 -1 -1 0", ANS_KEY, mesh->self->name, n->name);
			n->status.want_udp = false;
		}

		timeout = mesh->dev_class_traits[n->devclass].pinginterval;
		goto end;
	} else if(n->mtuprobes == 32) {
		timeout = mesh->dev_class_traits[n->devclass].pingtimeout;
	}

	for(int i = 0; i < 5; i++) {
		int len;

		if(i == 0) {
			if(n->mtuprobes < 30 || n->maxmtu + 8 >= MTU) {
				continue;
			}

			len = n->maxmtu + 8;
		} else if(n->maxmtu <= n->minmtu) {
			len = n->maxmtu;
		} else {
			len = n->minmtu + 1 + prng(mesh, n->maxmtu - n->minmtu);
		}

		if(len < 64) {
			len = 64;
		}

		vpn_packet_t packet;
		packet.probe = true;
		memset(packet.data, 0, 14);
		randomize(packet.data + 14, len - 14);
		packet.len = len;
		n->status.broadcast = i >= 4 && n->mtuprobes <= 10 && n->prevedge;
		n->out_meta += packet.len + PROBE_OVERHEAD;
		send_udppacket(mesh, n, &packet);
	}

	n->status.broadcast = false;

end:
	timeout_set(&mesh->loop, &n->mtutimeout, &(struct timespec) {
		timeout, prng(mesh, TIMER_FUDGE)
	});
}

void send_mtu_probe(meshlink_handle_t *mesh, node_t *n) {
	timeout_add(&mesh->loop, &n->mtutimeout, send_mtu_probe_handler, n, &(struct timespec) {
		1, 0
	});
	send_mtu_probe_handler(&mesh->loop, n);
}

static void mtu_probe_h(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet, uint16_t len) {
	n->in_meta += len + PROBE_OVERHEAD;

	if(len < 64) {
		logger(mesh, MESHLINK_WARNING, "Got too short MTU probe length %d from %s", packet->len, n->name);
		return;
	}

	logger(mesh, MESHLINK_DEBUG, "Got MTU probe length %d from %s", packet->len, n->name);

	if(!packet->data[0]) {
		/* It's a probe request, send back a reply */

		packet->data[0] = 1;

		/* Temporarily set udp_confirmed, so that the reply is sent
		   back exactly the way it came in. */

		bool udp_confirmed = n->status.udp_confirmed;
		n->status.temp_udp_confirmed = true;
		n->status.udp_confirmed = true;
		logger(mesh, MESHLINK_DEBUG, "Sending MTU probe reply %d to %s", packet->len, n->name);
		n->out_meta += packet->len + PROBE_OVERHEAD;
		send_udppacket(mesh, n, packet);

		if(n->status.udp_confirmed) {
			n->status.udp_confirmed = udp_confirmed;
		}

		n->status.temp_udp_confirmed = false;
	} else {
		/* It's a valid reply: now we know bidirectional communication
		   is possible using the address and socket that the reply
		   packet used. */

		if(!n->status.udp_confirmed) {
			char *address, *port;
			sockaddr2str(&n->address, &address, &port);

			if(n->nexthop && n->nexthop->connection) {
				send_request(mesh, n->nexthop->connection, NULL, "%d %s %s . -1 -1 -1 0 %s %s", ANS_KEY, n->name, n->name, address, port);
			} else {
				logger(mesh, MESHLINK_WARNING, "Cannot send reflexive address to %s via %s", n->name, n->nexthop ? n->nexthop->name : n->name);
			}

			free(address);
			free(port);
			n->status.udp_confirmed = true;

			/* The confirmed UDP address is a direct path to the node (UDP and TCP share
			   a port): remember it and see if it can replace a canonical meta connection. */

			if(n->address.sa.sa_family != AF_UNSPEC && node_add_recent_address(mesh, n, &n->address, ADDR_SRC_AUTH_DIRECT)) {
				n->upgrade_recent_idx = 0;
			}

			path_note_udp_confirmed(mesh, n);
			try_upgrade_probe(mesh, n);
			relay_update_destination_transport(mesh, n);
			relay_recompute_dependents(mesh, n);
		} else if(path_promote_udp_if_better(mesh, n, &n->last_udp_from)) {
			relay_update_destination_transport(mesh, n);
			relay_recompute_dependents(mesh, n);
		}

		/* If we haven't established the PMTU yet, restart the discovery process. */

		if(n->mtuprobes > 30) {
			if(len == n->maxmtu + 8) {
				logger(mesh, MESHLINK_INFO, "Increase in PMTU to %s detected, restarting PMTU discovery", n->name);
				n->maxmtu = MTU;
				n->mtuprobes = 10;
				return;
			}

			if(n->minmtu) {
				n->mtuprobes = 30;
			} else {
				n->mtuprobes = 1;
			}
		}

		/* If applicable, raise the minimum supported MTU */

		if(len > n->maxmtu) {
			len = n->maxmtu;
		}

		if(n->minmtu < len) {
			n->minmtu = len;
			update_node_pmtu(mesh, n);
		}
	}
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
			send_req_key(mesh, n);
		} else {
			logger(mesh, MESHLINK_DEBUG, "Got packet from %s but he hasn't got our key yet", n->name);
		}

		return;
	}

	if(!sptps_receive_data(&n->sptps, inpkt->data, inpkt->len)) {
		logger(mesh, MESHLINK_ERROR, "Could not process SPTPS data from %s: %s", n->name, strerror(errno));
	}
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
			send_req_key(mesh, n);
		} else if(n->last_req_key + 10 < mesh->loop.now.tv_sec) {
			logger(mesh, MESHLINK_DEBUG, "No key from %s after 10 seconds, restarting SPTPS", n->name);
			sptps_stop(&n->sptps);
			n->status.waitingforkey = false;
			send_req_key(mesh, n);
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

static bool try_canonical(meshlink_handle_t *mesh, node_t *n, const sockaddr_t **sa, int *sock, sockaddr_t *sa_buf) {
	char *host = NULL;
	const char *port = NULL;

	if(!parse_host_port_field(n->canonical_address, NULL, &host, &port)) {
		return false;
	}

	if(!host_port_to_sockaddr(host, port, sa_buf) || !udp_address_bound(sa_buf)) {
		free(host);
		return false;
	}

	logger(mesh, MESHLINK_DEBUG, "UDP dest for %s: canonical %s %s", n->name, host, port);
	free(host);

	if(!select_listen_socket(mesh, sa_buf, sock)) {
		return false;
	}

	*sa = sa_buf;
	return true;
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

	/* Unconfirmed. */
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
	} else if(lan_slot == UDP_LAN_SLOT_CATTA && lan_candidate(&n->catta_address, self_ext, skip)) {
		*sa = &n->catta_address;
	}

	if(!*sa) {
		/* UDP_LAN_SLOT_EDGE, or the slot's own source was empty: a random edge
		   address, then what the graph or a peer told us, then anything recent
		   (unless that was the slot that just came up empty), then canonical. */
		edge_t *candidate = NULL;
		int usable = 0;

		for splay_each(edge_t, e, n->edge_tree) {
			if(e->reverse && lan_candidate(&e->reverse->address, self_ext, skip)) {
				if(prng(mesh, ++usable) == 0) {
					candidate = e->reverse;
				}
			}
		}

		if(candidate) {
			*sa = &candidate->address;
		} else if(lan_candidate(&n->address, self_ext, skip)) {
			*sa = &n->address;
		} else if(lan_slot != UDP_LAN_SLOT_RECENT && try_recent(mesh, n, sa, sock, self_ext, skip)) {
			return;
		} else if(try_canonical(mesh, n, sa, sock, sa_buf)) {
			return;
		}
	}

	if(!*sa && rotate_wan && try_ext(mesh, n, sa, sock, sa_buf, &ext, "no LAN candidate")) {
		return;
	}

	finish_udp_dest(mesh, sa, sock);
}

static void choose_broadcast_address(meshlink_handle_t *mesh, const node_t *n, const sockaddr_t **sa, int *sock) {
	*sock = prng(mesh, mesh->listen_sockets);
	sockaddr_t *broadcast_sa = &mesh->listen_socket[*sock].broadcast_sa;

	if(broadcast_sa->sa.sa_family == AF_INET6) {
		broadcast_sa->in6.sin6_port = n->prevedge->address.in.sin_port;
	} else {
		broadcast_sa->in.sin_port = n->prevedge->address.in.sin_port;
	}

	*sa = broadcast_sa;
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

static bool send_sptps_via_meta(meshlink_handle_t *mesh, node_t *to, const void *data, size_t len) {
	connection_t *c = meta_connection_for(to);

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

static bool send_sptps_via_udp(meshlink_handle_t *mesh, node_t *to, const void *data, size_t len) {
	sockaddr_t sa_buf;
	const sockaddr_t *sa = NULL;
	int sock = -1;

	if(to->status.broadcast) {
		choose_broadcast_address(mesh, to, &sa, &sock);
	} else {
		choose_udp_address(mesh, to, &sa, &sock, &sa_buf);
	}

	if(!sa || sock < 0 || sock >= mesh->listen_sockets) {
		return true;
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
		logger(mesh, MESHLINK_WARNING, "Error sending UDP SPTPS packet to %s: %s", to->name, "injected hard send error");
		relay_on_hard_send_error(mesh, to, sa, sock);
		return false;
	}

	if(sendto(mesh->listen_socket[sock].udp.fd, data, len, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			if(to->maxmtu >= len) {
				to->maxmtu = len - 1;
			}

			if(to->mtu >= len) {
				to->mtu = len - 1;
			}
		} else {
			logger(mesh, MESHLINK_WARNING, "Error sending UDP SPTPS packet to %s: %s", to->name, sockstrerror(sockerrno));
			relay_on_hard_send_error(mesh, to, sa, sock);
			return false;
		}
	}

	return true;
}

static bool send_relay_outer(meshlink_handle_t *mesh, node_t *hop, const void *data, size_t len) {
	size_t payload = len - RELAY_INNER_MIN;
	uint16_t limit = hop->minmtu > MINMTU ? hop->minmtu : MINMTU;

	/* Ready oversize is a handled drop (no META fallback). */
	if(payload > limit) {
		return true;
	}

	if(!send_sptps_via_udp(mesh, hop, data, len)) {
		return false;
	}

	/* Hop scratch is set around sptps_send_record by relay_send_outer_record, then cleared. */
	const char *dest_name = hop->relay_send_dest;
	const char *origin_name = hop->relay_send_origin;

	/* Dest falls back to hop (first hop / dest==hop). Origin is unknown if not stashed. */
	logger(mesh, MESHLINK_DEBUG, "Relaying type-8 via UDP to %s for %s from %s",
	       hop->name,
	       dest_name && dest_name[0] ? dest_name : hop->name,
	       origin_name && origin_name[0] ? origin_name : "?");
	relay_wake_probes(mesh, hop);
	return true;
}

static bool send_application_record(meshlink_handle_t *mesh, node_t *to, const void *data, size_t len) {
	path_tier_t tier = path_select_destination_tier(to, false);

	if(to->last_path_tier != tier) {
		path_log_transition(mesh, to, to->last_path_tier, tier, "destination route");
		to->last_path_tier = tier;
	}

	/* Confirmed UDP does not compare (len-21) against minmtu. */
	if(to->status.udp_confirmed) {
		if(!send_sptps_via_udp(mesh, to, data, len)) {
			return false;
		}

		relay_wake_probes(mesh, to);
		return true;
	}

	if(relay_names_unusable(mesh->self->name, to->name)) {
		return send_sptps_via_meta(mesh, to, data, len);
	}

	if(to->nexthop && relay_hop_udp_ready(to->nexthop)) {
		uint8_t wrapped[MAXSIZE];
		size_t wlen = sizeof(wrapped);

		if(relay_encode(mesh->self->name, to->name, data, len, wrapped, &wlen)) {
			return relay_send_outer_record(mesh, to->nexthop, mesh->self->name, to->name, wrapped, wlen);
		}
	}

	return send_sptps_via_meta(mesh, to, data, len);
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
		sockaddr_t local;

		if(path_udp_should_probe_local(mesh, to) && path_pick_local_udp_candidate(mesh, to, &local)) {
			int sock = to->sock;

			if(select_listen_socket(mesh, &local, &sock)) {
				hash_insert(mesh->node_udp_cache, &local, to);
				to->udp_local_probe_next = mesh->loop.now.tv_sec + UDP_LOCAL_PROBE_SEC;

				if(mesh->log_level <= MESHLINK_INFO) {
					char *hostname = sockaddr2hostname(&local);
					logger(mesh, MESHLINK_INFO, "Path policy: validating local UDP candidate %s for %s", hostname, to->name);
					free(hostname);
				}

				if(sendto(mesh->listen_socket[sock].udp.fd, data, len, 0, &local.sa, SALEN(local.sa)) < 0 && !sockwouldblock(sockerrno) && !sockmsgsize(sockerrno)) {
					logger(mesh, MESHLINK_WARNING, "Error sending local UDP probe to %s: %s", to->name, sockstrerror(sockerrno));
				}

				return true;
			}
		}

		return send_sptps_via_udp(mesh, to, data, len);
	}

	if(type == PKT_RELAY_SPTPS) {
		return send_relay_outer(mesh, to, data, len);
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
			from->status.waitingforkey = false;

			if(from->utcp) {
				utcp_reset_timers(from->utcp);
			}
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
		mtu_probe_h(mesh, from, &inpkt, len);
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
		if(n->status.udp_confirmed && sockaddrcmp(&from, &n->address)) {
			hash_insert(mesh->node_udp_cache, &from, n);
		} else {
			update_node_udp_from(mesh, n, &from, ADDR_SRC_AUTH_DIRECT);
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
	n->last_udp_from = from;

	receive_udppacket(mesh, n, &pkt);
}
