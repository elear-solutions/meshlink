/*
    protocol_key.c -- handle the meta-protocol, key exchange
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

#include "connection.h"
#include "connection_policy.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "net_upgrade.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "path_scheduler.h"
#include "prf.h"
#include "protocol.h"
#include "relay.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

static const int req_key_timeout = 2;

bool key_changed_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	assert(request);
	assert(*request);

	char name[MAX_STRING_SIZE];
	node_t *n;

	if(sscanf(request, "%*d %*x " MAX_STRING, name) != 1) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s", "KEY_CHANGED", c->name);
		return false;
	}

	if(seen_request(mesh, request)) {
		return true;
	}

	n = lookup_node(mesh, name);

	if(!n) {
		logger(mesh, MESHLINK_ERROR, "Got %s from %s origin %s which does not exist", "KEY_CHANGED", c->name, name);
		return true;
	}

	/* Tell the others */

	forward_request(mesh, c, NULL, request);

	return true;
}

static bool send_initial_sptps_data(void *handle, uint8_t type, const void *data, size_t len) {
	(void)type;

	assert(data);
	assert(len);

	node_t *to = handle;
	meshlink_handle_t *mesh = to->mesh;

	if(!to->nexthop || !to->nexthop->connection) {
		logger(mesh, MESHLINK_WARNING, "Cannot send SPTPS data to %s via %s", to->name, to->nexthop ? to->nexthop->name : to->name);
		return false;
	}

	to->sptps.send_data = send_sptps_data;
	char buf[len * 4 / 3 + 5];
	b64encode(data, buf, len);
	return send_request(mesh, to->nexthop->connection, NULL, "%d %s %s %d %s", REQ_KEY, mesh->self->name, to->name, REQ_KEY, buf);
}

bool send_external_ip_address(meshlink_handle_t *mesh, node_t *to) {
	if(!mesh->self->external_ip_address) {
		logger(mesh, MESHLINK_INFO, "Skipping REQ_EXTERNAL to %s: no external IP learned", to->name);
		return true;
	}

	logger(mesh, MESHLINK_INFO, "Sending REQ_EXTERNAL %s %s to %s",
	       mesh->self->external_ip_address, mesh->myport, to->name);
	return send_request(mesh, to->nexthop->connection, NULL, "%d %s %s %d %s %s", REQ_KEY, mesh->self->name, to->name, REQ_EXTERNAL, mesh->self->external_ip_address, mesh->myport);
}

bool send_canonical_address(meshlink_handle_t *mesh, node_t *to) {
	if(!mesh->self->canonical_address) {
		return true;
	}

	return send_request(mesh, to->nexthop->connection, NULL, "%d %s %s %d %s", REQ_KEY, mesh->self->name, to->name, REQ_CANONICAL, mesh->self->canonical_address);
}

bool send_req_key(meshlink_handle_t *mesh, node_t *to) {
	if(!node_read_public_key(mesh, to)) {
		logger(mesh, MESHLINK_DEBUG, "No ECDSA key known for %s", to->name);

		if(!to->nexthop || !to->nexthop->connection) {
			logger(mesh, MESHLINK_WARNING, "Cannot send REQ_PUBKEY to %s via %s", to->name, to->nexthop ? to->nexthop->name : to->name);
			return true;
		}

		char *pubkey = ecdsa_get_base64_public_key(mesh->private_key);
		send_request(mesh, to->nexthop->connection, NULL, "%d %s %s %d %s", REQ_KEY, mesh->self->name, to->name, REQ_PUBKEY, pubkey);
		free(pubkey);
		return true;
	}

	if(to->sptps.label) {
		logger(mesh, MESHLINK_DEBUG, "send_req_key(%s) called while sptps->label != NULL!", to->name);
	}

	/* Send our canonical address to help with UDP hole punching */
	send_canonical_address(mesh, to);

	/* Send our external IP address to help with UDP hole punching */
	send_external_ip_address(mesh, to);

	char label[sizeof(meshlink_udp_label) + strlen(mesh->self->name) + strlen(to->name) + 2];
	snprintf(label, sizeof(label), "%s %s %s", meshlink_udp_label, mesh->self->name, to->name);
	to->sptps_restart_count++;
	sptps_stop(&to->sptps);
	node_set_validkey(mesh, to, false);
	to->status.waitingforkey = true;
	to->last_req_key = mesh->loop.now.tv_sec;
	return sptps_start(&to->sptps, to, true, true, mesh->private_key, to->ecdsa, label, sizeof(label) - 1, send_initial_sptps_data, receive_sptps_record);
}

bool send_punch_endpoint_request(meshlink_handle_t *mesh, node_t *peer) {
	node_t *backbone;

	if(!mesh || !peer || !mesh->self || !peer->name || !peer->status.reachable) {
		return false;
	}

	if(!path_peer_udp_punching_allowed(mesh, peer)) {
		return false;
	}

	backbone = connection_policy_backbone(mesh);

	if(!backbone || !backbone->name || !backbone->connection || !backbone->connection->status.active) {
		return false;
	}

	if(backbone->connection->protocol_minor < 4) {
		return false;
	}

	logger(mesh, MESHLINK_INFO, "Requesting punch endpoint for %s via %s", peer->name, backbone->name);

	if(!send_request(mesh, backbone->connection, NULL, "%d %s %s %d %s", REQ_KEY, mesh->self->name, backbone->name, REQ_PUNCH_ENDPOINT, peer->name)) {
		return false;
	}

	peer->peer_udp.requests_sent++;
	return true;
}

static bool punch_peer_eligible(const meshlink_handle_t *mesh, const node_t *n) {
	return n
	       && n != mesh->self
	       && connection_policy_lan_device_class(n->devclass)
	       && !connection_policy_is_backbone(mesh, n)
	       && !n->status.blacklisted
	       && !n->status.conflict_backbone;
}

static bool send_address_only_ans_key(meshlink_handle_t *mesh, node_t *observed, node_t *recipient, const sockaddr_t *sa) {
	char *host = NULL;
	char *port = NULL;
	bool ok;

	if(!recipient->status.reachable || !recipient->nexthop || !recipient->nexthop->connection) {
		logger(mesh, MESHLINK_WARNING, "Cannot send punch hint for %s to %s", observed->name, recipient->name);
		return false;
	}

	sockaddr2str(sa, &host, &port);
	logger(mesh, MESHLINK_INFO, "Sending punch hint for %s to %s: %s port %s", observed->name, recipient->name, host, port);
	ok = send_request(mesh, recipient->nexthop->connection, NULL, "%d %s %s . -1 -1 -1 0 %s %s", ANS_KEY, observed->name, recipient->name, host, port);
	free(host);
	free(port);

	if(ok && mesh->self) {
		mesh->self->punch_hints_sent++;
	}

	return ok;
}

static bool req_punch_endpoint_h(meshlink_handle_t *mesh, connection_t *c, const char *request, node_t *from) {
	char target_name[MAX_STRING_SIZE];
	node_t *target;
	sockaddr_t sa;

	if(!mesh->self || !connection_policy_is_backbone(mesh, mesh->self) || mesh->self->status.conflict_backbone) {
		logger(mesh, MESHLINK_WARNING, "Ignoring punch endpoint request from %s: this node is not the backbone", from->name);
		return true;
	}

	if(from->connection != c || !c->status.active) {
		logger(mesh, MESHLINK_WARNING, "Ignoring punch endpoint request from %s: not its live META connection", from->name);
		return true;
	}

	if(c->protocol_minor < 4) {
		logger(mesh, MESHLINK_INFO, "Ignoring punch endpoint request from %s: protocol %d.%d", from->name, c->protocol_major, c->protocol_minor);
		return true;
	}

	if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, target_name) != 1 || !check_id(target_name)) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "REQ_PUNCH_ENDPOINT", from->name, "invalid target");
		return true;
	}

	target = lookup_node(mesh, target_name);

	if(!target) {
		logger(mesh, MESHLINK_WARNING, "Punch endpoint request from %s for unknown node %s", from->name, target_name);
		return true;
	}

	logger(mesh, MESHLINK_INFO, "Punch endpoint request for %s from %s", target->name, from->name);

	if(!punch_peer_eligible(mesh, from) || !punch_peer_eligible(mesh, target) || from == target) {
		logger(mesh, MESHLINK_WARNING, "Rejected punch endpoint request from %s for %s", from->name, target->name);
		return true;
	}

	if(!target->status.reachable) {
		logger(mesh, MESHLINK_INFO, "No punch hint for %s: not reachable", target->name);
		return true;
	}

	if(path_get_fresh_udp_observation(mesh, target, &sa)) {
		logger(mesh, MESHLINK_INFO, "Fresh UDP observation for %s", target->name);
		send_address_only_ans_key(mesh, target, from, &sa);
	} else {
		logger(mesh, MESHLINK_INFO, "No UDP observation for %s", target->name);
	}

	if(path_get_fresh_udp_observation(mesh, from, &sa)) {
		logger(mesh, MESHLINK_INFO, "Fresh UDP observation for %s", from->name);
		send_address_only_ans_key(mesh, from, target, &sa);
	} else {
		logger(mesh, MESHLINK_INFO, "No UDP observation for %s", from->name);
	}

	return true;
}

/* REQ_KEY is overloaded to allow arbitrary requests to be routed between two nodes. */

static bool req_key_ext_h(meshlink_handle_t *mesh, connection_t *c, const char *request, node_t *from, int reqno) {
	if(reqno == REQ_RELAY_MTU) {
		return relay_handle_req_relay_mtu(mesh, c, request, from);
	}

	if(!from->nexthop || !from->nexthop->connection) {
		logger(mesh, MESHLINK_WARNING, "Cannot answer REQ_KEY from %s via %s", from->name, from->nexthop ? from->nexthop->name : from->name);
		return true;
	}

	switch(reqno) {
	case REQ_PUBKEY: {
		char *pubkey = ecdsa_get_base64_public_key(mesh->private_key);

		if(!node_read_public_key(mesh, from)) {
			char hiskey[MAX_STRING_SIZE];

			if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, hiskey) == 1) {
				from->ecdsa = ecdsa_set_base64_public_key(hiskey);

				if(!from->ecdsa) {
					logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "REQ_PUBKEY", from->name, "invalid pubkey");
					return true;
				}

				logger(mesh, MESHLINK_INFO, "Learned ECDSA public key from %s", from->name);
				from->status.dirty = true;
				from->last_connect_try = 0;

				for list_each(outgoing_t, outgoing, mesh->outgoings) {
					if(outgoing->node == from && outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED) {
						connection_policy_reset_backbone_retry(outgoing);
					}
				}

				connection_policy_tick(mesh);

				if(!node_write_config(mesh, from, true)) {
					// ignore
				}
			}
		}

		send_request(mesh, from->nexthop->connection, NULL, "%d %s %s %d %s", REQ_KEY, mesh->self->name, from->name, ANS_PUBKEY, pubkey);
		free(pubkey);
		return true;
	}

	case ANS_PUBKEY: {
		if(node_read_public_key(mesh, from)) {
			logger(mesh, MESHLINK_WARNING, "Got ANS_PUBKEY from %s even though we already have his pubkey", from->name);
			return true;
		}

		char pubkey[MAX_STRING_SIZE];

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, pubkey) != 1 || !(from->ecdsa = ecdsa_set_base64_public_key(pubkey))) {
			logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "ANS_PUBKEY", from->name, "invalid pubkey");
			return true;
		}

		logger(mesh, MESHLINK_INFO, "Learned ECDSA public key from %s", from->name);
		from->status.dirty = true;
		from->last_connect_try = 0;

		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			if(outgoing->node == from && outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED) {
				connection_policy_reset_backbone_retry(outgoing);
			}
		}

		connection_policy_tick(mesh);

		if(!node_write_config(mesh, from, true)) {
			// ignore
		}

		/* If we are trying to form an outgoing connection to this node, retry immediately */
		for list_each(outgoing_t, outgoing, mesh->outgoings) {
			if(outgoing->node == from && outgoing->ev.cb
			                && outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED) {
				outgoing->timeout = 0;
				timeout_set(&mesh->loop, &outgoing->ev, &(struct timespec) {
					0, 0
				});
			}
		}

		/* Also reset any UTCP timers */
		utcp_reset_timers(from->utcp);

		return true;
	}

	case REQ_KEY: {
		if(!node_read_public_key(mesh, from)) {
			logger(mesh, MESHLINK_DEBUG, "No ECDSA key known for %s", from->name);
			send_request(mesh, from->nexthop->connection, NULL, "%d %s %s %d", REQ_KEY, mesh->self->name, from->name, REQ_PUBKEY);
			return true;
		}

		if(from->sptps.label) {
			logger(mesh, MESHLINK_DEBUG, "Got REQ_KEY from %s while we already started a SPTPS session!", from->name);

			if(mesh->loop.now.tv_sec < from->last_req_key + req_key_timeout && strcmp(mesh->self->name, from->name) < 0) {
				logger(mesh, MESHLINK_DEBUG, "Ignoring REQ_KEY from %s.", from->name);
				return true;
			}
		}

		char buf[MAX_STRING_SIZE];
		int len;

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, buf) != 1 || !(len = b64decode(buf, buf, strlen(buf)))) {
			logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "REQ_SPTPS_START", from->name, "invalid SPTPS data");
			return true;
		}

		char label[sizeof(meshlink_udp_label) + strlen(from->name) + strlen(mesh->self->name) + 2];
		snprintf(label, sizeof(label), "%s %s %s", meshlink_udp_label, from->name, mesh->self->name);
		sptps_stop(&from->sptps);
		node_set_validkey(mesh, from, false);
		from->status.waitingforkey = true;
		from->last_req_key = mesh->loop.now.tv_sec;

		/* Send our canonical address to help with UDP hole punching */
		send_canonical_address(mesh, from);

		/* Send our external IP address to help with UDP hole punching */
		send_external_ip_address(mesh, from);

		if(!sptps_start(&from->sptps, from, false, true, mesh->private_key, from->ecdsa, label, sizeof(label) - 1, send_sptps_data, receive_sptps_record)) {
			logger(mesh, MESHLINK_ERROR, "Could not start SPTPS session with %s: %s", from->name, strerror(errno));
			return true;
		}

		if(!sptps_receive_data(&from->sptps, buf, len)) {
			logger(mesh, MESHLINK_ERROR, "Could not process SPTPS data from %s: %s", from->name, strerror(errno));
			return true;
		}

		return true;
	}

	case REQ_SPTPS: {
		if(!from->status.validkey) {
			logger(mesh, MESHLINK_ERROR, "Got REQ_SPTPS from %s but we don't have a valid key yet", from->name);
			return true;
		}

		char buf[MAX_STRING_SIZE];
		int len;

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, buf) != 1 || !(len = b64decode(buf, buf, strlen(buf)))) {
			logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "REQ_SPTPS", from->name, "invalid SPTPS data");
			return true;
		}

		from->status.in_req_sptps = true;

		if(!sptps_receive_data(&from->sptps, buf, len)) {
			logger(mesh, MESHLINK_ERROR, "Could not process SPTPS data from %s: %s", from->name, strerror(errno));
		}

		from->status.in_req_sptps = false;
		return true;
	}

	case REQ_CANONICAL: {
		char host[MAX_STRING_SIZE];
		char port[MAX_STRING_SIZE];

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING " " MAX_STRING, host, port) != 2) {
			logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "REQ_CANONICAL", from->name, "invalid canonical address");
			return true;
		}

		char *canonical_address;
		xasprintf(&canonical_address, "%s %s", host, port);

		if(mesh->log_level <= MESHLINK_DEBUG && (!from->canonical_address || strcmp(from->canonical_address, canonical_address))) {
			logger(mesh, MESHLINK_DEBUG, "Updating canonical address of %s to %s", from->name, canonical_address);
		}

		if(!path_assign_canonical_address(from, canonical_address)) {
			if(!path_canonical_is_hostname(from)) {
				try_upgrade_probe(mesh, from);
			}

			return true;
		}

		from->status.dirty = true;

		if(path_sanitize_recent(mesh, from)) {
			path_persist_node(mesh, from);
		}

		path_request_canonical_resolve(mesh, from);
		path_reclassify_active_meta(mesh, from);
		outgoing_on_canonical_reset(mesh, from);

		if(!path_canonical_is_hostname(from)) {
			try_upgrade_probe(mesh, from);
		}

		return true;
	}

	case REQ_EXTERNAL: {
		char ip[MAX_STRING_SIZE];
		char port[MAX_STRING_SIZE];
		logger(mesh, MESHLINK_INFO, "Got %s from %s with data: %s", "REQ_EXTERNAL", from->name, request);

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING " " MAX_STRING, ip, port) != 2) {
			logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "REQ_EXTERNAL", from->name, request);
			return true;
		}

		char *external_ip_address;
		xasprintf(&external_ip_address, "%s %s", ip, port);

		if(mesh->log_level <= MESHLINK_DEBUG && (!from->external_ip_address || strcmp(from->external_ip_address, external_ip_address))) {
			logger(mesh, MESHLINK_DEBUG, "Updating external IP address of %s to %s", from->name, external_ip_address);
		}

		free(from->external_ip_address);
		from->external_ip_address = external_ip_address;

		/* A REQ_EXTERNAL is the peer telling us where it can be reached directly:
		   remember it so the next (re)connect and the upgrade probe try it before
		   the canonical address. Our own external IP:port is a hairpin, skip it. */

		sockaddr_t sa;
		sockaddr_t self_ext;

		if(!host_port_to_sockaddr(ip, port, &sa) || !address_connectable(&sa)) {
			logger(mesh, MESHLINK_DEBUG, "Not remembering REQ_EXTERNAL address of %s: not a connectable numeric host and port", from->name);
			return true;
		}

		if(self_external_sockaddr(mesh, &self_ext) && !sockaddrcmp(&sa, &self_ext)) {
			logger(mesh, MESHLINK_DEBUG, "Not remembering REQ_EXTERNAL address of %s: it is our own external address", from->name);
			return true;
		}

		/* Only the peer itself, over our connection with it, can vouch for the address.
		   Anyone else may have forwarded (or forged) it: keep it as a last-resort
		   candidate behind the addresses we already know, and do not probe it. */

		if(from->connection != c) {
			if(node_append_recent_address(mesh, from, &sa, ADDR_SRC_INDIRECT)) {
				logger(mesh, MESHLINK_DEBUG, "Remembering forwarded REQ_EXTERNAL address of %s as a fallback", from->name);
			} else if(!from->recent[0].sa.sa_family) {
				logger(mesh, MESHLINK_DEBUG, "Not remembering forwarded REQ_EXTERNAL address of %s: no proven address to rank it behind", from->name);
			}

			return true;
		}

		/* While we reach the peer through its canonical address this is exactly what we
		   want to probe first. Once we are directly connected, the address that just
		   authenticated (which ack_h() put in front) is proven and this one is not: keep
		   it as a fallback instead of paying a connect timeout on it at every reconnect. */

		if(path_meta_is_canonical(from, c)) {
			if(node_add_recent_address_cap(mesh, from, &sa, ADDR_SRC_EXTERNAL, PATH_CAP_BOTH)) {
				from->upgrade_recent_idx = 0;
			}

			try_upgrade_probe(mesh, from);
		} else {
			node_append_recent_address_cap(mesh, from, &sa, ADDR_SRC_EXTERNAL, PATH_CAP_BOTH);
		}

		return true;
	}

	case REQ_PUNCH_ENDPOINT:
		return req_punch_endpoint_h(mesh, c, request, from);

	default:
		logger(mesh, MESHLINK_ERROR, "Unknown extended REQ_KEY request from %s: %s", from->name, request);
		return true;
	}
}

bool req_key_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	assert(request);
	assert(*request);

	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;
	int reqno = 0;

	if(sscanf(request, "%*d " MAX_STRING " " MAX_STRING " %d", from_name, to_name, &reqno) < 2) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s", "REQ_KEY", c->name);
		return false;
	}

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "REQ_KEY", c->name, "invalid name");
		return false;
	}

	from = lookup_node(mesh, from_name);

	if(!from) {
		logger(mesh, MESHLINK_ERROR, "Got %s from %s origin %s which does not exist in our connection list",
		       "REQ_KEY", c->name, from_name);
		return true;
	}

	to = lookup_node(mesh, to_name);

	if(!to) {
		logger(mesh, MESHLINK_ERROR, "Got %s from %s destination %s which does not exist in our connection list",
		       "REQ_KEY", c->name, to_name);
		return true;
	}

	/* Check if this key request is for us */

	if(to == mesh->self) {                      /* Yes */
		/* Is this an extended REQ_KEY message? */
		if(reqno) {
			return req_key_ext_h(mesh, c, request, from, reqno);
		}

		/* This should never happen. Ignore it, unless it came directly from the connected peer, in which case we disconnect. */
		return from->connection != c;
	} else {
		if(!to->status.reachable || !to->nexthop || !to->nexthop->connection) {
			logger(mesh, MESHLINK_WARNING, "Got %s from %s destination %s which is not reachable",
			       "REQ_KEY", c->name, to_name);
			return true;
		}

		size_t len = strlen(request);
		from->in_forward += len + SPTPS_OVERHEAD;
		to->out_forward += len + SPTPS_OVERHEAD;

		if(reqno == REQ_SPTPS) {
			logger(mesh, MESHLINK_DEBUG, "Path policy: META-in pins META-out for %s via %s", to->name, to->nexthop->name);
		}

		send_request(mesh, to->nexthop->connection, NULL, "%s", request);
	}

	return true;
}

/* A punch hint is the backbone's answer. A member who can emit ANS_KEY must
   not get to choose the socket we probe. */
static bool ans_key_from_backbone(meshlink_handle_t *mesh, connection_t *c) {
	node_t *backbone = connection_policy_backbone(mesh);

	return backbone
	       && c
	       && c->status.active
	       && c->node == backbone
	       && backbone->connection == c;
}

/* This node is the backbone, and `from` is an ordinary peer. An address that
   peer already wrote is their claim, not an observation. */
static bool ans_key_drop_member_address(meshlink_handle_t *mesh, const node_t *from) {
	if(!mesh || !mesh->self || !from || from == mesh->self) {
		return false;
	}

	if(connection_policy_backbone(mesh) != mesh->self) {
		return false;
	}

	if(!connection_policy_lan_device_class(mesh->self->devclass)
	                || !connection_policy_lan_device_class(from->devclass)) {
		return false;
	}

	return !connection_policy_is_backbone(mesh, from);
}

/* True when a pre-filled address must not be forwarded. `hint` is the
   observation to send instead, or AF_UNSPEC when there is nothing to append. */
static bool ans_key_backbone_hint(meshlink_handle_t *mesh, node_t *from, const char *address, sockaddr_t *hint) {
	if(!address || !*address || !hint || !ans_key_drop_member_address(mesh, from)) {
		return false;
	}

	if(!path_select_punch_hint(mesh, from, hint, NULL)) {
		memset(hint, 0, sizeof *hint);
	}

	return true;
}

bool ans_key_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	assert(request);
	assert(*request);

	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char key[MAX_STRING_SIZE];
	char address[MAX_STRING_SIZE] = "";
	char port[MAX_STRING_SIZE] = "";
	int cipher, digest, maclength, compression;
	node_t *from, *to;

	if(sscanf(request, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" %d %d %d %d "MAX_STRING" "MAX_STRING,
	                from_name, to_name, key, &cipher, &digest, &maclength,
	                &compression, address, port) < 7) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s", "ANS_KEY", c->name);
		return false;
	}

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "ANS_KEY", c->name, "invalid name");
		return false;
	}

	from = lookup_node(mesh, from_name);

	if(!from) {
		logger(mesh, MESHLINK_ERROR, "Got %s from %s origin %s which does not exist in our connection list",
		       "ANS_KEY", c->name, from_name);
		return true;
	}

	to = lookup_node(mesh, to_name);

	if(!to) {
		logger(mesh, MESHLINK_ERROR, "Got %s from %s destination %s which does not exist in our connection list",
		       "ANS_KEY", c->name, to_name);
		return true;
	}

	/* Forward it if necessary */

	if(to != mesh->self) {
		if(!to->status.reachable) {
			logger(mesh, MESHLINK_WARNING, "Got %s from %s destination %s which is not reachable",
			       "ANS_KEY", c->name, to_name);
			return true;
		}

		if(from == to) {
			logger(mesh, MESHLINK_WARNING, "Got %s from %s from %s to %s",
			       "ANS_KEY", c->name, from_name, to_name);
			return true;
		}

		if(!to->nexthop || !to->nexthop->connection) {
			logger(mesh, MESHLINK_WARNING, "Cannot forward ANS_KEY to %s via %s", to->name, to->nexthop ? to->nexthop->name : to->name);
			return false;
		}

		/* TODO: find a good way to avoid the use of strlen() */
		size_t len = strlen(request);
		from->in_forward += len + SPTPS_OVERHEAD;
		to->out_forward += len + SPTPS_OVERHEAD;

		/* Append a fresh observation, or a confirmed endpoint. Never recent[0].
		   An address already on the message is left alone. */
		if(!*address) {
			sockaddr_t hint;
			bool observed = false;

			if(path_select_punch_hint(mesh, from, &hint, &observed)) {
				char *reflexive_address, *reflexive_port;

				if(observed) {
					logger(mesh, MESHLINK_INFO, "Appending fresh UDP observation to ANS_KEY from %s to %s", from->name, to->name);
				} else {
					logger(mesh, MESHLINK_DEBUG, "Appending confirmed UDP endpoint to ANS_KEY from %s to %s", from->name, to->name);
				}

				sockaddr2str(&hint, &reflexive_address, &reflexive_port);
				send_request(mesh, to->nexthop->connection, NULL, "%s %s %s", request, reflexive_address, reflexive_port);
				free(reflexive_address);
				free(reflexive_port);
				return true;
			}
		}

		/* A member-filled address is not the backbone's observation. */
		if(*address) {
			sockaddr_t replaced;

			if(ans_key_backbone_hint(mesh, from, address, &replaced)) {
				if(replaced.sa.sa_family != AF_UNSPEC) {
					char *reflexive_address, *reflexive_port;

					logger(mesh, MESHLINK_INFO, "Replacing member UDP address on ANS_KEY from %s to %s", from->name, to->name);
					sockaddr2str(&replaced, &reflexive_address, &reflexive_port);
					send_request(mesh, to->nexthop->connection, NULL, "%d %s %s %s %d %d %d %d %s %s",
					             ANS_KEY, from_name, to_name, key, cipher, digest, maclength, compression,
					             reflexive_address, reflexive_port);
					free(reflexive_address);
					free(reflexive_port);
					return true;
				}

				logger(mesh, MESHLINK_DEBUG, "Dropping member UDP address on ANS_KEY from %s to %s", from->name, to->name);
				return send_request(mesh, to->nexthop->connection, NULL, "%d %s %s %s %d %d %d %d",
				                    ANS_KEY, from_name, to_name, key, cipher, digest, maclength, compression);
			}
		}

		return send_request(mesh, to->nexthop->connection, NULL, "%s", request);
	}

	/* Is this an ANS_KEY informing us of our own reflexive UDP address? */

	if(from == mesh->self) {
		if(*key == '.' && *address && *port) {
			logger(mesh, MESHLINK_DEBUG, "Learned our own reflexive UDP address from %s: %s port %s", c->name, address, port);

			/* Inform all other nodes we want to communicate with and which are reachable via this connection */
			for splay_each(node_t, n, mesh->nodes) {
				if(n->nexthop != c->node) {
					continue;
				}

				if(n->status.udp_confirmed) {
					continue;
				}

				if(!n->status.waitingforkey && !n->status.validkey) {
					continue;
				}

				if(!n->nexthop->connection) {
					continue;
				}

				logger(mesh, MESHLINK_DEBUG, "Forwarding our own reflexive UDP address to %s", n->name);
				send_request(mesh, c, NULL, "%d %s %s . -1 -1 -1 0 %s %s", ANS_KEY, mesh->self->name, n->name, address, port);
			}
		} else {
			logger(mesh, MESHLINK_WARNING, "Got %s from %s from %s to %s",
			       "ANS_KEY", c->name, from_name, to_name);
		}

		return true;
	}

	/* Process SPTPS data if present */

	if(*key != '.') {
		/* Don't use key material until every check has passed. */
		node_set_validkey(mesh, from, false);

		/* Compression is not supported. */
		if(compression != 0) {
			logger(mesh, MESHLINK_ERROR, "Node %s uses bogus compression level!", from->name);
			return true;
		}

		char buf[strlen(key)];
		int len = b64decode(key, buf, strlen(key));

		if(!len || !sptps_receive_data(&from->sptps, buf, len)) {
			logger(mesh, MESHLINK_ERROR, "Error processing SPTPS data from %s", from->name);
		}
	}

	if(from->status.validkey) {
		bool punched = false;

		if(*address && *port) {
			sockaddr_t sa = str2sockaddr(address, port);

			logger(mesh, MESHLINK_DEBUG, "Using reflexive UDP address from %s: %s port %s", from->name, address, port);

			if(path_peer_udp_punching_allowed(mesh, from)) {
				if(ans_key_from_backbone(mesh, c)) {
					path_note_punch_endpoint(mesh, from, &sa);
					punched = true;
				}
			} else if(connection_policy_backbone_udp_required(mesh, from)) {
				path_learn_address_cap(mesh, from, &sa, ADDR_SRC_UDP_REFLEXIVE, PATH_CAP_UDP);
				update_node_udp_from(mesh, from, &sa, ADDR_SRC_UDP_REFLEXIVE);
			}
		}

		/* Finding 9 gates peer punching. The backbone UDP mapping is started
		   here instead of send_mtu_probe(); PMTU starts after confirm. */
		if(connection_policy_backbone_udp_required(mesh, from)) {
			path_backbone_udp_start(mesh, from);
		} else if(!punched && path_peer_udp_punching_allowed(mesh, from)) {
			send_mtu_probe(mesh, from);
		}
	}

	return true;
}

bool punch_endpoint_cover_unit(meshlink_handle_t *mesh) {
	node_t *src = NULL;
	node_t *dst = NULL;
	node_t peer;
	node_t route;
	node_t fake_bb;
	connection_t live;
	connection_t back;
	connection_t fake_conn;
	node_t *saved_bb = NULL;
	char *saved_bb_name = NULL;
	sockaddr_t hint;
	sockaddr_t out;
	bool observed = false;
	bool ok = false;
	bool swapped_name = false;
	bool swapped_bb = false;
	uint32_t hints;
	uint32_t restarts;
	char punch_req[128];

	if(!mesh || !mesh->self) {
		return false;
	}

#define PUNCH_CHECK(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "punch_endpoint_cover_unit failed: %s", #cond); \
		goto done; \
	} \
} while(0)

	memset(&peer, 0, sizeof peer);
	memset(&route, 0, sizeof route);
	memset(&fake_bb, 0, sizeof fake_bb);
	memset(&fake_conn, 0, sizeof fake_conn);

	src = new_node();
	dst = new_node();
	src->name = xstrdup("punchsrc");
	dst->name = xstrdup("punchdst");
	src->devclass = DEV_CLASS_STATIONARY;
	dst->devclass = DEV_CLASS_STATIONARY;
	src->session_id = 11;
	dst->session_id = 22;
	src->status.reachable = true;
	dst->status.reachable = true;
	src->status.validkey = true;
	dst->status.validkey = true;
	src->devtool_force_meta = true;
	dst->devtool_force_meta = true;
	src->mesh = mesh;
	dst->mesh = mesh;
	node_add(mesh, src);
	node_add(mesh, dst);

	memset(&live, 0, sizeof live);
	memset(&back, 0, sizeof back);
	live.socket = -1;
	back.socket = -1;
	live.status.active = true;
	back.status.active = true;
	live.protocol_minor = 4;
	back.protocol_minor = 4;
	live.node = src;
	src->connection = &live;
	src->nexthop = src;
	dst->connection = &back;
	dst->nexthop = dst;

	hint = str2sockaddr("203.0.113.10", "4000");
	PUNCH_CHECK(!path_get_fresh_udp_observation(mesh, src, &out));
	src->session_id = 0;
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(!src->udp_observation.session_id);
	src->session_id = 11;
	hint.in.sin_port = 0;
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(!src->udp_observation.session_id);
	hint = str2sockaddr("10.1.0.9", "4000");
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(!src->udp_observation.session_id);
	hint = str2sockaddr("127.0.0.1", "4000");
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(!src->udp_observation.session_id);
	hint = str2sockaddr("169.254.1.1", "4000");
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(!src->udp_observation.session_id);
	hint = str2sockaddr("255.255.255.255", "4000");
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(!src->udp_observation.session_id);
	hint = str2sockaddr("203.0.113.10", "4000");
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(src->udp_observation.session_id == 11);
	PUNCH_CHECK(!src->status.udp_confirmed);
	PUNCH_CHECK(path_get_fresh_udp_observation(mesh, src, &out));
	PUNCH_CHECK(!sockaddrcmp(&out, &hint));
	src->session_id = 12;
	PUNCH_CHECK(!path_get_fresh_udp_observation(mesh, src, &out));
	src->session_id = 11;
	src->udp_observation.observed_at = mesh->loop.now;
	src->udp_observation.observed_at.tv_sec -= PATH_UDP_OBSERVATION_FRESH_SEC + 1;
	PUNCH_CHECK(!path_get_fresh_udp_observation(mesh, src, &out));
	src->udp_observation.observed_at = mesh->loop.now;
	PUNCH_CHECK(path_select_punch_hint(mesh, src, &out, &observed) && observed);

	src->recent[0] = str2sockaddr("198.51.100.8", "9");
	src->recent_source[0] = ADDR_SRC_UDP_REFLEXIVE;
	src->recent_cap[0] = PATH_CAP_UDP;
	path_clear_udp_observation(src);
	PUNCH_CHECK(!src->status.udp_confirmed);
	PUNCH_CHECK(!path_select_punch_hint(mesh, src, &out, &observed));
	src->status.udp_confirmed = true;
	src->address = str2sockaddr("203.0.113.40", "4100");
	PUNCH_CHECK(path_select_punch_hint(mesh, src, &out, &observed) && !observed);
	PUNCH_CHECK(!sockaddrcmp(&out, &src->address));
	src->status.udp_confirmed = false;

	snprintf(punch_req, sizeof punch_req, "%d punchsrc %s %d punchdst", REQ_KEY, mesh->self->name, REQ_PUNCH_ENDPOINT);
	saved_bb_name = mesh->backbone.name;
	mesh->backbone.name = mesh->self->name;
	swapped_name = true;
	hints = mesh->self->punch_hints_sent;
	PUNCH_CHECK(req_punch_endpoint_h(mesh, &live, "0 baz punchsrc", src));
	PUNCH_CHECK(mesh->self->punch_hints_sent == hints);
	src->status.blacklisted = true;
	PUNCH_CHECK(req_punch_endpoint_h(mesh, &live, punch_req, src));
	PUNCH_CHECK(mesh->self->punch_hints_sent == hints);
	src->status.blacklisted = false;
	src->status.conflict_backbone = true;
	PUNCH_CHECK(req_punch_endpoint_h(mesh, &live, punch_req, src));
	PUNCH_CHECK(mesh->self->punch_hints_sent == hints);
	src->status.conflict_backbone = false;
	live.protocol_minor = 3;
	path_note_authenticated_udp_observation(mesh, dst, &hint);
	PUNCH_CHECK(req_punch_endpoint_h(mesh, &live, punch_req, src));
	PUNCH_CHECK(mesh->self->punch_hints_sent == hints);
	live.protocol_minor = 4;
	dst->udp_observation.observed_at.tv_sec -= PATH_UDP_OBSERVATION_FRESH_SEC + 1;
	PUNCH_CHECK(req_punch_endpoint_h(mesh, &live, punch_req, src));
	PUNCH_CHECK(mesh->self->punch_hints_sent == hints);
	dst->udp_observation.observed_at = mesh->loop.now;
	dst->udp_observation.session_id = dst->session_id;
	path_copy_sockaddr(&dst->udp_observation.endpoint, &hint);
	src->peer_udp.channel_count = 1;
	PUNCH_CHECK(req_punch_endpoint_h(mesh, &live, punch_req, src));
	PUNCH_CHECK(mesh->self->punch_hints_sent > hints);
	PUNCH_CHECK(!src->status.udp_confirmed);
	PUNCH_CHECK(!dst->status.udp_confirmed);
	mesh->backbone.name = saved_bb_name;
	swapped_name = false;
	mesh->self->status.conflict_backbone = true;
	PUNCH_CHECK(req_punch_endpoint_h(mesh, &live, punch_req, src));
	mesh->self->status.conflict_backbone = false;

	src->status.udp_confirmed = false;
	memset(&src->address, 0, sizeof src->address);
	path_note_punch_endpoint(mesh, src, &hint);
	PUNCH_CHECK(!src->status.udp_confirmed);
	PUNCH_CHECK(!sockaddrcmp(&src->address, &hint));
	{
		char *saved_self_ext = mesh->self->external_ip_address;
		char *saved_peer_ext = src->external_ip_address;
		int saved_nsocks = mesh->listen_sockets;
		bool planted_sock = false;
		int v4 = -1;
		sockaddr_t chosen_buf;
		const sockaddr_t *chosen = NULL;
		int chosen_sock = -1;

		for(int i = 0; i < mesh->listen_sockets; i++) {
			if(mesh->listen_socket[i].sa.sa.sa_family == AF_INET) {
				v4 = i;
				break;
			}
		}

		if(v4 < 0 && mesh->listen_sockets < MAXSOCKETS) {
			v4 = mesh->listen_sockets;
			memset(&mesh->listen_socket[v4], 0, sizeof mesh->listen_socket[v4]);
			mesh->listen_socket[v4].sa.sa.sa_family = AF_INET;
			mesh->listen_socket[v4].udp.fd = -1;
			mesh->listen_sockets++;
			planted_sock = true;
		}

		if(v4 >= 0) {
			mesh->self->external_ip_address = (char *)"203.0.113.1";
			src->external_ip_address = (char *)"198.51.100.9 9";
			src->sock = v4;
			src->status.udp_confirmed = false;
			choose_udp_address(mesh, src, &chosen, &chosen_sock, &chosen_buf);
			mesh->self->external_ip_address = saved_self_ext;
			src->external_ip_address = saved_peer_ext;
		}

		if(planted_sock) {
			memset(&mesh->listen_socket[v4], 0, sizeof mesh->listen_socket[v4]);
			mesh->listen_sockets = saved_nsocks;
		}

		PUNCH_CHECK(v4 >= 0 && chosen && !sockaddrcmp(chosen, &hint));
	}
	src->status.udp_confirmed = true;
	src->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	{
		sockaddr_t newer = str2sockaddr("203.0.113.77", "4200");

		path_note_punch_endpoint(mesh, src, &newer);
		PUNCH_CHECK(!sockaddrcmp(&src->address, &hint));
		PUNCH_CHECK(src->status.udp_confirmed);
		PUNCH_CHECK(!sockaddrcmp(&src->recent[0], &newer));
		src->active_route.kind = DATA_ROUTE_DIRECT_UDP;
		src->active_route.udp_endpoint = src->address;
		path_note_udp_demoted_reason(mesh, src, "cover demotion");
		PUNCH_CHECK(!src->status.udp_confirmed);
		PUNCH_CHECK(!sockaddrcmp(&src->address, &src->peer_udp.last_hint));
		PUNCH_CHECK(src->active_route.kind != DATA_ROUTE_DIRECT_UDP);
	}

	peer.name = (char *)"punchpeer";
	peer.mesh = mesh;
	peer.devclass = DEV_CLASS_STATIONARY;
	peer.status.reachable = true;
	peer.status.validkey = true;
	peer.devtool_force_meta = true;
	peer.sptps_restart_count = 3;
	restarts = peer.sptps_restart_count;
	saved_bb = mesh->backbone.node;
	fake_bb.name = saved_bb ? saved_bb->name : mesh->self->name;
	fake_conn.socket = -1;
	fake_conn.status.active = true;
	fake_conn.protocol_minor = 4;
	fake_conn.node = &fake_bb;
	fake_bb.connection = &fake_conn;
	mesh->backbone.node = &fake_bb;
	swapped_bb = true;
	PUNCH_CHECK(path_channel_acquire(mesh, &peer));
	PUNCH_CHECK(peer.peer_udp.requests_sent == 1);
	PUNCH_CHECK(peer.sptps_restart_count == restarts);
	PUNCH_CHECK(path_channel_acquire(mesh, &peer));
	PUNCH_CHECK(peer.peer_udp.requests_sent == 1);
	peer.status.udp_confirmed = true;
	peer.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	path_route_tick(mesh, &peer);
	PUNCH_CHECK(peer.peer_udp.requests_sent == 1);
	peer.status.udp_confirmed = false;
	peer.udp_tier = PATH_TIER_NONE;
	peer.peer_udp.ladder_stopped = false;
	memset(&peer.peer_udp.next_request, 0, sizeof peer.peer_udp.next_request);
	peer.peer_udp.request_step = 0;
	path_route_tick(mesh, &peer);
	PUNCH_CHECK(peer.peer_udp.requests_sent == 2);
	peer.session_id = 9;
	peer.peer_udp.request_session = 1;
	path_route_tick(mesh, &peer);
	PUNCH_CHECK(peer.peer_udp.requests_sent == 2);
	PUNCH_CHECK(peer.peer_udp.ladder_stopped);
	peer.peer_udp.ladder_stopped = false;
	peer.session_id = peer.peer_udp.request_session;
	fake_conn.protocol_minor = 3;
	memset(&peer.peer_udp.next_request, 0, sizeof peer.peer_udp.next_request);
	peer.peer_udp.request_step = 0;
	path_route_tick(mesh, &peer);
	PUNCH_CHECK(peer.peer_udp.requests_sent == 2);
	PUNCH_CHECK(peer.peer_udp.request_step == 0);
	{
		char req[160];
		connection_t stranger;
		uint32_t requests_before;

		fake_conn.protocol_minor = 4;

		src->peer_udp.channel_count = 1;
		src->status.validkey = true;
		src->status.reachable = true;
		src->status.udp_confirmed = false;
		memset(&src->address, 0, sizeof src->address);
		memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
		requests_before = src->peer_udp.requests_sent;
		snprintf(req, sizeof req, "%d %s %s . -1 -1 -1 0 203.0.113.66 4400", ANS_KEY, src->name, mesh->self->name);
		memset(&stranger, 0, sizeof stranger);
		stranger.socket = -1;
		stranger.status.active = true;
		stranger.node = src;
		stranger.name = src->name;
		PUNCH_CHECK(ans_key_h(mesh, &stranger, req));
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);
		PUNCH_CHECK(src->peer_udp.requests_sent == requests_before);
		fake_conn.name = fake_bb.name;
		PUNCH_CHECK(ans_key_h(mesh, &fake_conn, req));
		PUNCH_CHECK(src->address.sa.sa_family == AF_INET);
		PUNCH_CHECK(ntohs(src->address.in.sin_port) == 4400);
		PUNCH_CHECK(src->peer_udp.requests_sent == requests_before + 1);
		PUNCH_CHECK(src->peer_udp.request_step == 1);
	}
	{
		node_t *during_bb = mesh->backbone.node;
		char *during_name = mesh->backbone.name;
		int saved_class = mesh->self->devclass;
		sockaddr_t repl;
		sockaddr_t observed_hint;
		char req[160];

		mesh->self->devclass = DEV_CLASS_STATIONARY;
		mesh->backbone.node = mesh->self;
		mesh->backbone.name = mesh->self->name;
		src->devclass = DEV_CLASS_STATIONARY;
		src->session_id = 11;
		src->status.udp_confirmed = false;
		memset(&src->address, 0, sizeof src->address);
		memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
		observed_hint = str2sockaddr("203.0.113.10", "4000");
		path_note_authenticated_udp_observation(mesh, src, &observed_hint);
		PUNCH_CHECK(ans_key_backbone_hint(mesh, src, "198.51.100.9", &repl));
		PUNCH_CHECK(repl.sa.sa_family == AF_INET);
		PUNCH_CHECK(ntohs(repl.in.sin_port) == 4000);
		snprintf(req, sizeof req, "%d %s %s . -1 -1 -1 0 198.51.100.9 9", ANS_KEY, src->name, dst->name);
		PUNCH_CHECK(ans_key_h(mesh, &live, req));
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);
		PUNCH_CHECK(dst->address.sa.sa_family == AF_UNSPEC);
		path_clear_udp_observation(src);
		src->status.udp_confirmed = false;
		memset(&src->address, 0, sizeof src->address);
		PUNCH_CHECK(ans_key_backbone_hint(mesh, src, "198.51.100.9", &repl));
		PUNCH_CHECK(repl.sa.sa_family == AF_UNSPEC);
		mesh->backbone.node = during_bb;
		PUNCH_CHECK(!ans_key_backbone_hint(mesh, src, "198.51.100.9", &repl));
		mesh->backbone.name = during_name;
		mesh->self->devclass = saved_class;
	}
	mesh->backbone.node = saved_bb;
	swapped_bb = false;
	path_channel_release(mesh, &peer);
	path_channel_release(mesh, &peer);

	route.name = (char *)"punchroute";
	route.mesh = mesh;
	route.devclass = DEV_CLASS_STATIONARY;
	route.status.reachable = true;
	route.status.validkey = true;
	route.status.udp_confirmed = true;
	route.udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	route.address = str2sockaddr("203.0.113.50", "4300");
	route.peer_udp.channel_count = 1;
	route.active_route.kind = DATA_ROUTE_RELAY;
	route.active_route.relay_carrier = RELAY_CARRIER_META_CANONICAL;
	route.promotion_candidate.active = true;
	route.promotion_candidate.kind = DATA_ROUTE_RELAY;
	route.promotion_candidate.relay_carrier = RELAY_CARRIER_UDP;
	route.promotion_candidate.successful_rounds = PATH_PROMOTION_ROUNDS;
	path_consider_route_promotion(mesh, &route, PATH_PROMOTION_DIRECT_UDP);
	PUNCH_CHECK(route.promotion_candidate.active);
	PUNCH_CHECK(route.promotion_candidate.kind == DATA_ROUTE_DIRECT_UDP);
	PUNCH_CHECK(!route.promotion_candidate.local);
	route.promotion_candidate.active = true;
	route.promotion_candidate.kind = DATA_ROUTE_DIRECT_UDP;
	route.promotion_candidate.local = true;
	route.promotion_candidate.successful_rounds = PATH_PROMOTION_ROUNDS;
	path_consider_route_promotion(mesh, &route, PATH_PROMOTION_DIRECT_UDP);
	PUNCH_CHECK(route.promotion_candidate.local);
	route.promotion_candidate.active = true;
	route.promotion_candidate.kind = DATA_ROUTE_RELAY;
	route.promotion_candidate.relay_carrier = RELAY_CARRIER_UDP;
	route.promotion_candidate.local = false;
	route.promotion_candidate.successful_rounds = PATH_PROMOTION_ROUNDS;
	route.promotion_candidate.first_success = mesh->loop.now;
	path_commit_candidate(mesh, &route);
	PUNCH_CHECK(route.active_route.relay_carrier != RELAY_CARRIER_UDP || route.active_route.kind != DATA_ROUTE_RELAY);
	PUNCH_CHECK(route.promotion_candidate.kind == DATA_ROUTE_DIRECT_UDP);

	ok = true;

done:
	if(swapped_name) {
		mesh->backbone.name = saved_bb_name;
	}

	if(swapped_bb) {
		mesh->backbone.node = saved_bb;
	}

	if(src) {
		src->connection = NULL;
		timeout_del(&mesh->loop, &src->mtutimeout);
		timeout_del(&mesh->loop, &src->promotion_timer);
		path_suspect_stop(mesh, src);
		path_scheduler_cancel_node(mesh, src);
		node_del(mesh, src);
	}

	if(dst) {
		dst->connection = NULL;
		timeout_del(&mesh->loop, &dst->mtutimeout);
		timeout_del(&mesh->loop, &dst->promotion_timer);
		path_suspect_stop(mesh, dst);
		path_scheduler_cancel_node(mesh, dst);
		node_del(mesh, dst);
	}

	timeout_del(&mesh->loop, &peer.mtutimeout);
	timeout_del(&mesh->loop, &peer.promotion_timer);
	timeout_del(&mesh->loop, &route.promotion_timer);
	path_suspect_stop(mesh, &peer);
	path_suspect_stop(mesh, &route);
	path_scheduler_cancel_node(mesh, &peer);
	path_scheduler_cancel_node(mesh, &route);
#undef PUNCH_CHECK
	return ok;
}
