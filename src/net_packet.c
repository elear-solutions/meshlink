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

/* data[0] is the request/reply flag and data[14..] is random padding. Bytes
   1..13 are zeroed on PMTU probes. Promotion, suspect, and backbone probes
   stamp a nonce at offset 1 so the echo can be identified without a wire
   format change. */
#define PROBE_NONCE_OFFSET 1

/* mtuprobes == 1..30: initial discovery, send bursts with 1 second interval
   mtuprobes ==    31: sleep pinginterval seconds
   mtuprobes ==    32: send 1 burst, sleep pingtimeout second
   mtuprobes ==    33: no response from other side, restart PMTU discovery process

   Discovery sends at most three probes per tick so one search fits in the
   4 pkt/s burst cap. The first sized probe is the midpoint of the remaining
   range; another is random; a local-discovery broadcast is included while
   mtuprobes <= 10 so LAN peers are not stuck on a canonical localhost dest.

   After parking, liveness is always one 64-byte probe. The occasional
   maxmtu+8 increase rides beside it and losing that reply does not demote.

*/

static void path_mtu_send_request(meshlink_handle_t *mesh, const path_probe_request_t *req) {
	node_t *n = req->node;
	int len = req->length;
	vpn_packet_t packet;
	bool saved_broadcast;
	uint16_t saved_len;

	if(!n) {
		return;
	}

	if(len < 64) {
		len = 64;
	}

	saved_broadcast = n->status.broadcast;
	saved_len = n->mtu_probe_request_len;
	n->status.broadcast = req->broadcast;
	n->mtu_probe_request_len = (uint16_t)len;

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	memset(packet.data, 0, 14);
	randomize(packet.data + 14, (size_t)len - 14);
	packet.len = (uint16_t)len;
	n->out_meta += packet.len + PROBE_OVERHEAD;
	send_udppacket(mesh, n, &packet);

	n->status.broadcast = saved_broadcast;
	n->mtu_probe_request_len = saved_len;
}

static path_sched_admit_t path_mtu_emit(meshlink_handle_t *mesh, node_t *n, path_sched_txn_t *txn,
                int len, bool broadcast, path_transaction_priority_t prio) {
	path_probe_request_t req;

	memset(&req, 0, sizeof req);
	req.node = n;
	req.length = (uint16_t)(len < 64 ? 64 : len);
	req.broadcast = broadcast;
	req.priority = prio;
	req.send = path_mtu_send_request;
	return path_scheduler_emit_packet(mesh, txn, &req);
}

/* Discovery ticks must not enqueue: a queued burst sits until the minute
   bucket refills (60s) and still consumes tokens that the next tick needs. */
static bool path_mtu_optional_ready(meshlink_handle_t *mesh, bool skip_minute) {
	path_scheduler_refill(mesh);

	if(!mesh->probe_budget.second_tokens) {
		return false;
	}

	return skip_minute || mesh->probe_budget.minute_tokens > 0;
}

/* Park discovery once the search has collapsed (30 probes, or earlier when
   minmtu has already met maxmtu — localhost often does this around 8).
   update_node_pmtu is skipped when minmtu was already <= maxmtu, so the
   channel resize has to happen here after mtuprobes becomes 31. */
static void mtu_probe_fix_if_ready(meshlink_handle_t *mesh, node_t *n) {
	if(!(n->status.udp_confirmed && (n->mtuprobes == 30 || (n->mtuprobes < 30 && n->minmtu >= n->maxmtu)))) {
		return;
	}

	if(n->minmtu > n->maxmtu) {
		n->minmtu = n->maxmtu;
		update_node_pmtu(mesh, n);
	} else {
		n->maxmtu = n->minmtu;
	}

	n->mtu = n->minmtu;
	logger(mesh, MESHLINK_INFO, "Fixing MTU of %s to %d after %d probes", n->name, n->mtu, n->mtuprobes);
	n->mtuprobes = 31;
	channel_refresh_carrier(mesh, n);
}

static void send_mtu_probe_handler(event_loop_t *loop, void *data) {
	meshlink_handle_t *mesh = loop->data;
	node_t *n = data;
	int timeout = 1;
	int prev = n->mtuprobes;
	int sent = 0;
	bool want_send;
	path_sched_txn_t *txn = NULL;

	n->mtuprobes++;

	if(!n->status.reachable || !n->status.validkey) {
		logger(mesh, MESHLINK_INFO, "Trying to send MTU probe to unreachable or rekeying node %s", n->name);
		n->mtuprobes = 0;
		n->pmtu_raise_pending = 0;
		path_scheduler_end_type(mesh, n, PATH_TXN_PMTU_DISCOVERY);
		timeout = 1;
		goto end;
	}

	if(n->mtuprobes > 32) {
		if(!n->minmtu) {
			n->mtuprobes = 31;
			timeout = mesh->dev_class_traits[n->devclass].pinginterval;
			goto end;
		}

		if(path_rebind_try_rescue(mesh, n)) {
			timeout = 1;
			goto end;
		}

		logger(mesh, MESHLINK_INFO, "%s did not respond to UDP ping, restarting PMTU discovery", n->name);
		path_note_udp_demoted_reason(mesh, n, "probe give-up");
		n->pmtu_raise_pending = 0;
		n->mtuprobes = 1;

		update_node_pmtu(mesh, n);
	}

	if(n->mtuprobes >= 10 && n->mtuprobes < 32 && !n->minmtu) {
		logger(mesh, MESHLINK_INFO, "No response to MTU probes from %s", n->name);
		n->mtuprobes = 31;
	}

	mtu_probe_fix_if_ready(mesh, n);

	if(n->mtuprobes == 31) {
		if(!n->minmtu && n->status.want_udp && n->nexthop && n->nexthop->connection) {
			/* Send a dummy ANS_KEY to try to update the reflexive UDP address */
			send_request(mesh, n->nexthop->connection, NULL, "%d %s %s . -1 -1 -1 0", ANS_KEY, mesh->self->name, n->name);
			n->status.want_udp = false;
		}

		timeout = mesh->dev_class_traits[n->devclass].pinginterval;
		goto end;
	} else if(n->mtuprobes == 32) {
		bool liveness_sent = false;

		timeout = mesh->dev_class_traits[n->devclass].pingtimeout;

		/* Liveness only matters for a peer we are actually talking to. An idle
		   peer is not probed at all, so a quiet mesh costs nothing (ADR 0004). */
		if(!path_liveness_probe_warranted(mesh, n)) {
			n->mtuprobes = 31;
			timeout = mesh->dev_class_traits[n->devclass].pinginterval;
			goto end;
		}

		/* Liveness is always the 64-byte probe. The maxmtu+8 raise rides
		   beside it; losing that reply must not demote the path. The raise
		   reply is matched by pmtu_raise_pending, not by mtuprobes. */
		if(path_mtu_optional_ready(mesh, false)
		                && path_mtu_emit(mesh, n, NULL, 64, false, PATH_TX_LIVENESS) == PATH_SCHED_SENT) {
			liveness_sent = true;
			n->liveness_probes_sent++;
		}

		if(n->maxmtu + 8 < MTU && mesh->loop.now.tv_sec >= n->pmtu_increase_next
		                && path_mtu_optional_ready(mesh, false)) {
			n->pmtu_increase_next = mesh->loop.now.tv_sec + PATH_PMTU_INCREASE_INTERVAL_SEC;

			if(path_mtu_emit(mesh, n, NULL, n->maxmtu + 8, false, PATH_TX_PMTU_INCREASE) == PATH_SCHED_SENT) {
				n->pmtu_raise_pending = (uint16_t)(n->maxmtu + 8);
			}
		}

		if(!liveness_sent) {
			n->mtuprobes = 31;
			timeout = 1;
		}

		goto end;
	}

	txn = path_scheduler_begin_transaction(mesh, n, PATH_TXN_PMTU_DISCOVERY, PATH_TX_LIVENESS, path_transaction_preempt);

	if(!txn) {
		n->mtuprobes = prev;
		timeout = 1;
		goto end;
	}

	want_send = n->mtuprobes < 31;

	for(int i = 0; i < 4; i++) {
		int len;
		path_transaction_priority_t prio;
		path_sched_admit_t admit;

		if(sent >= 3) {
			break;
		}

		if(i == 0) {
			if(n->mtuprobes < 30 || n->maxmtu + 8 >= MTU) {
				continue;
			}

			/* Looking for a bigger path is worth a full-size packet only
			   occasionally; it is the most expensive probe there is. */
			if(mesh->loop.now.tv_sec < n->pmtu_increase_next) {
				continue;
			}

			n->pmtu_increase_next = mesh->loop.now.tv_sec + PATH_PMTU_INCREASE_INTERVAL_SEC;
			len = n->maxmtu + 8;
			prio = PATH_TX_PMTU_INCREASE;
		} else if(i == 3) {
			if(n->mtuprobes > 10 || !n->prevedge) {
				continue;
			}

			len = n->minmtu ? n->minmtu : 64;
			prio = PATH_TX_LIVENESS;
		} else if(n->maxmtu <= n->minmtu) {
			len = n->maxmtu;
			prio = PATH_TX_LIVENESS;
		} else if(i == 1) {
			len = n->minmtu + 1 + (n->maxmtu - n->minmtu) / 2;
			prio = PATH_TX_LIVENESS;
		} else {
			len = n->minmtu + 1 + prng(mesh, n->maxmtu - n->minmtu);
			prio = PATH_TX_LIVENESS;
		}

		if(len < 64) {
			len = 64;
		}

		if(!path_mtu_optional_ready(mesh, true)) {
			break;
		}

		admit = path_mtu_emit(mesh, n, txn, len, i == 3, prio);

		if(!path_scheduler_has_transaction(mesh, n, PATH_TXN_PMTU_DISCOVERY)) {
			txn = NULL;
			break;
		}

		if(admit == PATH_SCHED_SENT) {
			sent++;

			if(prio == PATH_TX_PMTU_INCREASE) {
				n->pmtu_raise_pending = (uint16_t)len;
			}
		} else if(prio == PATH_TX_PMTU_INCREASE) {
			continue;
		} else {
			break;
		}
	}

	if(want_send && !sent) {
		n->mtuprobes = prev;
		timeout = 1;
	}

end:
	if(n->mtuprobes == 0 || n->mtuprobes == 31) {
		path_scheduler_end_type(mesh, n, PATH_TXN_PMTU_DISCOVERY);
	}

	if(n->mtutimeout.cb) {
		timeout_set(&mesh->loop, &n->mtutimeout, &(struct timespec) {
			timeout, prng(mesh, TIMER_FUDGE)
		});
	}
}

void send_mtu_probe(meshlink_handle_t *mesh, node_t *n) {
	if(n->devtool_force_meta) {
		return;
	}

	timeout_add(&mesh->loop, &n->mtutimeout, send_mtu_probe_handler, n, &(struct timespec) {
		1, 0
	});
	send_mtu_probe_handler(&mesh->loop, n);

	/* channel_demand_hold can arm from an app thread; wake the mesh loop so
	   the new timeout is not stuck until the next ping (~1s). */
	if(mesh->threadstarted && mesh->loop.pipefd[1] != -1 && !pthread_equal(mesh->thread, pthread_self())) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
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
	memcpy(packet.data + PROBE_NONCE_OFFSET, &n->udp_rebind.challenge_nonce, sizeof n->udp_rebind.challenge_nonce);
	randomize(packet.data + 14, PATH_PROMOTION_PROBE_LEN - 14);
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
	memcpy(packet.data + PROBE_NONCE_OFFSET, &s->nonce, sizeof s->nonce);
	randomize(packet.data + 14, PATH_PROMOTION_PROBE_LEN - 14);
	packet.len = PATH_PROMOTION_PROBE_LEN;
	n->out_meta += packet.len + PROBE_OVERHEAD;
	send_probe_to(mesh, n, &packet, &s->endpoint);
	s->probes_sent++;
}

void send_backbone_udp_probe(meshlink_handle_t *mesh) {
	node_t *n;
	vpn_packet_t packet;

	if(!mesh || !mesh->backbone_udp.node || !mesh->backbone_udp.liveness_nonce) {
		return;
	}

	n = mesh->backbone_udp.node;

	if(!n->status.reachable || !n->status.validkey) {
		return;
	}

	if(mesh->backbone_udp.endpoint.sa.sa_family == AF_UNSPEC
	                || mesh->backbone_udp.endpoint.sa.sa_family == AF_UNKNOWN) {
		return;
	}

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	memcpy(packet.data + PROBE_NONCE_OFFSET, &mesh->backbone_udp.liveness_nonce, sizeof mesh->backbone_udp.liveness_nonce);
	randomize(packet.data + 14, PATH_PROMOTION_PROBE_LEN - 14);
	packet.len = PATH_PROMOTION_PROBE_LEN;
	n->out_meta += packet.len + PROBE_OVERHEAD;
	send_probe_to(mesh, n, &packet, &mesh->backbone_udp.endpoint);
}

static bool sockaddr_is_set(const sockaddr_t *sa) {
	return sa->sa.sa_family != AF_UNSPEC && sa->sa.sa_family != AF_UNKNOWN;
}

/* The probe we would send uses the confirmed UDP dest. That can differ from
   the data route when application records still ride local META. A confirmed
   alias is the same session: the source port is often not n->address. */
static bool liveness_request_from_active_endpoint(meshlink_handle_t *mesh, const node_t *n) {
	if(!n->status.udp_confirmed || !sockaddr_is_set(&n->last_udp_from)) {
		return false;
	}

	if(sockaddr_is_set(&n->address) && !sockaddrcmp(&n->last_udp_from, &n->address)) {
		return true;
	}

	if(n->active_route.kind == DATA_ROUTE_DIRECT_UDP
	                && sockaddr_is_set(&n->active_route.udp_endpoint)
	                && !sockaddrcmp(&n->last_udp_from, &n->active_route.udp_endpoint)) {
		return true;
	}

	return lookup_node_udp(mesh, &n->last_udp_from) == n;
}

/* Higher name's next liveness sits past the lower name's next probe. */
#define GREATER_NAME_PARK_SLACK_SEC 1

static void mtu_probe_park_greater_name(meshlink_handle_t *mesh, node_t *n) {
	int interval = 60;
	int wait = 5;

	if(n->devclass >= 0 && n->devclass < DEV_CLASS_COUNT) {
		interval = mesh->dev_class_traits[n->devclass].pinginterval;
		wait = mesh->dev_class_traits[n->devclass].pingtimeout;
	}

	if(interval < 1) {
		interval = 1;
	}

	if(wait < 1) {
		wait = 1;
	}

	n->mtuprobes = 31;

	if(n->mtutimeout.cb) {
		timeout_set(&mesh->loop, &n->mtutimeout, &(struct timespec) {
			interval + wait + GREATER_NAME_PARK_SLACK_SEC, prng(mesh, TIMER_FUDGE)
		});
	}
}

static void mtu_probe_raise_settled(meshlink_handle_t *mesh, node_t *n, uint16_t len) {
	n->pmtu_raise_pending = 0;
	logger(mesh, MESHLINK_INFO, "Increase in PMTU to %s detected, raising MTU to %d", n->name, len);

	if(n->minmtu < len) {
		n->minmtu = len;
	}

	n->maxmtu = len;
	n->mtu = len;
	update_node_pmtu(mesh, n);
	n->mtuprobes = 30;
}

static void mtu_probe_h(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet, uint16_t len) {
	n->in_meta += len + PROBE_OVERHEAD;

	if(len < 64) {
		logger(mesh, MESHLINK_WARNING, "Got too short MTU probe length %d from %s", packet->len, n->name);
		return;
	}

	logger(mesh, MESHLINK_DEBUG, "Got MTU probe length %d from %s", packet->len, n->name);

	if(!packet->data[0]) {
		if(n->devtool_probe_reply_limit && len > n->devtool_probe_reply_limit) {
			return;
		}

		/* It's a probe request, send back a reply. A parked peer that just
		   heard a 64-byte liveness request from the active endpoint does not
		   need to send its own; the echo already proves both directions.
		   30 counts: our own echo lands first and sets 30 before this request. */
		uint64_t req_nonce = 0;

		memcpy(&req_nonce, packet->data + PROBE_NONCE_OFFSET, sizeof req_nonce);

		/* Nonce-bearing requests are promotion or suspect probes, not liveness. */
		bool park_liveness = n->mtuprobes >= 30
		                     && len == 64
		                     && req_nonce == 0
		                     && path_liveness_probe_warranted(mesh, n)
		                     && liveness_request_from_active_endpoint(mesh, n);

		packet->data[0] = 1;

		/* Temporarily set udp_confirmed, so that the reply is sent
		   back exactly the way it came in. */

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

		/* Both peers arm the same timer, so resetting the counter keeps them
		   in phase and both keep sending. The higher name yields: its next
		   send sits past the lower name's next probe, which parks it again. */
		if(park_liveness && mesh->self && mesh_self_name_is_greater(mesh->self->name, n->name)) {
			mtu_probe_park_greater_name(mesh, n);
		}
	} else {
		/* A test can pin application traffic to META. Requests are still
		   answered, but delayed replies cannot silently re-enable UDP. */
		if(n->devtool_force_meta) {
			return;
		}

		/* It's a valid reply: now we know bidirectional communication
		   is possible using the address and socket that the reply
		   packet used. */

		sockaddr_t from_snap;
		uint64_t nonce = 0;

		memcpy(&nonce, packet->data + PROBE_NONCE_OFFSET, sizeof nonce);
		/* Rebind commit can zero last_udp_from through the cache forget. */
		path_copy_sockaddr(&from_snap, &n->last_udp_from);

		if(n == mesh->backbone_udp.node) {
			uint64_t want = mesh->backbone_udp.liveness_nonce;

			if(want && nonce == want) {
				path_backbone_udp_observe_reply(mesh, n, &n->last_udp_from, nonce);
				return;
			}

			if(!mesh->backbone_udp.confirmed) {
				return;
			}
		}

		if(!n->status.udp_confirmed) {
			if(path_try_confirm_udp_probe_reply(mesh, n, &from_snap, nonce)) {
				return;
			}
		} else {
			path_observe_probe_reply(mesh, n, &from_snap, nonce);
		}

		/* Matched by the outstanding length, so a 64-byte liveness reply in
		   the same tick cannot clamp the raise away. */
		if(len == n->maxmtu + 8 && len < MTU && (n->mtuprobes > 30 || n->pmtu_raise_pending == len)) {
			n->pmtu_raise_pending = 0;
			mtu_probe_raise_settled(mesh, n, len);
			return;
		}

		/* Nonce-bearing echoes must not resize PMTU. A reply from the parked
		   endpoint is round-trip proof: liveness only, no resize. */
		if(nonce) {
			if(n->status.udp_confirmed && n->minmtu && n->mtuprobes > 30
			                && n->address.sa.sa_family && !sockaddrcmp(&from_snap, &n->address)) {
				n->mtuprobes = 30;
			}

			return;
		}

		/* If we haven't established the PMTU yet, restart the discovery process. */

		if(n->mtuprobes > 30) {
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

/* Caller holds mesh->mutex. Plants a settled PMTU and feeds the +8 reply. */
bool net_devtool_accept_pmtu_increase(meshlink_handle_t *mesh, node_t *n, uint16_t settled) {
	vpn_packet_t packet;
	uint16_t len;

	if(!mesh || !n || settled < 64 || (unsigned)settled + 8 >= MTU) {
		return false;
	}

	n->minmtu = settled;
	n->maxmtu = settled;
	n->mtuprobes = 32;
	len = (uint16_t)(settled + 8);

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = 1;
	packet.len = len;
	mtu_probe_h(mesh, n, &packet, len);
	return n->mtuprobes == 30 && n->maxmtu == len && n->minmtu == len;
}

/* Caller holds mesh->mutex. Plants an 8-probe collapse and runs Fixing MTU. */
bool net_devtool_fix_early_pmtu(meshlink_handle_t *mesh, node_t *n, uint16_t len) {
	if(!mesh || !n || !n->status.udp_confirmed || len < MINMTU || len > MTU) {
		return false;
	}

	n->minmtu = len;
	n->maxmtu = len;
	n->mtuprobes = 8;
	mtu_probe_fix_if_ready(mesh, n);
	return n->mtuprobes == 31 && n->mtu == len && n->minmtu == len;
}

/* Caller holds mesh->mutex. Parked-liveness and raise-reply cases. */
bool net_devtool_pmtu_liveness_cover_unit(meshlink_handle_t *mesh, node_t *n) {
	sockaddr_t saved_addr;
	sockaddr_t saved_from;
	data_route_t saved_route;
	udp_rebind_t saved_rebind;
	address_source_t saved_src;
	path_tier_t saved_tier;
	uint16_t saved_min;
	uint16_t saved_max;
	uint16_t saved_mtu;
	uint16_t saved_pending;
	int saved_probes;
	time_t saved_next;
	bool saved_confirmed;
	bool saved_force;
	bool ok = true;
	vpn_packet_t packet;

#define CHECK_P(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "pmtu liveness cover failed: %s", #cond); \
		ok = false; \
		goto done; \
	} \
} while(0)

	if(!mesh || !n || !n->address.sa.sa_family) {
		return false;
	}

	path_copy_sockaddr(&saved_addr, &n->address);
	path_copy_sockaddr(&saved_from, &n->last_udp_from);
	saved_route = n->active_route;
	saved_rebind = n->udp_rebind;
	saved_src = n->address_source;
	saved_tier = n->udp_tier;
	saved_min = n->minmtu;
	saved_max = n->maxmtu;
	saved_mtu = n->mtu;
	saved_pending = n->pmtu_raise_pending;
	saved_probes = n->mtuprobes;
	saved_next = n->pmtu_increase_next;
	saved_confirmed = n->status.udp_confirmed;
	saved_force = n->devtool_force_meta;
	path_rebind_cancel(mesh, n);

	n->devtool_force_meta = false;
	n->status.udp_confirmed = true;
	path_copy_sockaddr(&n->last_udp_from, &n->address);

	n->minmtu = 1200;
	n->maxmtu = 1200;
	n->mtu = 1200;
	n->mtuprobes = 32;
	n->pmtu_raise_pending = 1208;

	memset(&packet, 0, sizeof packet);
	packet.probe = true;
	packet.data[0] = 1;
	packet.len = 64;
	mtu_probe_h(mesh, n, &packet, 64);
	CHECK_P(n->mtuprobes == 30);

	packet.len = 1208;
	mtu_probe_h(mesh, n, &packet, 1208);
	CHECK_P(n->maxmtu == 1208 && n->minmtu == 1208 && n->pmtu_raise_pending == 0);

	n->minmtu = 1200;
	n->maxmtu = 1200;
	n->mtu = 1200;
	n->mtuprobes = 30;
	n->pmtu_raise_pending = 0;
	mtu_probe_h(mesh, n, &packet, 1208);
	CHECK_P(n->maxmtu == 1200 && n->minmtu == 1200);

	n->mtuprobes = 32;
	n->minmtu = 1200;
	n->maxmtu = 1200;
	{
		uint64_t nonce = 0x5eed;

		memcpy(packet.data + PROBE_NONCE_OFFSET, &nonce, sizeof nonce);
		packet.len = 64;
		path_copy_sockaddr(&n->last_udp_from, &n->address);
		mtu_probe_h(mesh, n, &packet, 64);
		CHECK_P(n->mtuprobes == 30);
		CHECK_P(n->minmtu == 1200 && n->maxmtu == 1200);
	}

	n->mtuprobes = 32;
	n->last_udp_from.in.sin_port = htons(4001);
	mtu_probe_h(mesh, n, &packet, 64);
	CHECK_P(n->mtuprobes == 32);

	n->minmtu = 0;
	n->mtuprobes = 32;
	path_copy_sockaddr(&n->last_udp_from, &n->address);
	mtu_probe_h(mesh, n, &packet, 64);
	CHECK_P(n->mtuprobes == 32);

	/* Commit zeros last_udp_from. The snapshot taken before that must still match. */
	n->minmtu = 1200;
	n->maxmtu = 1200;
	n->mtu = 1200;
	n->mtuprobes = 32;
	n->pmtu_raise_pending = 0;
	path_copy_sockaddr(&n->last_udp_from, &n->address);
	n->udp_rebind.challenge_active = true;
	n->udp_rebind.challenge_nonce = 0x1111;
	n->udp_rebind.challenge_session = n->session_id;
	n->udp_rebind.challenge_network_epoch = mesh->lan_network_epoch;
	path_copy_sockaddr(&n->udp_rebind.challenge_endpoint, &n->address);
	{
		uint64_t nonce = 0x1111;

		memcpy(packet.data + PROBE_NONCE_OFFSET, &nonce, sizeof nonce);
		packet.len = 64;
		mtu_probe_h(mesh, n, &packet, 64);
	}
	CHECK_P(n->mtuprobes == 30);
	CHECK_P(!n->last_udp_from.sa.sa_family);
	CHECK_P(!sockaddrcmp(&n->address, &saved_addr));

done:
	path_rebind_cancel(mesh, n);
	n->udp_rebind.seen = saved_rebind.seen;
	n->udp_rebind.migrated = saved_rebind.migrated;
	n->udp_rebind.failed = saved_rebind.failed;
	n->udp_rebind.current_rx_at = saved_rebind.current_rx_at;
	n->active_route = saved_route;
	n->udp_tier = saved_tier;
	n->minmtu = saved_min;
	n->maxmtu = saved_max;
	n->mtu = saved_mtu;
	n->pmtu_raise_pending = saved_pending;
	n->mtuprobes = saved_probes;
	n->pmtu_increase_next = saved_next;
	n->status.udp_confirmed = saved_confirmed;
	n->devtool_force_meta = saved_force;
	path_copy_sockaddr(&n->last_udp_from, &saved_from);
	update_node_udp_from(mesh, n, &saved_addr, saved_src);
	channel_refresh_carrier(mesh, n);
	return ok;
#undef CHECK_P
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
		return;
	}

	/* Direct, authenticated UDP only. META-carried and relayed SPTPS do not land here. */
	path_note_authenticated_udp_observation(mesh, n, &n->last_udp_from);
	path_observe_punch_ingress(mesh, n, &n->last_udp_from);
	path_observe_authenticated_rx(mesh, n, &n->last_udp_from);
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

			channel_refresh_mtu(mesh, to);
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
		if(hop->relay_oversize_drops < UINT32_MAX) {
			hop->relay_oversize_drops++;
		}

		if(mesh->loop.now.tv_sec >= hop->relay_oversize_logged_at + 10) {
			hop->relay_oversize_logged_at = mesh->loop.now.tv_sec;
			logger(mesh, MESHLINK_INFO, "Dropping %zu-byte relay record via %s: hop limit %u",
			       len, hop->name, (unsigned)limit);
		}

		return true;
	}

	if(!send_sptps_via_udp(mesh, hop, data, len)) {
		return false;
	}

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
		if(to->devtool_drop_direct_udp_records > 0) {
			to->devtool_drop_direct_udp_records--;
			return true;
		}

		path_copy_sockaddr(&to->app_udp_override, &target.udp_endpoint);
		to->app_udp_override_active = true;
		ok = send_sptps_via_udp(mesh, to, data, len);
		to->app_udp_override_active = false;
		return ok;
	}

	if(target.kind == DATA_ROUTE_RELAY && target.relay_carrier == RELAY_CARRIER_UDP && target.first_hop) {
		uint8_t wrapped[MAXSIZE];
		size_t wlen = sizeof(wrapped);

		if(relay_encode(mesh->self->name, to->name, data, len, wrapped, &wlen)) {
			path_copy_sockaddr(&target.first_hop->app_udp_override, &target.udp_endpoint);
			target.first_hop->app_udp_override_active = true;
			ok = relay_send_outer_record(mesh, target.first_hop, mesh->self->name, to->name, wrapped, wlen);
			target.first_hop->app_udp_override_active = false;
			return ok;
		}
	}

	if(target.kind == DATA_ROUTE_RELAY && target.first_hop) {
		return send_sptps_via_meta_conn(mesh, to, target.first_hop->connection, data, len);
	}

	return send_sptps_via_meta_conn(mesh, to, to->connection, data, len);
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

			if(!select_listen_socket(mesh, &dest, &sock)) {
				return true;
			}

			node_udp_cache_alias(mesh, to, &dest);

			if(sendto(mesh->listen_socket[sock].udp.fd, data, len, 0, &dest.sa, SALEN(dest.sa)) < 0 && !sockwouldblock(sockerrno) && !sockmsgsize(sockerrno)) {
				logger(mesh, MESHLINK_WARNING, "Error sending local UDP probe to %s: %s", to->name, sockstrerror(sockerrno));
			}

			return true;
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
			node_kex_clear(mesh, from);

			if(from->utcp) {
				utcp_reset_timers(from->utcp);
			}

			path_apply_pending_punch_hint(mesh, from);
			path_punch_arm_ingress(mesh, from);
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
