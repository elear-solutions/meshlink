/*
    protocol_key_cover.c -- punch endpoint, ANS_KEY, and UDP rebind cover unit
    Copyright (C) 2026 Elear Solutions

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
#include "protocol_key_internal.h"
#include "relay.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

#include <string.h>

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
	PUNCH_CHECK(!path_get_fresh_udp_observation(mesh, src, &out));
	path_clear_udp_observation(src);
	hint = str2sockaddr("127.0.0.1", "4000");
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(!path_get_fresh_udp_observation(mesh, src, &out));
	path_clear_udp_observation(src);
	hint = str2sockaddr("169.254.1.1", "4000");
	path_note_authenticated_udp_observation(mesh, src, &hint);
	PUNCH_CHECK(!path_get_fresh_udp_observation(mesh, src, &out));
	path_clear_udp_observation(src);
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
	PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);
	PUNCH_CHECK(src->peer_udp.challenge.active);
	PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_NMN_HINT);
	PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &hint));
	{
		sockaddr_t probed;

		PUNCH_CHECK(path_punch_last_probe_dest(mesh, &probed));
		PUNCH_CHECK(!sockaddrcmp(&probed, &hint));
	}
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
	src->address = hint;
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
		PUNCH_CHECK(!sockaddrcmp(&src->address, &hint));
		PUNCH_CHECK(src->peer_udp.challenge.active);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_NMN_HINT);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &newer));
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
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);
		PUNCH_CHECK(!src->status.udp_confirmed);
		PUNCH_CHECK(src->peer_udp.challenge.active);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_NMN_HINT);
		PUNCH_CHECK(ntohs(src->peer_udp.challenge.endpoint.in.sin_port) == 4400);
		PUNCH_CHECK(src->peer_udp.requests_sent == requests_before);
		PUNCH_CHECK(src->peer_udp.request_step == 0);
	}
	{
		node_t *during_bb = mesh->backbone.node;
		char *during_name = mesh->backbone.name;
		int saved_class = mesh->self->devclass;
		sockaddr_t repl;
		sockaddr_t observed_hint;
		char req[160];

		mesh->self->devclass = DEV_CLASS_BACKBONE;
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
		mesh->ans_witness_rewritten = false;
		mesh->ans_witness_has_addr = false;
		PUNCH_CHECK(ans_key_h(mesh, &live, req));
		PUNCH_CHECK(mesh->ans_witness_rewritten && mesh->ans_witness_has_addr);
		PUNCH_CHECK(!strcmp(mesh->ans_witness_host, "203.0.113.10"));
		PUNCH_CHECK(!strcmp(mesh->ans_witness_port, "4000"));
		PUNCH_CHECK(!strchr(mesh->ans_witness_host, ' '));
		PUNCH_CHECK(!strchr(mesh->ans_witness_port, ' '));
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);
		PUNCH_CHECK(dst->address.sa.sa_family == AF_UNSPEC);
		path_clear_udp_observation(src);
		src->status.udp_confirmed = false;
		memset(&src->address, 0, sizeof src->address);
		mesh->ans_witness_rewritten = false;
		mesh->ans_witness_has_addr = false;
		PUNCH_CHECK(ans_key_h(mesh, &live, req));
		PUNCH_CHECK(mesh->ans_witness_rewritten && !mesh->ans_witness_has_addr);
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

	{
		sockaddr_t ingress = str2sockaddr("203.0.113.50", "51873");
		sockaddr_t moving = str2sockaddr("203.0.113.10", "57670");
		sockaddr_t local = str2sockaddr("10.9.9.9", "5000");
		sockaddr_t changed = str2sockaddr("203.0.113.50", "51874");
		sockaddr_t dest;
		uint64_t nonce;
		uint64_t saved_epoch = mesh->lan_network_epoch;
		uint32_t observed_session;

		path_punch_cancel(mesh, src);
		src->devtool_force_meta = true;
		src->status.validkey = true;
		src->status.udp_confirmed = false;
		src->status.reachable = true;
		src->session_id = 11;
		src->peer_udp.channel_count = 1;
		src->peer_udp.hint_failed = false;
		memset(&src->address, 0, sizeof src->address);
		memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
		memset(&src->peer_udp.ingress, 0, sizeof src->peer_udp.ingress);
		memset(&src->peer_udp.failed_ingress, 0, sizeof src->peer_udp.failed_ingress);
		timeout_del(&mesh->loop, &src->promotion_timer);
		memset(&src->promotion_candidate, 0, sizeof src->promotion_candidate);

		path_observe_punch_ingress(mesh, src, &ingress);
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);
		PUNCH_CHECK(src->peer_udp.challenge.active);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &ingress));
		nonce = src->peer_udp.challenge.nonce;
		PUNCH_CHECK(nonce != 0);
		path_observe_punch_ingress(mesh, src, &ingress);
		PUNCH_CHECK(src->peer_udp.challenge.nonce == nonce);
		path_note_punch_endpoint(mesh, src, &moving);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
		PUNCH_CHECK(src->peer_udp.challenge.nonce == nonce);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &ingress));
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.last_hint, &moving));
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);

		path_observe_punch_ingress(mesh, src, &changed);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &changed));
		PUNCH_CHECK(src->peer_udp.challenge.nonce != nonce);

		path_punch_cancel(mesh, src);
		memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
		src->peer_udp.hint_failed = false;
		path_note_punch_endpoint(mesh, src, &moving);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_NMN_HINT);
		path_observe_punch_ingress(mesh, src, &ingress);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &ingress));
		nonce = src->peer_udp.challenge.nonce;
		PUNCH_CHECK(!path_punch_accept_reply(mesh, src, &ingress, nonce + 1));
		PUNCH_CHECK(!src->status.udp_confirmed);
		PUNCH_CHECK(!path_punch_accept_reply(mesh, src, &moving, nonce));
		PUNCH_CHECK(!src->status.udp_confirmed);
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);
		PUNCH_CHECK(path_punch_accept_reply(mesh, src, &ingress, nonce));
		PUNCH_CHECK(src->status.udp_confirmed);
		PUNCH_CHECK(!sockaddrcmp(&src->address, &ingress));
		PUNCH_CHECK(!src->peer_udp.challenge.active);
		timeout_del(&mesh->loop, &src->plpmtu.timer);
		timeout_del(&mesh->loop, &src->promotion_timer);
		path_scheduler_cancel(mesh, src, PATH_TX_CHANNEL_PROMOTION);
		memset(&src->promotion_candidate, 0, sizeof src->promotion_candidate);

		src->status.udp_confirmed = false;
		memset(&src->address, 0, sizeof src->address);
		observed_session = src->udp_observation.session_id;
		path_observe_punch_ingress(mesh, src, &local);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &local));
		PUNCH_CHECK(src->udp_observation.session_id == observed_session);
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);

		path_punch_cancel(mesh, src);
		src->status.udp_confirmed = false;
		src->peer_udp.hint_failed = false;
		memset(&src->address, 0, sizeof src->address);
		memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
		memset(&src->peer_udp.failed_ingress, 0, sizeof src->peer_udp.failed_ingress);
		path_note_punch_endpoint(mesh, src, &moving);
		path_observe_punch_ingress(mesh, src, &ingress);
		src->peer_udp.challenge.attempts = PATH_PUNCH_CHALLENGE_ATTEMPTS;
		path_punch_challenge_timeout(mesh, src);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.failed_ingress, &ingress));
		PUNCH_CHECK(src->peer_udp.challenge.active);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_NMN_HINT);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &moving));
		PUNCH_CHECK(!src->status.udp_confirmed);
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);
		src->peer_udp.challenge.attempts = PATH_PUNCH_CHALLENGE_ATTEMPTS;
		path_punch_challenge_timeout(mesh, src);
		PUNCH_CHECK(src->peer_udp.hint_failed);
		PUNCH_CHECK(!src->peer_udp.challenge.active);
		PUNCH_CHECK(!path_unconfirmed_punch_dest(mesh, src, &dest));

		path_observe_punch_ingress(mesh, src, &ingress);
		PUNCH_CHECK(!src->peer_udp.challenge.active);
		changed.in.sin_port = htons(51875);
		path_observe_punch_ingress(mesh, src, &changed);
		PUNCH_CHECK(src->peer_udp.challenge.active);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &changed));

		mesh->lan_network_epoch = saved_epoch + 1;
		path_punch_challenge_timeout(mesh, src);
		PUNCH_CHECK(!src->peer_udp.challenge.active);
		mesh->lan_network_epoch = saved_epoch;

		path_punch_cancel(mesh, src);
		src->status.validkey = false;
		src->status.udp_confirmed = false;
		src->peer_udp.hint_failed = false;
		memset(&src->address, 0, sizeof src->address);
		memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
		memset(&src->peer_udp.pending_hint, 0, sizeof src->peer_udp.pending_hint);
		path_observe_punch_ingress(mesh, src, &ingress);
		PUNCH_CHECK(!src->peer_udp.challenge.active);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.ingress, &ingress));
		path_note_punch_endpoint(mesh, src, &moving);
		PUNCH_CHECK(src->peer_udp.pending_hint.sa.sa_family != AF_UNSPEC);
		PUNCH_CHECK(!src->peer_udp.challenge.active);
		src->status.validkey = true;
		path_apply_pending_punch_hint(mesh, src);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_NMN_HINT);
		path_punch_arm_ingress(mesh, src);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &ingress));
		PUNCH_CHECK(src->address.sa.sa_family == AF_UNSPEC);

		src->session_id = 99;
		path_clear_udp_observation(src);
		PUNCH_CHECK(!src->peer_udp.challenge.active);
		PUNCH_CHECK(!src->peer_udp.ingress.sa.sa_family);
		src->session_id = 11;
		src->status.validkey = true;
	}

	/* Authenticated ingress is not exported. PMTU stays down until confirm.
	   Key loss drops a staged hint and keeps ingress. Demotion prefers ingress. */
	{
		sockaddr_t priv = str2sockaddr("10.9.9.9", "5000");
		sockaddr_t linklocal = str2sockaddr("169.254.8.8", "5000");
		sockaddr_t pub = str2sockaddr("203.0.113.77", "4242");
		sockaddr_t saved_addr;
		uint64_t nonce;
		bool saved_force;
		unsigned exports;

		path_punch_cancel(mesh, src);
		timeout_del(&mesh->loop, &src->plpmtu.timer);
		src->devtool_force_meta = true;
		src->status.validkey = true;
		src->status.reachable = true;
		src->status.udp_confirmed = false;
		src->peer_udp.channel_count = 1;
		src->plpmtu.state = PLPMTU_DISABLED;
		src->plpmtu.size = 0;
		memset(&src->address, 0, sizeof src->address);
		memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
		memset(&src->peer_udp.pending_hint, 0, sizeof src->peer_udp.pending_hint);
		memset(&src->peer_udp.failed_ingress, 0, sizeof src->peer_udp.failed_ingress);
		src->peer_udp.hint_failed = false;

		exports = path_punch_test_ans_exports(mesh);
		path_observe_punch_ingress(mesh, src, &priv);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
		PUNCH_CHECK(!src->plpmtu.timer.cb);
		PUNCH_CHECK(src->plpmtu.state == PLPMTU_DISABLED);
		nonce = src->peer_udp.challenge.nonce;
		PUNCH_CHECK(path_punch_accept_reply(mesh, src, &priv, nonce));
		PUNCH_CHECK(path_punch_test_ans_exports(mesh) == exports);
		PUNCH_CHECK(src->status.udp_confirmed);
		PUNCH_CHECK(!src->plpmtu.timer.cb);

		src->status.udp_confirmed = false;
		memset(&src->address, 0, sizeof src->address);
		path_punch_cancel(mesh, src);
		exports = path_punch_test_ans_exports(mesh);
		path_observe_punch_ingress(mesh, src, &linklocal);
		nonce = src->peer_udp.challenge.nonce;
		PUNCH_CHECK(path_punch_accept_reply(mesh, src, &linklocal, nonce));
		PUNCH_CHECK(path_punch_test_ans_exports(mesh) == exports);
		PUNCH_CHECK(!src->plpmtu.timer.cb);

		src->status.udp_confirmed = false;
		memset(&src->address, 0, sizeof src->address);
		path_punch_cancel(mesh, src);
		src->peer_udp.hint_failed = false;
		path_note_punch_endpoint(mesh, src, &pub);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_NMN_HINT);
		nonce = src->peer_udp.challenge.nonce;
		exports = path_punch_test_ans_exports(mesh);
		PUNCH_CHECK(path_punch_accept_reply(mesh, src, &pub, nonce));
		PUNCH_CHECK(path_punch_test_ans_exports(mesh) == exports + 1);
		PUNCH_CHECK(src->status.udp_confirmed);
		timeout_del(&mesh->loop, &src->plpmtu.timer);

		src->status.udp_confirmed = false;
		memset(&src->address, 0, sizeof src->address);
		path_punch_cancel(mesh, src);
		path_observe_punch_ingress(mesh, src, &priv);
		nonce = src->peer_udp.challenge.nonce;
		saved_force = src->devtool_force_meta;
		src->devtool_force_meta = false;
		src->status.reachable = false;
		PUNCH_CHECK(!src->plpmtu.timer.cb);
		PUNCH_CHECK(path_punch_accept_reply(mesh, src, &priv, nonce));
		PUNCH_CHECK(src->plpmtu.timer.cb);
		src->devtool_force_meta = saved_force;
		src->status.reachable = true;
		timeout_del(&mesh->loop, &src->plpmtu.timer);
		PUNCH_CHECK(!path_punch_accept_reply(mesh, src, &priv, nonce));
		PUNCH_CHECK(!src->plpmtu.timer.cb);

		src->status.validkey = false;
		src->status.udp_confirmed = false;
		path_note_punch_endpoint(mesh, src, &pub);
		PUNCH_CHECK(src->peer_udp.pending_hint.sa.sa_family != AF_UNSPEC);
		PUNCH_CHECK(src->peer_udp.ingress.sa.sa_family != AF_UNSPEC);
		src->status.validkey = true;
		node_set_validkey(mesh, src, false);
		PUNCH_CHECK(!src->peer_udp.pending_hint.sa.sa_family);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.ingress, &priv));

		src->status.validkey = true;
		src->status.udp_confirmed = false;
		src->status.reachable = true;
		src->devtool_force_meta = true;
		src->peer_udp.channel_count = 1;
		src->peer_udp.hint_failed = false;
		memset(&src->peer_udp.failed_ingress, 0, sizeof src->peer_udp.failed_ingress);
		path_punch_cancel(mesh, src);
		path_observe_punch_ingress(mesh, src, &priv);
		path_note_punch_endpoint(mesh, src, &pub);
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
		path_punch_cancel(mesh, src);
		src->address = pub;
		saved_addr = src->address;
		src->status.udp_confirmed = true;
		src->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
		path_note_udp_demoted_reason(mesh, src, "cover ingress demotion");
		PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
		PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &priv));
		PUNCH_CHECK(!sockaddrcmp(&src->address, &saved_addr));
		PUNCH_CHECK(!src->status.udp_confirmed);

		path_punch_cancel(mesh, src);
		src->status.udp_confirmed = false;
		src->devtool_force_meta = true;
		src->peer_udp.hint_failed = true;
		memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
		path_observe_punch_ingress(mesh, src, &priv);
		src->peer_udp.challenge.attempts = 0;
		src->peer_udp.challenge.deadline = mesh->loop.now;
		src->peer_udp.challenge.deadline.tv_sec -= 1;
		path_punch_challenge_timeout(mesh, src);
		PUNCH_CHECK(!src->peer_udp.challenge.active);
		PUNCH_CHECK(!src->punch_timer.cb);

		path_punch_cancel(mesh, src);
		timeout_del(&mesh->loop, &src->plpmtu.timer);
		timeout_del(&mesh->loop, &src->punch_timer);
		path_punch_cancel(mesh, src);

		/* Nonce zero cannot bypass an active private challenge. A matching
		   reply confirms that source. With no challenge, a local echo
		   installs the reply source rather than a stale n->address. */
		{
			sockaddr_t echo_priv = str2sockaddr("10.8.8.8", "5000");
			sockaddr_t echo_other = str2sockaddr("10.8.8.9", "5000");
			sockaddr_t echo_stale = str2sockaddr("203.0.113.88", "9");
			sockaddr_t echo_pub = str2sockaddr("198.51.100.8", "4000");
			uint64_t echo_nonce;
			unsigned echo_exports;

			path_punch_cancel(mesh, src);
			timeout_del(&mesh->loop, &src->plpmtu.timer);
			src->devtool_force_meta = true;
			src->status.validkey = true;
			src->status.reachable = true;
			src->status.udp_confirmed = false;
			src->peer_udp.channel_count = 1;
			src->session_id = 11;
			src->plpmtu.state = PLPMTU_DISABLED;
		src->plpmtu.size = 0;
			memset(&src->address, 0, sizeof src->address);
			memset(&src->peer_udp.last_hint, 0, sizeof src->peer_udp.last_hint);
			memset(&src->peer_udp.failed_ingress, 0, sizeof src->peer_udp.failed_ingress);
			src->peer_udp.hint_failed = false;

			path_observe_punch_ingress(mesh, src, &echo_priv);
			PUNCH_CHECK(src->peer_udp.challenge.active);
			PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
			echo_nonce = src->peer_udp.challenge.nonce;
			echo_exports = path_punch_test_ans_exports(mesh);
			PUNCH_CHECK(path_try_confirm_udp_probe_reply(mesh, src, &echo_priv, 0));
			PUNCH_CHECK(!src->status.udp_confirmed);
			PUNCH_CHECK(!src->address.sa.sa_family);
			PUNCH_CHECK(path_try_confirm_udp_probe_reply(mesh, src, &echo_other, echo_nonce));
			PUNCH_CHECK(!src->status.udp_confirmed);
			PUNCH_CHECK(path_punch_test_ans_exports(mesh) == echo_exports);
			PUNCH_CHECK(path_try_confirm_udp_probe_reply(mesh, src, &echo_priv, echo_nonce));
			PUNCH_CHECK(src->status.udp_confirmed);
			PUNCH_CHECK(!sockaddrcmp(&src->address, &echo_priv));
			PUNCH_CHECK(path_punch_test_ans_exports(mesh) == echo_exports);
			timeout_del(&mesh->loop, &src->plpmtu.timer);

			path_punch_cancel(mesh, src);
			src->status.udp_confirmed = false;
			src->address = echo_stale;
			echo_exports = path_punch_test_ans_exports(mesh);
			PUNCH_CHECK(!path_try_confirm_udp_probe_reply(mesh, src, &echo_priv, 0));
			PUNCH_CHECK(src->status.udp_confirmed);
			PUNCH_CHECK(!sockaddrcmp(&src->address, &echo_priv));
			PUNCH_CHECK(path_punch_test_ans_exports(mesh) == echo_exports);

			path_punch_cancel(mesh, src);
			src->status.udp_confirmed = false;
			memset(&src->address, 0, sizeof src->address);
			PUNCH_CHECK(path_try_confirm_udp_probe_reply(mesh, src, &echo_pub, 0));
			PUNCH_CHECK(!src->status.udp_confirmed);
			PUNCH_CHECK(src->peer_udp.challenge.provenance == PUNCH_PROV_AUTH_INGRESS);
			PUNCH_CHECK(!sockaddrcmp(&src->peer_udp.challenge.endpoint, &echo_pub));
			path_punch_cancel(mesh, src);
			timeout_del(&mesh->loop, &src->plpmtu.timer);
			timeout_del(&mesh->loop, &src->punch_timer);
		}
	}

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
		timeout_del(&mesh->loop, &src->plpmtu.timer);
		timeout_del(&mesh->loop, &src->promotion_timer);
		path_suspect_stop(mesh, src);
		path_scheduler_cancel_node(mesh, src);
		buffer_clear(&live.outbuf);
		node_del(mesh, src);
	}

	if(dst) {
		dst->connection = NULL;
		timeout_del(&mesh->loop, &dst->plpmtu.timer);
		timeout_del(&mesh->loop, &dst->promotion_timer);
		path_suspect_stop(mesh, dst);
		path_scheduler_cancel_node(mesh, dst);
		node_del(mesh, dst);
	}

	timeout_del(&mesh->loop, &peer.plpmtu.timer);
	timeout_del(&mesh->loop, &peer.promotion_timer);
	timeout_del(&mesh->loop, &peer.punch_timer);
	timeout_del(&mesh->loop, &route.promotion_timer);
	timeout_del(&mesh->loop, &route.punch_timer);
	path_suspect_stop(mesh, &peer);
	path_suspect_stop(mesh, &route);
	path_scheduler_cancel_node(mesh, &peer);
	path_scheduler_cancel_node(mesh, &route);
#undef PUNCH_CHECK
	return ok;
}

static void rebind_plant(meshlink_handle_t *mesh, node_t *n, const char *port) {
	memset(&n->udp_rebind, 0, sizeof n->udp_rebind);
	memset(&n->active_route, 0, sizeof n->active_route);
	n->status.udp_confirmed = true;
	n->status.validkey = true;
	n->status.reachable = true;
	n->devtool_force_meta = true;
	n->devclass = DEV_CLASS_STATIONARY;
	n->session_id = 11;
	n->plpmtu.size = 1414;
	n->plpmtu.state = PLPMTU_COMPLETE;
	n->address = str2sockaddr("203.0.113.50", port);
	n->udp_tier = PATH_TIER_DIRECT_WAN_UDP;
	n->active_route.kind = DATA_ROUTE_DIRECT_UDP;
	n->active_route.udp_endpoint = n->address;
	n->active_route.endpoint_source = ADDR_SRC_UDP_REFLEXIVE;
	n->active_route.selected_at = mesh->loop.now;
	n->active_route.selected_at.tv_sec -= 100;
	n->udp_rebind.current_rx_at = mesh->loop.now;
}

bool rebind_cover_unit(meshlink_handle_t *mesh) {
	node_t *n = NULL;
	int saved_class = 0;
	struct timespec saved_now;
	struct timespec selected;
	sockaddr_t live;
	sockaddr_t moved;
	sockaddr_t other_ip;
	sockaddr_t late;
	sockaddr_t pinned;
	uint64_t nonce;
	bool ok = false;
	unsigned i;

	if(!mesh || !mesh->self) {
		return false;
	}

#define REBIND_CHECK(cond) do { \
	if(!(cond)) { \
		logger(mesh, MESHLINK_ERROR, "rebind_cover_unit failed: %s", #cond); \
		goto done; \
	} \
} while(0)

	saved_class = mesh->self->devclass;
	saved_now = mesh->loop.now;
	mesh->self->devclass = DEV_CLASS_STATIONARY;
	n = new_node();
	n->name = xstrdup("rebindsrc");
	n->mesh = mesh;
	node_add(mesh, n);
	rebind_plant(mesh, n, "58402");
	selected = n->active_route.selected_at;
	live = n->address;
	moved = str2sockaddr("203.0.113.50", "54887");
	other_ip = str2sockaddr("203.0.113.99", "54887");
	late = str2sockaddr("203.0.113.50", "58402");

	path_rebind_observe_rx(mesh, n, &live);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	REBIND_CHECK(n->udp_rebind.seen == 0);

	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	REBIND_CHECK(n->udp_rebind.seen == 1);
	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(n->udp_rebind.seen == 1);
	REBIND_CHECK(n->udp_rebind.candidate_packets == 2);

	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(n->udp_rebind.challenge_active);
	REBIND_CHECK(n->udp_rebind.challenge_nonce != 0);
	nonce = n->udp_rebind.challenge_nonce;
	REBIND_CHECK(!path_rebind_accept_reply(mesh, n, &moved, nonce ^ 1));
	REBIND_CHECK(!sockaddrcmp(&n->address, &live));
	REBIND_CHECK(!path_rebind_accept_reply(mesh, n, &live, nonce));
	REBIND_CHECK(n->udp_rebind.challenge_active);
	REBIND_CHECK(path_rebind_accept_reply(mesh, n, &moved, nonce));
	REBIND_CHECK(n->status.udp_confirmed);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	REBIND_CHECK(!sockaddrcmp(&n->address, &moved));
	REBIND_CHECK(!sockaddrcmp(&n->active_route.udp_endpoint, &moved));
	REBIND_CHECK(n->active_route.kind == DATA_ROUTE_DIRECT_UDP);
	REBIND_CHECK(n->active_route.selected_at.tv_sec == selected.tv_sec);
	REBIND_CHECK(n->active_route.selected_at.tv_nsec == selected.tv_nsec);
	REBIND_CHECK(n->plpmtu.size == 1414);
	REBIND_CHECK(n->plpmtu.state == PLPMTU_COMPLETE);
	REBIND_CHECK(n->udp_rebind.migrated == 1);

	path_rebind_observe_rx(mesh, n, &late);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	REBIND_CHECK(!sockaddrcmp(&n->address, &moved));

	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &other_ip);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	REBIND_CHECK(!sockaddrcmp(&n->address, &moved));
	REBIND_CHECK(n->plpmtu.size == 1414);
	REBIND_CHECK(n->plpmtu.state == PLPMTU_COMPLETE);

	/* A rebind during relay residency must retarget the already-proved
	   direct candidate immediately, then commit without a stale-port cycle. */
	rebind_plant(mesh, n, "49000");
	n->peer_udp.channel_count = 1;
	n->active_route.kind = DATA_ROUTE_RELAY;
	n->active_route.relay_carrier = RELAY_CARRIER_META_CANONICAL;
	n->active_route.first_hop = mesh->backbone.node;
	n->active_route.selected_at = mesh->loop.now;
	n->active_route.selected_at.tv_sec -= 5;
	selected = n->active_route.selected_at;
	live = n->address;
	moved = str2sockaddr("203.0.113.50", "49001");
	memset(&n->promotion_candidate, 0, sizeof n->promotion_candidate);
	n->promotion_candidate.active = true;
	n->promotion_candidate.kind = DATA_ROUTE_DIRECT_UDP;
	n->promotion_candidate.endpoint = live;
	n->promotion_candidate.source = ADDR_SRC_UDP_REFLEXIVE;
	n->promotion_candidate.capability = PATH_CAP_UDP;
	n->promotion_candidate.successful_rounds = PATH_PROMOTION_ROUNDS;
	n->promotion_candidate.first_success = mesh->loop.now;
	n->promotion_candidate.first_success.tv_sec -= 2;
	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(n->udp_rebind.challenge_active);
	nonce = n->udp_rebind.challenge_nonce;
	n->devtool_force_meta = false;
	REBIND_CHECK(!path_rebind_accept_reply(mesh, n, &moved, nonce ^ 1));
	REBIND_CHECK(path_rebind_accept_reply(mesh, n, &moved, nonce));
	REBIND_CHECK(!sockaddrcmp(&n->address, &moved));
	REBIND_CHECK(n->active_route.kind == DATA_ROUTE_RELAY);
	REBIND_CHECK(n->active_route.selected_at.tv_sec == selected.tv_sec);
	REBIND_CHECK(n->active_route.selected_at.tv_nsec == selected.tv_nsec);
	REBIND_CHECK(n->promotion_candidate.active);
	REBIND_CHECK(!n->promotion_candidate.nonce);
	REBIND_CHECK(!sockaddrcmp(&n->promotion_candidate.endpoint, &moved));
	REBIND_CHECK(n->promotion_candidate.source == ADDR_SRC_UDP_REFLEXIVE);
	REBIND_CHECK(n->promotion_candidate.capability == PATH_CAP_UDP);
	REBIND_CHECK(n->promotion_candidate.first_success.tv_sec == mesh->loop.now.tv_sec);
	REBIND_CHECK(n->plpmtu.size == 1414);
	path_route_tick(mesh, n);
	REBIND_CHECK(n->active_route.kind == DATA_ROUTE_RELAY);
	n->promotion_candidate.first_success.tv_sec -= 1;
	n->active_route.selected_at.tv_sec -= 5;
	path_route_tick(mesh, n);
	REBIND_CHECK(n->active_route.kind == DATA_ROUTE_DIRECT_UDP);
	REBIND_CHECK(!n->promotion_candidate.active);
	REBIND_CHECK(!sockaddrcmp(&n->active_route.udp_endpoint, &moved));
	REBIND_CHECK(n->plpmtu.size == 1414);

	rebind_plant(mesh, n, "49444");
	pinned = n->address;
	moved = str2sockaddr("203.0.113.50", "53682");
	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &moved);
	n->udp_rebind.challenge_deadline = mesh->loop.now;
	n->udp_rebind.challenge_deadline.tv_sec -= 1;
	path_rebind_challenge_timeout(mesh, n);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	REBIND_CHECK(n->udp_rebind.failed == 1);
	REBIND_CHECK(!sockaddrcmp(&n->address, &pinned));
	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(!n->udp_rebind.challenge_active);

	rebind_plant(mesh, n, "51000");
	moved = str2sockaddr("203.0.113.50", "51001");
	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(n->udp_rebind.seen >= 1);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	REBIND_CHECK(path_rebind_try_rescue(mesh, n));
	REBIND_CHECK(n->status.udp_confirmed);
	REBIND_CHECK(n->udp_rebind.challenge_active);
	n->udp_rebind.challenge_deadline = mesh->loop.now;
	n->udp_rebind.challenge_deadline.tv_sec -= 1;
	path_rebind_challenge_timeout(mesh, n);
	REBIND_CHECK(!path_rebind_try_rescue(mesh, n));
	path_note_udp_demoted_reason(mesh, n, "probe give-up");
	REBIND_CHECK(!n->status.udp_confirmed);
	REBIND_CHECK(!n->udp_rebind.challenge_active);

	rebind_plant(mesh, n, "52000");
	moved = str2sockaddr("203.0.113.50", "52001");
	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(n->udp_rebind.challenge_active);
	n->session_id = 99;
	path_rebind_challenge_timeout(mesh, n);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	n->session_id = 11;

	rebind_plant(mesh, n, "53000");
	moved = str2sockaddr("203.0.113.50", "53001");
	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &moved);
	node_set_validkey(mesh, n, false);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	n->status.validkey = true;

	rebind_plant(mesh, n, "54000");
	moved = str2sockaddr("203.0.113.50", "54001");
	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &moved);
	n->udp_rebind.challenge_network_epoch = mesh->lan_network_epoch + 3;
	path_route_tick(mesh, n);
	REBIND_CHECK(!n->udp_rebind.challenge_active);

	rebind_plant(mesh, n, "55000");
	moved = str2sockaddr("203.0.113.50", "55001");
	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &moved);
	path_clear_udp_observation(n);
	REBIND_CHECK(!n->udp_rebind.challenge_active);

	rebind_plant(mesh, n, "56000");
	n->devclass = DEV_CLASS_BACKBONE;
	moved = str2sockaddr("203.0.113.50", "56001");
	n->udp_rebind.current_rx_at.tv_sec -= 1;
	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(n->udp_rebind.seen == 0);
	REBIND_CHECK(!n->udp_rebind.challenge_active);
	n->devclass = DEV_CLASS_UNKNOWN;
	path_rebind_observe_rx(mesh, n, &moved);
	REBIND_CHECK(!n->udp_rebind.challenge_active);

	rebind_plant(mesh, n, "57000");
	/* A burst warns once, including ring wrap. The warning window expires
	   at exactly 60 seconds; a later fresh burst can warn again. */
	const unsigned offsets_ms[] = {0, 59999, 60000, 121000};
	const unsigned migrations[] = {10, 1, 1, 10};
	const unsigned warned_until_sec[] = {60, 60, 120, 181};
	unsigned total = 0;

	for(unsigned phase = 0; phase < 4; phase++) {
		mesh->loop.now.tv_sec = saved_now.tv_sec + offsets_ms[phase] / 1000;
		mesh->loop.now.tv_nsec = (long)(offsets_ms[phase] % 1000) * 1000000L;

		for(i = 0; i < migrations[phase]; i++) {
			char port[8];

			snprintf(port, sizeof port, "%u", 58000 + total++);
			moved = str2sockaddr("203.0.113.50", port);
			n->udp_rebind.current_rx_at = mesh->loop.now;
			n->udp_rebind.current_rx_at.tv_sec -= 1;
			path_rebind_observe_rx(mesh, n, &moved);
			REBIND_CHECK(n->udp_rebind.challenge_active);
			nonce = n->udp_rebind.challenge_nonce;
			REBIND_CHECK(path_rebind_accept_reply(mesh, n, &moved, nonce));
		}

		REBIND_CHECK(n->udp_rebind.flap_warned_until.tv_sec == saved_now.tv_sec + warned_until_sec[phase]);
		REBIND_CHECK(n->udp_rebind.flap_warned_until.tv_nsec == 0);
	}

	REBIND_CHECK(n->udp_rebind.migrated == total);
	REBIND_CHECK(n->status.udp_confirmed);
	REBIND_CHECK(n->active_route.kind == DATA_ROUTE_DIRECT_UDP);
	ok = true;

done:
	mesh->self->devclass = saved_class;
	mesh->loop.now = saved_now;

	if(n) {
		timeout_del(&mesh->loop, &n->plpmtu.timer);
		timeout_del(&mesh->loop, &n->rebind_timer);
		timeout_del(&mesh->loop, &n->punch_timer);
		path_suspect_stop(mesh, n);
		path_rebind_cancel(mesh, n);
		node_del(mesh, n);
	}

#undef REBIND_CHECK
	return ok;
}
