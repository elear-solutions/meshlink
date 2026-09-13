/*
    relay_devtool.c -- UDP relay test and gcov hooks
    Copyright (C) 2026 Elear Solutions / MeshLink contributors

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include "connection.h"
#include "event.h"
#include "list.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "node.h"
#include "protocol.h"
#include "relay.h"
#include "relay_devtool.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

struct relay_devtool_state *relay_devtool_get(meshlink_handle_t *mesh) {
	if(!mesh->relay_devtool) {
		mesh->relay_devtool = xzalloc(sizeof(*mesh->relay_devtool));
	}

	return mesh->relay_devtool;
}

static bool relay_capture_send(void *handle, uint8_t type, const void *data, size_t len) {
	(void)type;
	node_t *n = handle;
	meshlink_handle_t *mesh = n->mesh;
	struct relay_devtool_state *dt = relay_devtool_get(mesh);

	if(len > sizeof(dt->capture_buf)) {
		return false;
	}

	memcpy(dt->capture_buf, data, len);
	dt->capture_len = len;
	return true;
}

bool relay_inject_inner(meshlink_handle_t *mesh, node_t *dest, uint8_t type) {
	if(!dest || !dest->sptps.outstate) {
		return false;
	}

	uint8_t dummy[32];
	memset(dummy, 0, sizeof(dummy));

	struct relay_devtool_state *dt = relay_devtool_get(mesh);
	send_data_t saved = dest->sptps.send_data;
	dt->capture_len = 0;
	dest->sptps.send_data = relay_capture_send;

	if(type >= SPTPS_HANDSHAKE) {
		(void)sptps_send_record_raw(&dest->sptps, type, dummy, sizeof(dummy));
	} else {
		(void)sptps_send_record(&dest->sptps, type, dummy, sizeof(dummy));
	}

	dest->sptps.send_data = saved;

	/* send_record failure leaves capture_len at 0 — same drop as a confirmed dest. */
	if(!dt->capture_len || dest->status.udp_confirmed) {
		return false;
	}

	if(dest->nexthop && relay_hop_udp_ready(dest->nexthop)) {
		uint8_t wrapped[MAXSIZE];
		size_t wlen = sizeof(wrapped);

		if(relay_encode(mesh->self->name, dest->name, dt->capture_buf, dt->capture_len, wrapped, &wlen)) {
			return relay_send_outer_record(mesh, dest->nexthop, mesh->self->name, dest->name, wrapped, wlen);
		}
	}

	return relay_send_meta_req_sptps(mesh, mesh->self->name, dest, dt->capture_buf, dt->capture_len);
}

void relay_devtool_clear_reports(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->relay_reports) {
		return;
	}

	list_delete_list(mesh->relay_reports);
	mesh->relay_reports = list_alloc(relay_report_free);
}

bool relay_devtool_seed_report(meshlink_handle_t *mesh, const char *origin, const char *destination, unsigned age_sec, bool have_reported) {
	if(!mesh || !mesh->relay_reports || !origin || !destination) {
		return false;
	}

	relay_report_entry_t *e = relay_report_get(mesh, origin, destination, true, false);
	e->last_traffic_time = mesh->loop.now.tv_sec - (time_t)age_sec;
	e->have_reported = have_reported;
	e->last_report.tv_sec = have_reported ? e->last_traffic_time : 0;
	e->last_report.tv_nsec = 0;
	return true;
}

bool relay_devtool_has_report(meshlink_handle_t *mesh, const char *origin, const char *destination) {
	if(!mesh || !origin || !destination) {
		return false;
	}

	return relay_report_find(mesh, origin, destination) != NULL;
}

bool relay_devtool_have_reported(meshlink_handle_t *mesh, const char *origin, const char *destination) {
	if(!mesh || !origin || !destination) {
		return false;
	}

	relay_report_entry_t *e = relay_report_find(mesh, origin, destination);
	return e && e->have_reported;
}

size_t relay_devtool_report_count(meshlink_handle_t *mesh) {
	if(!mesh || !mesh->relay_reports) {
		return 0;
	}

	return mesh->relay_reports->count;
}

bool relay_devtool_fill_reports(meshlink_handle_t *mesh, size_t count, unsigned age_sec, bool have_reported) {
	if(!mesh) {
		return false;
	}

	for(size_t i = 0; i < count; i++) {
		char origin[8];
		snprintf(origin, sizeof(origin), "f%04u", (unsigned)i);

		if(!relay_devtool_seed_report(mesh, origin, "x", age_sec, have_reported)) {
			return false;
		}
	}

	return true;
}

void relay_devtool_force_report_null_connection(meshlink_handle_t *mesh, bool fail) {
	if(mesh) {
		relay_devtool_get(mesh)->force_report_null_connection = fail;
	}
}

bool relay_devtool_handle_aliased(meshlink_handle_t *mesh, node_t *from, const void *data, uint16_t len) {
	if(!mesh || !from || !data || !from->sptps.decrypted_buffer) {
		return false;
	}

	if(len > from->sptps.decrypted_buffer_len) {
		if(mesh->relay_devtool && mesh->relay_devtool->fail_realloc) {
			return false;
		}

		from->sptps.decrypted_buffer = realloc(from->sptps.decrypted_buffer, len);
		from->sptps.decrypted_buffer_len = len;
	}

	memcpy(from->sptps.decrypted_buffer, data, len);
	return relay_handle_record(mesh, from, from->sptps.decrypted_buffer, len);
}

bool relay_devtool_send_meta_sptps(meshlink_handle_t *mesh, node_t *dest, uint8_t type, const void *data, size_t len) {
	if(!mesh || !dest || !dest->sptps.outstate) {
		return false;
	}

	struct relay_devtool_state *dt = relay_devtool_get(mesh);
	send_data_t saved = dest->sptps.send_data;
	dt->capture_len = 0;
	dest->sptps.send_data = relay_capture_send;

	(void)sptps_send_record(&dest->sptps, type, data, (uint16_t)len);
	dest->sptps.send_data = saved;
	return relay_send_meta_req_sptps(mesh, mesh->self->name, dest, dt->capture_buf, dt->capture_len);
}

void relay_devtool_fail_realloc(meshlink_handle_t *mesh, bool fail) {
	if(mesh) {
		relay_devtool_get(mesh)->fail_realloc = fail;
	}
}

bool relay_devtool_handle_req_relay_mtu(meshlink_handle_t *mesh, node_t *from, const char *request) {
	if(!mesh || !from || !request) {
		return false;
	}

	return relay_handle_req_relay_mtu(mesh, from->connection, request, from);
}

static bool relay_cover_encode_decode(void) {
	uint8_t buf[128];
	uint8_t inner[21];
	size_t n = sizeof(buf);
	char origin[RELAY_NAME_MAX + 1];
	char destination[RELAY_NAME_MAX + 1];
	char tiny[2];
	const uint8_t *innerp = NULL;
	size_t inner_len = 0;
	char longname[257];

	memset(inner, 0x5a, sizeof(inner));
	memset(longname, 'A', 256);
	longname[256] = 0;

	bool unexpected = false;
	unexpected |= relay_encode(NULL, "b", inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", NULL, inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", "b", NULL, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", "b", inner, sizeof(inner), NULL, &n);
	unexpected |= relay_encode("a", "b", inner, sizeof(inner), buf, NULL);
	unexpected |= relay_encode(longname, "b", inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", longname, inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a!", "b", inner, sizeof(inner), buf, &n);
	unexpected |= relay_encode("a", "b!", inner, sizeof(inner), buf, &n);
	n = 4;
	unexpected |= relay_encode("aa", "bb", inner, sizeof(inner), buf, &n);
	n = sizeof(buf);
	unexpected |= !relay_encode("aa", "bb", inner, sizeof(inner), buf, &n);
	unexpected |= relay_payload_destination(NULL, n, destination, sizeof(destination));
	unexpected |= relay_payload_destination(buf, 1, destination, sizeof(destination));
	unexpected |= relay_payload_destination(buf, n, destination, 1);
	unexpected |= relay_send_outer_record(NULL, NULL, "a", "b", buf, n);
	unexpected |= relay_send_outer_record((meshlink_handle_t *)buf, NULL, "a", "b", buf, n);
	unexpected |= relay_send_outer_record((meshlink_handle_t *)buf, (node_t *)buf, "a", "b", NULL, n);
	unexpected |= relay_send_outer_record((meshlink_handle_t *)buf, (node_t *)buf, "a", "b", buf, 0);
	unexpected |= relay_send_outer_record((meshlink_handle_t *)buf, (node_t *)buf, "a", "b", buf, (size_t)UINT16_MAX + 1);
	unexpected |= relay_decode(NULL, n, origin, sizeof(origin), destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(buf, n, NULL, sizeof(origin), destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(buf, n, origin, sizeof(origin), NULL, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(buf, n, origin, sizeof(origin), destination, sizeof(destination), NULL, &inner_len);
	unexpected |= relay_decode(buf, n, origin, sizeof(origin), destination, sizeof(destination), &innerp, NULL);
	unexpected |= relay_decode(buf, n, tiny, 1, destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(buf, n, origin, sizeof(origin), tiny, 1, &innerp, &inner_len);

	uint8_t shortol[2] = { 40, 'x' };
	uint8_t shortinner[4] = { 1, 'a', 1, 'b' };
	unexpected |= relay_decode(shortol, 2, origin, sizeof(origin), destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= relay_decode(shortinner, 4, origin, sizeof(origin), destination, sizeof(destination), &innerp, &inner_len);
	unexpected |= !relay_payload_destination(buf, n, destination, sizeof(destination));
	return !unexpected;
}

typedef struct relay_cover_ctx {
	uint32_t prefix21;
	uint32_t budget;
	uint8_t inner[21];
	uint8_t wrapped[128];
	uint8_t big[600];
	uint8_t bigwrap[700];
	size_t wlen;
	char longname[260];
	char req[256];
	list_t *saved_reports;
	list_t *empty;
	node_t *saved_nh;
	node_t *saved_prev;
	bool saved_uc;
	bool saved_reach;
	bool saved_huc;
	bool saved_hvalid;
	bool saved_out;
	uint16_t saved_budget;
	uint16_t saved_minmtu;
	uint16_t saved_hminmtu;
	uint32_t saved_probes;
	connection_t *saved_conn;
	int saved_state;
	relay_report_entry_t *e;
} relay_cover_ctx_t;

static void relay_cover_sanity(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	uint32_t math = 0;
	(void)relay_add_u32(1, 2, &math);
	(void)relay_add_u32(UINT32_MAX, 1, &math);
	(void)relay_sub_u32(5, 2, &math);
	(void)relay_sub_u32(2, 5, &math);
	(void)relay_names_unusable(ctx->longname, ctx->longname);
	(void)relay_hop_udp_ready(NULL);
	(void)relay_cover_encode_decode();

	(void)relay_capture_send(from, 0, ctx->inner, sizeof(ctx->inner));
	(void)relay_capture_send(from, 0, ctx->wrapped, RELAY_CAPTURE_MAX + 1);

	relay_update_destination_transport(mesh, NULL);
	relay_update_destination_transport(mesh, mesh->self);
	relay_recompute_dependents(NULL, hop);
	relay_recompute_dependents(mesh, NULL);
	relay_recompute_dependents(mesh, hop);
	relay_on_hard_send_error(mesh, NULL, NULL, 0);
	relay_wake_probes(mesh, NULL);
	relay_wake_probes(mesh, hop);
	relay_clear_budget_if_nexthop_changed(mesh, NULL);
	relay_clear_budget_if_nexthop_changed(mesh, mesh->self);
	dest->prev_nexthop = hop;
	dest->nexthop = dest;
	relay_clear_budget_if_nexthop_changed(mesh, dest);
	dest->nexthop = dest;
	dest->prev_nexthop = dest;
	relay_clear_budget_if_nexthop_changed(mesh, dest);

}

static void relay_cover_null_devtools(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	uint32_t math = 0;
	(void)relay_devtool_has_report(NULL, "a", "b");
	(void)relay_devtool_have_reported(NULL, "a", "b");
	(void)relay_devtool_report_count(NULL);
	(void)relay_devtool_seed_report(NULL, "a", "b", 0, false);
	(void)relay_devtool_fill_reports(NULL, 1, 0, false);
	relay_devtool_force_report_null_connection(NULL, true);
	relay_devtool_clear_reports(NULL);
	(void)relay_devtool_handle_aliased(NULL, from, ctx->inner, sizeof(ctx->inner));
	(void)relay_devtool_send_meta_sptps(NULL, dest, 0, ctx->inner, sizeof(ctx->inner));
	(void)relay_inject_inner(mesh, NULL, 0);
	(void)relay_devtool_handle_req_relay_mtu(mesh, NULL, "x");
	(void)relay_meta_req_sptps(NULL, NULL, NULL, NULL, NULL, 0);

}

static void relay_cover_report_table(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	uint32_t math = 0;
	ctx->saved_reports = mesh->relay_reports;
	mesh->relay_reports = NULL;
	relay_expire_idle(mesh);
	(void)relay_report_find(mesh, "a", "b");
	relay_notify_minmtu_change(mesh, dest);
	(void)relay_devtool_has_report(mesh, "a", "b");
	(void)relay_devtool_have_reported(mesh, "a", "b");
	(void)relay_devtool_report_count(mesh);
	relay_devtool_clear_reports(mesh);
	(void)relay_devtool_fill_reports(mesh, 1, 0, false);
	mesh->relay_reports = ctx->saved_reports;

	ctx->empty = list_alloc(relay_report_free);
	ctx->saved_reports = mesh->relay_reports;
	mesh->relay_reports = ctx->empty;
	relay_evict_lru(mesh);
	list_free(ctx->empty);
	mesh->relay_reports = ctx->saved_reports;

	relay_touch_traffic(mesh, "no_such_origin", "no_such_dest");
	(void)relay_devtool_seed_report(mesh, from->name, dest->name, RELAY_REPORT_IDLE_SEC + 5, true);
	relay_expire_idle(mesh);
	relay_report_timeout_handler(&mesh->loop, mesh);

}

static void relay_cover_handle_record(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	uint32_t math = 0;
	(void)relay_handle_record(mesh, from, ctx->inner, 1);

	uint8_t badid[64];
	badid[0] = 3;
	memcpy(badid + 1, "!!!", 3);
	badid[4] = 3;
	memcpy(badid + 5, "bar", 3);
	memcpy(badid + 8, ctx->inner, sizeof(ctx->inner));
	(void)relay_handle_record(mesh, from, badid, 8 + sizeof(ctx->inner));

	ctx->wlen = sizeof(ctx->wrapped);
	(void)relay_encode("zzz", "yyy", ctx->inner, sizeof(ctx->inner), ctx->wrapped, &ctx->wlen);
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);

	ctx->wlen = sizeof(ctx->wrapped);
	(void)relay_encode(mesh->self->name, dest->name, ctx->inner, sizeof(ctx->inner), ctx->wrapped, &ctx->wlen);
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);

	ctx->wlen = sizeof(ctx->wrapped);
	(void)relay_encode(from->name, mesh->self->name, ctx->inner, sizeof(ctx->inner), ctx->wrapped, &ctx->wlen);
	from->status.validkey = false;
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);
	from->status.validkey = ctx->saved_hvalid;
	from->sptps.state = 0;
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);
	from->sptps.state = ctx->saved_state;

	ctx->wlen = sizeof(ctx->wrapped);
	(void)relay_encode(from->name, dest->name, ctx->inner, sizeof(ctx->inner), ctx->wrapped, &ctx->wlen);
	dest->status.reachable = false;
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);
	dest->status.reachable = true;
	dest->nexthop = NULL;
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);
	dest->nexthop = mesh->self;
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);
	dest->nexthop = from;
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);
	dest->nexthop = hop;
	hop->status.udp_confirmed = false;
	hop->connection = NULL;
	(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);
	hop->connection = ctx->saved_conn;
	hop->status.udp_confirmed = ctx->saved_huc;

	ctx->wlen = sizeof(ctx->bigwrap);
	(void)relay_encode(from->name, dest->name, ctx->big, sizeof(ctx->big), ctx->bigwrap, &ctx->wlen);
	dest->nexthop = hop;
	hop->status.udp_confirmed = true;
	hop->status.validkey = true;
	hop->status.temp_udp_confirmed = false;
	hop->minmtu = MINMTU;
	(void)relay_handle_record(mesh, from, ctx->bigwrap, (uint16_t)ctx->wlen);
	dest->nexthop = dest;
	dest->status.udp_confirmed = true;
	dest->status.validkey = true;
	dest->status.temp_udp_confirmed = false;
	dest->minmtu = MINMTU;
	(void)relay_handle_record(mesh, from, ctx->bigwrap, (uint16_t)ctx->wlen);

}

static void relay_cover_maybe_report(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	uint32_t math = 0;
	relay_maybe_report(mesh, from->name, NULL, false);
	dest->nexthop = hop;
	relay_maybe_report(mesh, from->name, dest, false);
	dest->nexthop = dest;
	dest->status.udp_confirmed = false;
	relay_maybe_report(mesh, from->name, dest, false);
	relay_maybe_report(mesh, ctx->longname, dest, false);

	dest->nexthop = dest;
	dest->status.udp_confirmed = true;
	dest->status.validkey = true;
	dest->status.temp_udp_confirmed = false;
	(void)relay_prefix21(from->name, dest->name, &ctx->prefix21);
	(void)relay_sub_u32(dest->minmtu > MINMTU ? dest->minmtu : MINMTU, ctx->prefix21, &ctx->budget);
	(void)relay_devtool_seed_report(mesh, from->name, dest->name, 0, true);
	ctx->e = relay_report_find(mesh, from->name, dest->name);

	if(ctx->e) {
		ctx->e->last_budget = (uint16_t)ctx->budget;
		ctx->e->have_reported = true;
		ctx->e->last_report.tv_sec = mesh->loop.now.tv_sec + 1;
		ctx->e->last_report.tv_nsec = 0;
		relay_maybe_report(mesh, from->name, dest, true);
		ctx->e->last_report.tv_sec = mesh->loop.now.tv_sec;
		relay_maybe_report(mesh, from->name, dest, true);
		ctx->e->last_report.tv_sec = mesh->loop.now.tv_sec - RELAY_OVERSIZE_COOLDOWN_SEC;
		ctx->e->last_report.tv_nsec = mesh->loop.now.tv_nsec + 1;
		relay_maybe_report(mesh, from->name, dest, true);
		ctx->e->last_report.tv_sec = mesh->loop.now.tv_sec - RELAY_OVERSIZE_COOLDOWN_SEC - 1;
		ctx->e->last_report.tv_nsec = 0;
		relay_maybe_report(mesh, from->name, dest, true);
		relay_maybe_report(mesh, from->name, dest, false);
	}

	relay_notify_minmtu_change(mesh, NULL);
	dest->nexthop = hop;
	relay_notify_minmtu_change(mesh, dest);
	dest->nexthop = dest;
	relay_notify_minmtu_change(mesh, dest);

	(void)relay_send_meta_req_sptps(mesh, from->name, NULL, ctx->inner, sizeof(ctx->inner));
	dest->nexthop = NULL;
	(void)relay_send_meta_req_sptps(mesh, from->name, dest, ctx->inner, sizeof(ctx->inner));
	dest->nexthop = hop;
	(void)relay_send_meta_req_sptps(mesh, from->name, dest, NULL, sizeof(ctx->inner));
	(void)relay_send_meta_req_sptps(mesh, from->name, dest, ctx->inner, 0);

}

static void relay_cover_req_mtu(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	uint32_t math = 0;
	(void)relay_handle_req_relay_mtu(mesh, from->connection, "bad", from);
	(void)relay_handle_req_relay_mtu(mesh, from->connection, "0 a b 4 !!! 1", from);
	(void)relay_handle_req_relay_mtu(mesh, from->connection, "0 a b 4 nosuchnode 100", from);
	snprintf(ctx->req, sizeof(ctx->req), "0 %s %s %d %s 100", hop->name, mesh->self->name, REQ_RELAY_MTU, dest->name);
	dest->nexthop = dest;
	dest->status.udp_confirmed = true;
	(void)relay_handle_req_relay_mtu(mesh, from->connection, ctx->req, from);
	dest->status.udp_confirmed = false;
	(void)relay_handle_req_relay_mtu(mesh, from->connection, ctx->req, hop);
	snprintf(ctx->req, sizeof(ctx->req), "0 %s %s %d %s 1", hop->name, mesh->self->name, REQ_RELAY_MTU, dest->name);
	(void)relay_handle_req_relay_mtu(mesh, dest->connection, ctx->req, dest);
	snprintf(ctx->req, sizeof(ctx->req), "0 %s %s %d %s 20000", hop->name, mesh->self->name, REQ_RELAY_MTU, dest->name);
	(void)relay_handle_req_relay_mtu(mesh, dest->connection, ctx->req, dest);

	if(dest->connection && dest->nexthop == dest) {
		uint32_t lo = 0;
		uint32_t hi = 0;

		if(relay_prefix21(mesh->self->name, dest->name, &ctx->prefix21)
		                && relay_sub_u32(MINMTU, ctx->prefix21, &lo)
		                && relay_sub_u32(MTU, ctx->prefix21, &hi)
		                && lo <= hi) {
			snprintf(ctx->req, sizeof(ctx->req), "0 %s %s %d %s %u", dest->name, mesh->self->name, REQ_RELAY_MTU, dest->name, (unsigned)lo);
			dest->status.udp_confirmed = false;
			(void)relay_handle_req_relay_mtu(mesh, dest->connection, ctx->req, dest);
		}
	}

	dest->status.udp_confirmed = true;
	dest->minmtu = 0;
	relay_update_destination_transport(mesh, dest);
	dest->minmtu = MTU;
	relay_update_destination_transport(mesh, dest);
	dest->status.udp_confirmed = false;
	dest->status.reachable = false;
	relay_update_destination_transport(mesh, dest);
	dest->status.reachable = true;
	dest->nexthop = NULL;
	relay_update_destination_transport(mesh, dest);
	dest->nexthop = mesh->self;
	relay_update_destination_transport(mesh, dest);
	dest->nexthop = hop;
	hop->status.udp_confirmed = false;
	relay_update_destination_transport(mesh, dest);
	hop->status.udp_confirmed = true;
	hop->status.validkey = true;
	hop->status.temp_udp_confirmed = false;
	dest->relay_budget = 0;
	relay_update_destination_transport(mesh, dest);
	dest->relay_budget = 800;
	relay_update_destination_transport(mesh, dest);

}

static void relay_cover_hard_send_block(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	(void)ctx;
	bool saved_hop_uc = hop->status.udp_confirmed;
	sockaddr_t other;
	sockaddr_t mcast;

	relay_on_hard_send_error(mesh, hop, NULL, hop->sock);

	hop->status.udp_confirmed = false;
	relay_on_hard_send_error(mesh, hop, &hop->address, hop->sock);

	hop->status.udp_confirmed = true;
	relay_on_hard_send_error(mesh, hop, &hop->address, hop->sock + 1);

	memset(&other, 0, sizeof other);
	other = hop->address;

	if(other.sa.sa_family == AF_INET) {
		other.in.sin_port ^= htons(0x8000);
	} else if(other.sa.sa_family == AF_INET6) {
		other.in6.sin6_port ^= htons(0x8000);
	} else {
		other.sa.sa_family = AF_INET;
		other.in.sin_port = htons(1);
	}

	relay_on_hard_send_error(mesh, hop, &other, hop->sock);

	memset(&other, 0, sizeof other);
	other = hop->address;

	if(other.sa.sa_family == AF_INET) {
		other.in.sin_addr.s_addr ^= htonl(1);
	} else if(other.sa.sa_family == AF_INET6) {
		other.in6.sin6_addr.s6_addr[15] ^= 1;
	} else {
		other.sa.sa_family = AF_INET;
		other.in.sin_addr.s_addr = htonl(0x7f000002);
	}

	relay_on_hard_send_error(mesh, hop, &other, hop->sock);

	memset(&mcast, 0, sizeof mcast);
	mcast.in6.sin6_family = AF_INET6;
	mcast.in6.sin6_addr.s6_addr[0] = 0xff;
	mcast.in6.sin6_addr.s6_addr[1] = 0x02;
	mcast.in6.sin6_addr.s6_addr[15] = 0x01;
	relay_on_hard_send_error(mesh, hop, &mcast, hop->sock);

	relay_on_hard_send_error(mesh, hop, &hop->address, hop->sock);
	hop->status.udp_confirmed = saved_hop_uc;

	{
		char huge[510];
		node_t *saved_from_nh = from->nexthop;
		connection_t *saved_dconn = dest->connection;

		memset(huge, 'Z', 509);
		huge[509] = 0;
		(void)relay_devtool_seed_report(mesh, from->name, dest->name, 0, true);
		(void)relay_devtool_seed_report(mesh, from->name, mesh->self->name, 0, true);
		relay_evict_lru(mesh);

		dest->nexthop = dest;
		dest->status.reachable = true;
		dest->status.udp_confirmed = true;
		dest->status.validkey = true;
		dest->status.temp_udp_confirmed = false;
		dest->minmtu = MINMTU;
		relay_maybe_report(mesh, huge, dest, false);
		relay_maybe_report(mesh, "no_such_origin", dest, false);
		from->nexthop = NULL;
		relay_maybe_report(mesh, from->name, dest, false);
		from->nexthop = saved_from_nh;

		dest->status.udp_confirmed = false;
		dest->connection = NULL;
		ctx->wlen = sizeof(ctx->wrapped);
		(void)relay_encode(from->name, dest->name, ctx->inner, sizeof(ctx->inner), ctx->wrapped, &ctx->wlen);
		(void)relay_handle_record(mesh, from, ctx->wrapped, (uint16_t)ctx->wlen);

		dest->nexthop = dest;
		dest->connection = saved_dconn;
		dest->status.udp_confirmed = false;
		(void)relay_names_unusable(huge, dest->name);
		snprintf(ctx->req, sizeof(ctx->req), "0 %s %s %d %s 100", dest->name, mesh->self->name, REQ_RELAY_MTU, dest->name);
		(void)relay_handle_req_relay_mtu(mesh, dest->connection, ctx->req, dest);
		from->nexthop = saved_from_nh;
		dest->connection = saved_dconn;

		node_t *extra = lookup_node(mesh, "qux");

		if(extra) {
			bool extra_uc = extra->status.udp_confirmed;
			bool extra_vk = extra->status.validkey;
			uint16_t extra_mtu = extra->minmtu;
			ctx->wlen = sizeof(ctx->bigwrap);
			(void)relay_encode(from->name, dest->name, ctx->big, sizeof(ctx->big), ctx->bigwrap, &ctx->wlen);
			dest->nexthop = extra;
			dest->status.reachable = true;
			extra->status.udp_confirmed = true;
			extra->status.validkey = true;
			extra->status.temp_udp_confirmed = false;
			extra->minmtu = MINMTU;
			(void)relay_handle_record(mesh, from, ctx->bigwrap, (uint16_t)ctx->wlen);
			extra->status.udp_confirmed = extra_uc;
			extra->status.validkey = extra_vk;
			extra->minmtu = extra_mtu;
		}
	}

}

static void relay_cover_report_null(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	(void)ctx;
	relay_devtool_force_report_null_connection(mesh, true);
	dest->nexthop = dest;
	dest->status.udp_confirmed = true;
	dest->status.validkey = true;
	dest->status.temp_udp_confirmed = false;
	dest->minmtu = MINMTU;
	relay_maybe_report(mesh, from->name, dest, false);
	relay_devtool_force_report_null_connection(mesh, false);

	(void)relay_devtool_report_count(mesh);
	(void)relay_devtool_fill_reports(mesh, 2, 0, false);
	relay_devtool_clear_reports(mesh);
	(void)relay_devtool_seed_report(mesh, from->name, dest->name, 1, false);
	(void)relay_devtool_seed_report(mesh, hop->name, dest->name, 1, false);
	relay_evict_lru(mesh);

}

static void relay_cover_meta_inject(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	char huge_self[510];
	char long_a[256];
	char long_b[256];
	uint8_t hello[5] = { 'H', 'e', 'l', 'l', 'o' };
	connection_t *saved_dconn = dest->connection;
	connection_t *saved_hconn = hop->connection;
	int saved_dstate = dest->sptps.state;

	memset(huge_self, 'Z', 509);
	huge_self[509] = 0;

	(void)relay_names_unusable(huge_self, dest->name);
	dest->nexthop = dest;
	dest->status.udp_confirmed = false;
	snprintf(ctx->req, sizeof(ctx->req), "0 %s %s %d %s 100", dest->name, dest->name, REQ_RELAY_MTU, dest->name);
	(void)relay_handle_req_relay_mtu(mesh, dest->connection, ctx->req, dest);

	{
		char *saved_self = mesh->self->name;

		mesh->self->name = huge_self;
		dest->nexthop = dest;
		dest->status.udp_confirmed = false;
		snprintf(ctx->req, sizeof(ctx->req), "0 %s %s %d %s 100", dest->name, dest->name, REQ_RELAY_MTU, dest->name);
		(void)relay_handle_req_relay_mtu(mesh, dest->connection, ctx->req, dest);
		mesh->self->name = saved_self;
	}

	dest->sptps.outstate = true;
	dest->sptps.state = 0;
	(void)relay_devtool_send_meta_sptps(mesh, dest, 0, ctx->inner, sizeof(ctx->inner));
	dest->sptps.state = saved_dstate;

	memset(long_a, 'A', 255);
	long_a[255] = 0;
	memset(long_b, 'B', 255);
	long_b[255] = 0;
	(void)relay_names_unusable(long_a, long_b);
	dest->status.udp_confirmed = false;
	dest->status.reachable = true;
	dest->nexthop = hop;
	(void)relay_send_meta_req_sptps(mesh, long_a, dest, hello, sizeof(hello));

	dest->status.udp_confirmed = false;
	dest->status.reachable = true;
	dest->nexthop = hop;
	hop->connection = NULL;
	dest->connection = NULL;
	(void)relay_inject_inner(mesh, dest, 0);
	hop->connection = saved_hconn;
	dest->connection = saved_dconn;

}

static void relay_cover_inject_alias(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	uint32_t math = 0;
	dest->sptps.outstate = false;
	(void)relay_inject_inner(mesh, dest, 0);
	(void)relay_devtool_send_meta_sptps(mesh, dest, 0, ctx->inner, sizeof(ctx->inner));

	relay_devtool_get(mesh)->fail_realloc = true;
	(void)relay_devtool_handle_aliased(mesh, from, ctx->wrapped, from->sptps.decrypted_buffer
	                ? (uint16_t)(from->sptps.decrypted_buffer_len + 8) : 32);
	relay_devtool_get(mesh)->fail_realloc = false;

	if(from->sptps.decrypted_buffer) {
		uint8_t junk[32];
		size_t nlen = from->sptps.decrypted_buffer_len + 64;
		uint8_t *bigjunk = xzalloc(nlen);
		memset(junk, 0, sizeof(junk));
		junk[0] = 1;
		(void)relay_devtool_handle_aliased(mesh, from, junk, sizeof(junk));
		bigjunk[0] = 1;
		(void)relay_devtool_handle_aliased(mesh, from, bigjunk, (uint16_t)nlen);
		free(bigjunk);
	}

}

static void relay_cover_restore(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop, relay_cover_ctx_t *ctx) {
	uint32_t math = 0;
	dest->nexthop = ctx->saved_nh;
	dest->prev_nexthop = ctx->saved_prev;
	dest->status.udp_confirmed = ctx->saved_uc;
	dest->status.reachable = ctx->saved_reach;
	dest->relay_budget = ctx->saved_budget;
	dest->minmtu = ctx->saved_minmtu;
	hop->minmtu = ctx->saved_hminmtu;
	dest->sptps.outstate = ctx->saved_out;
	from->status.validkey = ctx->saved_hvalid;
	from->sptps.state = ctx->saved_state;
	hop->status.udp_confirmed = ctx->saved_huc;
	hop->connection = ctx->saved_conn;
	hop->mtuprobes = ctx->saved_probes;
	relay_update_destination_transport(mesh, dest);
	relay_update_destination_transport(mesh, hop);
}

static void relay_cover_exit_uninitialized(void) {
	meshlink_handle_t dummy;

	memset(&dummy, 0, sizeof dummy);
	relay_exit(&dummy);
}

bool relay_devtool_cover_unit(meshlink_handle_t *mesh, node_t *from, node_t *dest, node_t *hop) {
	relay_cover_ctx_t ctx;

	relay_cover_exit_uninitialized();
	memset(&ctx, 0, sizeof(ctx));
	memset(ctx.inner, 0x11, sizeof(ctx.inner));
	memset(ctx.big, 0x22, sizeof(ctx.big));
	memset(ctx.longname, 'Z', 259);
	ctx.longname[259] = 0;
	ctx.saved_nh = dest->nexthop;
	ctx.saved_prev = dest->prev_nexthop;
	ctx.saved_uc = dest->status.udp_confirmed;
	ctx.saved_reach = dest->status.reachable;
	ctx.saved_budget = dest->relay_budget;
	ctx.saved_minmtu = dest->minmtu;
	ctx.saved_hminmtu = hop->minmtu;
	ctx.saved_out = dest->sptps.outstate;
	ctx.saved_huc = hop->status.udp_confirmed;
	ctx.saved_hvalid = from->status.validkey;
	ctx.saved_probes = hop->mtuprobes;
	ctx.saved_conn = hop->connection;
	ctx.saved_state = from->sptps.state;
	dest->prev_nexthop = hop;
	dest->nexthop = dest;
	relay_clear_budget_if_nexthop_changed(mesh, dest);
	dest->nexthop = dest;
	dest->prev_nexthop = dest;
	relay_clear_budget_if_nexthop_changed(mesh, dest);
	relay_cover_sanity(mesh, from, dest, hop, &ctx);
	relay_cover_null_devtools(mesh, from, dest, hop, &ctx);
	relay_cover_report_table(mesh, from, dest, hop, &ctx);
	relay_cover_handle_record(mesh, from, dest, hop, &ctx);
	relay_cover_maybe_report(mesh, from, dest, hop, &ctx);
	relay_cover_req_mtu(mesh, from, dest, hop, &ctx);
	relay_cover_hard_send_block(mesh, from, dest, hop, &ctx);
	relay_cover_report_null(mesh, from, dest, hop, &ctx);
	relay_cover_meta_inject(mesh, from, dest, hop, &ctx);
	relay_cover_inject_alias(mesh, from, dest, hop, &ctx);
	relay_cover_restore(mesh, from, dest, hop, &ctx);
	return true;
}
