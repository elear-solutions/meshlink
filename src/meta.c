/*
    meta.c -- handle the meta communication
    Copyright (C) 2014-2017 Guus Sliepen <guus@meshlink.io>,

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
#include "logger.h"
#include "meshlink_internal.h"
#include "meta.h"
#include "net.h"
#include "net_upgrade.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

/* pselect() waits on a copy of the fd set. A write interest armed from
   another thread stays invisible until some other event wakes the loop,
   which on a quiet host is the 1s ping timer. */
static void meta_watch_write(meshlink_handle_t *mesh, connection_t *c) {
	io_set(&mesh->loop, &c->io, IO_READ | IO_WRITE);

	if(mesh->threadstarted && mesh->loop.pipefd[1] != -1 && !pthread_equal(mesh->thread, pthread_self())) {
		signal_trigger(&mesh->loop, &mesh->datafromapp);
	}
}

bool send_meta_sptps(void *handle, uint8_t type, const void *buffer, size_t length) {
	(void)type;

	assert(handle);
	assert(buffer);
	assert(length);

	connection_t *c = handle;
	meshlink_handle_t *mesh = c->mesh;

	buffer_add(&c->outbuf, (const char *)buffer, length);
	meta_watch_write(mesh, c);

	return true;
}

static bool meta_bypasses_freeze(const char *buffer) {
	int req = atoi(buffer);

	return req == PING || req == PONG
	       || req == REQ_META_CUTOVER_PREPARE
	       || req == REQ_META_CUTOVER_READY
	       || req == REQ_META_CUTOVER_COMMIT
	       || req == REQ_META_CUTOVER_ACK
	       || req == REQ_META_CUTOVER_EMERGENCY;
}

static bool send_meta_immediate(meshlink_handle_t *mesh, connection_t *c, const void *buffer, size_t length) {
	if(c->meta_teardown || c->meta_replay_failed) {
		return false;
	}

	if(c->socket < 0) {
		return true;
	}

	if(c->allow_request == ID) {
		buffer_add(&c->outbuf, buffer, length);
		meta_watch_write(mesh, c);
		return true;
	}

	return sptps_send_record(&c->sptps, 0, buffer, length);
}

bool send_meta_cutover_control(meshlink_handle_t *mesh, connection_t *c, const char *buffer, int length) {
	assert(c);
	assert(buffer);
	assert(length >= 0);

	return send_meta_immediate(mesh, c, buffer, (size_t)length);
}

bool send_meta(meshlink_handle_t *mesh, connection_t *c, const char *buffer, int length) {
	assert(c);
	assert(buffer);
	assert(length >= 0);

	logger(mesh, MESHLINK_DEBUG, "Sending %d bytes of metadata to %s", length, c->name);

	/* A replay failure already decided this socket is done. Do not park the
	   record on a connection that receive_request() is still using. */
	if(c->meta_teardown || c->meta_replay_failed) {
		return false;
	}

	/* Freeze before the socketless short-circuit. An overflow abort replays
	   the FIFO first; this record is written only when that replay succeeded.
	   Synthetic inject peers (allow_request == ID, socket < 0) still skip the
	   freeze and return from send_meta_immediate without arming I/O. */
	if(c->allow_request != ID && !meta_bypasses_freeze(buffer)
	                && upgrade_meta_enqueue_if_frozen(mesh, c, buffer, length)) {
		return true;
	}

	if(c->meta_teardown || c->meta_replay_failed) {
		return false;
	}

	return send_meta_immediate(mesh, c, buffer, (size_t)length);
}

void broadcast_meta(meshlink_handle_t *mesh, connection_t *from, const char *buffer, int length) {
	assert(buffer);
	assert(length);

	for list_each(connection_t, c, mesh->connections)
		if(c != from && c->status.active && !c->status.drain_only && !c->status.spare && !(c->flags & PROTOCOL_TINY)) {
			send_meta(mesh, c, buffer, length);
		}
}

void broadcast_submesh_meta(meshlink_handle_t *mesh, connection_t *from, const submesh_t *s, const char *buffer, int length) {
	assert(buffer);
	assert(length);

	for list_each(connection_t, c, mesh->connections)
		if(c != from && c->status.active && !c->status.drain_only && !c->status.spare && !(c->flags & PROTOCOL_TINY)) {
			if(c->node && submesh_allows_node(s, c->node)) {
				send_meta(mesh, c, buffer, length);
			}
		}
}

bool receive_meta_sptps(void *handle, uint8_t type, const void *data, uint16_t length) {
	assert(handle);
	assert(!length || data);

	connection_t *c = handle;
	meshlink_handle_t *mesh = c->mesh;
	char *request = (char *)data;

	if(!c) {
		logger(mesh, MESHLINK_ERROR, "receive_meta_sptps() called with NULL pointer!");
		abort();
	}

	if(type == SPTPS_HANDSHAKE) {
		if(c->allow_request == ACK) {
			/* The responder of an upgrade probe ACKs from ack_h() instead: see upgrade_defers_ack(). */
			if(upgrade_defers_ack(c)) {
				return true;
			}

			return send_ack(mesh, c);
		} else {
			return true;
		}
	}

	if(!request) {
		return true;
	}

	/* Are we receiving a raw packet? */

	if(c->status.raw_packet) {
		c->status.raw_packet = false;

		if(mesh->receive_cb) {
			mesh->receive_cb(mesh, (meshlink_node_t *)c->node, data, length);
		}

		return true;
	}

	/* Change newline to null byte, just like non-SPTPS requests */

	if(request[length - 1] == '\n') {
		request[length - 1] = 0;
	}

	/* Otherwise we are waiting for a request */

	return receive_request(mesh, c, request);
}

bool receive_meta(meshlink_handle_t *mesh, connection_t *c) {
	int inlen;
	char inbuf[MAXBUFSIZE];

	inlen = recv(c->socket, inbuf, sizeof(inbuf), 0);

	if(inlen <= 0) {
		if(!inlen || !errno) {
			logger(mesh, MESHLINK_INFO, "Connection closed by %s", c->name);
		} else if(sockwouldblock(sockerrno)) {
			return true;
		} else {
			logger(mesh, MESHLINK_ERROR, "Metadata socket read error for %s: %s", c->name, sockstrerror(sockerrno));
		}

		return false;
	}

	logger(mesh, MESHLINK_DEBUG, "Received %d bytes of metadata from %s", inlen, c->name);

	if(c->node) {
		c->node->in_meta += inlen;
	}

	if(c->allow_request == ID) {
		buffer_add(&c->inbuf, inbuf, inlen);

		char *request = buffer_readline(&c->inbuf);

		if(request) {
			if(!receive_request(mesh, c, request) || c->allow_request == ID) {
				return false;
			}

			int left = c->inbuf.len - c->inbuf.offset;

			if(left > 0) {
				return sptps_receive_data(&c->sptps, buffer_read(&c->inbuf, left), left);
			} else {
				return true;
			}
		}

		if(c->inbuf.len >= sizeof(inbuf)) {
			logger(mesh, MESHLINK_ERROR, "Input buffer full for %s", c->name);
			return false;
		} else {
			return true;
		}
	}

	return sptps_receive_data(&c->sptps, inbuf, inlen);
}
