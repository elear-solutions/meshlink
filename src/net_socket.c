/*
    net_socket.c -- Handle various kinds of sockets.
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

#include "adns.h"
#include "conf.h"
#include "connection.h"
#include "list.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

/* Needed on Mac OS/X */
#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static const int max_connection_burst = 100;

static void free_outgoing_addresses(outgoing_t *outgoing);

/* Setup sockets */

static void configure_tcp(connection_t *c) {
#ifdef O_NONBLOCK
	int flags = fcntl(c->socket, F_GETFL);

	if(fcntl(c->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
		logger(c->mesh, MESHLINK_ERROR, "System call `%s' failed: %s", "fcntl", strerror(errno));
	}

#elif defined(WIN32)
	unsigned long arg = 1;

	if(ioctlsocket(c->socket, FIONBIO, &arg) != 0) {
		logger(c->mesh, MESHLINK_ERROR, "System call `%s' failed: %s", "ioctlsocket", sockstrerror(sockerrno));
	}

#endif

#if defined(SOL_TCP) && defined(TCP_NODELAY)
	int nodelay = 1;
	setsockopt(c->socket, SOL_TCP, TCP_NODELAY, (void *)&nodelay, sizeof(nodelay));
#endif

#if defined(IP_TOS) && defined(IPTOS_LOWDELAY)
	int lowdelay = IPTOS_LOWDELAY;
	setsockopt(c->socket, IPPROTO_IP, IP_TOS, (void *)&lowdelay, sizeof(lowdelay));
#endif

#if defined(SO_NOSIGPIPE)
	int nosigpipe = 1;
	setsockopt(c->socket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&nosigpipe, sizeof(nosigpipe));
#endif
}

static void retry_outgoing_handler(event_loop_t *loop, void *data) {
	assert(data);

	meshlink_handle_t *mesh = loop->data;
	outgoing_t *outgoing = data;
	setup_outgoing_connection(mesh, outgoing);
}

void outgoing_arm_retry(meshlink_handle_t *mesh, outgoing_t *outgoing, int delay_sec) {
	outgoing->timeout = delay_sec;
	timeout_add(&mesh->loop, &outgoing->ev, retry_outgoing_handler, outgoing, &(struct timespec) {
		delay_sec, prng(mesh, TIMER_FUDGE)
	});
}

void retry_outgoing(meshlink_handle_t *mesh, outgoing_t *outgoing) {
	if(outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED) {
		connection_policy_schedule_backbone_retry(mesh, outgoing);
		return;
	}

	/* A burst of refused connects used to stack this delay into minutes
	   before a discovery callback could replace the address list. One
	   armed retry is enough; the next failure after it fires may wait longer. */
	if(outgoing->ev.cb) {
		return;
	}

	if(!mesh->reachable && mesh->loop.now.tv_sec < mesh->last_unreachable + mesh->dev_class_traits[outgoing->node->devclass].fast_retry_period) {
		outgoing->timeout = 1;
	} else {
		outgoing->timeout += 5;
	}

	int maxtimeout = mesh->dev_class_traits[outgoing->node->devclass].maxtimeout;

	if(outgoing->timeout > maxtimeout) {
		outgoing->timeout = maxtimeout;
	}

	outgoing_arm_retry(mesh, outgoing, outgoing->timeout);
	logger(mesh, MESHLINK_INFO, "Trying to re-establish outgoing connection in %d seconds", outgoing->timeout);
}

void finish_connecting(meshlink_handle_t *mesh, connection_t *c) {
	logger(mesh, MESHLINK_INFO, "Connected to %s", c->name);

	c->last_ping_time = mesh->loop.now.tv_sec;
	c->status.connecting = false;

	send_id(mesh, c);
}

static bool handle_meta_write(meshlink_handle_t *mesh, connection_t *c) {
	if(c->outbuf.len <= c->outbuf.offset) {
		return true;
	}

	ssize_t outlen = send(c->socket, c->outbuf.data + c->outbuf.offset, c->outbuf.len - c->outbuf.offset, MSG_NOSIGNAL);

	if(outlen <= 0) {
		if(!errno || errno == EPIPE) {
			logger(mesh, MESHLINK_INFO, "Connection closed by %s", c->name);
		} else if(sockwouldblock(sockerrno)) {
			logger(mesh, MESHLINK_DEBUG, "Sending %lu bytes to %s would block", (unsigned long)(c->outbuf.len - c->outbuf.offset), c->name);
			return true;
		} else {
			logger(mesh, MESHLINK_ERROR, "Could not send %lu bytes of data to %s: %s", (unsigned long)(c->outbuf.len - c->outbuf.offset), c->name, strerror(errno));
		}

		terminate_connection(mesh, c, c->status.active);
		return false;
	}

	if(c->node) {
		c->node->out_meta += outlen;
	}

	buffer_read(&c->outbuf, outlen);

	if(!c->outbuf.len) {
		io_set(&mesh->loop, &c->io, IO_READ);
	}

	return true;
}

void flush_meta(meshlink_handle_t *mesh, connection_t *c) {
	(void)handle_meta_write(mesh, c);
}

static void handle_meta_io(event_loop_t *loop, void *data, int flags) {
	meshlink_handle_t *mesh = loop->data;
	connection_t *c = data;

	mesh->protocol_connection = c;

	if(c->status.connecting) {
		c->status.connecting = false;

		int result;
		socklen_t len = sizeof(result);
		getsockopt(c->socket, SOL_SOCKET, SO_ERROR, (void *)&result, &len);

		if(!result) {
			finish_connecting(mesh, c);
		} else {
			logger(mesh, MESHLINK_ERROR, "Error while connecting to %s: %s", c->name, sockstrerror(result));
			terminate_connection(mesh, c, false);
			mesh->protocol_connection = NULL;
			return;
		}
	}

	if((flags & IO_WRITE) && !handle_meta_write(mesh, c)) {
		mesh->protocol_connection = NULL;
		return;
	}

	if(flags & IO_READ) {
		handle_meta_connection_data(mesh, c);
	}

	mesh->protocol_connection = NULL;
}

/* Find edges pointing to this node, and use them to build a list of unique, known addresses.
   An edge marked OPTION_INDIRECT carries the address of a relay the other node reached
   n through, not n's own: with indirect set, only those are returned, otherwise only
   the addresses of direct edges. */
static struct addrinfo *get_known_addresses(node_t *n, bool indirect) {
	struct addrinfo *ai = NULL;

	for splay_each(edge_t, e, n->edge_tree) {
		if(!e->reverse) {
			continue;
		}

		if(!!(e->reverse->options & OPTION_INDIRECT) != indirect) {
			continue;
		}

		if(!indirect && !path_is_direct_candidate(n, &e->reverse->address, ADDR_SRC_EDGE_DIRECT)) {
			continue;
		}

		bool found = false;

		for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
			if(!sockaddrcmp(&e->reverse->address, (sockaddr_t *)aip->ai_addr)) {
				found = true;
				break;
			}
		}

		if(found) {
			continue;
		}

		// Create a new struct addrinfo, and put it at the head of the list.
		struct addrinfo *nai = xzalloc(sizeof(*nai) + SALEN(e->reverse->address.sa));
		nai->ai_next = ai;
		ai = nai;

		ai->ai_family = e->reverse->address.sa.sa_family;
		ai->ai_socktype = SOCK_STREAM;
		ai->ai_protocol = IPPROTO_TCP;
		ai->ai_addrlen = SALEN(e->reverse->address.sa);
		ai->ai_addr = (struct sockaddr *)(nai + 1);
		memcpy(ai->ai_addr, &e->reverse->address, ai->ai_addrlen);
	}

	return ai;
}

// Free struct addrinfo list from get_known_addresses().
static void free_known_addresses(struct addrinfo *ai) {
	for(struct addrinfo *aip = ai, *next; aip; aip = next) {
		next = aip->ai_next;
		free(aip);
	}
}

static int outgoing_startup_ms = OUTGOING_STARTUP_MS;

void outgoing_set_startup_ms(int ms) {
	outgoing_startup_ms = ms > 0 ? ms : OUTGOING_STARTUP_MS;
}

int outgoing_get_startup_ms(void) {
	return outgoing_startup_ms > 0 ? outgoing_startup_ms : OUTGOING_STARTUP_MS;
}

static bool outgoing_has_canonical(const outgoing_t *outgoing) {
	return outgoing->node && outgoing->node->canonical_address;
}

/* After canonical is exhausted: leftover generic outgoings may try graph-indirect hops;
   backbone and LAN-resilience intents do not. */
static void outgoing_advance_past_canonical(outgoing_t *outgoing) {
	if(outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED
	                || outgoing->purpose == META_PURPOSE_LAN_RESILIENCE) {
		outgoing->state = OUTGOING_END;
	} else {
		outgoing->state = OUTGOING_KNOWN_INDIRECT;
	}
}

/* The startup budget applies only when a canonical NLB exists to fall back to. */
static bool outgoing_is_startup_direct(const outgoing_t *outgoing) {
	if(outgoing->purpose == META_PURPOSE_LAN_RESILIENCE) {
		return false;
	}

	return outgoing_has_canonical(outgoing) && (outgoing->state == OUTGOING_RECENT || outgoing->state == OUTGOING_KNOWN);
}

static struct timespec outgoing_startup_tv(void) {
	int ms = outgoing_get_startup_ms();

	return (struct timespec) {
		ms / 1000, (long)(ms % 1000) * 1000000L
	};
}

static bool connection_is_listed(meshlink_handle_t *mesh, const connection_t *c) {
	if(!mesh || !c) {
		return false;
	}

	for list_each(connection_t, other, mesh->connections) {
		if(other == c) {
			return true;
		}
	}

	return false;
}

void outgoing_note_failed_dest(outgoing_t *outgoing, const sockaddr_t *sa) {
	if(!outgoing || !sa || !sa->sa.sa_family) {
		return;
	}

	path_copy_sockaddr(&outgoing->skip_sa, sa);

	/* Node skip is a pre-activation hint. A live META must stay probeable
	   (inbound leftover terminate is not a failed dest). */
	if(outgoing->node && !(outgoing->node->connection && outgoing->node->connection->status.active)) {
		path_copy_sockaddr(&outgoing->node->startup_skip_sa, sa);
	}
}

/* cancel: bump generation and unlink the socket so a late ACK is stale.
   Keep generation unchanged when the socket just became the primary. */
static void outgoing_clear_pending(meshlink_handle_t *mesh, outgoing_t *outgoing, bool cancel) {
	connection_t *c;

	if(!mesh || !outgoing) {
		return;
	}

	c = outgoing->pending;
	timeout_del(&mesh->loop, &outgoing->startup_ev);
	outgoing->startup_waiting_dns = false;

	if(c && cancel) {
		outgoing_note_failed_dest(outgoing, &c->address);
		outgoing->generation++;
		c->outgoing = NULL;
	} else if(c && !cancel) {
		/* Activation: keep c->outgoing so retry still owns the walk. */
	}

	outgoing->pending = NULL;
}

void outgoing_detach_startup(meshlink_handle_t *mesh, outgoing_t *outgoing) {
	outgoing_clear_pending(mesh, outgoing, true);
}

void outgoing_abort_startup(meshlink_handle_t *mesh, outgoing_t *outgoing) {
	connection_t *c;

	if(!mesh || !outgoing) {
		return;
	}

	c = outgoing->pending;

	if(c && c->status.active) {
		outgoing_clear_pending(mesh, outgoing, false);
		return;
	}

	outgoing_clear_pending(mesh, outgoing, true);

	/* Never terminate a socket the caller still owns via list_delete(outgoings). */
	if(c && connection_is_listed(mesh, c)) {
		terminate_connection(mesh, c, false);
	}
}

static void outgoing_startup_timeout(event_loop_t *loop, void *data) {
	outgoing_t *outgoing = data;
	meshlink_handle_t *mesh = loop->data;
	connection_t *c = outgoing->pending;
	node_t *n = outgoing->node;

	if(c && c->status.active) {
		outgoing_clear_pending(mesh, outgoing, false);
		return;
	}

	if(n && path_canonical_is_hostname(n) && n->canonical_resolve_pending && n->canonical_sa_count == 0) {
		outgoing->startup_waiting_dns = true;
		return;
	}

	if(c) {
		outgoing_abort_startup(mesh, outgoing);
	} else {
		outgoing_clear_pending(mesh, outgoing, true);
	}

	free_outgoing_addresses(outgoing);
	outgoing->state = OUTGOING_CANONICAL_RESOLVE;
	do_outgoing_connection(mesh, outgoing);
}

void outgoing_on_canonical_resolved(meshlink_handle_t *mesh, node_t *n, struct addrinfo *ai, int err, bool usable, char *host, char *serv) {
	bool logged_fail = false;
	bool stale_resolve = false;

	/* Process every waiter for n before freeing the shared resolve result. */
	for list_each(outgoing_t, outgoing, mesh->outgoings) {
		if(outgoing->node != n) {
			continue;
		}

		if(outgoing->startup_waiting_dns) {
			if(outgoing->pending && outgoing->pending->status.active) {
				outgoing_clear_pending(mesh, outgoing, false);
				continue;
			}

			if(outgoing->pending) {
				outgoing_abort_startup(mesh, outgoing);
			} else {
				outgoing_clear_pending(mesh, outgoing, true);
			}

			free_outgoing_addresses(outgoing);

			if(usable) {
				outgoing->ai = path_canonical_addrinfo(n);
				outgoing->aip = NULL;
				outgoing->ai_is_getaddrinfo = false;
				outgoing->state = OUTGOING_CANONICAL;
			} else {
				outgoing_advance_past_canonical(outgoing);
			}

			do_outgoing_connection(mesh, outgoing);
			continue;
		}

		if(outgoing->state != OUTGOING_CANONICAL_RESOLVE) {
			continue;
		}

		if(usable) {
			outgoing->ai = path_canonical_addrinfo(n);
			outgoing->aip = NULL;
			outgoing->ai_is_getaddrinfo = false;
			outgoing->state = OUTGOING_CANONICAL;
			do_outgoing_connection(mesh, outgoing);
			continue;
		}

		if(!path_canonical_host_matches(n, host, serv) && path_canonical_is_hostname(n)) {
			stale_resolve = true;
			continue;
		}

		if(!logged_fail) {
			if(err) {
				logger(mesh, MESHLINK_WARNING, "Canonical resolve for %s failed: %s%s", n->name, strerror(err),
				       outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED ? "" : "; trying indirect addresses");
			} else {
				logger(mesh, MESHLINK_WARNING, "Canonical resolve for %s failed%s", n->name,
				       outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED ? "" : "; trying indirect addresses");
			}

			logged_fail = true;
		}

		outgoing_advance_past_canonical(outgoing);
		do_outgoing_connection(mesh, outgoing);
	}

	if(stale_resolve) {
		path_request_canonical_resolve(mesh, n);
	}

	if(ai) {
		freeaddrinfo(ai);
	}

	free(host);
	free(serv);
}

void outgoing_on_canonical_reset(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh || !n || !mesh->outgoings) {
		return;
	}

	for list_each(outgoing_t, outgoing, mesh->outgoings) {
		if(outgoing->node == n && outgoing->state == OUTGOING_CANONICAL_RESOLVE) {
			do_outgoing_connection(mesh, outgoing);
		}
	}
}

// Free whatever address list the outgoing currently holds, honouring its origin.
static void free_outgoing_addresses(outgoing_t *outgoing) {
	if(outgoing->ai) {
		if(outgoing->ai_is_getaddrinfo) {
			freeaddrinfo(outgoing->ai);
		} else {
			free_known_addresses(outgoing->ai);
		}
	}

	outgoing->ai = NULL;
	outgoing->aip = NULL;
	outgoing->ai_is_getaddrinfo = false;
}

/* Where the address an outgoing_t is about to try came from, for the logs. */
static const char *outgoing_address_source(const outgoing_t *outgoing) {
	switch(outgoing->state) {
	case OUTGOING_RECENT:
		return "recent";

	case OUTGOING_CANONICAL:
		return "canonical";

	case OUTGOING_KNOWN:
		return "known";

	case OUTGOING_KNOWN_INDIRECT:
		return "known-indirect";

	default:
		return "unknown";
	}
}

/* One best direct (recent[], then a known edge), then CANONICAL, then KNOWN_INDIRECT
   (skipped for BACKBONE_REQUIRED and LAN_RESILIENCE). */
static bool get_next_outgoing_address(meshlink_handle_t *mesh, outgoing_t *outgoing) {
	bool start = false;

	if(outgoing->purpose == META_PURPOSE_LAN_RESILIENCE) {
		sockaddr_t sa;
		address_source_t src = ADDR_SRC_UNKNOWN;
		const sockaddr_t *skip = outgoing->skip_sa.sa.sa_family ? &outgoing->skip_sa : NULL;

		if(outgoing->state != OUTGOING_START && outgoing->state != OUTGOING_RECENT
		                && outgoing->state != OUTGOING_KNOWN) {
			outgoing->state = OUTGOING_END;
			return false;
		}

		start = (outgoing->state == OUTGOING_START);

		if(outgoing->direct_tries >= OUTGOING_MAX_DIRECT_TRIES
		                || !path_best_local_meta(outgoing->node, skip, &sa, &src)) {
			outgoing->state = start ? OUTGOING_NO_KNOWN_ADDRESSES : OUTGOING_END;
			return false;
		}

		outgoing->direct_tries++;
		outgoing->ai = sockaddr_to_stream_addrinfo(&sa);
		outgoing->aip = outgoing->ai;
		outgoing->ai_is_getaddrinfo = false;
		outgoing->state = OUTGOING_RECENT;
		path_copy_sockaddr(&outgoing->startup_sa, &sa);
		return outgoing->ai != NULL;
	}

	if((outgoing->state == OUTGOING_RECENT || outgoing->state == OUTGOING_KNOWN) && !outgoing_has_canonical(outgoing)) {
		if(outgoing->startup_sa.sa.sa_family) {
			outgoing_note_failed_dest(outgoing, &outgoing->startup_sa);
		}

		timeout_del(&mesh->loop, &outgoing->startup_ev);
		free_outgoing_addresses(outgoing);
		outgoing->state = OUTGOING_START;
	}

	if(outgoing->state == OUTGOING_START) {
		sockaddr_t sa;
		address_source_t src = ADDR_SRC_UNKNOWN;
		const sockaddr_t *skip = outgoing->skip_sa.sa.sa_family ? &outgoing->skip_sa : NULL;

		start = true;

		if(outgoing->direct_tries >= OUTGOING_MAX_DIRECT_TRIES) {
			outgoing->state = OUTGOING_CANONICAL_RESOLVE;
		} else if(path_best_startup_meta(outgoing->node, skip, &sa, &src)) {
			outgoing->direct_tries++;
			outgoing->ai = sockaddr_to_stream_addrinfo(&sa);
			outgoing->aip = outgoing->ai;
			outgoing->ai_is_getaddrinfo = false;
			outgoing->state = (src == ADDR_SRC_EDGE_DIRECT) ? OUTGOING_KNOWN : OUTGOING_RECENT;
			path_copy_sockaddr(&outgoing->startup_sa, &sa);
			return outgoing->ai != NULL;
		} else {
			outgoing->state = OUTGOING_CANONICAL_RESOLVE;
		}
	}

	if(outgoing_is_startup_direct(outgoing)) {
		timeout_del(&mesh->loop, &outgoing->startup_ev);

		if(outgoing->startup_sa.sa.sa_family) {
			outgoing_note_failed_dest(outgoing, &outgoing->startup_sa);
		}

		free_outgoing_addresses(outgoing);
		outgoing->state = OUTGOING_CANONICAL_RESOLVE;
	}

	if(outgoing->state == OUTGOING_CANONICAL_RESOLVE) {
		node_t *n = outgoing->node;

		if(n->canonical_sa_count > 0) {
			outgoing->ai = path_canonical_addrinfo(n);
			outgoing->aip = NULL;
			outgoing->ai_is_getaddrinfo = false;
			outgoing->state = OUTGOING_CANONICAL;
		} else if(path_canonical_is_hostname(n)) {
			if(n->canonical_resolve_pending) {
				return false;
			}

			if(n->canonical_resolve_next && mesh->loop.now.tv_sec < n->canonical_resolve_next) {
				outgoing_advance_past_canonical(outgoing);
			} else {
				path_request_canonical_resolve(mesh, n);

				if(n->canonical_resolve_pending) {
					return false;
				}

				outgoing_advance_past_canonical(outgoing);
			}
		} else if(n->canonical_address) {
			path_refresh_canonical_endpoint(n);

			if(n->canonical_sa_count > 0) {
				outgoing->ai = path_canonical_addrinfo(n);
				outgoing->aip = NULL;
				outgoing->ai_is_getaddrinfo = false;
				outgoing->state = OUTGOING_CANONICAL;
			} else {
				logger(mesh, MESHLINK_ERROR, "Canonical address for %s is missing port number", n->name);
				outgoing_advance_past_canonical(outgoing);
			}
		} else {
			outgoing_advance_past_canonical(outgoing);
		}
	}

	if(outgoing->state == OUTGOING_CANONICAL) {
		if(!outgoing->aip) {
			outgoing->aip = outgoing->ai;
		} else {
			outgoing->aip = outgoing->aip->ai_next;
		}

		if(outgoing->aip) {
			return true;
		}

		free_outgoing_addresses(outgoing);
		outgoing_advance_past_canonical(outgoing);
	}

	if(outgoing->state == OUTGOING_KNOWN_INDIRECT) {
		if(!outgoing->aip) {
			outgoing->ai = get_known_addresses(outgoing->node, true);
			outgoing->aip = outgoing->ai;
			outgoing->ai_is_getaddrinfo = false;
		} else {
			outgoing->aip = outgoing->aip->ai_next;
		}

		if(outgoing->aip) {
			return true;
		}

		free_outgoing_addresses(outgoing);
		outgoing->state = OUTGOING_END;
	}

	if(start) {
		outgoing->state = OUTGOING_NO_KNOWN_ADDRESSES;
	}

	return false;
}

void do_outgoing_connection(meshlink_handle_t *mesh, outgoing_t *outgoing) {
begin:

	if(!get_next_outgoing_address(mesh, outgoing)) {
		if(outgoing->state == OUTGOING_CANONICAL_RESOLVE) {
			/* We are waiting for a callback from the ADNS thread */
		} else if(outgoing->state == OUTGOING_NO_KNOWN_ADDRESSES) {
			logger(mesh, MESHLINK_ERROR, "No known addresses for %s", outgoing->node->name);

			if(meta_purpose_is_persistent(outgoing->purpose)) {
				retry_outgoing(mesh, outgoing);
			} else {
				list_delete(mesh->outgoings, outgoing);
			}
		} else {
			logger(mesh, MESHLINK_ERROR, "Could not set up a meta connection to %s", outgoing->node->name);
			retry_outgoing(mesh, outgoing);
		}

		return;
	}

	if(outgoing->generation == 0) {
		outgoing->generation = 1;
	}

	connection_t *c = new_connection();
	c->outgoing = outgoing;
	c->outgoing_generation = outgoing->generation;
	c->name = xstrdup(outgoing->node->name);
	memcpy(&c->address, outgoing->aip->ai_addr, outgoing->aip->ai_addrlen);
	path_mark_meta_dial(c, outgoing->state == OUTGOING_CANONICAL || outgoing->state == OUTGOING_KNOWN_INDIRECT || path_address_matches_canonical(outgoing->node, &c->address));
	path_log_meta(mesh, outgoing->node, &c->address, c->status.via_canonical ? "dial canonical" : "dial direct");

	if(mesh->log_level <= MESHLINK_INFO) {
		char *hostname = sockaddr2hostname(&c->address);
		logger(mesh, MESHLINK_INFO, "Trying to connect to %s at %s (%s)", outgoing->node->name, hostname, outgoing_address_source(outgoing));
		free(hostname);
	}

	if(!connect_meta_socket(mesh, c)) {
		sockaddr_t failed = c->address;
		free_connection(c);

		if(outgoing->purpose == META_PURPOSE_LAN_RESILIENCE) {
			outgoing_note_failed_dest(outgoing, &failed);
			free_outgoing_addresses(outgoing);
			outgoing->state = OUTGOING_END;
			logger(mesh, MESHLINK_ERROR, "Could not set up a meta connection to %s", outgoing->node->name);
			retry_outgoing(mesh, outgoing);
			return;
		}

		if(outgoing_is_startup_direct(outgoing)) {
			timeout_del(&mesh->loop, &outgoing->startup_ev);
			outgoing_note_failed_dest(outgoing, &outgoing->startup_sa);
			free_outgoing_addresses(outgoing);
			outgoing->state = OUTGOING_CANONICAL_RESOLVE;
		} else if(outgoing->state == OUTGOING_RECENT || outgoing->state == OUTGOING_KNOWN) {
			if(outgoing->startup_sa.sa.sa_family) {
				outgoing_note_failed_dest(outgoing, &outgoing->startup_sa);
			}

			free_outgoing_addresses(outgoing);
			outgoing->state = OUTGOING_START;
		}

		goto begin;
	}

	outgoing->pending = c;

	if(outgoing_is_startup_direct(outgoing)) {
		struct timespec tv = outgoing_startup_tv();
		timeout_add(&mesh->loop, &outgoing->startup_ev, outgoing_startup_timeout, outgoing, &tv);
		path_request_canonical_resolve(mesh, outgoing->node);
	}
}

/* Create a non-blocking TCP socket for c->address, start connecting, and register
   the connection with the event loop. c->name and c->address must already be set.
   On failure the caller owns c and must free it. */
bool connect_meta_socket(meshlink_handle_t *mesh, connection_t *c) {
	c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(c->socket == -1) {
		if(mesh->log_level <= MESHLINK_ERROR) {
			char *hostname = sockaddr2hostname(&c->address);
			logger(mesh, MESHLINK_ERROR, "Creating socket for %s at %s failed: %s", c->name, hostname, sockstrerror(sockerrno));
			free(hostname);
		}

		return false;
	}

	configure_tcp(c);

#ifdef FD_CLOEXEC
	fcntl(c->socket, F_SETFD, FD_CLOEXEC);
#endif

#if defined(IPV6_V6ONLY)

	if(c->address.sa.sa_family == AF_INET6) {
		static const int option = 1;
		setsockopt(c->socket, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
	}

#endif

	/* Connect */

	int result = connect(c->socket, &c->address.sa, SALEN(c->address.sa));

	if(result == -1 && !sockinprogress(sockerrno)) {
		if(mesh->log_level <= MESHLINK_ERROR) {
			char *hostname = sockaddr2hostname(&c->address);
			logger(mesh, MESHLINK_ERROR, "Could not connect to %s at %s: %s", c->name, hostname, sockstrerror(sockerrno));
			free(hostname);
		}

		return false;
	}

	/* Now that there is a working socket, fill in the rest and register this connection. */

	c->status.connecting = true;
	c->status.initiator = true;
	event_loop_stamp_now(&mesh->loop);
	c->last_ping_time = mesh->loop.now.tv_sec;

	connection_add(mesh, c);

	io_add(&mesh->loop, &c->io, handle_meta_io, c, c->socket, IO_READ | IO_WRITE);

	return true;
}

void reset_outgoing(outgoing_t *outgoing) {
	if(outgoing->node && outgoing->node->mesh) {
		outgoing_clear_pending(outgoing->node->mesh, outgoing, false);
	}

	free_outgoing_addresses(outgoing);
	outgoing->state = OUTGOING_START;
	outgoing->startup_waiting_dns = false;
	outgoing->direct_tries = 0;
	memset(&outgoing->startup_sa, 0, sizeof outgoing->startup_sa);
	memset(&outgoing->skip_sa, 0, sizeof outgoing->skip_sa);
}

void setup_outgoing_connection(meshlink_handle_t *mesh, outgoing_t *outgoing) {
	if(outgoing->pending) {
		return;
	}

	timeout_del(&mesh->loop, &outgoing->ev);
	outgoing_abort_startup(mesh, outgoing);

	if(outgoing->node->connection) {
		logger(mesh, MESHLINK_INFO, "Already connected to %s", outgoing->node->name);

		outgoing->node->connection->outgoing = outgoing;
		return;
	}

	reset_outgoing(outgoing);

	if(outgoing->node->status.blacklisted) {
		return;
	}

	if(mesh->connection_try_cb) {
		mesh->connection_try_cb(mesh, (meshlink_node_t *)outgoing->node);
	}

	do_outgoing_connection(mesh, outgoing);
}

/// Delayed close of a filedescriptor.
static void tarpit(meshlink_handle_t *mesh, int fd) {
	if(!fd) {
		return;
	}

	if(mesh->pits[mesh->next_pit]) {
		closesocket(mesh->pits[mesh->next_pit]);
	}

	mesh->pits[mesh->next_pit++] = fd;

	if(mesh->next_pit >= (int)(sizeof mesh->pits / sizeof mesh->pits[0])) {
		mesh->next_pit = 0;
	}
}

/*
  accept a new tcp connect and create a
  new connection
*/
void handle_new_meta_connection(event_loop_t *loop, void *data, int flags) {
	(void)flags;
	meshlink_handle_t *mesh = loop->data;
	listen_socket_t *l = data;
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof(sa);

	memset(&sa, 0, sizeof(sa));

	fd = accept(l->tcp.fd, &sa.sa, &len);

	if(fd < 0) {
		if(sockwouldblock(errno)) {
			return;
		}

		if(errno == EINVAL) { // TODO: check if Windows agrees
			event_loop_stop(loop);
			return;
		}

		logger(mesh, MESHLINK_ERROR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return;
	}

	sockaddrunmap(&sa);

	/* Rate limit incoming connections to max_connection_burst/second. */

	if(mesh->loop.now.tv_sec != mesh->connection_burst_time) {
		mesh->connection_burst_time = mesh->loop.now.tv_sec;
		mesh->connection_burst = 0;
	}

	if(mesh->connection_burst >= max_connection_burst) {
		tarpit(mesh, fd);
		return;
	}

	mesh->connection_burst++;

	// Accept the new connection

	c = new_connection();
	c->name = xstrdup("<unknown>");

	c->address = sa;
	c->socket = fd;
	c->last_ping_time = mesh->loop.now.tv_sec;

	char *hostname = sockaddr2hostname(&sa);
	logger(mesh, MESHLINK_INFO, "Connection from %s", hostname);
	free(hostname);

	io_add(&mesh->loop, &c->io, handle_meta_io, c, c->socket, IO_READ);

	configure_tcp(c);

	connection_add(mesh, c);

	c->allow_request = ID;
	send_id(mesh, c);
}

static void free_outgoing(outgoing_t *outgoing) {
	meshlink_handle_t *mesh = outgoing->node->mesh;

	outgoing_clear_pending(mesh, outgoing, true);
	timeout_del(&mesh->loop, &outgoing->ev);
	timeout_del(&mesh->loop, &outgoing->startup_ev);
	free_outgoing_addresses(outgoing);
	free(outgoing);
}

void init_outgoings(meshlink_handle_t *mesh) {
	mesh->outgoings = list_alloc((list_action_t)free_outgoing);
}

void exit_outgoings(meshlink_handle_t *mesh) {
	if(mesh->outgoings) {
		list_delete_list(mesh->outgoings);
		mesh->outgoings = NULL;
	}
}
