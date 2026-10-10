/*
    net.c -- most of the network code
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

#include "utils.h"
#include "conf.h"
#include "connection.h"
#include "connection_policy.h"
#include "devtools.h"
#include "graph.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "meta.h"
#include "net.h"
#include "net_upgrade.h"
#include "netutl.h"
#include "node.h"
#include "path_policy.h"
#include "protocol.h"
#include "relay.h"
#include "sptps.h"
#include "xalloc.h"

#include <assert.h>

static const int default_timeout = 5;
static const int default_interval = 60;

/* LAN TCP has no NAT timeout. While that peer's direct UDP is up and a
   channel still wants it, a META ping only duplicates the UDP liveness probe. */
static bool lan_meta_quiet_ok(meshlink_handle_t *mesh, connection_t *c) {
	node_t *n = c->node;

	if(!n || !connection_policy_is_local_adjacency(mesh, n)) {
		return false;
	}

	if(!path_peer_udp_demanded(mesh, n) || !n->status.udp_confirmed) {
		return false;
	}

	return !n->active_route.suspect;
}

/* An outgoing connection that dies this soon after it activated did not really work:
   the peer dropped it on purpose (simultaneous-connect tie-break, connection limit) and
   will do so again, so reconnecting at once only produces a handshake per round trip. */
static const int min_connection_lifetime = 5;

/* Build the self->n edge that represents c. Not yet in the graph: see add_connection_edge(). */
edge_t *new_connection_edge(meshlink_handle_t *mesh, connection_t *c, node_t *n, const char *hisport, int devclass) {
	assert(devclass >= 0 && devclass < DEV_CLASS_COUNT);

	edge_t *e = new_edge();
	e->from = mesh->self;
	e->to = n;
	sockaddrcpy_setport(&e->address, &c->address, atoi(hisport));
	e->weight = mesh->dev_class_traits[devclass].edge_weight;
	e->connection = c;

	/* The initiator who dialled a relay must advertise that hop as indirect.
	   The responder's edge carries the initiator's advertised listen port on
	   the TCP source IP; that is a real candidate, not the NLB. */
	if(c->status.via_canonical && c->outgoing) {
		e->options |= OPTION_INDIRECT;
	}

	return e;
}

/* Make c the connection we reach n through. */
void install_node_connection(meshlink_handle_t *mesh, node_t *n, connection_t *c) {
	if(n->connection != c) {
		relay_invalidate_connection(mesh, n);
		relay_hop_stop(mesh, n);
		if(mesh->self->devclass == DEV_CLASS_BACKBONE) { memset(&n->udp_observation, 0, sizeof n->udp_observation); }
	}
	n->connection = c;
	n->nexthop = n;
	n->last_successfull_connection = mesh->loop.now.tv_sec;
	c->node = n;
}

/* Put c->edge in the graph, tell everyone, and recompute routes. */
void add_connection_edge(meshlink_handle_t *mesh, connection_t *c) {
	edge_add(mesh, c->edge);
	send_add_edge(mesh, mesh->everyone, c->edge, 0);
	graph(mesh);
}

/*
  Terminate a connection:
  - Mark it as inactive
  - Remove the edge representing this connection
  - Kill it with fire
  - Check if we need to retry making an outgoing connection
*/
void connection_defer_teardown(meshlink_handle_t *mesh, connection_t *c) {
	(void)mesh;

	if(!c || c->meta_teardown) {
		return;
	}

	c->meta_teardown = true;

	/* The connection stays allocated. The next read sees EOF and
	   terminate_connection() runs outside receive_request(). */
	if(c->socket >= 0) {
		shutdown(c->socket, SHUT_RDWR);
	}
}

void terminate_connection(meshlink_handle_t *mesh, connection_t *c, bool report) {
	/* last_key_renewal is restamped hourly; do not use it for backbone
	   stability. Non-backbone flap detection still uses it. */
	bool was_active = c->status.active && !c->status.drain_only;
	bool flapped = was_active && mesh->loop.now.tv_sec - c->last_key_renewal < min_connection_lifetime;
	time_t activated_at = c->activated_at;

	timeout_del(&mesh->loop, &c->drain_ev);

	if(c->status.active && !c->status.drain_only) {
		logger(mesh, MESHLINK_INFO, "Closing connection with %s", c->name);
	}

	/* Probe bookkeeping and, if a spare is held for this node, hand the node over to it. */

	upgrade_connection_closing(mesh, c);

	if(c->node && c->node->connection == c) {
		if(was_active && connection_policy_is_local_adjacency(mesh, c->node)) {
			connection_policy_note_lan_drop(mesh, c->node);
		}

		if(c->status.active && mesh->meta_status_cb) {
			mesh->meta_status_cb(mesh, (meshlink_node_t *)c->node, false);
		}

		c->node->connection = NULL;
	}

	c->status.active = false;

	if(c->edge) {
		if(report) {
			send_del_edge(mesh, mesh->everyone, c->edge, 0);
		}

		edge_del(mesh, c->edge);
		c->edge = NULL;

		/* Run MST and SSSP algorithms */

		graph(mesh);

		/* If the node is not reachable anymore but we remember it had an edge to us, clean it up */

		if(report && c->node && !c->node->status.reachable) {
			edge_t *e;
			e = lookup_edge(c->node, mesh->self);

			if(e) {
				send_del_edge(mesh, mesh->everyone, e, 0);
				edge_del(mesh, e);
			}
		}
	}

	if(mesh->outgoings) {
		for list_each(outgoing_t, o, mesh->outgoings) {
			if(o->pending == c) {
				outgoing_note_failed_dest(o, &c->address);
				o->pending = NULL;
				timeout_del(&mesh->loop, &o->startup_ev);
			}
		}
	}

	outgoing_t *outgoing = c->outgoing;
	node_t *peer = c->node;
	meta_connection_purpose_t purpose = outgoing ? outgoing->purpose : META_PURPOSE_NONE;
	c->outgoing = NULL;
	connection_del(mesh, c);

	/* Check if this was our outgoing connection. ack_h() reset the address walk when it
	   activated, so either path starts over at recent[]. A refused/timeout startup
	   socket continues the epoch (direct then canonical). An authenticated
	   BACKBONE_REQUIRED drop always waits on the telescopic ladder, and only
	   a session that lived BACKBONE_STABLE_RESET_SEC clears retry_step first.
	   LAN_RESILIENCE always waits on the generic retry; immediate redial plus
	   tick resetting skip_sa busy-loops. Other outgoings that flapped go through
	   retry_outgoing(); a stable drop of a non-persistent intent redials
	   immediately. Persistent outgoings stay on the list
	   (meta_purpose_is_persistent). Retiring an intent must not redial it. */

	if(outgoing && !mesh->retiring_outgoing) {
		if(outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED && was_active) {
			if(activated_at && mesh->loop.now.tv_sec - activated_at >= BACKBONE_STABLE_RESET_SEC) {
				connection_policy_reset_backbone_retry(outgoing);
			}

			retry_outgoing(mesh, outgoing);
		} else if(outgoing->purpose == META_PURPOSE_LAN_RESILIENCE) {
			retry_outgoing(mesh, outgoing);
		} else if(flapped) {
			retry_outgoing(mesh, outgoing);
		} else {
			do_outgoing_connection(mesh, outgoing);
		}
	}

	connection_policy_on_connection_closed(mesh, peer, purpose);
}

/*
  Check if the other end is active.
  If we have sent packets, but didn't receive any,
  then possibly the other end is dead. We send a
  PING request over the meta connection. If the other
  end does not reply in time, we consider them dead
  and close the connection.
*/
static void timeout_handler(event_loop_t *loop, void *data) {
	assert(data);

	meshlink_handle_t *mesh = loop->data;

	for list_each(connection_t, c, mesh->connections) {
		int pingtimeout = c->node ? mesh->dev_class_traits[c->node->devclass].pingtimeout : default_timeout;
		int pinginterval = c->node ? mesh->dev_class_traits[c->node->devclass].pinginterval : default_interval;

		if(c->status.drain_only) {
			continue;
		}

		if(c->outgoing && !c->status.active && c->outgoing->timeout < 5) {
			pingtimeout = 1;
		}

		if(c->status.active && c->last_key_renewal + 3600 < mesh->loop.now.tv_sec) {
			devtool_sptps_renewal_probe((meshlink_node_t *)c->node);

			if(!sptps_force_kex(&c->sptps)) {
				logger(mesh, MESHLINK_ERROR, "SPTPS key renewal for connection with %s failed", c->name);
				terminate_connection(mesh, c, true);
				continue;
			} else {
				c->last_key_renewal = mesh->loop.now.tv_sec;
			}
		}

		if(c->last_ping_time + pingtimeout < mesh->loop.now.tv_sec) {
			if(c->status.active) {
				/* UDP liveness already covers this LAN peer. Do not tear
				   down an outstanding PING, and stamp the timer so the
				   next tick does not re-enter this arm. */
				if(lan_meta_quiet_ok(mesh, c)) {
					c->status.pinged = false;
					c->last_ping_time = mesh->loop.now.tv_sec;
					continue;
				}

				if(c->status.pinged) {
					logger(mesh, MESHLINK_INFO, "%s didn't respond to PING in %ld seconds", c->name, (long)mesh->loop.now.tv_sec - c->last_ping_time);
				} else if(c->last_ping_time + pinginterval <= mesh->loop.now.tv_sec) {
					send_ping(mesh, c);
					continue;
				} else {
					continue;
				}
			} else {
				if(c->status.connecting) {
					logger(mesh, MESHLINK_WARNING, "Timeout while connecting to %s", c->name);
				} else {
					logger(mesh, MESHLINK_WARNING, "Timeout from %s during authentication", c->name);
				}
			}

			terminate_connection(mesh, c, c->status.active);
		}
	}

	node_kex_watchdog(mesh);

	timeout_set(&mesh->loop, data, &(struct timespec) {
		1, prng(mesh, TIMER_FUDGE)
	});
}

static void periodic_handler(event_loop_t *loop, void *data) {
	meshlink_handle_t *mesh = loop->data;

	/* Check if there are too many contradicting ADD_EDGE and DEL_EDGE messages.
	   This usually only happens when another node has the same Name as this node.
	   If so, sleep for a short while to prevent a storm of contradicting messages.
	*/

	if(mesh->contradicting_del_edge > 100 && mesh->contradicting_add_edge > 100) {
		logger(mesh, MESHLINK_WARNING, "Possible node with same Name as us! Sleeping %d seconds.", mesh->sleeptime);
		struct timespec ts = {mesh->sleeptime, 0};
		nanosleep(&ts, NULL);
		mesh->sleeptime *= 2;

		if(mesh->sleeptime < 0) {
			mesh->sleeptime = 3600;
		}
	} else {
		mesh->sleeptime /= 2;

		if(mesh->sleeptime < 10) {
			mesh->sleeptime = 10;
		}
	}

	mesh->contradicting_add_edge = 0;
	mesh->contradicting_del_edge = 0;

	/* Expire stale candidates, resolve suspect routes and reset failures
	   from healthy_since, never selected_at, never while cooldown is live. */
	for splay_each(node_t, n, mesh->nodes) {
		if(n != mesh->self) {
			path_route_tick(mesh, n);
		}
	}

	int timeout = default_timeout;

	connection_policy_tick(mesh);


	/* Retry canonical -> direct upgrades whose backoff expired. */

	upgrade_probe_sweep(mesh);

	for splay_each(node_t, n, mesh->nodes) {
		if(n->status.dirty) {
			if(!node_write_config(mesh, n, false)) {
				logger(mesh, MESHLINK_DEBUG, "Could not update %s", n->name);
			}
		}

		if(n->status.reachable && n->status.validkey && n->last_req_key + 3600 < mesh->loop.now.tv_sec) {
			logger(mesh, MESHLINK_DEBUG, "SPTPS key renewal for node %s", n->name);
			devtool_sptps_renewal_probe((meshlink_node_t *)n);

			if(!sptps_force_kex(&n->sptps)) {
				logger(mesh, MESHLINK_ERROR, "SPTPS key renewal for node %s failed", n->name);
				node_set_validkey(mesh, n, false);
				sptps_stop(&n->sptps);
				n->status.waitingforkey = false;
				n->last_req_key = -3600;
			} else {
				n->last_req_key = mesh->loop.now.tv_sec;
			}
		}
	}

	timeout_set(&mesh->loop, data, &(struct timespec) {
		timeout, prng(mesh, TIMER_FUDGE)
	});
}

void handle_meta_connection_data(meshlink_handle_t *mesh, connection_t *c) {
	if(!receive_meta(mesh, c)) {
		terminate_connection(mesh, c, c->status.active);
		return;
	}
}

void retry(meshlink_handle_t *mesh) {
	/* Reset the reconnection timers for all outgoing connections */
	for list_each(outgoing_t, outgoing, mesh->outgoings) {
		if(outgoing->purpose == META_PURPOSE_BACKBONE_REQUIRED) {
			connection_policy_reset_backbone_retry(outgoing);
		} else {
			outgoing->timeout = 0;
		}

		/* Arm the retry before dialling: do_outgoing_connection() can run out
		   of addresses and delete this entry, and free_outgoing() takes the
		   timer with it. Touching outgoing afterwards would be a use after
		   free. */
		if(outgoing->ev.cb) {
			timeout_set(&mesh->loop, &outgoing->ev, &(struct timespec) {
				0, 0
			});
		}

		if(outgoing->pending && !outgoing->pending->status.active) {
			outgoing_abort_startup(mesh, outgoing);
			outgoing->state = OUTGOING_START;
			do_outgoing_connection(mesh, outgoing);
		}
	}

	/* For active connections, check if their addresses are still valid.
	 * If yes, reset their ping timers, otherwise terminate them. */
	for list_each(connection_t, c, mesh->connections) {
		if(!c->status.active) {
			continue;
		}

		if(!c->status.pinged) {
			c->last_ping_time = -3600;
		}

		sockaddr_t sa;
		socklen_t salen = sizeof(sa);

		if(getsockname(c->socket, &sa.sa, &salen)) {
			continue;
		}

		switch(sa.sa.sa_family) {
		case AF_INET:
			sa.in.sin_port = 0;
			break;

		case AF_INET6:
			sa.in6.sin6_port = 0;
			break;

		default:
			continue;
		}

		/* retry() also runs on the app thread (hint_network_change); probe the
		   address in the mesh's namespace, not the caller's. */
		int sock = socket_in_netns(sa.sa.sa_family, SOCK_STREAM, IPPROTO_TCP, mesh->netns);

		if(sock == -1) {
			continue;
		}

		if(bind(sock, &sa.sa, salen) && errno == EADDRNOTAVAIL) {
			logger(mesh, MESHLINK_DEBUG, "Local address for connection to %s no longer valid, terminating", c->name);
			terminate_connection(mesh, c, c->status.active);
		}

		closesocket(sock);
	}

	/* Kick the ping timeout handler */
	if(mesh->pingtimer.cb) {
		timeout_set(&mesh->loop, &mesh->pingtimer, &(struct timespec) {
			0, 0
		});
	}
}

/*
  this is where it all happens...
*/
void main_loop(meshlink_handle_t *mesh) {
	event_loop_stamp_now(&mesh->loop);
	timeout_add(&mesh->loop, &mesh->pingtimer, timeout_handler, &mesh->pingtimer, &(struct timespec) {
		1, prng(mesh, TIMER_FUDGE)
	});
	timeout_add(&mesh->loop, &mesh->periodictimer, periodic_handler, &mesh->periodictimer, &(struct timespec) {
		0, 0
	});
	path_scheduler_init(mesh);

	//Add signal handler
	mesh->datafromapp.signum = 0;
	signal_add(&mesh->loop, &mesh->datafromapp, meshlink_send_from_queue, mesh, mesh->datafromapp.signum);

	if(!event_loop_run(&mesh->loop, mesh)) {
		logger(mesh, MESHLINK_ERROR, "Error while waiting for input: %s", strerror(errno));
		call_error_cb(mesh, MESHLINK_ENETWORK);
	}

	signal_del(&mesh->loop, &mesh->datafromapp);
	timeout_del(&mesh->loop, &mesh->periodictimer);
	timeout_del(&mesh->loop, &mesh->pingtimer);
	path_scheduler_stop(mesh);
}
