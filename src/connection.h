#ifndef MESHLINK_CONNECTION_H
#define MESHLINK_CONNECTION_H

/*
    connection.h -- header for connection.c
    Copyright (C) 2000-2013, 2017 Guus Sliepen <guus@meshlink.io>

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

#include "buffer.h"
#include "list.h"
#include "sptps.h"

#include <time.h>

#define OPTION_INDIRECT         0x0001
#define OPTION_TCPONLY          0x0002
#define OPTION_PMTU_DISCOVERY   0x0004
#define OPTION_CLAMP_MSS        0x0008
#define OPTION_VERSION(x) ((x) >> 24) /* Top 8 bits are for protocol minor version */

/* One 32-bit word. The flags that predate private paths already filled a
   uint16_t; the private-path bits stay in that same word. */
typedef struct connection_status_t {
	uint32_t pinged: 1;                 /* sent ping */
	uint32_t active: 1;                 /* 1 if active.. */
	uint32_t connecting: 1;             /* 1 if we are waiting for a non-blocking connect() to finish */
	uint32_t drain_only: 1;             /* 1 if retired after META promotion; flush then close */
	uint32_t control: 1;                /* 1 if this is a control connection */
	uint32_t pcap: 1;                   /* 1 if this is a control connection requesting packet capture */
	uint32_t log: 1;                    /* 1 if this is a control connection requesting log dump */
	uint32_t invitation: 1;             /* 1 if this is an invitation */
	uint32_t invitation_used: 1;        /* 1 if the invitation has been consumed */
	uint32_t initiator: 1;              /* 1 if we initiated this connection */
	uint32_t raw_packet: 1;             /* 1 if we are expecting a raw packet next */
	uint32_t via_canonical: 1;          /* protocol-facing META class; written only via path_mark_meta_dial */
	uint32_t upgrade_probe: 1;          /* 1 if this is a probe trying to replace a canonical connection with a direct one */
	uint32_t spare: 1;                  /* 1 if authenticated but held behind the node's current connection until that one closes */
	uint32_t meta_dial_tier: 2;         /* mirror of via_canonical as meta_dial_tier_t (devtools/logs) */
	uint32_t private_carrier: 1;        /* promoted private backbone META */
	uint32_t bb_private_queried: 1;     /* this member asked us for private endpoints */
	uint32_t bb_private_asked: 1;       /* we asked the backbone over this connection; it now pushes CHANGED here */
	uint32_t bb_private_probe: 1;       /* upgrade probe dialed from the backbone's private endpoint set */
} connection_status_t;

#include "ecdsa.h"
#include "edge.h"
#include "net.h"
#include "node.h"
#include "submesh.h"

typedef struct connection_t {
	char *name;                     /* name he claims to have */
	struct node_t *node;            /* node associated with the other end */

	connection_status_t status;     /* status info */
	int socket;                     /* socket used for this connection */
	union sockaddr_t address;       /* his real (internet) ip */

	uint64_t generation;           /* Assigned by connection_add for every accepted/outgoing socket */
	struct meshlink_handle *mesh;   /* the mesh this connection belongs to */

	// I/O
	sptps_t sptps;
	struct buffer_t inbuf;
	struct buffer_t outbuf;
	io_t io;                        /* input/output event on this metadata connection */
	int tcplen;                     /* length of incoming TCPpacket */
	int allow_request;              /* defined if there's only one request possible */
	time_t last_ping_time;          /* last time we saw some activity from the other end or pinged them */
	unsigned pings_sent;            /* send_ping() calls on this socket; tests read it */
	time_t last_key_renewal;        /* last time we renewed the SPTPS key */
	time_t activated_at;            /* first time this META socket became active; never restamped on key renewal */

	struct outgoing_t *outgoing;    /* used to keep track of outgoing connections */
	uint32_t outgoing_generation;   /* outgoing_t.generation when this socket was opened */
	timeout_t drain_ev;             /* cleanup guard for drain_only sockets */
	struct list_t *standby_held;    /* ordinary META received while spare; replayed on promotion */
	size_t standby_held_bytes;
	int meta_receive_depth;         /* receive_request() frames currently on this connection */
	bool meta_replay_failed;        /* a nested replay failed; the outer frame must return false */
	bool meta_teardown;             /* deferred close: send_meta fails, I/O frees the connection */

	struct edge_t *edge;            /* edge associated with this connection */
	struct submesh_t *submesh;      /* his submesh handle if available in invitation file */

	// Only used during authentication
	ecdsa_t *ecdsa;                 /* his public ECDSA key */
	int protocol_major;             /* used protocol */
	int protocol_minor;             /* used protocol */
	uint32_t flags;                 /* used protocol flags */
	time_t bb_private_reply_at;     /* backbone: earliest next private-endpoint reply */
} connection_t;

void init_connections(struct meshlink_handle *mesh);
void exit_connections(struct meshlink_handle *mesh);
connection_t *new_connection(void) __attribute__((__malloc__));
void free_connection(connection_t *);
void connection_add(struct meshlink_handle *mesh, connection_t *);
void connection_del(struct meshlink_handle *mesh, connection_t *);

#endif
