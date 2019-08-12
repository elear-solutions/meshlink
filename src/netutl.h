#ifndef MESHLINK_NETUTL_H
#define MESHLINK_NETUTL_H

/*
    netutl.h -- header file for netutl.c
    Copyright (C) 2014, 2017 Guus Sliepen <guus@meshlink.io>

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

#include "net.h"
#include "packmsg.h"

extern struct addrinfo *str2addrinfo(const char *, const char *, int) __attribute__((__malloc__));
extern sockaddr_t str2sockaddr(const char *, const char *);
extern void sockaddr2str(const sockaddr_t *, char **, char **);
extern char *sockaddr2hostname(const sockaddr_t *) __attribute__((__malloc__));
extern int sockaddrcmp(const sockaddr_t *, const sockaddr_t *);
extern int sockaddrcmp_noport(const sockaddr_t *, const sockaddr_t *);
extern void sockaddrunmap(sockaddr_t *);
extern void sockaddrfree(sockaddr_t *);
extern void sockaddrcpy(sockaddr_t *, const sockaddr_t *);
extern void sockaddrcpy_setport(sockaddr_t *, const sockaddr_t *, uint16_t port);

extern void packmsg_add_sockaddr(struct packmsg_output *out, const sockaddr_t *);
extern sockaddr_t packmsg_get_sockaddr(struct packmsg_input *in);

#endif
