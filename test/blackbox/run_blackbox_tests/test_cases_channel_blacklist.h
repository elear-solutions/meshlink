#ifndef TEST_CASES_CHANNEL_CONN_H
#define TEST_CASES_CHANNEL_CONN_H

/*
    test_cases_channel_blacklist.h -- Declarations for Individual Test Case implementation functions
    Copyright (C) 2018  Guus Sliepen <guus@meshlink.io>

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


#include <stdbool.h>
extern int total_tests;
extern int test_meshlink_channel_blacklist(void);

extern void *test_channel_blacklist_disconnection_nut_01(void *arg);
extern void *test_channel_blacklist_disconnection_peer_01(void *arg);
extern void *test_channel_blacklist_disconnection_relay_01(void *arg);

extern int total_reachable_callbacks_01;
extern int total_unreachable_callbacks_01;
extern int total_channel_closure_callbacks_01;
extern bool channel_discon_case_ping;
extern bool channel_discon_network_failure_01;
extern bool channel_discon_network_failure_02;
extern bool test_channel_blacklist_disconnection_peer_01_running;
extern bool test_channel_blacklist_disconnection_relay_01_running;
extern bool test_blacklist_whitelist_01;
extern bool test_channel_restart_01;
extern bool test_channel_blacklist_disconnection_nut_running;
extern bool test_channel_blacklist_disconnection_nut2_running;
extern bool test_channel_blacklist_disconnection_peer_running;
extern bool test_channel_blacklist_disconnection_relay_running;
extern struct sync_flag test_channel_discon_close;
extern bool test_channel_discon_case_02;
extern bool test_channel_discon_case_03;
extern bool test_channel_discon_case_04;
extern bool nut_peer_metaconn;
extern bool nut_relay_metaconn;
extern bool peer_nut_metaconn;
extern bool peer_relay_metaconn;
extern bool relay_nut_metaconn;
extern bool relay_peer_metaconn;

#define MESHLINK_LOG_LEVEL MESHLINK_DEBUG

#define PRINT_FAILURE_MSG(...) \
	do { \
		fprintf(stderr, "\x1b[1m\x1b[31m[FAILURE]\x1b[97m  "); \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n[in %s, line no : %d]\x1b[0m\n", __FILE__, __LINE__); \
	} while(0)

#endif // TEST_CASES_CHANNEL_CONN_H
