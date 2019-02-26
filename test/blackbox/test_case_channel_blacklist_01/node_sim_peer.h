#ifndef NODE_SIM_PEER_02_H
#define NODE_SIM_PEER_02_H

/*
    node_sim_peer_02.h -- Implementation of Node Simulation for Meshlink Testing
    Copyright (C) 2019  Guus Sliepen <guus@meshlink.io>

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

extern void *test_channel_blacklist_disconnection_peer_02(void *arg);
extern bool test_channel_blacklist_disonnection_peer_02_running;
extern bool test_case_signal_peer_nut_open_channel_02;
extern bool test_case_signal_peer_restart_02;
extern bool test_case_signal_peer_start_02;
extern bool test_case_signal_peer_stop_02;

#endif
