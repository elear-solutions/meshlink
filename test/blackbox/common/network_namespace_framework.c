/*
    test_optimal_pmtu.c -- Execution of specific meshlink black box test cases
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
#include "network_namespace_framework.h"

#define DEFAULT_PUB_NET_ADDR "203.0.113.0/24"
#define DEFAULT_GATEWAY_NET_ADDR "203.0.113.254"
#define NS_PEER0  " ns_peer0 "
#define NS_ETH0   " ns_eth0 "
#define PEER_INDEX i ? 0 : 1
#define get_namespace_handle_by_index(state_ptr, index) index < state_ptr->num_namespaces ? &(state_ptr->namespaces[index]) : NULL
#define get_interface_handle_by_index(namespace, index) index < namespace->interfaces_no  ? &((namespace->interfaces)[index]) : NULL
#define netns_run_cmd(test_state, namespace_name, str) netns_exec_prog(test_state, namespace_name, str, NULL, 0)
#define netns_run_daemon(test_state, namespace_name, str) netns_exec_prog(test_state, namespace_name, str, NULL, 1)

#define NETNS_DEBUG

#ifdef NETNS_DEBUG
#include <stdarg.h>

static void debug(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#else
#define debug(...) do {} while(0)
#endif

static inline char *xstrdup(const char *s) __attribute__((__malloc__));
static inline char *xstrdup(const char *s) {
	char *p = strdup(s);

	if(!p) {
		abort();
	}

	return p;
}

static char **parse_strtoargs(char *str) {
	int ch, n, len, word_start;
	char **argv;

	ch = n = 0;
	word_start = 1;
	len = strlen(str);

	argv = (char **)calloc(234, sizeof(char *));
	assert(argv);

	for(ch = 0; ch <= len; ch++) {
		if(str[ch] == ' ' || str[ch] == '\0') {
			str[ch] = '\0';
			word_start = 1;
		} else if(word_start) {
			argv[n++] = str + ch;
			word_start = 0;
		}
	}

	argv[n] = NULL;

	return argv;
}

static int ipv4_str_check_cidr(const char *ip_addr) {
	int cidr = 0;
	sscanf(ip_addr, "%*d.%*d.%*d.%*d/%d", &cidr);
	return cidr;
}

static char *ipv4_str_remove_cidr(const char *ipv4_addr) {
	char *ptr = xstrdup(ipv4_addr);

	if(ipv4_str_check_cidr(ptr)) {
		char *end = strchr(ptr, '/');
		*end = '\0';
	}

	return ptr;
}

static int set_netns(const char *namespace_name) {
	char cmd[PATH_MAX];
	assert(sprintf(cmd, "/var/run/netns/%s", namespace_name) >= 0);
	int netns_fd = open(cmd, O_RDONLY);

	if(netns_fd == -1) {
		fprintf(stderr, "Opening namespace file failed due to : %s", strerror(errno));
		return -1;
	}

	if(setns(netns_fd, CLONE_NEWNET) == -1) {
		fprintf(stderr, "Setting namespace failed due to : %s", strerror(errno));
		return -1;
	}

	return 0;
}

static void *pthread_fun(void *arg) {
	netns_thread_t *netns_arg = (netns_thread_t *)arg;

	assert(!set_netns(netns_arg->namespace_name));
	void *ret = (netns_arg->netns_thread)(netns_arg->arg);
	pthread_detach(netns_arg->thread_handle);
	pthread_exit(ret);
}

static void increment_ipv4_str(char *ip_addr, int ip_addr_size) {
	uint32_t addr_int_n, addr_int_h;

	assert(inet_pton(AF_INET, ip_addr, &addr_int_n) > 0);
	addr_int_h = ntohl(addr_int_n);
	addr_int_h = addr_int_h + 1;
	addr_int_n = htonl(addr_int_h);
	assert(inet_ntop(AF_INET, &addr_int_n, ip_addr, ip_addr_size));
}

static void increment_ipv4_cidr_str(char *ip) {
	int subnet;
	assert(ip);
	assert(sscanf(ip, "%*d.%*d.%*d.%*d/%d", &subnet) >= 0);
	char *ptr = strchr(ip, '/');
	*ptr = '\0';
	increment_ipv4_str(ip, INET6_ADDRSTRLEN);
	sprintf(ip, "%s/%d", ip, subnet);
}

static void reset_priv_interfaces(netns_state_t *test_state) {
	for(int netns_no = 0; netns_no < test_state->num_namespaces; netns_no++) {
		namespace_t *netns = get_namespace_handle_by_index(test_state, netns_no);
		assert(netns->interfaces);

		for(int if_no = 0; if_no < netns->interfaces_no; if_no++) {
			interface_t *interface_handle = get_interface_handle_by_index(netns, if_no);
			assert(interface_handle);
			interface_handle->priv = NULL;
		}
	}
}

static namespace_t *find_namespace(netns_state_t *state, const char *namespace_name) {
	for(int i = 0; i < state->num_namespaces; i++) {
		if(!strcmp((state->namespaces[i]).name, namespace_name)) {
			return &(state->namespaces[i]);
		}
	}

	return NULL;
}

static interface_t *get_peer_interface_handle(netns_state_t *test_state, namespace_t *netns, namespace_t *peer_namespace) {
	interface_t *interfaces = netns->interfaces;
	int if_no = netns->interfaces_no;
	char *peer_name = peer_namespace->name;

	for(int i = 0; i < if_no; i++) {
		if(!strcasecmp(interfaces[i].if_peer, peer_name)) {
			return &interfaces[i];
		}
	}

	return NULL;
}

static interface_t *get_interface_handle_by_name(netns_state_t *test_state, namespace_t *netns, const char *peer_name) {
	namespace_t *peer_ns = find_namespace(test_state, peer_name);
	assert(peer_ns);

	return get_peer_interface_handle(test_state, netns, peer_ns);
}

static bool check_interfaces_visited(netns_state_t *test_state, namespace_t *ns1, namespace_t *ns2) {
	interface_t *iface = get_peer_interface_handle(test_state, ns1, ns2);
	interface_t *peer_iface = get_peer_interface_handle(test_state, ns2, ns1);
	assert(iface && peer_iface);

	return iface->priv || peer_iface->priv;
}

static interface_t *netns_get_priv_addr(netns_state_t *test_state, const char *namespace_name) {
	namespace_t *namespace_handle = find_namespace(test_state, namespace_name);
	assert(namespace_handle);

	for(int if_no = 0; if_no < namespace_handle->interfaces_no; if_no++) {
		interface_t *interface_handle = get_interface_handle_by_index(namespace_handle, if_no);

		if(!strcmp(namespace_handle->name, interface_handle->fetch_ip_netns_name)) {
			return interface_handle;
		}
	}

	return NULL;
}

/* Create new network namespace using namespace handle */
static void netns_create_namespace(netns_state_t *test_state, namespace_t *namespace_handle) {
	char cmd[200];

	debug("Creating %s", namespace_handle->name);

	if(namespace_handle->type != BRIDGE) {
		sprintf(cmd, "ip netns add %s", namespace_handle->name);
		assert(system(cmd) == 0);
		sprintf(cmd, "ip netns exec %s ip link set dev lo up", namespace_handle->name);
		assert(system(cmd) == 0);
	} else {
		sprintf(cmd, "ip link add name %s type bridge", namespace_handle->name);
		assert(system(cmd) == 0);
		sprintf(cmd, "ip link set %s up", namespace_handle->name);
		assert(system(cmd) == 0);
	}
}

static int netns_delete_namespace(namespace_t *namespace_handle) {
	char cmd[200];

	if(namespace_handle->type != BRIDGE) {
		assert(sprintf(cmd, "ip netns del %s 2>/dev/null", namespace_handle->name) >= 0);
	} else {
		assert(sprintf(cmd, "ip link del %s 2>/dev/null", namespace_handle->name) >= 0);
	}

	return system(cmd);
}

static void netns_connect_namespaces(netns_state_t *test_state, namespace_t *ns1, namespace_t *ns2) {
	char buff[20], cmd[200], ns_eth0[20], ns_peer0[20];
	int cmd_ret, if_no, i;
	char eth_pairs[2][20];
	namespace_t *ns[2] = { ns1, ns2 };
	interface_t *interface;

	// Check if visited already
	if(check_interfaces_visited(test_state, ns1, ns2)) {
		return;
	}

	assert(sprintf(eth_pairs[0], "%.7s_%.7s", ns2->name, ns1->name) >= 0);
	assert(sprintf(eth_pairs[1], "%.7s_%.7s", ns1->name, ns2->name) >= 0);

	// Delete veth pair if already exists
	for(int i = 0; i < 2; i++) {
		assert(sprintf(cmd, "ip link del %s 2>/dev/null", eth_pairs[i]) >= 0);
		cmd_ret = system(cmd);
	}

	// Create veth pair
	assert(sprintf(cmd, "ip link add %s type veth peer name %s", eth_pairs[0], eth_pairs[1]) >= 0);
	assert(system(cmd) == 0);
	debug("[%s->%s] Veth pairs: %s->%s", ns1->name, ns2->name, eth_pairs[0], eth_pairs[1]);

	for(int i = 0; i < 2; i++) {

		// Find interface handle that with it's peer interface
		interface =  get_peer_interface_handle(test_state, ns[i], ns[PEER_INDEX]);
		assert(interface);

		if(ns[i]->type != BRIDGE) {

			// Define interface name
			if(interface->if_name) {
				interface->if_name  = xstrdup(interface->if_name);
			} else {
				assert(sprintf(buff, "eth_%s", interface->if_peer) >= 0);
				interface->if_name  = xstrdup(buff);
			}

			// Connect one end of the the veth pair to the namespace's interface
			debug("[%s->%s] Linking veth %s to %s's interface %s", ns1->name, ns2->name, eth_pairs[i], ns[i]->name, interface->if_name);
			assert(sprintf(cmd, "ip link set %s netns %s name %s", eth_pairs[i], ns[i]->name, interface->if_name) >= 0);
			assert(system(cmd) == 0);
		} else {

			// Connect one end of the the veth pair to the bridge
			debug("[%s->%s] Linking veth %s to %s's interface", ns1->name, ns2->name, eth_pairs[i], ns[i]->name);
			assert(sprintf(cmd, "ip link set %s master %s up", eth_pairs[i], ns[i]->name) >= 0);
			assert(system(cmd) == 0);
		}

		// Mark interfaces as connected
		interface->priv = (void *)1;
		interface = get_peer_interface_handle(test_state, ns[PEER_INDEX], ns[i]);
		assert(interface);
		interface->priv = (void *)1;
	}
}

static void netns_create_all_namespaces(netns_state_t *test_state) {
	for(int netns_no = 0; netns_no < test_state->num_namespaces; netns_no++) {
		namespace_t *netns = get_namespace_handle_by_index(test_state, netns_no);

		// Delete the namespace if already exists
		netns_delete_namespace(netns);

		// Create namespace
		netns_create_namespace(test_state, netns);
	}
}

static void netns_connect_all_namespaces(netns_state_t *test_state) {
	for(int netns_no = 0; netns_no < test_state->num_namespaces; netns_no++) {
		namespace_t *netns = get_namespace_handle_by_index(test_state, netns_no);
		assert(netns->interfaces);
		interface_t *interfaces = netns->interfaces;

		for(int if_no = 0; if_no < netns->interfaces_no; if_no++) {
			namespace_t *peer_namespace = find_namespace(test_state, interfaces[if_no].if_peer);
			assert(peer_namespace);
			netns_connect_namespaces(test_state, netns, peer_namespace);
		}
	}

	// Reset all priv members of the interfaces
	reset_priv_interfaces(test_state);
}

static void netns_add_default_route_addr(netns_state_t *test_state) {
	for(int netns_no = 0; netns_no < test_state->num_namespaces; netns_no++) {
		namespace_t *namespace_handle = get_namespace_handle_by_index(test_state, netns_no);
		assert(namespace_handle);

		if(namespace_handle->type != HOST) {
			continue;
		}

		for(int if_no = 0; if_no < namespace_handle->interfaces_no; if_no++) {
			interface_t *interface_handle = get_interface_handle_by_index(namespace_handle, if_no);

			if(!interface_handle->if_default_route_ip) {
				if(interface_handle->fetch_ip_netns_name) {
					interface_t *peer_interface_handle = netns_get_priv_addr(test_state, interface_handle->fetch_ip_netns_name);
					assert(peer_interface_handle && peer_interface_handle->if_addr);
					interface_handle->if_default_route_ip  = ipv4_str_remove_cidr(peer_interface_handle->if_addr);
				} else {
					interface_handle->if_default_route_ip = xstrdup(DEFAULT_GATEWAY_NET_ADDR);
				}
			} else {
				interface_handle->if_default_route_ip = xstrdup(interface_handle->if_default_route_ip);
			}

			debug("[%s] Assigning default route IP address: %s (for %s)", namespace_handle->name, interface_handle->if_default_route_ip, interface_handle->if_peer);
			break;
		}
	}
}

static void netns_assign_ip_addresses(netns_state_t *test_state) {
	char *ip;
	char *addr = malloc(INET6_ADDRSTRLEN);
	assert(addr);

	if(test_state->public_net_addr) {
		assert(strncpy(addr, test_state->public_net_addr, INET6_ADDRSTRLEN));
	} else {
		assert(strncpy(addr, DEFAULT_PUB_NET_ADDR, INET6_ADDRSTRLEN));
	}

	test_state->public_net_addr = addr;
	debug("Setting global start IP address as %s", test_state->public_net_addr);

	for(int netns_no = 0; netns_no < test_state->num_namespaces; netns_no++) {
		namespace_t *namespace_handle = get_namespace_handle_by_index(test_state, netns_no);
		assert(namespace_handle);

		if(namespace_handle->type == BRIDGE) {
			continue;
		}

		for(int if_no = 0; if_no < namespace_handle->interfaces_no; if_no++) {
			interface_t *interface_handle = get_interface_handle_by_index(namespace_handle, if_no);
			assert(interface_handle);

			if(interface_handle->if_addr) {
				continue;
			}

			// If fetch ip net namespace name is given get IP address from it, else get a public IP address

			if(interface_handle->fetch_ip_netns_name) {
				if(!strcmp(namespace_handle->name, interface_handle->fetch_ip_netns_name)) {
					ip = interface_handle->host_config_start_addr;
				} else {
					namespace_t *gw_netns_handle = find_namespace(test_state, interface_handle->fetch_ip_netns_name);
					assert(gw_netns_handle);

					interface_t *peer_interface_handle = get_peer_interface_handle(test_state, gw_netns_handle, namespace_handle);
					ip = peer_interface_handle->host_config_start_addr;
				}
			} else {
				ip = test_state->public_net_addr;
			}

			increment_ipv4_cidr_str(ip);
			interface_handle->if_addr = xstrdup(ip);
			debug("[%s]-->[%s] interface %s assigned with IP address: %s\n", namespace_handle->name, interface_handle->if_peer, interface_handle->if_name, interface_handle->if_addr);
		}
	}

	debug("\n\x1b[34m***** Assigning default route IP addresses for host namespaces *****\x1b[0m");
	netns_add_default_route_addr(test_state);
}

static void netns_configure_ip_address(netns_state_t *test_state) {
	char cmd[200];

	for(int netns_no = 0; netns_no < test_state->num_namespaces; netns_no++) {
		namespace_t *netns = get_namespace_handle_by_index(test_state, netns_no);

		for(int if_no = 0; if_no < netns->interfaces_no; if_no++) {
			interface_t *if_handle = get_interface_handle_by_index(netns, if_no);
			assert(if_handle);

			if(if_handle->if_addr && netns->type != BRIDGE) {
				debug("[%s] Setting %s's interface %s with %s network namespace with IP address %s", netns->name, netns->name, if_handle->if_name, if_handle->if_peer, if_handle->if_addr);

				assert(sprintf(cmd, "ip netns exec %s ip addr add %s dev %s", netns->name, if_handle->if_addr, if_handle->if_name) >= 0);
				assert(system(cmd) == 0);
				assert(sprintf(cmd, "ip netns exec %s ip link set dev %s up", netns->name, if_handle->if_name) >= 0);
				assert(system(cmd) == 0);

				if(if_handle->if_default_route_ip && !netns->priv) {
					char *route_ip = ipv4_str_remove_cidr(if_handle->if_default_route_ip);
					debug("[%s] Configuring %s's default route IP address as %s", netns->name, netns->name, route_ip);

					assert(sprintf(cmd, "ip netns exec %s ip route add default via %s", netns->name, route_ip) >= 0);
					assert(system(cmd) == 0);
					free(route_ip);
					netns->priv = (void *)1;
				}
			}
		}
	}

	// Reset all priv members of the interfaces
	reset_priv_interfaces(test_state);
}

static void netns_enable_all_nats(netns_state_t *test_state) {
	char cmd[200];
	char *nat_type[4] = {"full", "address", "port", "symmetric"};

	for(int netns_no = 0; netns_no < test_state->num_namespaces; netns_no++) {
		namespace_t *netns = get_namespace_handle_by_index(test_state, netns_no);

		if(netns->type < FULL_CONE || netns->type > SYMMERTRIC) {
			continue;
		}

		assert(netns->nat_arg);

		netns_nat_handle_t **nat_rules = netns->nat_arg;

		for(int rule_no = 0; nat_rules[rule_no]; rule_no++) {
			netns_nat_handle_t *nat_rule = nat_rules[rule_no];
			assert(nat_rule->wan);
			assert(nat_rule->lan);

			if(!nat_rule->timeout) {
				nat_rule->timeout = 180;
			}

			debug("[%s] Configuring netns to %s NAT", netns->name, nat_type[netns->type]);
			debug("wan interface: %s \tlan interface: %s\ttimeout: %d", nat_rule->wan, nat_rule->lan, nat_rule->timeout);
			snprintf(cmd, sizeof(cmd), "python " POOR_MANS_NAT_SIM_PATH " --type %s --wan eth_%s --lan eth_%s --timeout %d -v", nat_type[netns->type],
			         nat_rule->wan, nat_rule->lan, nat_rule->timeout);

			assert(netns_exec_prog(test_state, netns->name, cmd, NULL, true) != -1);
		}
	}
}

static void netns_namespace_init_pids(netns_state_t *test_state) {
	for(int if_no = 0; if_no < test_state->num_namespaces; if_no++) {
		namespace_t *namespace_handle = get_namespace_handle_by_index(test_state, if_no);
		assert(namespace_handle);
		namespace_handle->pid_nos = 0;
		namespace_handle->pids = NULL;
	}
}

int netns_exec_prog(netns_state_t *test_state, const char *namespace_name, const char *str, const char *redirect_file, bool daemon_stat) {
	pid_t pid;

	if(!test_state || !namespace_name || !str) {
		fprintf(stderr, "Invalid input arguments!\n");
		return -1;
	}

	namespace_t *namespace_handle = find_namespace(test_state, namespace_name);

	if(!namespace_handle) {
		fprintf(stderr, "Could not find the given namespace in the topology\n");
		return -1;
	}

	if((pid = fork()) == 0) {
		char cmd[PATH_MAX];
		assert(!set_netns(namespace_name));

		/*if(daemon_stat) {
		    assert(daemon(1, 0) != -1);
		}*/

		if(redirect_file) {
			int log_fd = open(redirect_file, O_CREAT | O_RDWR | O_TRUNC, 0644);
			assert(log_fd != -1);
			assert(dup2(log_fd, STDOUT_FILENO) != -1);
			assert(dup2(log_fd, STDERR_FILENO) != -1);
			close(log_fd);
		}

		char **argv = parse_strtoargs(xstrdup(str));
		assert(getcwd(cmd, sizeof(cmd)));
		strcpy(cmd, argv[0]);

		assert(execvp(cmd, argv) != -1);
	}

	if(daemon_stat) {
		pid_t *pid_ptr = realloc(namespace_handle->pids, (namespace_handle->pid_nos + 1) * sizeof(pid_t));
		assert(pid_ptr);
		namespace_handle->pids = pid_ptr;
		(namespace_handle->pids)[namespace_handle->pid_nos] = pid;
		namespace_handle->pid_nos = namespace_handle->pid_nos + 1;
		return pid;
	} else {
		int status;
		assert(waitpid(pid, &status, 0) != -1);

		if(WIFEXITED(status)) {
			debug("exited with status %d\n", WEXITSTATUS(status));
			return WEXITSTATUS(status);
		} else if(WIFSIGNALED(status)) {
			debug("Received signal %d\n", WTERMSIG(status));
		}

		return -1;
	}
}

void run_node_in_namespace_thread(netns_thread_t *netns_arg) {
	assert(netns_arg->namespace_name && netns_arg->netns_thread);
	assert(!pthread_create(&(netns_arg->thread_handle), NULL, pthread_fun, netns_arg));
}

bool netns_create_topology(netns_state_t *test_state) {
	debug("\x1b[32mCreating network namespace topology for %s\x1b[0m", test_state->test_case_name);

	debug("\n\x1b[34m***** (Re)create name-spaces and bridges *****\x1b[0m");
	netns_create_all_namespaces(test_state);

	debug("\n\x1b[34m***** Connect namespaces and bridges(if any) with their interfaces *****\x1b[0m");
	netns_connect_all_namespaces(test_state);

	debug("\n\x1b[34m***** Assign IP addresses for the interfaces in namespaces *****\x1b[0m");
	netns_assign_ip_addresses(test_state);

	debug("\n\x1b[34m***** Configure assigned IP addresses with the interfaces in netns *****\x1b[0m");
	netns_configure_ip_address(test_state);

	debug("\n\x1b[34m***** Enable all NATs in the topology *****\x1b[0m");
	netns_enable_all_nats(test_state);

	netns_namespace_init_pids(test_state);

	fprintf(stderr, "\x1b[32mTopology created for %s\x1b[0m\n\n", test_state->test_case_name);
	return true;
}

void netns_destroy_topology(netns_state_t *test_state) {
	for(int if_no = 0; if_no < test_state->num_namespaces; if_no++) {
		namespace_t *namespace_handle = get_namespace_handle_by_index(test_state, if_no);
		assert(namespace_handle->interfaces);

		for(int i = 0; i < namespace_handle->pid_nos; i++) {
			pid_t pid = (namespace_handle->pids)[i];
			assert(kill(pid, SIGINT) != -1);
			pid_t pid_ret = waitpid(pid, NULL, WNOHANG);
			assert(pid_ret != -1);

			if(pid_ret == 0) {
				fprintf(stderr, "pid: %d, is still running\n", pid);
			}
		}

		// Free interface name, interface address, interface default address etc.,
		// which are dynamically allocated and set the values to NULL

		for(int j = 0; j < namespace_handle->interfaces_no; j++) {
			interface_t *interface_handle = get_interface_handle_by_index(namespace_handle, j);
			assert(interface_handle);

			free(interface_handle->if_name);
			interface_handle->if_name = NULL;
			free(interface_handle->if_addr);
			interface_handle->if_addr = NULL;
			free(interface_handle->if_default_route_ip);
			interface_handle->if_default_route_ip = NULL;
		}

		// Delete namespace
		assert(netns_delete_namespace(namespace_handle) == 0);
	}

	free(test_state->public_net_addr);
	test_state->public_net_addr = NULL;
}
