#ifdef NDEBUG
#undef NDEBUG
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "meshlink.h"
#include "devtools.h"
#include "netns_utils.h"
#include "utils.h"

/* Same routed topology as backbone-private-path: NMN in <prefix>0 starts on
   10.30.1.2 (public 203.0.113.2), VSN in <prefix>1, router <prefix>r. */
#define PREFIX "bbreloc"
#define NMN_FIRST "10.30.1.2"
#define NMN_SECOND "10.30.1.3"
#define NMN_THIRD "10.30.1.4"
#define NMN_PUBLIC "203.0.113.2"
#define CHANNEL_PORT 7

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char channel_rx[256];
static size_t channel_rx_len;
static bool channel_closed;
static meshlink_log_level_t log_level;

static void sh(const char *fmt, ...) {
	char *command = NULL;
	va_list ap;

	va_start(ap, fmt);
	assert(vasprintf(&command, fmt, ap) > 0);
	va_end(ap);
	assert(system(command) == 0);
	free(command);
}

static bool endpoint_is(const struct sockaddr_storage *ss, const char *ip, int port) {
	char buf[INET_ADDRSTRLEN] = "";

	if(ss->ss_family != AF_INET) {
		return false;
	}

	const struct sockaddr_in *in = (const struct sockaddr_in *)ss;
	inet_ntop(AF_INET, &in->sin_addr, buf, sizeof buf);
	return !strcmp(buf, ip) && ntohs(in->sin_port) == port;
}

static bool meta_private_at(meshlink_handle_t *mesh, const char *ip, int port) {
	meshlink_node_t *node = meshlink_get_node(mesh, "nmn");
	devtool_node_status_t st;
	bool up;

	assert(node);
	memset(&st, 0, sizeof st);
	devtool_get_node_status(mesh, node, &st);
	up = st.meta_connected && !st.meta_via_canonical && endpoint_is(&st.meta_address, ip, port);
	devtool_free_node_status(&st);
	return up;
}

static int private_state(meshlink_handle_t *mesh) {
	meshlink_node_t *node = meshlink_get_node(mesh, "nmn");
	devtool_node_status_t st;
	int state;

	assert(node);
	memset(&st, 0, sizeof st);
	devtool_get_node_status(mesh, node, &st);
	state = st.private_path_state;
	devtool_free_node_status(&st);
	return state;
}

static bool udp_private_at(meshlink_handle_t *mesh, const char *ip, int port) {
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof ss);
	return devtool_backbone_udp_confirmed(mesh)
	       && devtool_backbone_udp_endpoint(mesh, &ss)
	       && endpoint_is(&ss, ip, port);
}

static bool set_has(meshlink_handle_t *mesh, const char *ip, int port, uint32_t *revision) {
	struct sockaddr_storage set[8];
	size_t count = devtool_backbone_private_set(mesh, set, 8, revision);

	for(size_t i = 0; i < count && i < 8; i++) {
		if(endpoint_is(&set[i], ip, port)) {
			return true;
		}
	}

	return false;
}

static size_t set_size(meshlink_handle_t *mesh) {
	return devtool_backbone_private_set(mesh, NULL, 0, NULL);
}

/* The set is refreshed by the member's query on the new connection, which
   can land a tick after the carriers converge. */
static bool wait_set_only(meshlink_handle_t *mesh, const char *ip, int port, int seconds) {
	for(int i = 0; i <= seconds * 4; i++) {
		if(set_size(mesh) == 1 && set_has(mesh, ip, port, NULL)) {
			return true;
		}

		usleep(250000);
	}

	return false;
}

static void channel_receive(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	pthread_mutex_lock(&lock);

	if(!data || !len) {
		channel_closed = true;
	} else if(channel_rx_len + len < sizeof channel_rx) {
		memcpy(channel_rx + channel_rx_len, data, len);
		channel_rx_len += len;
		channel_rx[channel_rx_len] = 0;
	}

	pthread_mutex_unlock(&lock);
}

static bool channel_accept(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	if(port != CHANNEL_PORT) {
		return false;
	}

	meshlink_set_channel_receive_cb(mesh, channel, channel_receive);

	if(data && len) {
		channel_receive(mesh, channel, data, len);
	}

	return true;
}

static void channel_reset(void) {
	pthread_mutex_lock(&lock);
	channel_rx_len = 0;
	channel_rx[0] = 0;
	channel_closed = false;
	pthread_mutex_unlock(&lock);
}

static bool wait_channel(const char *expect, int seconds) {
	for(int i = 0; i <= seconds * 4; i++) {
		bool ok;

		pthread_mutex_lock(&lock);
		ok = !strcmp(channel_rx, expect) && !channel_closed;
		pthread_mutex_unlock(&lock);

		if(ok) {
			return true;
		}

		usleep(250000);
	}

	return false;
}

/* Both carriers proven private on exactly ip:port. */
static bool wait_private_at(meshlink_handle_t *mesh, const char *ip, int port, int seconds) {
	for(int i = 0; i <= seconds * 4; i++) {
		if(meta_private_at(mesh, ip, port) && udp_private_at(mesh, ip, port)) {
			return true;
		}

		usleep(250000);
	}

	return false;
}

static void dump(meshlink_handle_t *mesh, const char *what, const char *ip, int port) {
	uint32_t revision = 0;
	size_t count = devtool_backbone_private_set(mesh, NULL, 0, &revision);

	fprintf(stderr, "%s: want %s:%d meta_private=%d udp_private=%d private_state=%d set=%zu revision=%u rx='%s' closed=%d\n",
	        what, ip, port, meta_private_at(mesh, ip, port), udp_private_at(mesh, ip, port),
	        private_state(mesh), count, revision, channel_rx, channel_closed);
}

static void configure_nmn(meshlink_handle_t *nmn_mesh) {
	meshlink_set_log_cb(nmn_mesh, log_level, log_cb);
	meshlink_enable_discovery(nmn_mesh, false);
	meshlink_set_dev_class_timeouts(nmn_mesh, DEV_CLASS_STATIONARY, 3, 2);
	meshlink_set_channel_accept_cb(nmn_mesh, channel_accept);
	/* The open-time inventory predates the address change; take a fresh scan. */
	meshlink_hint_network_change(nmn_mesh);
}

int main(void) {
	peer_config_t *peers;
	meshlink_handle_t *nmn_mesh;
	meshlink_handle_t *vsn_mesh;
	meshlink_node_t *nmn;
	meshlink_channel_t *channel;
	char *invitation;
	char port[16];
	int first_port;
	int moved_port;
	uint32_t revision = 0;
	uint32_t learned = 0;

	log_level = getenv("MESHLINK_TEST_DEBUG") ? MESHLINK_DEBUG : MESHLINK_INFO;
	peers = setup_backbone_private_routed(PREFIX);
	assert(peers);
	nmn_mesh = peers[0].mesh;
	vsn_mesh = peers[1].mesh;

	first_port = meshlink_get_port(nmn_mesh);
	assert(first_port > 0);
	snprintf(port, sizeof port, "%d", first_port);
	assert(meshlink_set_canonical_address(nmn_mesh, meshlink_get_self(nmn_mesh), NMN_PUBLIC, port));

	configure_nmn(nmn_mesh);
	meshlink_enable_discovery(vsn_mesh, false);
	meshlink_hint_network_change(vsn_mesh);
	meshlink_set_backbone_path_policy(vsn_mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	/* The NMN publishes private listeners with its default disabled member policy. */
	devtool_set_backbone_udp_keepalive(vsn_mesh, 1);
	meshlink_set_dev_class_timeouts(vsn_mesh, DEV_CLASS_BACKBONE, 3, 2);
	meshlink_set_log_cb(vsn_mesh, log_level, log_cb);

	assert(meshlink_start(nmn_mesh));
	invitation = meshlink_invite_ex(nmn_mesh, NULL, peers[1].name, MESHLINK_INVITE_PUBLIC | MESHLINK_INVITE_NUMERIC);
	assert(invitation);
	assert(meshlink_join(vsn_mesh, invitation));
	free(invitation);
	meshlink_stop(nmn_mesh);
	assert(meshlink_start(nmn_mesh));
	assert(meshlink_start(vsn_mesh));

	if(!wait_private_at(vsn_mesh, NMN_FIRST, first_port, 60)) {
		dump(vsn_mesh, "initial migration", NMN_FIRST, first_port);
		assert(false);
	}

	nmn = meshlink_get_node(vsn_mesh, "nmn");
	assert(nmn);
	channel = meshlink_channel_open(vsn_mesh, nmn, CHANNEL_PORT, NULL, NULL, 0);
	assert(channel);
	assert(meshlink_channel_send(vsn_mesh, channel, "A1A2", 4) == 4);
	assert(wait_channel("A1A2", 20));
	assert(set_has(vsn_mesh, NMN_FIRST, first_port, &revision));

	/* 1. Make-before-break IP change. The new address is pushed with CHANGED
	   well inside the 300 s set lifetime, and the still-vouched carrier stays. */
	/* Without promote_secondaries, deleting the primary address below would
	   take the secondary on the same /24 with it. */
	sh("/bin/ip netns exec " PREFIX "0 sysctl -qw net.ipv4.conf.all.promote_secondaries=1 net.ipv4.conf.eth-priv.promote_secondaries=1");
	sh("/bin/ip netns exec " PREFIX "0 ip addr add " NMN_SECOND "/24 dev eth-priv");
	meshlink_hint_network_change(nmn_mesh);

	{
		bool both = false;

		for(int i = 0; i <= 15 * 4 && !both; i++) {
			both = set_has(vsn_mesh, NMN_FIRST, first_port, &learned) && set_has(vsn_mesh, NMN_SECOND, first_port, NULL);

			if(!both) {
				usleep(250000);
			}
		}

		if(!both || learned <= revision) {
			dump(vsn_mesh, "changed push", NMN_SECOND, first_port);
			assert(false);
		}
	}

	for(int i = 0; i < 3; i++) {
		if(!meta_private_at(vsn_mesh, NMN_FIRST, first_port) || !udp_private_at(vsn_mesh, NMN_FIRST, first_port)) {
			dump(vsn_mesh, "vouched carrier churned", NMN_FIRST, first_port);
			assert(false);
		}

		sleep(1);
	}

	/* Retire the old address. Both carriers converge on the new one and the
	   channel keeps its byte stream. */
	sh("/bin/ip netns exec " PREFIX "0 ip addr del " NMN_FIRST "/24 dev eth-priv");
	sh("/bin/ip netns exec " PREFIX "0 ip -4 addr show dev eth-priv | grep -q 'inet " NMN_SECOND "/'");
	meshlink_hint_network_change(nmn_mesh);
	assert(meshlink_channel_send(vsn_mesh, channel, "B1B2", 4) == 4);

	if(!wait_private_at(vsn_mesh, NMN_SECOND, first_port, 60)) {
		dump(vsn_mesh, "graceful change", NMN_SECOND, first_port);
		assert(false);
	}

	if(!wait_channel("A1A2B1B2", 30)) {
		dump(vsn_mesh, "graceful change channel", NMN_SECOND, first_port);
		assert(false);
	}

	assert(private_state(vsn_mesh) == 2);

	if(!wait_set_only(vsn_mesh, NMN_SECOND, first_port, 10)) {
		dump(vsn_mesh, "graceful change set", NMN_SECOND, first_port);
		assert(false);
	}

	/* 2. NMN restarts on a new private IP and port behind a stable canonical.
	   DNAT on the canonical address stands in for the NLB. */
	moved_port = first_port < 65000 ? first_port + 1 : first_port - 1;
	meshlink_channel_close(vsn_mesh, channel);
	meshlink_close(nmn_mesh);
	peers[0].mesh = NULL;
	/* Losing the last address on the link would flush the route to the VSN subnet. */
	sh("/bin/ip netns exec " PREFIX "0 ip addr add " NMN_THIRD "/24 dev eth-priv");
	sh("/bin/ip netns exec " PREFIX "0 ip addr del " NMN_SECOND "/24 dev eth-priv");
	sh("/bin/ip netns exec " PREFIX "0 ip route replace 10.30.2.0/24 via 10.30.1.1");
	sh("/bin/ip netns exec " PREFIX "0 iptables -w -t nat -A PREROUTING -d " NMN_PUBLIC
	   " -p tcp --dport %d -j DNAT --to-destination " NMN_PUBLIC ":%d", first_port, moved_port);

	{
		meshlink_open_params_t *params = meshlink_open_params_init(PREFIX "_conf.1", "nmn", PREFIX, DEV_CLASS_BACKBONE);

		assert(params);
		/* meshlink_close() closed the previous namespace fd. */
		peers[0].netns = open("/run/netns/" PREFIX "0", O_RDONLY);
		assert(peers[0].netns != -1);
		assert(meshlink_open_params_set_netns(params, peers[0].netns));
		assert(meshlink_open_params_set_port_range(params, (uint16_t)moved_port, (uint16_t)moved_port));
		nmn_mesh = meshlink_open_ex(params);
		free(params);
		assert(nmn_mesh);
		peers[0].mesh = nmn_mesh;
	}

	assert(meshlink_get_port(nmn_mesh) == moved_port);
	configure_nmn(nmn_mesh);
	channel_reset();
	assert(meshlink_start(nmn_mesh));

	/* The new session wipes the old set; nothing from 10.30.1.3 survives. */
	if(!wait_private_at(vsn_mesh, NMN_THIRD, moved_port, 90)) {
		dump(vsn_mesh, "restart relocation", NMN_THIRD, moved_port);
		assert(false);
	}

	assert(private_state(vsn_mesh) == 2);

	if(!wait_set_only(vsn_mesh, NMN_THIRD, moved_port, 10)) {
		dump(vsn_mesh, "restart set", NMN_THIRD, moved_port);
		assert(false);
	}

	nmn = meshlink_get_node(vsn_mesh, "nmn");
	assert(nmn);
	channel = meshlink_channel_open(vsn_mesh, nmn, CHANNEL_PORT, NULL, NULL, 0);
	assert(channel);
	assert(meshlink_channel_send(vsn_mesh, channel, "R1R2", 4) == 4);

	if(!wait_channel("R1R2", 20)) {
		dump(vsn_mesh, "restart channel", NMN_THIRD, moved_port);
		assert(false);
	}

	meshlink_channel_close(vsn_mesh, channel);
	close_backbone_private_routed(peers);
	return 0;
}
