#ifdef NDEBUG
#undef NDEBUG
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <assert.h>
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

/* NMN in <prefix>0 (10.30.1.2, public 203.0.113.2), VSN in <prefix>1
   (10.30.2.2, public 203.0.113.3), routed through <prefix>r. */
#define PREFIX "bbpriv"
#define NMN_PRIVATE "10.30.1.2"
#define NMN_PUBLIC "203.0.113.2"
#define VSN_PUBLIC "203.0.113.3"
#define CHANNEL_PORT 7

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char channel_rx[256];
static size_t channel_rx_len;
static bool channel_closed;

static void sh(const char *fmt, ...) {
	char *command = NULL;
	va_list ap;

	va_start(ap, fmt);
	assert(vasprintf(&command, fmt, ap) > 0);
	va_end(ap);
	assert(system(command) == 0);
	free(command);
}

/* Packets this netns sent to dest, counted by an OUTPUT rule added in count_start(). */
static unsigned long output_packets(const char *ns, const char *dest) {
	char *command = NULL;
	char line[512];
	unsigned long total = 0;
	FILE *p;

	assert(asprintf(&command, "/bin/ip netns exec %s iptables -w -nvxL OUTPUT", ns) > 0);
	p = popen(command, "r");
	free(command);
	assert(p);

	while(fgets(line, sizeof line, p)) {
		unsigned long pkts;
		char target[32], prot[16], opt[16], in[32], out[32], src[64], dst[64];

		if(sscanf(line, "%lu %*u %31s %15s %15s %31s %31s %63s %63s", &pkts, target, prot, opt, in, out, src, dst) == 8
		                && !strcmp(dst, dest)) {
			total += pkts;
		}
	}

	pclose(p);
	return total;
}

static void count_start(const char *ns, const char *dest) {
	sh("/bin/ip netns exec %s iptables -w -I OUTPUT -d %s -j ACCEPT", ns, dest);
}

static void count_zero(const char *ns) {
	sh("/bin/ip netns exec %s iptables -w -Z OUTPUT", ns);
}

static void block_private(bool block) {
	const char *op = block ? "-I" : "-D";

	sh("/bin/ip netns exec " PREFIX "r iptables -w %s FORWARD -s 10.30.2.0/24 -d 10.30.1.0/24 -j DROP", op);
	sh("/bin/ip netns exec " PREFIX "r iptables -w %s FORWARD -s 10.30.1.0/24 -d 10.30.2.0/24 -j DROP", op);
}

static bool sockaddr_is(const struct sockaddr_storage *ss, const char *ip) {
	char buf[INET6_ADDRSTRLEN] = "";

	if(ss->ss_family == AF_INET) {
		inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, buf, sizeof buf);
	} else if(ss->ss_family == AF_INET6) {
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr, buf, sizeof buf);
	}

	return !strcmp(buf, ip);
}

static void status(meshlink_handle_t *mesh, devtool_node_status_t *st) {
	meshlink_node_t *node = meshlink_get_node(mesh, "nmn");

	assert(node);
	memset(st, 0, sizeof *st);
	devtool_get_node_status(mesh, node, st);
}

static bool meta_connected(meshlink_handle_t *mesh) {
	devtool_node_status_t st;
	bool up;

	status(mesh, &st);
	up = st.meta_connected;
	devtool_free_node_status(&st);
	return up;
}

static bool meta_private(meshlink_handle_t *mesh) {
	devtool_node_status_t st;
	bool up;

	status(mesh, &st);
	up = st.meta_connected && !st.meta_via_canonical && sockaddr_is(&st.meta_address, NMN_PRIVATE);
	devtool_free_node_status(&st);
	return up;
}

static int private_state(meshlink_handle_t *mesh) {
	devtool_node_status_t st;
	int state;

	status(mesh, &st);
	state = st.private_path_state;
	devtool_free_node_status(&st);
	return state;
}

static bool udp_private(meshlink_handle_t *mesh) {
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof ss);
	return devtool_backbone_udp_confirmed(mesh)
	       && devtool_backbone_udp_endpoint(mesh, &ss)
	       && sockaddr_is(&ss, NMN_PRIVATE);
}

static bool udp_public_confirmed(meshlink_handle_t *mesh) {
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof ss);
	return devtool_backbone_udp_confirmed(mesh)
	       && devtool_backbone_udp_endpoint(mesh, &ss)
	       && sockaddr_is(&ss, NMN_PUBLIC);
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

static bool channel_has(const char *expect) {
	bool ok;

	pthread_mutex_lock(&lock);
	ok = !strcmp(channel_rx, expect);
	pthread_mutex_unlock(&lock);
	return ok;
}

static bool wait_until(bool (*cond)(meshlink_handle_t *), meshlink_handle_t *mesh, int seconds) {
	for(int i = 0; i < seconds * 4; i++) {
		if(cond(mesh)) {
			return true;
		}

		usleep(250000);
	}

	return cond(mesh);
}

static bool discovery_quiet(meshlink_handle_t *mesh, const char *name) {
	meshlink_node_t *node = meshlink_get_node(mesh, name);
	devtool_node_status_t st;
	bool quiet;

	assert(node);
	memset(&st, 0, sizeof st);
	devtool_get_node_status(mesh, node, &st);
	quiet = !st.local_discovery_runs && !st.local_discovery_broadcasts && !st.local_discovery_unicasts
	        && !st.local_discovery_active;
	devtool_free_node_status(&st);
	return quiet;
}

static bool both_private(meshlink_handle_t *mesh) {
	return meta_private(mesh) && udp_private(mesh);
}

static bool public_meta_only(meshlink_handle_t *mesh) {
	return meta_connected(mesh) && !meta_private(mesh) && !udp_private(mesh);
}

static bool wait_channel(const char *expect, int seconds) {
	for(int i = 0; i < seconds * 4; i++) {
		if(channel_has(expect)) {
			return true;
		}

		usleep(250000);
	}

	return channel_has(expect);
}

static void dump(meshlink_handle_t *mesh, const char *what) {
	fprintf(stderr, "%s: meta=%d meta_private=%d udp_private=%d udp_public=%d private_state=%d rx='%s' closed=%d\n",
	        what, meta_connected(mesh), meta_private(mesh), udp_private(mesh), udp_public_confirmed(mesh),
	        private_state(mesh), channel_rx, channel_closed);
}

int main(void) {
	peer_config_t *peers;
	meshlink_handle_t *nmn_mesh;
	meshlink_handle_t *vsn_mesh;
	meshlink_node_t *nmn;
	meshlink_channel_t *channel;
	char *invitation;
	char port[16];
	int bound;

	peers = setup_backbone_private_routed(PREFIX);
	assert(peers);
	nmn_mesh = peers[0].mesh;
	vsn_mesh = peers[1].mesh;

	/* Listen sockets are bound inside the peer netns at open. set_port()
	   rebinds from the calling netns, which would hide the canonical address. */
	bound = meshlink_get_port(nmn_mesh);
	assert(bound > 0);
	snprintf(port, sizeof port, "%d", bound);
	assert(meshlink_set_canonical_address(nmn_mesh, meshlink_get_self(nmn_mesh), NMN_PUBLIC, port));

	meshlink_enable_discovery(nmn_mesh, false);
	meshlink_enable_discovery(vsn_mesh, false);
	/* Interfaces are attached after open, so the open-time inventory is only loopback. */
	meshlink_hint_network_change(nmn_mesh);
	meshlink_hint_network_change(vsn_mesh);
	devtool_set_backbone_udp_keepalive(vsn_mesh, 1);

	/* A blackholed private META must be noticed in seconds, not minutes. */
	meshlink_set_dev_class_timeouts(vsn_mesh, DEV_CLASS_BACKBONE, 3, 2);
	meshlink_set_dev_class_timeouts(nmn_mesh, DEV_CLASS_STATIONARY, 3, 2);

	meshlink_log_level_t level = getenv("MESHLINK_TEST_DEBUG") ? MESHLINK_DEBUG : MESHLINK_INFO;
	meshlink_set_log_cb(nmn_mesh, level, log_cb);
	meshlink_set_log_cb(vsn_mesh, level, log_cb);
	meshlink_set_channel_accept_cb(nmn_mesh, channel_accept);

	assert(meshlink_start(nmn_mesh));
	invitation = meshlink_invite_ex(nmn_mesh, NULL, peers[1].name, MESHLINK_INVITE_PUBLIC | MESHLINK_INVITE_NUMERIC);
	assert(invitation);

	if(!meshlink_join(vsn_mesh, invitation)) {
		fprintf(stderr, "join failed: %s\n", meshlink_strerror(meshlink_errno));
		assert(false);
	}

	free(invitation);
	meshlink_stop(nmn_mesh);
	assert(meshlink_start(nmn_mesh));
	assert(meshlink_start(vsn_mesh));

	assert(devtool_get_backbone_name(vsn_mesh));
	assert(!strcmp(devtool_get_backbone_name(vsn_mesh), "nmn"));
	assert(wait_until(meta_connected, vsn_mesh, 30));
	nmn = meshlink_get_node(vsn_mesh, "nmn");
	assert(nmn);

	/* 1. A channel opened before migration delivers in order across it. */
	channel = meshlink_channel_open(vsn_mesh, nmn, CHANNEL_PORT, NULL, NULL, 0);
	assert(channel);
	assert(meshlink_channel_send(vsn_mesh, channel, "A1A2", 4) == 4);
	assert(wait_channel("A1A2", 20));

	/* 2. Both carriers move: META by ordered cutover, UDP by nonce proof. */
	if(!wait_until(both_private, vsn_mesh, 60)) {
		dump(vsn_mesh, "migration");
		assert(false);
	}

	assert(private_state(vsn_mesh) == 2);
	assert(discovery_quiet(vsn_mesh, "nmn"));
	assert(discovery_quiet(nmn_mesh, "vsn"));
	assert(meshlink_channel_send(vsn_mesh, channel, "B1B2", 4) == 4);

	if(!wait_channel("A1A2B1B2", 20)) {
		dump(vsn_mesh, "post-migration channel");
		assert(false);
	}

	assert(!channel_closed);

	/* 3. Healthy private steady state sends nothing on superseded public carriers. */
	count_start(PREFIX "1", NMN_PUBLIC);
	count_start(PREFIX "0", VSN_PUBLIC);
	sleep(3);
	count_zero(PREFIX "1");
	count_zero(PREFIX "0");
	sleep(6);
	assert(both_private(vsn_mesh));
	assert(!udp_public_confirmed(vsn_mesh));

	{
		unsigned long vsn_public = output_packets(PREFIX "1", NMN_PUBLIC);
		unsigned long nmn_public = output_packets(PREFIX "0", VSN_PUBLIC);

		if(vsn_public || nmn_public) {
			fprintf(stderr, "public packets in steady state: vsn->nmn %lu nmn->vsn %lu\n", vsn_public, nmn_public);
			assert(false);
		}
	}

	/* 4. PRIVATE_ONLY: losing every private carrier makes data unavailable,
	   even though canonical META reconnects. */
	meshlink_set_backbone_path_policy(vsn_mesh, MESHLINK_BACKBONE_PATH_PRIVATE_ONLY);
	block_private(true);

	if(!wait_until(public_meta_only, vsn_mesh, 45)) {
		dump(vsn_mesh, "private-only outage");
		assert(false);
	}

	assert(private_state(vsn_mesh) == 3);

	/* While a channel exists the receiver hands every record to UTCP, so
	   channel bytes are the delivery probe for both outage phases. */
	assert(meshlink_channel_send(vsn_mesh, channel, "P1P2", 4) == 4);
	sleep(6);

	if(!channel_has("A1A2B1B2") || channel_closed) {
		dump(vsn_mesh, "private-only outage data");
		assert(false);
	}

	/* 5. PREFER_PRIVATE: the same outage falls back to public at once. No
	   hold-down turns a private outage into a data outage, and the bytes held
	   back under PRIVATE_ONLY arrive in order ahead of new ones. */
	meshlink_set_backbone_path_policy(vsn_mesh, MESHLINK_BACKBONE_PATH_PREFER_PRIVATE);
	assert(meshlink_channel_send(vsn_mesh, channel, "C1C2", 4) == 4);

	if(!wait_channel("A1A2B1B2P1P2C1C2", 30) || channel_closed) {
		dump(vsn_mesh, "prefer fallback");
		assert(false);
	}

	assert(public_meta_only(vsn_mesh));

	block_private(false);
	meshlink_channel_close(vsn_mesh, channel);
	close_backbone_private_routed(peers);
	return 0;
}
