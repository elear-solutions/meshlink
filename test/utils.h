#ifndef MESHLINK_TEST_UTILS_H
#define MESHLINK_TEST_UTILS_H

#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../src/meshlink.h"

// Simple synchronisation between threads
struct sync_flag {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool flag;
};

extern void init_sync_flag(struct sync_flag *s);
extern void set_sync_flag(struct sync_flag *s, bool value);
extern void reset_sync_flag(struct sync_flag *s);
extern bool check_sync_flag(struct sync_flag *s);
extern bool wait_sync_flag(struct sync_flag *s, int seconds);

/// Create a pair of meshlink instances that are already joined together.
/// `a` is the unique backbone; `b` is a stationary peer that joins through `a`.
extern void open_meshlink_pair(meshlink_handle_t **a, meshlink_handle_t **b, const char *prefix);
extern void open_meshlink_pair_ephemeral(meshlink_handle_t **a, meshlink_handle_t **b, const char *prefix);

/// Start `backbone` if needed, invite `peer` by name, and join. Leaves `backbone` running.
extern void join_meshlink_peer(meshlink_handle_t *backbone, meshlink_handle_t *peer);

/// Start a pair of meshlink instances and wait for them to connect together.
extern void start_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b);

/// Stop a pair of meshlink instances.
extern void stop_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b);

/// Stop and cleanup a pair of meshlink instances.
extern void close_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b);

/// Link two meshlink instances.
extern void link_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b);

/// Default log callback
extern void log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text);

/// Log callback that also keeps every line as "<mesh name>: <text>\n" so tests can assert on ordering.
/// Register with meshlink_set_log_cb(NULL, level, capture_log_cb); free with free_captured_log().
extern void capture_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text);

/// Current end of the captured log, to search only what came after it.
extern size_t log_mark(void);

/// Offset of the first occurrence of needle at or after from in the captured log, or -1.
extern long log_find(size_t from, const char *needle);

/// True if needle occurs anywhere in the captured log.
extern bool log_contains(const char *needle);

/// Number of (non-overlapping) occurrences of needle in the captured log at or after from.
extern int log_count_from(size_t from, const char *needle);

/// Number of (non-overlapping) occurrences of needle in the captured log.
extern int log_count(const char *needle);

/// Release the captured log.
extern void free_captured_log(void);

/// Build an IPv4 socket address; ip must be numeric.
extern struct sockaddr_in ipv4(const char *ip, uint16_t port);

/// Port of an IPv4 or IPv6 socket address in host order, -1 for anything else.
extern int port_of(const struct sockaddr_storage *ss);

/// True if ss is exactly the IPv4 address ip:port.
extern bool addr_is(const struct sockaddr_storage *ss, const char *ip, int port);

/// Drop everything mesh learned about where node lives: its UDP address and recent[].
/// Fresh imports carry the peer's own local addresses, which would otherwise win as RECENT.
extern void forget_addresses(meshlink_handle_t *mesh, meshlink_node_t *node);

/// meshlink_hint_address() with a numeric IPv4 address.
extern void hint_address(meshlink_handle_t *mesh, meshlink_node_t *node, const char *ip, int port);

/// Import each side's export into the other, without touching canonical addresses (unlike link_meshlink_pair).
extern void exchange_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b);

/// A TCP relay: accepts on listen_host:listen_port and byte-copies both ways to target_host:target_port.
/// Stands in for a load balancer / demux so tests can tell "via relay" from "direct" by peer port and accept count.
typedef struct tcp_relay tcp_relay_t;

/// Start a relay. Pass *listen_port_out == 0 to let the OS pick a port; the chosen port is written back.
extern tcp_relay_t *start_tcp_relay(const char *listen_host, int *listen_port_out, const char *target_host, int target_port);

/// Number of client connections accepted so far.
extern int tcp_relay_accept_count(tcp_relay_t *relay);

/// Change where new connections are forwarded to. Existing connections are unaffected.
extern void tcp_relay_set_target(tcp_relay_t *relay, int target_port);

/// Stop the relay and close every connection it is carrying.
extern void stop_tcp_relay(tcp_relay_t *relay);

/// Bind and listen on listen_host with an OS-chosen port but never accept(): connects succeed, then hang.
/// Returns the listen fd; the caller closes it. The port is written to *port_out.
extern int start_black_hole(const char *listen_host, int *port_out);

/// Bind a TCP socket on listen_host, learn its port, close it again: a port that is (very likely) closed.
extern int find_closed_port(const char *listen_host);

/// True if this host lets us bind a second loopback address (Linux: all of 127/8).
extern bool loopback_alias_available(const char *ip);

/// Number of edge pairs between nodes x and y in mesh's view of the graph (devtool_get_all_edges).
extern int count_edge_pairs(meshlink_handle_t *mesh, const char *x, const char *y);

/// Edge option bits as they appear on the wire in ADD_EDGE (OPTION_* in src/connection.h, not exported).
#define EDGE_OPTION_INDIRECT 0x0001
#define EDGE_OPTION_PMTU_DISCOVERY 0x0004

#define assert_after(cond, timeout)\
	do {\
		for(int i = 0; i++ <= timeout;) {\
			if(cond)\
				break;\
			if(i == timeout)\
				assert(cond);\
			sleep(1);\
		}\
	} while(0)

#endif

/// Compare two timespec values.
static inline bool timespec_lt(const struct timespec *a, const struct timespec *b) {
	if(a->tv_sec == b->tv_sec) {
		return a->tv_nsec < b->tv_nsec;
	} else {
		return a->tv_sec < b->tv_sec;
	}
}
