#ifndef MESHLINK_TEST_UTILS_H
#define MESHLINK_TEST_UTILS_H

#include <assert.h>
#include <time.h>
#include <pthread.h>

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
extern void open_meshlink_pair(meshlink_handle_t **a, meshlink_handle_t **b, const char *prefix);
extern void open_meshlink_pair_ephemeral(meshlink_handle_t **a, meshlink_handle_t **b, const char *prefix);

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
