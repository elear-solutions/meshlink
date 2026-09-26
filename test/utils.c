#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#include "utils.h"
#include "../src/devtools.h"

/* Conf and scratch files follow the process cwd. Park unit tests in test/tmp/
   so ./test/foo from the repo root and make check (cwd test/) share one place.
   Blackbox does not link this file. */
static void test_enter_tmp(void) __attribute__((constructor));

static int mkdir_tmp(const char *path) {
	if(!mkdir(path, 0755) || errno == EEXIST) {
		return 0;
	}

	return -1;
}

static void test_enter_tmp(void) {
	const char *override = getenv("MESHLINK_TEST_TMP");
	char exe[PATH_MAX];
	char *slash;

	if(override && *override) {
		if(!mkdir_tmp(override) && chdir(override) != 0) {
			return;
		}

		return;
	}

	exe[0] = 0;
#if defined(__APPLE__)
	{
		uint32_t size = sizeof exe;

		if(_NSGetExecutablePath(exe, &size) != 0) {
			return;
		}
	}
#else
	{
		ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);

		if(n <= 0) {
			return;
		}

		exe[n] = 0;
	}
#endif

	slash = strrchr(exe, '/');

	if(!slash) {
		return;
	}

	*slash = 0;
	slash = strrchr(exe, '/');

	if(slash && !strcmp(slash + 1, ".libs")) {
		*slash = 0;
	}

	{
		size_t len = strlen(exe);

		if(len + strlen("/tmp") >= sizeof exe) {
			return;
		}

		memcpy(exe + len, "/tmp", strlen("/tmp") + 1);
	}

	if(!mkdir_tmp(exe) && chdir(exe) != 0) {
		return;
	}
}

#define RELAY_MAX_CONNS 64

struct tcp_relay {
	int listen_fd;
	int listen_port;
	char target_host[64];
	int target_port;
	pthread_t thread;
	pthread_mutex_t mutex;
	int accept_count;
	bool stopping;
	size_t nconns;
	struct relay_conn *conns[RELAY_MAX_CONNS];
};

/* fd ownership: a conn thread only ever shutdown()s its two sockets; stop_tcp_relay()
   close()s them after joining the thread. Closing from the thread would let the kernel
   hand the same fd numbers to a meshlink socket in this process before stop_tcp_relay()
   gets to shutdown() them, cutting a live meta connection instead of a dead relay one. */
struct relay_conn {
	tcp_relay_t *relay;
	int client_fd;
	int target_fd;
	pthread_t thread;
};

static int listen_on(const char *host, int *port_inout) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(*port_inout);
	assert(inet_pton(AF_INET, host, &sa.sin_addr) == 1);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd != -1);

	int one = 1;
	assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0);
	assert(bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0);
	assert(listen(fd, 16) == 0);

	socklen_t salen = sizeof sa;
	assert(getsockname(fd, (struct sockaddr *)&sa, &salen) == 0);
	*port_inout = ntohs(sa.sin_port);

	return fd;
}

static int connect_to(const char *host, int port) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);

	if(inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
		return -1;
	}

	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if(fd == -1) {
		return -1;
	}

	if(connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/* Copy bytes from one fd to the other until either side closes. */
static bool pump(int from, int to) {
	char buf[4096];
	ssize_t len = recv(from, buf, sizeof buf, 0);

	if(len <= 0) {
		return false;
	}

	for(ssize_t off = 0; off < len;) {
		ssize_t sent = send(to, buf + off, len - off, MSG_NOSIGNAL);

		if(sent <= 0) {
			return false;
		}

		off += sent;
	}

	return true;
}

static void *relay_conn_thread(void *arg) {
	struct relay_conn *conn = arg;
	struct pollfd fds[2] = {
		{.fd = conn->client_fd, .events = POLLIN},
		{.fd = conn->target_fd, .events = POLLIN},
	};

	while(true) {
		if(poll(fds, 2, -1) < 0) {
			if(errno == EINTR) {
				continue;
			}

			break;
		}

		if(fds[0].revents && !pump(conn->client_fd, conn->target_fd)) {
			break;
		}

		if(fds[1].revents && !pump(conn->target_fd, conn->client_fd)) {
			break;
		}
	}

	shutdown(conn->client_fd, SHUT_RDWR);
	shutdown(conn->target_fd, SHUT_RDWR);

	return NULL;
}

static void *relay_accept_thread(void *arg) {
	tcp_relay_t *relay = arg;

	while(true) {
		int client_fd = accept(relay->listen_fd, NULL, NULL);

		if(client_fd < 0) {
			if(errno == EINTR) {
				continue;
			}

			break;
		}

		assert(pthread_mutex_lock(&relay->mutex) == 0);
		relay->accept_count++;
		bool stopping = relay->stopping;
		int target_port = relay->target_port;
		assert(pthread_mutex_unlock(&relay->mutex) == 0);

		if(stopping) {
			close(client_fd);
			break;
		}

		int target_fd = connect_to(relay->target_host, target_port);

		if(target_fd < 0) {
			close(client_fd);
			continue;
		}

		struct relay_conn *conn = calloc(1, sizeof *conn);
		assert(conn);
		conn->relay = relay;
		conn->client_fd = client_fd;
		conn->target_fd = target_fd;

		assert(pthread_mutex_lock(&relay->mutex) == 0);
		assert(relay->nconns < RELAY_MAX_CONNS);
		relay->conns[relay->nconns++] = conn;
		assert(pthread_mutex_unlock(&relay->mutex) == 0);

		assert(pthread_create(&conn->thread, NULL, relay_conn_thread, conn) == 0);
	}

	return NULL;
}

tcp_relay_t *start_tcp_relay(const char *listen_host, int *listen_port_out, const char *target_host, int target_port) {
	tcp_relay_t *relay = calloc(1, sizeof *relay);
	assert(relay);

	assert(pthread_mutex_init(&relay->mutex, NULL) == 0);
	snprintf(relay->target_host, sizeof relay->target_host, "%s", target_host);
	relay->target_port = target_port;
	relay->listen_port = *listen_port_out;
	relay->listen_fd = listen_on(listen_host, &relay->listen_port);
	*listen_port_out = relay->listen_port;

	assert(pthread_create(&relay->thread, NULL, relay_accept_thread, relay) == 0);

	return relay;
}

int tcp_relay_accept_count(tcp_relay_t *relay) {
	assert(pthread_mutex_lock(&relay->mutex) == 0);
	int count = relay->accept_count;
	assert(pthread_mutex_unlock(&relay->mutex) == 0);
	return count;
}

void tcp_relay_set_target(tcp_relay_t *relay, int target_port) {
	assert(pthread_mutex_lock(&relay->mutex) == 0);
	relay->target_port = target_port;
	assert(pthread_mutex_unlock(&relay->mutex) == 0);
}

void stop_tcp_relay(tcp_relay_t *relay) {
	assert(pthread_mutex_lock(&relay->mutex) == 0);
	relay->stopping = true;
	assert(pthread_mutex_unlock(&relay->mutex) == 0);

	/* Wake accept() and let the thread exit before the fd is closed, so it
	   cannot come back to accept() on a reused fd number. shutdown() does
	   that on Linux. Darwin leaves accept() blocked, so also connect. */
	shutdown(relay->listen_fd, SHUT_RDWR);
	{
		struct sockaddr_storage ss;
		socklen_t len = sizeof ss;

		if(getsockname(relay->listen_fd, (struct sockaddr *)&ss, &len) == 0) {
			if(ss.ss_family == AF_INET) {
				struct sockaddr_in *in = (struct sockaddr_in *)&ss;

				if(in->sin_addr.s_addr == htonl(INADDR_ANY)) {
					in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				}
			} else if(ss.ss_family == AF_INET6) {
				struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;

				if(IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr)) {
					in6->sin6_addr = in6addr_loopback;
				}
			}

			int poke = socket(ss.ss_family, SOCK_STREAM, 0);

			if(poke >= 0) {
				connect(poke, (struct sockaddr *)&ss, len);
				close(poke);
			}
		}
	}
	pthread_join(relay->thread, NULL);
	close(relay->listen_fd);

	/* Every conn fd is still open (only the thread's shutdown() may have run), so
	   these shutdown()s hit our own sockets, never a reused fd number. */
	for(size_t i = 0; i < relay->nconns; i++) {
		struct relay_conn *conn = relay->conns[i];

		shutdown(conn->client_fd, SHUT_RDWR);
		shutdown(conn->target_fd, SHUT_RDWR);
		pthread_join(conn->thread, NULL);
		close(conn->client_fd);
		close(conn->target_fd);
		free(conn);
	}

	pthread_mutex_destroy(&relay->mutex);
	free(relay);
}

int start_black_hole(const char *listen_host, int *port_out) {
	*port_out = 0;
	return listen_on(listen_host, port_out);
}

int find_closed_port(const char *listen_host) {
	int port = 0;
	int fd = listen_on(listen_host, &port);
	close(fd);
	return port;
}

bool loopback_alias_available(const char *ip) {
	struct sockaddr_in sa = ipv4(ip, 0);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd != -1);
	bool ok = bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0;
	close(fd);
	return ok;
}

int count_edge_pairs(meshlink_handle_t *mesh, const char *x, const char *y) {
	size_t nedges = 0;
	devtool_edge_t *edges = devtool_get_all_edges(mesh, NULL, &nedges);
	assert(edges || !nedges);
	int count = 0;

	for(size_t i = 0; i < nedges; i++) {
		const char *from = edges[i].from->name;
		const char *to = edges[i].to->name;

		if((!strcmp(from, x) && !strcmp(to, y)) || (!strcmp(from, y) && !strcmp(to, x))) {
			count++;
		}
	}

	free(edges);
	return count;
}

void init_sync_flag(struct sync_flag *s) {
	assert(pthread_mutex_init(&s->mutex, NULL) == 0);
	assert(pthread_cond_init(&s->cond, NULL) == 0);
	s->flag = false;
}

void set_sync_flag(struct sync_flag *s, bool value) {
	assert(pthread_mutex_lock(&s->mutex) == 0);
	s->flag = value;
	assert(pthread_cond_broadcast(&s->cond) == 0);
	assert(pthread_mutex_unlock(&s->mutex) == 0);
}

void reset_sync_flag(struct sync_flag *s) {
	assert(pthread_mutex_lock(&s->mutex) == 0);
	s->flag = false;
	assert(pthread_mutex_unlock(&s->mutex) == 0);
}

bool check_sync_flag(struct sync_flag *s) {
	bool flag;
	assert(pthread_mutex_lock(&s->mutex) == 0);
	flag = s->flag;
	assert(pthread_mutex_unlock(&s->mutex) == 0);
	return flag;
}

bool wait_sync_flag(struct sync_flag *s, int seconds) {
	struct timespec timeout;

	clock_gettime(CLOCK_REALTIME, &timeout);
	timeout.tv_sec += seconds;

	assert(pthread_mutex_lock(&s->mutex) == 0);

	while(!s->flag) {
		int rc = pthread_cond_timedwait(&s->cond, &s->mutex, &timeout);

		if(rc == ETIMEDOUT) {
			break;
		}

		if(rc != 0 && rc != EINTR) {
			break;
		}
	}

	bool flag = s->flag;
	assert(pthread_mutex_unlock(&s->mutex) == 0);
	return flag;
}

void join_meshlink_peer(meshlink_handle_t *backbone, meshlink_handle_t *peer) {
	assert(backbone && peer);
	assert(meshlink_start(backbone));
	char *url = meshlink_invite(backbone, NULL, meshlink_get_self(peer)->name);
	assert(url);
	assert(meshlink_join(peer, url));
	free(url);
}

void link_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b) {
	// Import and export both side's data

	assert(meshlink_set_canonical_address(a, meshlink_get_self(a), "localhost", NULL));
	assert(meshlink_set_canonical_address(b, meshlink_get_self(b), "localhost", NULL));

	char *data = meshlink_export(a);
	assert(data);
	assert(meshlink_import(b, data));
	free(data);

	data = meshlink_export(b);
	assert(data);
	assert(meshlink_import(a, data));
	free(data);
}

void open_meshlink_pair(meshlink_handle_t **pa, meshlink_handle_t **pb, const char *prefix) {
	// Create two new MeshLink instances

	*pa = *pb = NULL;

	char *a_name, *b_name;

	assert(asprintf(&a_name, "%s_conf.1", prefix) > 0);
	assert(a_name);

	assert(asprintf(&b_name, "%s_conf.2", prefix) > 0);
	assert(b_name);

	assert(meshlink_destroy(a_name));
	assert(meshlink_destroy(b_name));

	meshlink_handle_t *a = meshlink_open(a_name, "a", prefix, DEV_CLASS_BACKBONE);
	assert(a);

	meshlink_handle_t *b = meshlink_open(b_name, "b", prefix, DEV_CLASS_STATIONARY);
	assert(b);

	free(a_name);
	free(b_name);

	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_set_canonical_address(a, meshlink_get_self(a), "localhost", NULL));
	assert(meshlink_set_canonical_address(b, meshlink_get_self(b), "localhost", NULL));
	join_meshlink_peer(a, b);

	*pa = a;
	*pb = b;
}

void open_meshlink_pair_ephemeral(meshlink_handle_t **pa, meshlink_handle_t **pb, const char *prefix) {
	// Create two new MeshLink instances

	*pa = *pb = NULL;

	meshlink_handle_t *a = meshlink_open_ephemeral("a", prefix, DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open_ephemeral("b", prefix, DEV_CLASS_STATIONARY);

	assert(a);
	assert(b);

	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_set_canonical_address(a, meshlink_get_self(a), "localhost", NULL));
	assert(meshlink_set_canonical_address(b, meshlink_get_self(b), "localhost", NULL));
	join_meshlink_peer(a, b);

	*pa = a;
	*pb = b;
}

// Don't poll in the application thread, use a condition variable to signal when the peer is online.
static void pair_status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)node;

	if(reachable && meshlink_get_self(mesh) != node) {
		set_sync_flag(mesh->priv, true);
	}
}

void start_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b) {
	struct sync_flag pair_status = {.flag = false};
	init_sync_flag(&pair_status);

	a->priv = &pair_status;
	meshlink_set_node_status_cb(a, pair_status_cb);

	assert(meshlink_start(a));
	assert(meshlink_start(b));

	assert(wait_sync_flag(&pair_status, 15));

	meshlink_set_node_status_cb(a, NULL);
	a->priv = NULL;
}

void stop_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b) {
	meshlink_stop(a);
	meshlink_stop(b);
}

void close_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b) {
	meshlink_close(a);
	meshlink_close(b);
}

void log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	static const char *levelstr[] = {
		[MESHLINK_DEBUG] = "DEBUG",
		[MESHLINK_INFO] = "INFO",
		[MESHLINK_WARNING] = "WARNING",
		[MESHLINK_ERROR] = "ERROR",
		[MESHLINK_CRITICAL] = "CRITICAL",
	};

	static struct timespec ts0;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if(ts0.tv_sec == 0) {
		ts0 = ts;
	}

	float diff = (ts.tv_sec - ts0.tv_sec) + (ts.tv_nsec - ts0.tv_nsec) * 1e-9;

	fprintf(stderr, "%7.3f (%s) [%s] %s\n",
	        diff,
	        mesh ? mesh->name : "",
	        levelstr[level],
	        text);
}

static pthread_mutex_t captured_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char *captured_log;
static size_t captured_len;

void capture_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	log_cb(mesh, level, text);

	assert(pthread_mutex_lock(&captured_log_mutex) == 0);
	size_t add = strlen(text) + 32;
	captured_log = realloc(captured_log, captured_len + add + 1);
	assert(captured_log);
	captured_len += snprintf(captured_log + captured_len, add + 1, "%s: %s\n", mesh ? mesh->name : "-", text);
	assert(pthread_mutex_unlock(&captured_log_mutex) == 0);
}

size_t log_mark(void) {
	assert(pthread_mutex_lock(&captured_log_mutex) == 0);
	size_t mark = captured_len;
	assert(pthread_mutex_unlock(&captured_log_mutex) == 0);
	return mark;
}

long log_find(size_t from, const char *needle) {
	assert(pthread_mutex_lock(&captured_log_mutex) == 0);
	long result = -1;

	if(captured_log && from < captured_len) {
		const char *hit = strstr(captured_log + from, needle);

		if(hit) {
			result = hit - captured_log;
		}
	}

	assert(pthread_mutex_unlock(&captured_log_mutex) == 0);
	return result;
}

bool log_contains(const char *needle) {
	return log_find(0, needle) >= 0;
}

int log_count_from(size_t from, const char *needle) {
	int count = 0;
	size_t len = strlen(needle);

	assert(pthread_mutex_lock(&captured_log_mutex) == 0);

	if(captured_log && from < captured_len) {
		for(const char *p = captured_log + from; (p = strstr(p, needle)); p += len) {
			count++;
		}
	}

	assert(pthread_mutex_unlock(&captured_log_mutex) == 0);
	return count;
}

int log_count(const char *needle) {
	return log_count_from(0, needle);
}

void free_captured_log(void) {
	assert(pthread_mutex_lock(&captured_log_mutex) == 0);
	free(captured_log);
	captured_log = NULL;
	captured_len = 0;
	assert(pthread_mutex_unlock(&captured_log_mutex) == 0);
}

struct sockaddr_in ipv4(const char *ip, uint16_t port) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	assert(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
	return sa;
}

int port_of(const struct sockaddr_storage *ss) {
	if(ss->ss_family == AF_INET) {
		return ntohs(((const struct sockaddr_in *)ss)->sin_port);
	}

	if(ss->ss_family == AF_INET6) {
		return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
	}

	return -1;
}

bool addr_is(const struct sockaddr_storage *ss, const char *ip, int port) {
	if(ss->ss_family != AF_INET) {
		return false;
	}

	struct sockaddr_in want = ipv4(ip, (uint16_t)port);
	const struct sockaddr_in *got = (const struct sockaddr_in *)ss;
	return got->sin_addr.s_addr == want.sin_addr.s_addr && got->sin_port == want.sin_port;
}

void forget_addresses(meshlink_handle_t *mesh, meshlink_node_t *node) {
	struct sockaddr_in unset;
	memset(&unset, 0, sizeof unset);
	unset.sin_family = AF_UNSPEC;
	devtool_update_node_udp(mesh, node, (struct sockaddr *)&unset);
}

void hint_address(meshlink_handle_t *mesh, meshlink_node_t *node, const char *ip, int port) {
	struct sockaddr_in sa = ipv4(ip, (uint16_t)port);
	meshlink_hint_address(mesh, node, (struct sockaddr *)&sa);
}

void exchange_meshlink_pair(meshlink_handle_t *a, meshlink_handle_t *b) {
	char *data = meshlink_export(a);
	assert(data);
	assert(meshlink_import(b, data));
	free(data);

	data = meshlink_export(b);
	assert(data);
	assert(meshlink_import(a, data));
	free(data);
}
