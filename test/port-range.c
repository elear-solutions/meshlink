#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

/* meshlink_open_params_set_port_range():

   T10: the drawn port is inside the range and both TCP and UDP listen on it.
   T11: only the free port of the range is picked; a fully occupied range makes
        meshlink_open_ex() fail with MESHLINK_ENETWORK instead of falling back to port 0.
   T12: the persisted port is reused while it is inside the range; a range that
        excludes it makes the next open draw a new one, which is then persisted too.
   T13: invalid ranges are rejected with MESHLINK_EINVAL; without a range the
        port still comes from the default 4096-32767 band. */

/* Two adjacent 10-port ranges, picked at startup from ports that are free right now
   (see find_free_band) instead of a fixed band that could collide with other tests
   or services bound on the wildcard address. */
#define RANGE_SIZE 10
static uint16_t RANGE_A_LO, RANGE_A_HI, RANGE_B_LO, RANGE_B_HI;

static struct sockaddr_in any4(uint16_t port) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	return sa;
}

static struct sockaddr_in loopback4(uint16_t port) {
	struct sockaddr_in sa = any4(port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return sa;
}

/* Occupy a port the way another process would: a listening TCP socket and a bound
   UDP socket on the wildcard address. Returns the two fds through out[0..1]. */
static void occupy_port(uint16_t port, int out[2]) {
	struct sockaddr_in sa = any4(port);

	out[0] = socket(AF_INET, SOCK_STREAM, 0);
	assert(out[0] != -1);
	assert(bind(out[0], (struct sockaddr *)&sa, sizeof sa) == 0);
	assert(listen(out[0], 1) == 0);

	out[1] = socket(AF_INET, SOCK_DGRAM, 0);
	assert(out[1] != -1);
	assert(bind(out[1], (struct sockaddr *)&sa, sizeof sa) == 0);
}

static void release_port(int fds[2]) {
	close(fds[0]);
	close(fds[1]);
	fds[0] = -1;
	fds[1] = -1;
}

/* True if both a TCP and a UDP socket can be bound to port on the wildcard address right now. */
static bool port_is_free(uint16_t port) {
	struct sockaddr_in sa = any4(port);
	int tcp = socket(AF_INET, SOCK_STREAM, 0);
	int udp = socket(AF_INET, SOCK_DGRAM, 0);
	assert(tcp != -1 && udp != -1);

	bool free_now = bind(tcp, (struct sockaddr *)&sa, sizeof sa) == 0 && bind(udp, (struct sockaddr *)&sa, sizeof sa) == 0;

	close(tcp);
	close(udp);
	return free_now;
}

/* Find count consecutive free ports above the Linux ephemeral range (so a connection
   made in the meantime cannot grab one) and return the first. Starts at a random
   offset so parallel runs of this test do not all settle on the same band. */
static uint16_t find_free_band(int count) {
	const int lo = 61000;
	const int hi = 65535 - count;
	srand((unsigned)(time(NULL) ^ getpid()));
	int start = lo + rand() % (hi - lo);

	for(int attempt = 0; attempt < hi - lo; attempt++) {
		int base = lo + (start - lo + attempt) % (hi - lo);
		int i;

		for(i = 0; i < count && port_is_free((uint16_t)(base + i)); i++) {
		}

		if(i == count) {
			return (uint16_t)base;
		}
	}

	assert(!"no free port band found");
	return 0;
}

static bool tcp_connects(int port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd != -1);
	struct sockaddr_in sa = loopback4((uint16_t)port);
	bool ok = connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0;
	close(fd);
	return ok;
}

/* A UDP listener is invisible to a client; the proof it is there is that the port
   cannot be bound again and that a datagram towards it is accepted by the kernel. */
static bool udp_listening(int port) {
	struct sockaddr_in sa = any4((uint16_t)port);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd != -1);
	bool taken = bind(fd, (struct sockaddr *)&sa, sizeof sa) == -1 && errno == EADDRINUSE;
	close(fd);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd != -1);
	struct sockaddr_in dest = loopback4((uint16_t)port);
	bool sent = sendto(fd, "x", 1, 0, (struct sockaddr *)&dest, sizeof dest) == 1;
	close(fd);

	return taken && sent;
}

static meshlink_open_params_t *params_with_range(const char *confbase, const char *name, uint16_t lo, uint16_t hi) {
	meshlink_open_params_t *params = meshlink_open_params_init(confbase, name, "port-range", DEV_CLASS_STATIONARY);
	assert(params);
	assert(meshlink_open_params_set_port_range(params, lo, hi));
	return params;
}

static meshlink_handle_t *open_with_range(const char *confbase, const char *name, uint16_t lo, uint16_t hi) {
	meshlink_open_params_t *params = params_with_range(confbase, name, lo, hi);
	meshlink_handle_t *mesh = meshlink_open_ex(params);
	meshlink_open_params_free(params);
	return mesh;
}

static void test_port_inside_range(void) {
	printf("\n=== T10: port drawn inside the range, TCP and UDP bound ===\n");

	assert(meshlink_destroy("port_range_conf.1"));
	meshlink_handle_t *mesh = open_with_range("port_range_conf.1", "foo", RANGE_A_LO, RANGE_A_HI);
	assert(mesh);
	meshlink_enable_discovery(mesh, false);
	assert(meshlink_start(mesh));

	int port = meshlink_get_port(mesh);
	assert(port >= RANGE_A_LO && port <= RANGE_A_HI);
	assert(tcp_connects(port));
	assert(udp_listening(port));

	printf("T10 ok: port %d in %d-%d, TCP and UDP listening\n", port, RANGE_A_LO, RANGE_A_HI);

	meshlink_close(mesh);
	assert(meshlink_destroy("port_range_conf.1"));
}

static void test_range_exhaustion(void) {
	printf("\n=== T11: last free port is found, full range fails without port 0 fallback ===\n");

	int taken[RANGE_SIZE][2];
	int count = RANGE_SIZE;

	/* Everything but the last port is busy. */
	for(int i = 0; i < count - 1; i++) {
		occupy_port((uint16_t)(RANGE_A_LO + i), taken[i]);
	}

	assert(meshlink_destroy("port_range_conf.1"));
	meshlink_handle_t *mesh = open_with_range("port_range_conf.1", "foo", RANGE_A_LO, RANGE_A_HI);
	assert(mesh);
	meshlink_enable_discovery(mesh, false);
	assert(meshlink_start(mesh));
	assert(meshlink_get_port(mesh) == RANGE_A_HI);
	printf("T11: got the only free port %d\n", RANGE_A_HI);
	meshlink_close(mesh);

	/* Now the whole range is busy: a fresh instance must not come up on some other port. */
	occupy_port(RANGE_A_HI, taken[count - 1]);

	assert(meshlink_destroy("port_range_conf.2"));
	meshlink_errno = MESHLINK_OK;
	mesh = open_with_range("port_range_conf.2", "bar", RANGE_A_LO, RANGE_A_HI);
	assert(!mesh);
	assert(meshlink_errno == MESHLINK_ENETWORK);
	printf("T11: fresh open with a full range failed with %s\n", meshlink_strerror(meshlink_errno));

	/* The same for an existing configuration whose persisted port is now taken. */
	meshlink_errno = MESHLINK_OK;
	mesh = open_with_range("port_range_conf.1", "foo", RANGE_A_LO, RANGE_A_HI);
	assert(!mesh);
	assert(meshlink_errno == MESHLINK_ENETWORK);
	printf("T11: reopen with a full range failed with %s\n", meshlink_strerror(meshlink_errno));

	for(int i = 0; i < count; i++) {
		release_port(taken[i]);
	}

	/* Sanity: with the range free again the persisted configuration opens on its old port. */
	mesh = open_with_range("port_range_conf.1", "foo", RANGE_A_LO, RANGE_A_HI);
	assert(mesh);
	assert(meshlink_get_port(mesh) == RANGE_A_HI);
	meshlink_close(mesh);

	printf("T11 ok\n");

	assert(meshlink_destroy("port_range_conf.1"));
	assert(meshlink_destroy("port_range_conf.2"));
}

static void test_persisted_port(void) {
	printf("\n=== T12: persisted port first, redraw only when it leaves the range ===\n");

	assert(meshlink_destroy("port_range_conf.1"));
	meshlink_handle_t *mesh = open_with_range("port_range_conf.1", "foo", RANGE_A_LO, RANGE_A_HI);
	assert(mesh);
	meshlink_enable_discovery(mesh, false);
	assert(meshlink_start(mesh));
	int first = meshlink_get_port(mesh);
	assert(first >= RANGE_A_LO && first <= RANGE_A_HI);
	meshlink_stop(mesh);
	meshlink_close(mesh);

	/* Same range: same port. */
	mesh = open_with_range("port_range_conf.1", "foo", RANGE_A_LO, RANGE_A_HI);
	assert(mesh);
	assert(meshlink_start(mesh));
	assert(meshlink_get_port(mesh) == first);
	meshlink_stop(mesh);
	meshlink_close(mesh);
	printf("T12: reopened on the persisted port %d\n", first);

	/* A range that excludes the persisted port: a new port inside the new range. */
	mesh = open_with_range("port_range_conf.1", "foo", RANGE_B_LO, RANGE_B_HI);
	assert(mesh);
	assert(meshlink_start(mesh));
	int second = meshlink_get_port(mesh);
	assert(second >= RANGE_B_LO && second <= RANGE_B_HI);
	meshlink_stop(mesh);
	meshlink_close(mesh);
	printf("T12: range %d-%d moved the port to %d\n", RANGE_B_LO, RANGE_B_HI, second);

	/* The redrawn port is persisted: reopening with the new range keeps it... */
	mesh = open_with_range("port_range_conf.1", "foo", RANGE_B_LO, RANGE_B_HI);
	assert(mesh);
	assert(meshlink_get_port(mesh) == second);
	meshlink_close(mesh);

	/* ...and so does opening without any range at all. */
	mesh = meshlink_open("port_range_conf.1", "foo", "port-range", DEV_CLASS_STATIONARY);
	assert(mesh);
	assert(meshlink_get_port(mesh) == second);
	meshlink_close(mesh);

	printf("T12 ok\n");

	assert(meshlink_destroy("port_range_conf.1"));
}

static void test_invalid_and_default(void) {
	printf("\n=== T13: invalid ranges rejected, no range keeps the default band ===\n");

	meshlink_open_params_t *params = meshlink_open_params_init("port_range_conf.1", "foo", "port-range", DEV_CLASS_STATIONARY);
	assert(params);

	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_open_params_set_port_range(params, 30009, 30000));
	assert(meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_open_params_set_port_range(params, 1023, 2000));
	assert(meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_open_params_set_port_range(params, 0, 2000));
	assert(meshlink_errno == MESHLINK_EINVAL);

	assert(!meshlink_open_params_set_port_range(NULL, RANGE_A_LO, RANGE_A_HI));
	assert(meshlink_errno == MESHLINK_EINVAL);

	/* Both zero is "no range" and a single-port range is fine. */
	assert(meshlink_open_params_set_port_range(params, 0, 0));
	assert(meshlink_open_params_set_port_range(params, 1024, 1024));
	assert(meshlink_open_params_set_port_range(params, 0, 0));

	meshlink_open_params_free(params);

	/* Regression: no range means the historical 4096-32767 draw. */
	assert(meshlink_destroy("port_range_conf.1"));
	meshlink_handle_t *mesh = meshlink_open("port_range_conf.1", "foo", "port-range", DEV_CLASS_STATIONARY);
	assert(mesh);
	int port = meshlink_get_port(mesh);
	assert(port >= 0x1000 && port < 0x8000);
	meshlink_close(mesh);
	assert(meshlink_destroy("port_range_conf.1"));

	printf("T13 ok: default draw gave %d\n", port);
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	RANGE_A_LO = find_free_band(2 * RANGE_SIZE);
	RANGE_A_HI = RANGE_A_LO + RANGE_SIZE - 1;
	RANGE_B_LO = RANGE_A_HI + 1;
	RANGE_B_HI = RANGE_B_LO + RANGE_SIZE - 1;
	printf("port bands: A %d-%d, B %d-%d\n", RANGE_A_LO, RANGE_A_HI, RANGE_B_LO, RANGE_B_HI);

	test_port_inside_range();
	test_range_exhaustion();
	test_persisted_port();
	test_invalid_and_default();

	return 0;
}
