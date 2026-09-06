#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "meshlink.h"
#include "utils.h"

struct http_reply {
	int fd;
	const char *body;
	char request[1024];
};

static void *http_serve(void *arg) {
	struct http_reply *r = arg;
	int c = accept(r->fd, NULL, NULL);
	assert(c >= 0);

	int n = recv(c, r->request, sizeof(r->request) - 1, 0);
	assert(n > 0);
	r->request[n] = 0;

	size_t len = strlen(r->body);
	assert(send(c, r->body, len, 0) == (ssize_t)len);
	shutdown(c, SHUT_RDWR);
	close(c);
	return NULL;
}

static void check_address(meshlink_handle_t *mesh, int fd, int port, const char *path, const char *response, const char *expected) {
	struct http_reply r = {
		.fd = fd,
		.body = response,
	};
	memset(r.request, 0, sizeof(r.request));

	pthread_t thr;
	assert(!pthread_create(&thr, NULL, http_serve, &r));

	char url[128];
	assert(snprintf(url, sizeof(url), "http://127.0.0.1:%d%s", port, path) > 0);
	meshlink_set_external_address_discovery_url(mesh, url);

	char *addr = meshlink_get_external_address_for_family(mesh, AF_INET);
	assert(!pthread_join(thr, NULL));

	assert(strstr(r.request, "GET "));
	assert(strstr(r.request, " HTTP/1.0"));
	assert(!strstr(r.request, "GET http://"));
	assert(strstr(r.request, "Host: 127.0.0.1"));

	if(expected) {
		assert(addr);
		assert(!strcmp(addr, expected));
		free(addr);
	} else {
		assert(!addr);
	}
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	assert(meshlink_destroy("get_external_address_conf"));

	// STATIONARY so meshlink_open() does not call findmyip itself
	meshlink_handle_t *mesh = meshlink_open("get_external_address_conf", "foo", "get-external-address", DEV_CLASS_STATIONARY);
	assert(mesh);
	meshlink_enable_discovery(mesh, false);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd >= 0);

	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = 0;
	assert(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	assert(listen(fd, 1) == 0);

	socklen_t slen = sizeof(sin);
	assert(getsockname(fd, (struct sockaddr *)&sin, &slen) == 0);
	int port = ntohs(sin.sin_port);
	assert(port);

	check_address(mesh, fd, port, "/plain",
	              "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n183.83.169.155\n",
	              "183.83.169.155");

	check_address(mesh, fd, port, "/crlf",
	              "HTTP/1.0 200 OK\r\n\r\n16.112.61.125\r\n",
	              "16.112.61.125");

	check_address(mesh, fd, port, "/chunked",
	              "HTTP/1.1 200 OK\r\n"
	              "Transfer-Encoding: chunked\r\n"
	              "\r\n"
	              "0e\r\n"
	              "183.83.169.155\n"
	              "\r\n"
	              "0\r\n"
	              "\r\n",
	              "183.83.169.155");

	check_address(mesh, fd, port, "/empty",
	              "HTTP/1.0 200 OK\r\n\r\n",
	              NULL);

	close(fd);
	meshlink_close(mesh);
	assert(meshlink_destroy("get_external_address_conf"));
	return 0;
}
