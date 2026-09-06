#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/external_address_http.h"

static void assert_hostname(const char *response, const char *expected) {
	char buf[2048];
	size_t n = strlen(response);
	assert(n < sizeof(buf));
	memcpy(buf, response, n + 1);
	char *got = external_address_hostname_from_http(buf);

	if(expected) {
		assert(got);
		assert(!strcmp(got, expected));
		free(got);
	} else {
		assert(!got);
	}
}

int main(void) {
	char req[512];
	assert(external_address_format_http_request(NULL, sizeof(req), "/host.cgi", "findmyip.getcoco.buzz") == -1);
	int reqlen = external_address_format_http_request(req, sizeof(req), "/host.cgi", "findmyip.getcoco.buzz");
	assert(reqlen > 0 && reqlen < (int)sizeof(req));
	assert(strstr(req, "GET /host.cgi HTTP/1.0\r\n"));
	assert(strstr(req, "Host: findmyip.getcoco.buzz\r\n"));
	assert(strstr(req, "Connection: close\r\n\r\n"));
	assert(!strstr(req, "GET http://"));

	/* HTTP/1.0, body is IP + LF — what findmyip used to look like. */
	assert_hostname(
	        "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n183.83.169.155\n",
	        "183.83.169.155");

	/* Trailing CR would fail is_valid_hostname() if left on the token. */
	assert_hostname(
	        "HTTP/1.0 200 OK\r\n\r\n16.112.61.125\r\n",
	        "16.112.61.125");

	/* HTTP/1.1 chunked — the live findmyip response that broke the old parser. */
	assert_hostname(
	        "HTTP/1.1 200 OK\r\n"
	        "Transfer-Encoding: chunked\r\n"
	        "\r\n"
	        "0e\r\n"
	        "183.83.169.155\n"
	        "\r\n"
	        "0\r\n"
	        "\r\n",
	        "183.83.169.155");

	/* LF-only header terminator. */
	assert_hostname(
	        "HTTP/1.0 200 OK\n\n203.0.113.10\n",
	        "203.0.113.10");

	/* Bare body, no headers. */
	assert_hostname("198.51.100.7\n", "198.51.100.7");

	assert_hostname("HTTP/1.0 200 OK\r\n\r\n", NULL);
	assert_hostname("", NULL);

	printf("parse-external-http: ok\n");
	return 0;
}
