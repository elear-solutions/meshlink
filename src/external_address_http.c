#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "external_address_http.h"

int external_address_format_http_request(char *req, size_t reqsz, const char *path, const char *host) {
	if(!req || !path || !host || reqsz == 0) {
		return -1;
	}

	return snprintf(req, reqsz,
	                "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
	                path, host);
}

char *external_address_hostname_from_http(char *buf) {
	if(!buf || !*buf) {
		return NULL;
	}

	char *body = strstr(buf, "\r\n\r\n");

	if(body) {
		body += 4;
	} else if((body = strstr(buf, "\n\n"))) {
		body += 2;
	} else {
		body = buf;
	}

	/* Skip a Transfer-Encoding: chunked size line (hex only). */
	char *line_end = strpbrk(body, "\r\n");

	if(line_end && line_end != body) {
		bool hex_only = true;

		for(char *p = body; p < line_end; p++) {
			if(!isxdigit((unsigned char)*p)) {
				hex_only = false;
				break;
			}
		}

		if(hex_only) {
			body = line_end;

			while(*body == '\r' || *body == '\n') {
				body++;
			}
		}
	}

	while(*body == ' ' || *body == '\r' || *body == '\n') {
		body++;
	}

	char *tok_end = body;

	while(*tok_end && *tok_end != ' ' && *tok_end != '\r' && *tok_end != '\n') {
		tok_end++;
	}

	if(tok_end == body) {
		return NULL;
	}

	size_t n = (size_t)(tok_end - body);
	char *hostname = malloc(n + 1);

	if(!hostname) {
		return NULL;
	}

	memcpy(hostname, body, n);
	hostname[n] = 0;
	return hostname;
}
