#ifndef MESHLINK_EXTERNAL_ADDRESS_HTTP_H
#define MESHLINK_EXTERNAL_ADDRESS_HTTP_H

#include <stddef.h>

/// Format the findmyip HTTP request (origin-form GET + Host).
/// Returns snprintf-style length, or -1 on bad args.
int external_address_format_http_request(char *req, size_t reqsz, const char *path, const char *host);

/// Pull the first hostname/IP token out of a findmyip HTTP response.
/// `buf` must be writable and NUL-terminated. Returns a malloc'd string or NULL.
char *external_address_hostname_from_http(char *buf);

#endif
