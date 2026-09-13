#ifndef MESHLINK_RELAY_DEVTOOL_H
#define MESHLINK_RELAY_DEVTOOL_H

#include "relay.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct meshlink_handle;
struct node_t;
struct connection_t;
struct list_t;

typedef struct relay_report_entry {
	char *origin;
	char *destination;
	uint16_t last_budget;
	struct timespec last_report;
	time_t last_traffic_time;
	bool have_reported;
} relay_report_entry_t;

struct relay_devtool_state {
	bool force_report_null_connection;
	bool fail_realloc;
	bool inject_hard_send_error;
	uint8_t capture_buf[RELAY_CAPTURE_MAX];
	size_t capture_len;
};

struct relay_devtool_state *relay_devtool_get(struct meshlink_handle *mesh);

/* relay.c internals shared with relay_devtool.c (not public API). */
void relay_report_timeout_handler(event_loop_t *loop, void *data);
void relay_report_free(const void *data);
void relay_expire_idle(struct meshlink_handle *mesh);
relay_report_entry_t *relay_report_find(struct meshlink_handle *mesh, const char *origin, const char *destination);
void relay_evict_lru(struct meshlink_handle *mesh);
relay_report_entry_t *relay_report_get(struct meshlink_handle *mesh, const char *origin, const char *destination, bool create, bool require_nodes);
bool relay_decode(const void *data, size_t len, char *origin, size_t origin_size, char *destination, size_t destination_size, const uint8_t **inner, size_t *inner_len);
bool relay_add_u32(uint32_t a, uint32_t b, uint32_t *out);
bool relay_sub_u32(uint32_t a, uint32_t b, uint32_t *out);
bool relay_prefix21(const char *origin, const char *destination, uint32_t *out);

bool relay_inject_inner(struct meshlink_handle *mesh, struct node_t *dest, uint8_t type);

void relay_devtool_clear_reports(struct meshlink_handle *mesh);
bool relay_devtool_seed_report(struct meshlink_handle *mesh, const char *origin, const char *destination, unsigned age_sec, bool have_reported);
bool relay_devtool_has_report(struct meshlink_handle *mesh, const char *origin, const char *destination);
bool relay_devtool_have_reported(struct meshlink_handle *mesh, const char *origin, const char *destination);
size_t relay_devtool_report_count(struct meshlink_handle *mesh);
bool relay_devtool_fill_reports(struct meshlink_handle *mesh, size_t count, unsigned age_sec, bool have_reported);
void relay_devtool_force_report_null_connection(struct meshlink_handle *mesh, bool force);
bool relay_devtool_handle_aliased(struct meshlink_handle *mesh, struct node_t *from, const void *data, uint16_t len);
bool relay_devtool_send_meta_sptps(struct meshlink_handle *mesh, struct node_t *dest, uint8_t type, const void *data, size_t len);
void relay_devtool_fail_realloc(struct meshlink_handle *mesh, bool fail);
bool relay_devtool_handle_req_relay_mtu(struct meshlink_handle *mesh, struct node_t *from, const char *request);
bool relay_devtool_cover_unit(struct meshlink_handle *mesh, struct node_t *from, struct node_t *dest, struct node_t *hop);

#endif
