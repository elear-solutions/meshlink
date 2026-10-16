#ifndef MESHLINK_CONF_H
#define MESHLINK_CONF_H

/*
    econf.h -- header for econf.c
    Copyright (C) 2018 Guus Sliepen <guus@meshlink.io>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

struct meshlink_handle;

typedef struct config_t {
	const uint8_t *buf;
	size_t len;
} config_t;

typedef bool (*config_scan_action_t)(struct meshlink_handle *mesh, const char *name, void *arg);

bool config_read_file(struct meshlink_handle *mesh, FILE *f, struct config_t *, const void *key) __attribute__((__warn_unused_result__));
bool config_write_file(struct meshlink_handle *mesh, FILE *f, const struct config_t *, const void *key) __attribute__((__warn_unused_result__));
void config_free(struct config_t *config);

/* Native storage backend: no mesh access, logging, or application callbacks.
 * A non-NULL raw key points to CHACHA_POLY1305_KEYLEN bytes (64), not an
 * Ed25519 public key or an application passphrase. */
bool config_read_path(const char *path, struct config_t *config, const void *key) __attribute__((__warn_unused_result__));
bool config_write_path(const char *path, const struct config_t *config, const void *key) __attribute__((__warn_unused_result__));
bool config_cache_read(struct meshlink_handle *mesh, const char *conf_subdir, const char *name, struct config_t *config, const void *key) __attribute__((__warn_unused_result__));
bool config_cache_delete(struct meshlink_handle *mesh, const char *conf_subdir, const char *name) __attribute__((__warn_unused_result__));

/* Deterministic, process-wide native backend failures for internal tests. */
typedef enum {
	CONFIG_FAULT_NONE,
	CONFIG_FAULT_WRITE,
	CONFIG_FAULT_FILE_SYNC,
	CONFIG_FAULT_RENAME,
	CONFIG_FAULT_DIR_SYNC,
	CONFIG_FAULT_SCAN,
} config_fault_t;

void config_fault_inject(config_fault_t fault, unsigned count);

/* Distinguish an empty store from a failed authoritative-record recovery. */
bool config_recover(struct meshlink_handle *mesh, bool *exists) __attribute__((__warn_unused_result__));

bool config_init(struct meshlink_handle *mesh, const char *conf_subdir) __attribute__((__warn_unused_result__));
bool config_destroy(const char *confbase, const char *conf_subdir) __attribute__((__warn_unused_result__));
bool config_copy(struct meshlink_handle *mesh, const char *src_dir_name, const void *src_key, const char *dst_dir_name, const void *dst_key) __attribute__((__warn_unused_result__));
bool config_rename(struct meshlink_handle *mesh, const char *old_conf_subdir, const char *new_conf_subdir) __attribute__((__warn_unused_result__));

typedef enum config_active_t {
	CONFIG_ACTIVE_NONE,
	CONFIG_ACTIVE_OLD,
	CONFIG_ACTIVE_NEW,
} config_active_t;

/* Activate staged new/ after the caller has frozen and drained persistence and
 * removed old/. Success acknowledges both namespace syncs. On failure, attempt
 * rollback and report which identity actually occupies current/, independently
 * of durability. Probe stages 2 and 3 follow forward renames; -3 and -2 precede
 * rollback renames. The caller must adopt the reported active identity/key. */
bool config_activate(struct meshlink_handle *mesh, config_active_t *active, void (*probe)(int)) __attribute__((__warn_unused_result__));
bool config_sync(struct meshlink_handle *mesh, const char *conf_subdir) __attribute__((__warn_unused_result__));
bool sync_path(const char *path) __attribute__((__warn_unused_result__));

bool main_config_exists(struct meshlink_handle *mesh, const char *conf_subdir) __attribute__((__warn_unused_result__));
bool main_config_lock(struct meshlink_handle *mesh, const char *lock_filename) __attribute__((__warn_unused_result__));
void main_config_unlock(struct meshlink_handle *mesh);
bool main_config_read(struct meshlink_handle *mesh, const char *conf_subdir, struct config_t *, void *key) __attribute__((__warn_unused_result__));
bool main_config_write(struct meshlink_handle *mesh, const char *conf_subdir, const struct config_t *, void *key) __attribute__((__warn_unused_result__));

bool config_exists(struct meshlink_handle *mesh, const char *conf_subdir, const char *name) __attribute__((__warn_unused_result__));
bool config_read(struct meshlink_handle *mesh, const char *conf_subdir, const char *name, struct config_t *, void *key) __attribute__((__warn_unused_result__));
bool config_write(struct meshlink_handle *mesh, const char *conf_subdir, const char *name, const struct config_t *, void *key) __attribute__((__warn_unused_result__));
bool config_delete(struct meshlink_handle *mesh, const char *conf_subdir, const char *name) __attribute__((__warn_unused_result__));
bool config_scan_all(struct meshlink_handle *mesh, const char *conf_subdir, const char *conf_type, config_scan_action_t action, void *arg) __attribute__((__warn_unused_result__));

bool backbone_config_exists(struct meshlink_handle *mesh, const char *conf_subdir) __attribute__((__warn_unused_result__));
bool backbone_config_read(struct meshlink_handle *mesh, const char *conf_subdir, struct config_t *, void *key) __attribute__((__warn_unused_result__));
bool backbone_config_write(struct meshlink_handle *mesh, const char *conf_subdir, const struct config_t *, void *key) __attribute__((__warn_unused_result__));

bool invitation_read(struct meshlink_handle *mesh, const char *conf_subdir, const char *name, struct config_t *, void *key) __attribute__((__warn_unused_result__));
bool invitation_write(struct meshlink_handle *mesh, const char *conf_subdir, const char *name, const struct config_t *, void *key) __attribute__((__warn_unused_result__));
size_t invitation_purge_old(struct meshlink_handle *mesh, time_t deadline);
size_t invitation_purge_node(struct meshlink_handle *mesh, const char *node_name);

#endif
