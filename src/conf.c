/*
    econf.c -- configuration code
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

#include "system.h"
#include <assert.h>
#include <sys/types.h>
#include <utime.h>

#include "conf.h"
#include "crypto.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "xalloc.h"
#include "packmsg.h"

/// Generate a path to the main configuration file.
static void make_main_path(meshlink_handle_t *mesh, const char *conf_subdir, char *path, size_t len) {
	assert(conf_subdir);
	assert(path);
	assert(len);

	snprintf(path, len, "%s" SLASH "%s" SLASH "meshlink.conf", mesh->confbase, conf_subdir);
}

/// Generate a path to the backbone identity file.
static void make_backbone_path(meshlink_handle_t *mesh, const char *conf_subdir, char *path, size_t len) {
	assert(conf_subdir);
	assert(path);
	assert(len);

	snprintf(path, len, "%s" SLASH "%s" SLASH "backbone", mesh->confbase, conf_subdir);
}

/// Generate a path to a host configuration file.
static void make_host_path(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, char *path, size_t len) {
	assert(conf_subdir);
	assert(name);
	assert(path);
	assert(len);

	snprintf(path, len, "%s" SLASH "%s" SLASH "hosts" SLASH "%s", mesh->confbase, conf_subdir, name);
}

/// Generate a path to an optional path cache file.
static void make_cache_path(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, char *path, size_t len) {
	assert(conf_subdir);
	assert(name);
	assert(path);
	assert(len);

	snprintf(path, len, "%s" SLASH "%s" SLASH "path-cache" SLASH "%s", mesh->confbase, conf_subdir, name);
}

/// Generate a path to an unused invitation file.
static void make_invitation_path(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, char *path, size_t len) {
	assert(conf_subdir);
	assert(name);
	assert(path);
	assert(len);

	snprintf(path, len, "%s" SLASH "%s" SLASH "invitations" SLASH "%s", mesh->confbase, conf_subdir, name);
}

/// Generate a path to a used invitation file.
static void make_used_invitation_path(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, char *path, size_t len) {
	assert(conf_subdir);
	assert(name);
	assert(path);
	assert(len);

	snprintf(path, len, "%s" SLASH "%s" SLASH "invitations" SLASH "%s.used", mesh->confbase, conf_subdir, name);
}

/// Remove a directory recursively
static bool deltree(const char *dirname) {
	assert(dirname);

	DIR *d = opendir(dirname);

	if(d) {
		struct dirent *ent;

		while((ent = readdir(d))) {
			if(ent->d_name[0] == '.') {
				if(!ent->d_name[1] || (ent->d_name[1] == '.' && !ent->d_name[2])) {
					continue;
				}
			}

			char filename[PATH_MAX];
			snprintf(filename, sizeof(filename), "%s" SLASH "%s", dirname, ent->d_name);

			if(unlink(filename)) {
				if(!deltree(filename)) {
					int saved_errno = errno;
					closedir(d);
					errno = saved_errno;
					return false;
				}
			}
		}

		closedir(d);
	} else {
		return errno == ENOENT;
	}

	return rmdir(dirname) == 0;
}

static pthread_mutex_t fault_mutex = PTHREAD_MUTEX_INITIALIZER;
static config_fault_t injected_fault;
static unsigned injected_count;

void config_fault_inject(config_fault_t fault, unsigned count) {
	pthread_mutex_lock(&fault_mutex);
	injected_fault = fault;
	injected_count = count;
	pthread_mutex_unlock(&fault_mutex);
}

static bool config_fault(config_fault_t fault) {
	pthread_mutex_lock(&fault_mutex);
	bool fail = injected_fault == fault && injected_count;

	if(fail) {
		injected_count--;
	}

	pthread_mutex_unlock(&fault_mutex);

	if(fail) {
		errno = EIO;
	}

	return fail;
}

static bool sync_path_native(const char *pathname, bool directory) {
	int fd = open(pathname, O_RDONLY);

	if(fd < 0) {
		return false;
	}

	bool success = !config_fault(directory ? CONFIG_FAULT_DIR_SYNC : CONFIG_FAULT_FILE_SYNC) && !fsync(fd);
	int saved_errno = errno;

	if(close(fd) && success) {
		success = false;
		saved_errno = errno;
	}

	errno = saved_errno;
	return success;
}

static bool sync_parent(const char *pathname) {
	char *parent = xstrdup(pathname);
	size_t len = strlen(parent);

	while(len > 1 && parent[len - 1] == '/') {
		parent[--len] = 0;
	}

	char *separator = strrchr(parent, '/');
#ifdef HAVE_MINGW
	char *backslash = strrchr(parent, '\\');

	if(backslash && (!separator || backslash > separator)) {
		separator = backslash;
	}
#endif

	if(separator) {
		separator[separator == parent ? 1 : 0] = 0;
	} else {
		free(parent);
		parent = xstrdup(".");
	}

	bool success = sync_path_native(parent, true);
	int saved_errno = errno;
	free(parent);
	errno = saved_errno;
	return success;
}

bool sync_path(const char *pathname) {
	assert(pathname);

	if(!sync_path_native(pathname, true)) {
		logger(NULL, MESHLINK_ERROR, "Failed to sync %s: %s", pathname, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/* Validate the main record header before selecting a recovery candidate. */
static bool main_config_readable(meshlink_handle_t *mesh, const char *conf_subdir, bool *decoded) {
	assert(mesh->confbase);
	assert(conf_subdir);
	char path[PATH_MAX];
	make_main_path(mesh, conf_subdir, path, sizeof(path));
	config_t config = {0};
	*decoded = config_read_path(path, &config, mesh->config_key);

	if(!*decoded) {
		return false;
	}

	packmsg_input_t in = {config.buf, config.len};

	uint32_t version = packmsg_get_uint32(&in);
	bool valid = packmsg_input_ok(&in) && version == MESHLINK_CONFIG_VERSION;
	config_free(&config);
	return valid;
}

/// Create a fresh configuration directory
bool config_init(meshlink_handle_t *mesh, const char *conf_subdir) {
	assert(conf_subdir);

	if(!mesh->confbase) {
		return true;
	}

	char path[PATH_MAX];

	// Create "current" sub-directory in the confbase
	snprintf(path, sizeof(path), "%s" SLASH "%s", mesh->confbase, conf_subdir);

	if(!deltree(path)) {
		logger(mesh, MESHLINK_DEBUG, "Could not delete directory %s: %s\n", path, strerror(errno));
		return false;
	}

	if(mkdir(path, 0700)) {
		logger(mesh, MESHLINK_DEBUG, "Could not create directory %s: %s\n", path, strerror(errno));
		return false;
	}

	make_host_path(mesh, conf_subdir, "", path, sizeof(path));

	if(mkdir(path, 0700)) {
		logger(mesh, MESHLINK_DEBUG, "Could not create directory %s: %s\n", path, strerror(errno));
		return false;
	}

	make_cache_path(mesh, conf_subdir, "", path, sizeof(path));

	if(mkdir(path, 0700)) {
		logger(mesh, MESHLINK_DEBUG, "Could not create directory %s: %s", path, strerror(errno));
		return false;
	}

	make_invitation_path(mesh, conf_subdir, "", path, sizeof(path));

	if(mkdir(path, 0700)) {
		logger(mesh, MESHLINK_DEBUG, "Could not create directory %s: %s\n", path, strerror(errno));
		return false;
	}

	return config_sync(mesh, conf_subdir) && sync_path(mesh->confbase);
}

/// Wipe an existing configuration directory
bool config_destroy(const char *confbase, const char *conf_subdir) {
	assert(conf_subdir);

	if(!confbase) {
		return true;
	}

	struct stat st;

	char path[PATH_MAX];

	// Check the presence of configuration base sub directory.
	snprintf(path, sizeof(path), "%s" SLASH "%s", confbase, conf_subdir);

	if(stat(path, &st)) {
		if(errno == ENOENT) {
			return true;
		} else {
			logger(NULL, MESHLINK_ERROR, "Cannot stat %s: %s\n", path, strerror(errno));
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		}
	}

	// Remove meshlink.conf
	snprintf(path, sizeof(path), "%s" SLASH "%s" SLASH "meshlink.conf", confbase, conf_subdir);

	if(unlink(path)) {
		if(errno != ENOENT) {
			logger(NULL, MESHLINK_ERROR, "Cannot delete %s: %s\n", path, strerror(errno));
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		}
	}

	snprintf(path, sizeof(path), "%s" SLASH "%s", confbase, conf_subdir);

	if(!deltree(path)) {
		logger(NULL, MESHLINK_ERROR, "Cannot delete %s: %s\n", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return sync_path(confbase);
}

static bool read_file(FILE *f, config_t *config, const void *key, size_t max_size);

static bool copytree(const char *src_dir_name, const void *src_key, const char *dst_dir_name, const void *dst_key, bool optional_cache) {
	DIR *src_dir = opendir(src_dir_name);

	if(!src_dir) {
		return false;
	}

	bool success = deltree(dst_dir_name) && !mkdir(dst_dir_name, 0700);
	struct dirent *ent;

	while(success) {
		errno = 0;
		ent = readdir(src_dir);

		if(!ent) {
			success = !errno;
			break;
		}

		/* Temporary files are hidden and never become records during a rotation. */
		if(ent->d_name[0] == '.') {
			continue;
		}

		char src_filename[PATH_MAX];
		char dst_filename[PATH_MAX];

		if(snprintf(src_filename, sizeof(src_filename), "%s" SLASH "%s", src_dir_name, ent->d_name) >= (int)sizeof(src_filename)
		                || snprintf(dst_filename, sizeof(dst_filename), "%s" SLASH "%s", dst_dir_name, ent->d_name) >= (int)sizeof(dst_filename)) {
			errno = ENAMETOOLONG;
			success = false;
			break;
		}

		struct stat st;

		if(lstat(src_filename, &st)) {
			if(optional_cache) {
				continue;
			}

			success = false;
			break;
		}

		bool cache_directory = !strcmp(ent->d_name, "path-cache");

		if(S_ISDIR(st.st_mode)) {
			if(optional_cache) {
				continue;
			}

			success = copytree(src_filename, src_key, dst_filename, dst_key, cache_directory);

			if(!success && cache_directory) {
				/* An unusable cache directory is equivalent to an empty cache. */
				success = deltree(dst_filename) && !mkdir(dst_filename, 0700);
			}

			continue;
		}

		if(cache_directory && !optional_cache) {
			/* A damaged optional directory must not be copied as a regular file. */
			continue;
		}

		if(!S_ISREG(st.st_mode)) {
			if(optional_cache) {
				continue;
			}

			errno = EINVAL;
			success = false;
			break;
		}

		config_t config = {0};
		FILE *f = fopen(src_filename, "rb");
		bool copied = f && read_file(f, &config, src_key, optional_cache ? 65536 : SIZE_MAX);

		if(f && fclose(f)) {
			copied = false;
		}

		if(copied) {
			copied = config_write_path(dst_filename, &config, dst_key);
		}

		config_free(&config);

		if(copied) {
			struct utimbuf times = {.actime = st.st_atime, .modtime = st.st_mtime};
			/* utime modifies inode metadata after the write, so sync it again. */
			copied = !utime(dst_filename, &times) && sync_path_native(dst_filename, false);
		}

		if(!copied) {
			if(optional_cache) {
				/* Cache damage cannot prevent rotating authoritative identity/history. */
				unlink(dst_filename);
			} else {
				success = false;
			}
		}
	}

	int saved_errno = errno;

	if(closedir(src_dir) && success) {
		success = false;
		saved_errno = errno;
	}

	errno = saved_errno;
	return success && sync_path_native(dst_dir_name, true) && sync_parent(dst_dir_name);
}

bool config_copy(meshlink_handle_t *mesh, const char *src_dir_name, const void *src_key, const char *dst_dir_name, const void *dst_key) {
	assert(src_dir_name);
	assert(dst_dir_name);

	char src_filename[PATH_MAX];
	char dst_filename[PATH_MAX];

	snprintf(dst_filename, sizeof(dst_filename), "%s" SLASH "%s", mesh->confbase, dst_dir_name);
	snprintf(src_filename, sizeof(src_filename), "%s" SLASH "%s", mesh->confbase, src_dir_name);

	if(!copytree(src_filename, src_key, dst_filename, dst_key, false)) {
		logger(mesh, MESHLINK_ERROR, "Could not copy configuration: %s", strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	make_cache_path(mesh, dst_dir_name, "", dst_filename, sizeof(dst_filename));

	if(mkdir(dst_filename, 0700) && errno != EEXIST) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return config_sync(mesh, dst_dir_name) && sync_path(mesh->confbase);
}

/// Check the presence of the main configuration file.
bool main_config_exists(meshlink_handle_t *mesh, const char *conf_subdir) {
	assert(conf_subdir);

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	make_main_path(mesh, conf_subdir, path, sizeof(path));
	return access(path, F_OK) == 0;
}

/* Keep the namespace result separate from its subsequent durability result. */
static bool rename_subdir(meshlink_handle_t *mesh, const char *old_conf_subdir, const char *new_conf_subdir) {
	assert(old_conf_subdir);
	assert(new_conf_subdir);

	if(!mesh->confbase) {
		return false;
	}

	char old_path[PATH_MAX];
	char new_path[PATH_MAX];

	snprintf(old_path, sizeof(old_path), "%s" SLASH "%s", mesh->confbase, old_conf_subdir);
	snprintf(new_path, sizeof(new_path), "%s" SLASH "%s", mesh->confbase, new_conf_subdir);

	return !config_fault(CONFIG_FAULT_RENAME) && !rename(old_path, new_path);
}

bool config_rename(meshlink_handle_t *mesh, const char *old_conf_subdir, const char *new_conf_subdir) {
	return rename_subdir(mesh, old_conf_subdir, new_conf_subdir) && sync_path(mesh->confbase);
}

bool config_activate(meshlink_handle_t *mesh, config_active_t *active, void (*probe)(int)) {
	assert(mesh);
	assert(mesh->confbase);
	assert(active);
	/* Distinguish "activation never started" from an unrestorable namespace. */
	*active = CONFIG_ACTIVE_UNTOUCHED;
	char path[PATH_MAX];
	struct stat st;
	snprintf(path, sizeof(path), "%s" SLASH "current", mesh->confbase);

	if(stat(path, &st)) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	*active = CONFIG_ACTIVE_OLD;
	/* Never overwrite a backup the caller has not retired. */
	snprintf(path, sizeof(path), "%s" SLASH "old", mesh->confbase);

	int old_status = lstat(path, &st);

	if(!old_status) {
		errno = EEXIST;
	}

	if(!old_status || errno != ENOENT) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(!rename_subdir(mesh, "current", "old")) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	*active = CONFIG_ACTIVE_NONE;

	if(probe) {
		probe(2);
	}

	if(sync_path_native(mesh->confbase, true) && rename_subdir(mesh, "new", "current")) {
		*active = CONFIG_ACTIVE_NEW;

		if(probe) {
			probe(3);
		}

		if(sync_path_native(mesh->confbase, true)) {
			return true;
		}
	}

	int saved_errno = errno;
	bool changed = false;

	if(*active == CONFIG_ACTIVE_NEW && probe) {
		probe(-3);
	}

	if(*active == CONFIG_ACTIVE_NEW && rename_subdir(mesh, "current", "new")) {
		*active = CONFIG_ACTIVE_NONE;
		changed = true;
	}

	if(*active == CONFIG_ACTIVE_NONE && probe) {
		probe(-2);
	}
	if(*active == CONFIG_ACTIVE_NONE && rename_subdir(mesh, "old", "current")) {
		*active = CONFIG_ACTIVE_OLD;
		changed = true;
	}

	if(changed) {
		/* Even a failed rollback sync does not undo an observed rename. */
		(void)sync_path_native(mesh->confbase, true);
	}

	errno = saved_errno;
	meshlink_errno = MESHLINK_ESTORAGE;
	return false;
}

bool config_sync(meshlink_handle_t *mesh, const char *conf_subdir) {
	assert(conf_subdir);

	if(!mesh->confbase || mesh->storage_policy == MESHLINK_STORAGE_DISABLED) {
		return true;
	}

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s" SLASH "%s" SLASH "hosts", mesh->confbase, conf_subdir);

	if(!sync_path(path)) {
		return false;
	}

	make_cache_path(mesh, conf_subdir, "", path, sizeof(path));

	if(!sync_path_native(path, true) && errno != ENOENT) {
		logger(mesh, MESHLINK_ERROR, "Failed to sync %s: %s", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	make_invitation_path(mesh, conf_subdir, "", path, sizeof(path));

	if(!sync_path(path)) {
		return false;
	}

	snprintf(path, sizeof(path), "%s" SLASH "%s", mesh->confbase, conf_subdir);

	if(!sync_path(path)) {
		return false;
	}

	return true;
}

static bool host_records_exist(meshlink_handle_t *mesh, const char *subdir, bool *found) {
	char path[PATH_MAX];
	make_host_path(mesh, subdir, "", path, sizeof(path));
	DIR *directory = opendir(path);

	if(!directory) {
		return errno == ENOENT;
	}

	bool success = true;

	while(!*found) {
		errno = 0;
		struct dirent *entry = readdir(directory);

		if(!entry) {
			success = !errno;
			break;
		}

		*found = entry->d_name[0] != '.';
	}

	return !closedir(directory) && success;
}

bool config_recover(meshlink_handle_t *mesh, bool *exists) {
	assert(exists);
	*exists = false;

	if(!mesh->confbase) {
		return true;
	}

	const char *subdirs[] = {"current", "old", "new"};
	bool present[3] = {false};

	for(unsigned i = 0; i < 3; i++) {
		char path[PATH_MAX];
		struct stat st;
		make_main_path(mesh, subdirs[i], path, sizeof(path));

		if(!stat(path, &st)) {
			present[i] = true;
			*exists = true;
		} else if(errno != ENOENT) {
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		}
	}

	if(!*exists) {
		for(unsigned i = 0; i < 3; i++) {
			bool hosts = false;

			if(!host_records_exist(mesh, subdirs[i], &hosts) || hosts) {
				*exists = hosts;
				meshlink_errno = MESHLINK_ESTORAGE;
				return false;
			}
		}

		return true;
	}

	bool decoded = false;
	bool ready = present[0] && main_config_readable(mesh, "current", &decoded);

	/* A readable but malformed current record remains an authoritative error.
	 * Encrypted rotations may recover a different epoch matching the supplied
	 * key when current cannot be decrypted. */
	if(present[0] && !ready && (decoded || !mesh->config_key)) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	for(unsigned i = 1; !ready && i < 3; i++) {
		if(!present[i] || !main_config_readable(mesh, subdirs[i], &decoded)) {
			continue;
		}

		/* Prefer the pre-operation identity if both epochs use the same key. */
		if(!config_destroy(mesh->confbase, "current") || !config_rename(mesh, subdirs[i], "current")) {
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		}

		ready = true;
	}

	if(!ready || !config_destroy(mesh->confbase, "old") || !config_destroy(mesh->confbase, "new")) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/// Lock the main configuration file. Creates confbase if necessary.
bool main_config_lock(meshlink_handle_t *mesh, const char *lock_filename) {
	if(!mesh->confbase) {
		return true;
	}

	assert(lock_filename);

	bool created = !mkdir(mesh->confbase, 0700);

	if(!created && errno != EEXIST) {
		logger(NULL, MESHLINK_ERROR, "Cannot create configuration directory %s: %s", mesh->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(created && !sync_parent(mesh->confbase)) {
		logger(mesh, MESHLINK_ERROR, "Cannot sync parent of configuration directory %s: %s", mesh->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	mesh->lockfile = fopen(lock_filename, "w+");

	if(!mesh->lockfile) {
		logger(NULL, MESHLINK_ERROR, "Cannot not open %s: %s\n", lock_filename, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(fileno(mesh->lockfile), F_SETFD, FD_CLOEXEC);
#endif

#ifdef HAVE_MINGW
	// TODO: use _locking()?
#else

	if(flock(fileno(mesh->lockfile), LOCK_EX | LOCK_NB) != 0) {
		logger(NULL, MESHLINK_ERROR, "Cannot lock %s: %s\n", lock_filename, strerror(errno));
		fclose(mesh->lockfile);
		mesh->lockfile = NULL;
		meshlink_errno = MESHLINK_EBUSY;
		return false;
	}

#endif

	return true;
}

/// Unlock the main configuration file.
void main_config_unlock(meshlink_handle_t *mesh) {
	if(mesh->lockfile) {
		fclose(mesh->lockfile);
		mesh->lockfile = NULL;
	}
}

static bool read_file(FILE *f, config_t *config, const void *key, size_t max_size) {
	*config = (config_t) {0};

	if(fseek(f, 0, SEEK_END)) {
		return false;
	}

	long file_size = ftell(f);

	if(file_size <= 0 || (uintmax_t)file_size > max_size) {
		errno = EINVAL;
		return false;
	}

	if(fseek(f, 0, SEEK_SET)) {
		return false;
	}

	size_t len = file_size;
	uint8_t *buf = xmalloc(len);

	if(fread(buf, 1, len, f) != len) {
		free(buf);
		errno = EIO;
		return false;
	}

	if(key) {
		uint8_t *decrypted = xmalloc(len);
		size_t decrypted_len = len;
		chacha_poly1305_ctx_t *ctx = chacha_poly1305_init();
		chacha_poly1305_set_key(ctx, key);
		bool success = len > 28 && chacha_poly1305_decrypt_iv96(ctx, buf, buf + 12, len - 12, decrypted, &decrypted_len);
		chacha_poly1305_exit(ctx);
		free(buf);

		if(!success) {
			free(decrypted);
			errno = EINVAL;
			return false;
		}

		config->buf = decrypted;
		config->len = decrypted_len;
		return true;
	}

	config->buf = buf;
	config->len = len;
	return true;
}

/// Read a configuration file from a FILE handle.
bool config_read_file(meshlink_handle_t *mesh, FILE *f, config_t *config, const void *key) {
	assert(f);

	if(!read_file(f, config, key, SIZE_MAX)) {
		logger(mesh, MESHLINK_ERROR, "Cannot read configuration: %s", strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

bool config_read_path(const char *path, config_t *config, const void *key) {
	assert(path);
	assert(config);
	*config = (config_t) {0};
	FILE *f = fopen(path, "rb");

	if(!f) {
		return false;
	}

	/* Native records are bounded; do not allocate arbitrary corrupt cache sizes. */
	bool success = read_file(f, config, key, 65536);
	int saved_errno = errno;

	if(fclose(f) && success) {
		success = false;
		saved_errno = errno;
		config_free(config);
	}

	errno = saved_errno;
	return success;
}

static bool write_file(FILE *f, const config_t *config, const void *key) {
	if(config_fault(CONFIG_FAULT_WRITE)) {
		return false;
	}

	if(key) {
		if(config->len > SIZE_MAX - 16) {
			errno = EOVERFLOW;
			return false;
		}

		size_t len = config->len + 16;
		uint8_t *buf = xmalloc(len);
		uint8_t nonce[12];
		randomize(nonce, sizeof(nonce));
		chacha_poly1305_ctx_t *ctx = chacha_poly1305_init();
		chacha_poly1305_set_key(ctx, key);
		bool success = chacha_poly1305_encrypt_iv96(ctx, nonce, config->buf, config->len, buf, &len);
		chacha_poly1305_exit(ctx);

		if(success) {
			success = fwrite(nonce, 1, sizeof(nonce), f) == sizeof(nonce) && fwrite(buf, 1, len, f) == len;
		} else {
			errno = EIO;
		}

		free(buf);

		if(!success) {
			return false;
		}
	} else if(fwrite(config->buf, 1, config->len, f) != config->len) {
		return false;
	}

	return !fflush(f) && !config_fault(CONFIG_FAULT_FILE_SYNC) && !fsync(fileno(f));
}

/// Write a configuration file to a FILE handle, including durable final bytes.
bool config_write_file(meshlink_handle_t *mesh, FILE *f, const config_t *config, const void *key) {
	assert(f);

	if(!write_file(f, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Cannot write configuration: %s", strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/* Host, main, and cache paths are built with SLASH. On MinGW that is '\\'. */
static const char *path_separator(const char *path) {
	const char *separator = strrchr(path, '/');
#ifdef HAVE_MINGW
	const char *backslash = strrchr(path, '\\');

	if(backslash && (!separator || backslash > separator)) {
		separator = backslash;
	}
#endif

	return separator;
}

/* Optional cache directories may disappear independently of authoritative
 * storage. Recreate only that directory, never a retired storage epoch. */
static bool create_cache_parent(const char *path, bool *cache_path) {
	*cache_path = false;
	char *parent = xstrdup(path);
	char *filename = (char *)path_separator(parent);
	bool success = false;

	if(!filename) {
		goto done;
	}

	*filename = 0;
	char *cache = (char *)path_separator(parent);

	if(!cache || strcmp(cache + 1, "path-cache")) {
		goto done;
	}

	char saved = *cache;
	*cache = 0;
	const char *epoch = path_separator(parent);
	epoch = epoch ? epoch + 1 : parent;

	if(strcmp(epoch, "current") && strcmp(epoch, "new")) {
		goto done;
	}

	*cache_path = true;
	struct stat st;

	if(stat(parent, &st)) {
		goto done;
	}

	if(!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		goto done;
	}

	*cache = saved;

	bool created = !mkdir(parent, 0700);

	if(!created && errno != EEXIST) {
		goto done;
	}

	success = (!created || sync_path_native(parent, true)) && sync_parent(parent);

done:
	free(parent);
	return success;
}

bool config_write_path(const char *path, const config_t *config, const void *key) {
	assert(path);
	assert(config);

	if(access(path, F_OK) && errno == ENOENT) {
		/* Recheck the epoch sync until this record exists. A failed directory
		 * initialization must not become an acknowledged commit on retry. */
		bool cache_path;

		if(!create_cache_parent(path, &cache_path) && cache_path) {
			return false;
		}
	}

	char *temporary = xmalloc(strlen(path) + 6);
	const char *separator = path_separator(path);
	const char *basename = separator ? separator + 1 : path;
	size_t prefix = basename - path;
	memcpy(temporary, path, prefix);
	snprintf(temporary + prefix, strlen(basename) + 6, ".%s.tmp", basename);

	int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	FILE *f = fd < 0 ? NULL : fdopen(fd, "wb");

	if(!f) {
		int saved_errno = errno;

		if(fd >= 0) {
			close(fd);
		}

		free(temporary);
		errno = saved_errno;
		return false;
	}

	bool success = write_file(f, config, key);
	int saved_errno = errno;

	if(fclose(f) && success) {
		success = false;
		saved_errno = errno;
	}

	if(success) {
		success = !config_fault(CONFIG_FAULT_RENAME) && !rename(temporary, path);
		saved_errno = errno;
	}

	if(success) {
		success = sync_parent(path);
		saved_errno = errno;
	}

	if(!success) {
		unlink(temporary);
	}

	free(temporary);
	errno = saved_errno;
	return success;
}

/// Free resources of a loaded configuration file.
void config_free(config_t *config) {
	assert(!config->len || config->buf);

	free((uint8_t *)config->buf);
	config->buf = NULL;
	config->len = 0;
}

/// Check the presence of a host configuration file.
bool config_exists(meshlink_handle_t *mesh, const char *conf_subdir, const char *name) {
	assert(conf_subdir);

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	make_host_path(mesh, conf_subdir, name, path, sizeof(path));

	return access(path, F_OK) == 0;
}

/// Read a host configuration file.
bool config_read(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, config_t *config, void *key) {
	assert(conf_subdir);

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	make_host_path(mesh, conf_subdir, name, path, sizeof(path));

	FILE *f = fopen(path, "rb");

	if(!f) {
		logger(mesh, MESHLINK_ERROR, "Failed to open `%s': %s", path, strerror(errno));
		return false;
	}

	if(!config_read_file(mesh, f, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Failed to read `%s': %s", path, strerror(errno));
		fclose(f);
		return false;
	}

	fclose(f);

	return true;
}

bool config_scan_all(meshlink_handle_t *mesh, const char *conf_subdir, const char *conf_type, config_scan_action_t action, void *arg) {
	assert(conf_subdir);
	assert(conf_type);

	if(!mesh->confbase) {
		return true;
	}

	DIR *dir;
	struct dirent *ent;
	char dname[PATH_MAX];
	snprintf(dname, sizeof(dname), "%s" SLASH "%s" SLASH "%s", mesh->confbase, conf_subdir, conf_type);

	dir = opendir(dname);

	if(!dir) {
		logger(mesh, MESHLINK_ERROR, "Could not open %s: %s", dname, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	int scan_error = 0;
	for(;;) {
		errno = 0;
		ent = readdir(dir);
		if(!ent) {
			scan_error = errno;
			break;
		}
		if(ent->d_name[0] == '.') {
			continue;
		}

		if(!action(mesh, ent->d_name, arg)) {
			closedir(dir);
			return false;
		}
		if(config_fault(CONFIG_FAULT_SCAN)) {
			scan_error = errno;
			break;
		}
	}

	if(closedir(dir) && !scan_error) {
		scan_error = errno;
	}
	if(scan_error) {
		errno = scan_error;
		meshlink_errno = MESHLINK_ESTORAGE;
		mesh->storage_error = true;
		return false;
	}
	return true;
}

/// Write a host configuration file.
bool config_write(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, const config_t *config, void *key) {
	assert(conf_subdir);
	assert(name);
	assert(config);

	if(!mesh->confbase) {
		return true;
	}

	char path[PATH_MAX];
	make_host_path(mesh, conf_subdir, name, path, sizeof(path));

	if(!config_write_path(path, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Failed to write `%s': %s", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/// Delete a host configuration file.
bool config_delete(meshlink_handle_t *mesh, const char *conf_subdir, const char *name) {
	assert(conf_subdir);
	assert(name);

	if(!mesh->confbase) {
		return true;
	}

	char path[PATH_MAX];
	make_host_path(mesh, conf_subdir, name, path, sizeof(path));

	if(unlink(path) && errno != ENOENT) {
		logger(mesh, MESHLINK_ERROR, "Failed to unlink `%s': %s", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(!sync_parent(path)) {
		logger(mesh, MESHLINK_ERROR, "Failed to sync deletion of `%s': %s", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

bool config_cache_read(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, config_t *config, const void *key) {
	assert(conf_subdir);
	assert(name);
	assert(config);
	*config = (config_t) {0};

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	make_cache_path(mesh, conf_subdir, name, path, sizeof(path));
	return config_read_path(path, config, key);
}

bool config_cache_delete(meshlink_handle_t *mesh, const char *conf_subdir, const char *name) {
	assert(conf_subdir);
	assert(name);

	if(!mesh->confbase) {
		return true;
	}

	char path[PATH_MAX];
	make_cache_path(mesh, conf_subdir, name, path, sizeof(path));

	if(unlink(path)) {
		return errno == ENOENT;
	}

	return sync_parent(path);
}

/// Read the main configuration file.
bool main_config_read(meshlink_handle_t *mesh, const char *conf_subdir, config_t *config, void *key) {
	assert(conf_subdir);
	assert(config);

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	make_main_path(mesh, conf_subdir, path, sizeof(path));

	FILE *f = fopen(path, "rb");

	if(!f) {
		logger(mesh, MESHLINK_ERROR, "Failed to open `%s': %s", path, strerror(errno));
		return false;
	}

	if(!config_read_file(mesh, f, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Failed to read `%s': %s", path, strerror(errno));
		fclose(f);
		return false;
	}

	fclose(f);

	return true;
}

/// Write the main configuration file.
bool main_config_write(meshlink_handle_t *mesh, const char *conf_subdir, const config_t *config, void *key) {
	assert(conf_subdir);
	assert(config);

	if(!mesh->confbase) {
		return true;
	}

	char path[PATH_MAX];
	make_main_path(mesh, conf_subdir, path, sizeof(path));

	if(!config_write_path(path, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Failed to write `%s': %s", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/// Check the presence of the backbone identity file.
bool backbone_config_exists(meshlink_handle_t *mesh, const char *conf_subdir) {
	assert(conf_subdir);

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	make_backbone_path(mesh, conf_subdir, path, sizeof(path));
	return access(path, F_OK) == 0;
}

/// Read the backbone identity file.
bool backbone_config_read(meshlink_handle_t *mesh, const char *conf_subdir, config_t *config, void *key) {
	assert(conf_subdir);
	assert(config);

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	make_backbone_path(mesh, conf_subdir, path, sizeof(path));

	FILE *f = fopen(path, "rb");

	if(!f) {
		logger(mesh, MESHLINK_ERROR, "Failed to open `%s': %s", path, strerror(errno));
		return false;
	}

	if(!config_read_file(mesh, f, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Failed to read `%s': %s", path, strerror(errno));
		fclose(f);
		return false;
	}

	fclose(f);

	return true;
}

/// Write the backbone identity file.
bool backbone_config_write(meshlink_handle_t *mesh, const char *conf_subdir, const config_t *config, void *key) {
	assert(conf_subdir);
	assert(config);

	if(!mesh->confbase) {
		return true;
	}

	char path[PATH_MAX];
	make_backbone_path(mesh, conf_subdir, path, sizeof(path));

	if(!config_write_path(path, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Failed to write `%s': %s", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/// Read an invitation file from the confbase sub-directory, and immediately delete it.
bool invitation_read(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, config_t *config, void *key) {
	assert(conf_subdir);
	assert(name);
	assert(config);

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	char used_path[PATH_MAX];
	make_invitation_path(mesh, conf_subdir, name, path, sizeof(path));
	make_used_invitation_path(mesh, conf_subdir, name, used_path, sizeof(used_path));

	// Atomically rename the invitation file
	if(rename(path, used_path)) {
		if(errno == ENOENT) {
			logger(mesh, MESHLINK_ERROR, "Peer tried to use non-existing invitation %s\n", name);
		} else {
			logger(mesh, MESHLINK_ERROR, "Error trying to rename invitation %s\n", name);
		}

		return false;
	}

	FILE *f = fopen(used_path, "r");

	if(!f) {
		logger(mesh, MESHLINK_ERROR, "Failed to open `%s': %s", path, strerror(errno));
		return false;
	}

	// Check the timestamp
	struct stat st;

	if(fstat(fileno(f), &st)) {
		logger(mesh, MESHLINK_ERROR, "Could not stat invitation file %s\n", name);
		fclose(f);
		unlink(used_path);
		return false;
	}

	if(time(NULL) >= st.st_mtime + mesh->invitation_timeout) {
		logger(mesh, MESHLINK_ERROR, "Peer tried to use an outdated invitation file %s\n", name);
		fclose(f);
		unlink(used_path);
		return false;
	}

	if(!config_read_file(mesh, f, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Failed to read `%s': %s", path, strerror(errno));
		fclose(f);
		unlink(used_path);
		return false;
	}

	fclose(f);

	if(unlink(used_path)) {
		logger(mesh, MESHLINK_ERROR, "Failed to unlink `%s': %s", path, strerror(errno));
		return false;
	}

	snprintf(path, sizeof(path), "%s" SLASH "%s" SLASH "invitations", mesh->confbase, conf_subdir);

	if(!sync_path(path)) {
		logger(mesh, MESHLINK_ERROR, "Failed to sync `%s': %s", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/// Write an invitation file.
bool invitation_write(meshlink_handle_t *mesh, const char *conf_subdir, const char *name, const config_t *config, void *key) {
	assert(conf_subdir);
	assert(name);
	assert(config);

	if(!mesh->confbase) {
		return false;
	}

	char path[PATH_MAX];
	make_invitation_path(mesh, conf_subdir, name, path, sizeof(path));

	if(!config_write_path(path, config, key)) {
		logger(mesh, MESHLINK_ERROR, "Failed to write `%s': %s", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/// Purge old invitation files
size_t invitation_purge_old(meshlink_handle_t *mesh, time_t deadline) {
	if(!mesh->confbase) {
		return true;
	}

	char path[PATH_MAX];
	make_invitation_path(mesh, "current", "", path, sizeof(path));

	DIR *dir = opendir(path);

	if(!dir) {
		logger(mesh, MESHLINK_DEBUG, "Could not read directory %s: %s\n", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return 0;
	}

	errno = 0;
	size_t count = 0;
	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(strlen(ent->d_name) != 24) {
			continue;
		}

		char invname[PATH_MAX];
		struct stat st;

		if(snprintf(invname, sizeof(invname), "%s" SLASH "%s", path, ent->d_name) >= PATH_MAX) {
			logger(mesh, MESHLINK_DEBUG, "Filename too long: %s" SLASH "%s", path, ent->d_name);
			continue;
		}

		if(!stat(invname, &st)) {
			if(mesh->invitation_key && deadline < st.st_mtime) {
				count++;
			} else {
				unlink(invname);
			}
		} else {
			logger(mesh, MESHLINK_DEBUG, "Could not stat %s: %s\n", invname, strerror(errno));
			errno = 0;
		}
	}

	if(errno) {
		logger(mesh, MESHLINK_DEBUG, "Error while reading directory %s: %s\n", path, strerror(errno));
		closedir(dir);
		meshlink_errno = MESHLINK_ESTORAGE;
		return 0;
	}

	closedir(dir);

	return count;
}

/// Purge invitations for the given node
size_t invitation_purge_node(meshlink_handle_t *mesh, const char *node_name) {
	if(!mesh->confbase) {
		return true;
	}

	char path[PATH_MAX];
	make_invitation_path(mesh, "current", "", path, sizeof(path));

	DIR *dir = opendir(path);

	if(!dir) {
		logger(mesh, MESHLINK_DEBUG, "Could not read directory %s: %s\n", path, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return 0;
	}

	errno = 0;
	size_t count = 0;
	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(strlen(ent->d_name) != 24) {
			continue;
		}

		char invname[PATH_MAX];

		if(snprintf(invname, sizeof(invname), "%s" SLASH "%s", path, ent->d_name) >= PATH_MAX) {
			logger(mesh, MESHLINK_DEBUG, "Filename too long: %s" SLASH "%s", path, ent->d_name);
			continue;
		}

		FILE *f = fopen(invname, "r");

		if(!f) {
			errno = 0;
			continue;
		}

		config_t config;

		if(!config_read_file(mesh, f, &config, mesh->config_key)) {
			logger(mesh, MESHLINK_ERROR, "Failed to read `%s': %s", invname, strerror(errno));
			config_free(&config);
			fclose(f);
			errno = 0;
			continue;
		}

		packmsg_input_t in = {config.buf, config.len};
		packmsg_get_uint32(&in); // skip version
		char *name = packmsg_get_str_dup(&in);

		if(name && !strcmp(name, node_name)) {
			logger(mesh, MESHLINK_DEBUG, "Removing invitation for %s", node_name);
			unlink(invname);
		}

		free(name);
		config_free(&config);
		fclose(f);
	}

	if(errno) {
		logger(mesh, MESHLINK_DEBUG, "Error while reading directory %s: %s\n", path, strerror(errno));
		closedir(dir);
		meshlink_errno = MESHLINK_ESTORAGE;
		return 0;
	}

	closedir(dir);

	return count;
}
