#ifdef NDEBUG
#undef NDEBUG
#endif

#include "meshlink_internal.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>

#include "devtools.h"
#include "node.h"
#include "chacha-poly1305/chacha-poly1305.h"
#include "conf.h"
#include "utils.h"

static unsigned native_log_messages;

static void native_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *message) {
	(void)mesh;
	(void)level;
	(void)message;
	native_log_messages++;
}

static void check_record(const char *path, const config_t *expected, const void *key) {
	config_t actual = {0};
	assert(config_read_path(path, &actual, key));
	assert(actual.len == expected->len);
	assert(!memcmp(actual.buf, expected->buf, actual.len));
	config_free(&actual);
}

static void test_native_durability(void) {
	const char *path = "encrypted_native_conf/record";
	const char *temporary = "encrypted_native_conf/.record.tmp";
	const uint8_t key[CHACHA_POLY1305_KEYLEN] = {0x42};
	const config_t before = {(const uint8_t *)"before", 6};
	const config_t after = {(const uint8_t *)"after", 5};
	assert(!mkdir("encrypted_native_conf", 0700) || errno == EEXIST);
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, native_log_cb);

	for(unsigned encrypted = 0; encrypted < 2; encrypted++) {
		const void *storage_key = encrypted ? key : NULL;
		assert(config_write_path(path, &before, storage_key));
		check_record(path, &before, storage_key);

		for(config_fault_t fault = CONFIG_FAULT_WRITE; fault <= CONFIG_FAULT_DIR_SYNC; fault++) {
			assert(config_write_path(path, &before, storage_key));
			config_fault_inject(fault, 1);
			assert(!config_write_path(path, &after, storage_key));
			assert(errno == EIO);
			config_fault_inject(CONFIG_FAULT_NONE, 0);
			/* Rename is the visibility boundary; directory sync is the commit boundary. */
			check_record(path, fault == CONFIG_FAULT_DIR_SYNC ? &after : &before, storage_key);
			assert(access(temporary, F_OK) && errno == ENOENT);
			assert(config_write_path(path, &after, storage_key));
			check_record(path, &after, storage_key);
			assert(access(temporary, F_OK) && errno == ENOENT);
		}
	}

	/* Corrupt optional ciphertext is a quiet cache miss with an empty result. */
	const config_t malformed = {key, sizeof(key)};
	assert(config_write_path(path, &malformed, NULL));
	config_t invalid = {0};
	assert(!config_read_path(path, &invalid, key));
	assert(!invalid.buf && !invalid.len);
	assert(!native_log_messages);
	assert(!unlink(path));
	assert(!rmdir("encrypted_native_conf"));
}

static const char activation_base[] = "encrypted_activation_conf";
static unsigned activation_fault;

static void activation_probe(int stage) {
	if((activation_fault == 1 && stage == 2) || (activation_fault == 2 && stage == 3)) {
		config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	} else if(activation_fault == 3 && stage == 2) {
		config_fault_inject(CONFIG_FAULT_RENAME, 2);
	} else if(activation_fault == 4 && stage == 3) {
		config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	} else if(activation_fault == 4 && stage == -3) {
		config_fault_inject(CONFIG_FAULT_RENAME, 1);
	}
}

static void test_activation(void) {
	meshlink_handle_t mesh = {.confbase = (char *)activation_base};
	const config_t old = {(const uint8_t *)"old", 3};
	const config_t replacement = {(const uint8_t *)"new", 3};
	const config_active_t expected[] = {CONFIG_ACTIVE_NEW, CONFIG_ACTIVE_OLD, CONFIG_ACTIVE_OLD, CONFIG_ACTIVE_NONE, CONFIG_ACTIVE_NEW};
	assert(!mkdir(activation_base, 0700) || errno == EEXIST);

	for(activation_fault = 0; activation_fault < sizeof(expected) / sizeof(*expected); activation_fault++) {
		assert(config_destroy(activation_base, "current"));
		assert(config_destroy(activation_base, "old"));
		assert(config_destroy(activation_base, "new"));
		assert(config_init(&mesh, "current"));
		assert(config_init(&mesh, "new"));
		assert(config_write_path("encrypted_activation_conf/current/marker", &old, NULL));
		assert(config_write_path("encrypted_activation_conf/new/marker", &replacement, NULL));
		config_active_t active;
		assert(config_activate(&mesh, &active, activation_probe) == !activation_fault);
		assert(active == expected[activation_fault]);
		config_fault_inject(CONFIG_FAULT_NONE, 0);

		if(active == CONFIG_ACTIVE_NONE) {
			assert(access("encrypted_activation_conf/current", F_OK) && errno == ENOENT);
		} else {
			check_record("encrypted_activation_conf/current/marker", active == CONFIG_ACTIVE_NEW ? &replacement : &old, NULL);
		}
	}

	assert(config_destroy(activation_base, "current"));
	assert(config_destroy(activation_base, "old"));
	assert(config_destroy(activation_base, "new"));
	assert(!rmdir(activation_base));
}

static void test_optional_cache_directory(void) {
	meshlink_handle_t mesh = {.confbase = (char *)activation_base};
	const config_t record = {(const uint8_t *)"cache", 5};
	const char *cache = "encrypted_activation_conf/current/path-cache/peer";
	assert(!mkdir(activation_base, 0700));
	assert(config_init(&mesh, "current"));
	assert(!rmdir("encrypted_activation_conf/current/path-cache"));
	assert(config_sync(&mesh, "current"));

	// A failed cache-directory sync must be retried even if mkdir already worked.
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	assert(!config_write_path(cache, &record, NULL));
	assert(access(cache, F_OK) && errno == ENOENT);
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	assert(!config_write_path(cache, &record, NULL));
	assert(access(cache, F_OK) && errno == ENOENT);
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	assert(config_write_path(cache, &record, NULL));
	check_record(cache, &record, NULL);
	assert(!rmdir("encrypted_activation_conf/current/hosts"));
	assert(!config_sync(&mesh, "current"));
	assert(config_destroy(activation_base, "current"));
	assert(!config_write_path(cache, &record, NULL));
	assert(access("encrypted_activation_conf/current", F_OK) && errno == ENOENT);
	assert(!rmdir(activation_base));
}

static int rotation_fault_stage;

static void rotation_fault_probe(int stage) {
	if(stage == rotation_fault_stage || (rotation_fault_stage == 5 && stage == 3)) {
		config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	} else if(rotation_fault_stage == 5 && stage == -3) {
		config_fault_inject(CONFIG_FAULT_RENAME, 1);
	}
}

static void test_rotation_failure_writes(void) {
	void (*previous_probe)(int) = devtool_keyrotate_probe;

	for(rotation_fault_stage = 2; rotation_fault_stage <= 5; rotation_fault_stage++) {
		assert(meshlink_destroy("encrypted_rotation_fault_conf"));
		meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_rotation_fault_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "old", 3);
		assert(mesh);
		devtool_keyrotate_probe = rotation_fault_probe;
		assert(!meshlink_encrypted_key_rotate(mesh, "new", 3));
		assert(meshlink_errno == MESHLINK_ESTORAGE);
		devtool_keyrotate_probe = previous_probe;
		config_fault_inject(CONFIG_FAULT_NONE, 0);
		assert(meshlink_set_canonical_address(mesh, meshlink_get_self(mesh), "after.example", "443"));
		meshlink_close(mesh);
		const char *key = rotation_fault_stage >= 4 ? "new" : "old";
		mesh = meshlink_open_encrypted("encrypted_rotation_fault_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, key, 3);
		assert(mesh && mesh->self->canonical_address);
		assert(!strcmp(mesh->self->canonical_address, "after.example 443"));
		meshlink_close(mesh);
		assert(meshlink_destroy("encrypted_rotation_fault_conf"));
	}
}

static meshlink_handle_t *open_recovery(bool encrypted) {
	return encrypted ? meshlink_open_encrypted("encrypted_recovery_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "same", 4)
	       : meshlink_open("encrypted_recovery_conf", "foo", "encrypted", DEV_CLASS_BACKBONE);
}

static void test_recovery(void) {
	for(unsigned encrypted = 0; encrypted < 2; encrypted++) {
		assert(meshlink_destroy("encrypted_recovery_conf"));
		meshlink_handle_t *mesh = open_recovery(encrypted);
		assert(mesh);
		meshlink_close(mesh);
		config_t host = {0};
		assert(config_read_path("encrypted_recovery_conf/current/hosts/foo", &host, NULL));
		assert(!unlink("encrypted_recovery_conf/current/meshlink.conf"));
		assert(!open_recovery(encrypted));
		assert(access("encrypted_recovery_conf/current/meshlink.conf", F_OK) && errno == ENOENT);
		check_record("encrypted_recovery_conf/current/hosts/foo", &host, NULL);
		config_free(&host);
		assert(meshlink_destroy("encrypted_recovery_conf"));
		mesh = open_recovery(encrypted);
		assert(mesh);
		assert(meshlink_set_canonical_address(mesh, meshlink_get_self(mesh), "old.example", "443"));
		assert(config_copy(mesh, "current", mesh->config_key, "old", mesh->config_key));
		assert(meshlink_set_canonical_address(mesh, meshlink_get_self(mesh), "new.example", "443"));
		assert(config_copy(mesh, "current", mesh->config_key, "new", mesh->config_key));
		meshlink_close(mesh);
		assert(config_destroy("encrypted_recovery_conf", "current"));

		// An operational recovery error must preserve backups and refuse fresh setup.
		config_fault_inject(CONFIG_FAULT_RENAME, 1);
		assert(!open_recovery(encrypted));
		config_fault_inject(CONFIG_FAULT_NONE, 0);
		assert(!access("encrypted_recovery_conf/old/meshlink.conf", F_OK));
		assert(access("encrypted_recovery_conf/current", F_OK) && errno == ENOENT);
		mesh = open_recovery(encrypted);
		assert(mesh && mesh->self->canonical_address);
		assert(!strcmp(mesh->self->canonical_address, "old.example 443"));
		meshlink_close(mesh);

		// Unreadable authoritative recovery data is an error, not an empty store.
		char confbase[] = "encrypted_recovery_conf";
		meshlink_handle_t location = {.confbase = confbase};
		assert(config_rename(&location, "current", "old"));
		const config_t malformed = {(const uint8_t *)"bad", 3};
		assert(config_write_path("encrypted_recovery_conf/old/meshlink.conf", &malformed, NULL));
		assert(!open_recovery(encrypted));
		assert(access("encrypted_recovery_conf/current", F_OK) && errno == ENOENT);
		check_record("encrypted_recovery_conf/old/meshlink.conf", &malformed, NULL);
		assert(meshlink_destroy("encrypted_recovery_conf"));
	}
}

int main(void) {
	test_native_durability();
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	test_activation();
	test_optional_cache_directory();
	test_rotation_failure_writes();
	test_recovery();

	// Open a new meshlink instance.

	assert(meshlink_destroy("encrypted_conf"));
	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "right", 5);
	assert(mesh);

	// Close the mesh and open it again, now with a different key.

	meshlink_close(mesh);

	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "wrong", 5);
	assert(!mesh);

	// Open it again, now with the right key.

	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "right", 5);
	assert(mesh);

	// That's it.

	meshlink_close(mesh);

	// Destroy the mesh.

	assert(meshlink_destroy("encrypted_conf"));

	DIR *dir = opendir("encrypted_conf");
	assert(dir);
	struct dirent *ent;

	while((ent = readdir(dir))) {
		fprintf(stderr, "%s\n", ent->d_name);
		assert(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."));
	}

	closedir(dir);
}
