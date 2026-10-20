#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include <assert.h>

#include "meshlink_internal.h"
#include "node.h"
#include "chacha-poly1305/chacha-poly1305.h"
#include "ecdsa.h"
#include "net.h"
#include "../src/utils.h"
#include "node_storage.h"
#include "node-storage-tests.h"
#include "netutl.h"
#include "packmsg.h"
#include "path_plpmtu.h"
#include "submesh.h"

typedef struct cached_values {
	sockaddr_t recent[MAX_RECENT];
	address_source_t sources[MAX_RECENT];
	path_cap_t caps[MAX_RECENT];
	path_mtu_cache_entry_t mtu[PATH_MTU_CACHE_ENTRIES];
} cached_values_t;

static const char *storage_conf = "node_storage_conf";
static const char *storage_core = "node_storage_conf/current/hosts/peer";
static const char *storage_cache = "node_storage_conf/current/path-cache/peer";
static const time_t storage_seen = 1700000000;

static meshlink_handle_t *storage_open(dev_class_t role) {
	meshlink_handle_t *mesh = meshlink_open(storage_conf, "owner", "node-storage", role);
	assert(mesh);
	return mesh;
}

static node_t *storage_peer(meshlink_handle_t *mesh) {
	node_t *peer = (node_t *)meshlink_get_node(mesh, "peer");
	assert(peer);
	return peer;
}

static config_t storage_read(const char *path) {
	config_t config = {0};
	assert(config_read_path(path, &config, NULL));
	return config;
}

static void check_core(const config_t *config, time_t seen, uint8_t incarnation[16]) {
	packmsg_input_t in = {config->buf, config->len};
	assert(packmsg_get_array(&in) == 10);
	assert(packmsg_get_uint32(&in) == 1);
	char *name = packmsg_get_str_dup(&in);
	assert(name && !strcmp(name, "peer"));
	free(name);
	const void *id = NULL;
	assert(packmsg_get_bin_raw(&in, &id) == 16);
	assert(memcmp(id, (uint8_t[16]) {0}, 16));
	memcpy(incarnation, id, 16);
	packmsg_skip_element(&in); // Submesh.
	assert(packmsg_get_int32(&in) == DEV_CLASS_BACKBONE);
	assert(!packmsg_get_bool(&in));
	const void *key = NULL;
	assert(packmsg_get_bin_raw(&in, &key) == 32);
	packmsg_skip_element(&in); // Canonical hostname and port.
	assert(packmsg_get_int64(&in) == seen);
	assert(packmsg_get_int64(&in) == (seen ? storage_seen + 10 : 0));
	assert(packmsg_done(&in));
}

static void check_cache_schema(const config_t *config, unsigned endpoints) {
	packmsg_input_t in = {config->buf, config->len};
	assert(packmsg_get_array(&in) == 7);
	assert(packmsg_get_uint32(&in) == 1);
	char *name = packmsg_get_str_dup(&in);
	assert(name && !strcmp(name, "peer"));
	free(name);
	const void *binding = NULL;
	assert(packmsg_get_bin_raw(&in, &binding) == 16);
	assert(packmsg_get_bin_raw(&in, &binding) == 32);
	assert(packmsg_get_bin_raw(&in, &binding) == 32);
	assert(packmsg_get_array(&in) == endpoints);

	for(unsigned i = 0; i < endpoints; i++) {
		assert(packmsg_get_array(&in) == 3);
		packmsg_skip_element(&in);
		packmsg_skip_element(&in);
		packmsg_skip_element(&in);
	}

	assert(packmsg_get_array(&in) == PATH_MTU_CACHE_ENTRIES);

	for(unsigned i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		assert(packmsg_get_array(&in) == 8);

		for(unsigned field = 0; field < 8; field++) {
			packmsg_skip_element(&in);
		}
	}

	assert(packmsg_done(&in));
}

static void seed_cache(node_t *peer) {
	memset(peer->recent, 0, sizeof peer->recent);
	memset(peer->recent_source, 0, sizeof peer->recent_source);
	memset(peer->recent_cap, 0, sizeof peer->recent_cap);

	for(unsigned i = 0; i < MAX_RECENT; i++) {
		peer->recent[i].in.sin_family = AF_INET;
		peer->recent[i].in.sin_port = htons(9000 + i);
		peer->recent[i].in.sin_addr.s_addr = htonl(0xc6336401 + i);
		peer->recent_source[i] = i % 2 ? ADDR_SRC_UDP_REFLEXIVE : ADDR_SRC_AUTH_DIRECT;
		peer->recent_cap[i] = i % 2 ? PATH_CAP_UDP : PATH_CAP_BOTH;
	}

	for(unsigned i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		path_mtu_cache_entry_t *entry = &peer->mtu_cache[i];
		memset(entry, 0, sizeof *entry);
		entry->family = i % 2 ? AF_INET6 : AF_INET;
		assert(inet_pton(entry->family, i % 2 ? "2001:db8::1" : "198.51.100.1", entry->addr) == 1);
		entry->addr[i % 2 ? 15 : 3] += i;
		entry->size = 1200 + i * 20;
		entry->largest_failed = 1400 + i;
		entry->flags = PATH_MTU_CACHE_KEEPALIVE_V2 | PATH_MTU_CACHE_HOSTILE;
		entry->raise_backoff = i + 1;
		entry->keepalive_ms = 15000 + i * 1000;
		entry->updated_at = storage_seen + i;
		entry->net_fp = 100 + i;
	}

	node_storage_mark(peer, NODE_STORAGE_ENDPOINTS | NODE_STORAGE_PATH_HISTORY);
}

static void check_cache_roundtrip(const node_t *peer, const cached_values_t *expected, bool endpoints) {
	for(unsigned i = 0; i < MAX_RECENT; i++) {
		if(endpoints) {
			assert(!sockaddrcmp(&peer->recent[i], &expected->recent[i]));
			assert(peer->recent_source[i] == expected->sources[i]);
			assert(peer->recent_cap[i] == expected->caps[i]);
		} else {
			assert(!peer->recent[i].sa.sa_family);
		}
	}

	for(unsigned i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		const path_mtu_cache_entry_t *actual = &peer->mtu_cache[i], *saved = &expected->mtu[i];
		assert(actual->family == saved->family);
		assert(!memcmp(actual->addr, saved->addr, actual->family == AF_INET6 ? 16 : 4));
		assert(actual->size == saved->size && actual->largest_failed == saved->largest_failed);
		assert(actual->flags == saved->flags && actual->raise_backoff == saved->raise_backoff);
		assert(actual->keepalive_ms == saved->keepalive_ms && actual->updated_at == saved->updated_at);
		assert(actual->net_fp == saved->net_fp);
	}
	/* Disk hints cannot restore runtime path or presence authority. */
	assert(!peer->status.udp_confirmed && !peer->lan_presence.last_discovered_at);
	assert(!peer->relay_hop.confirmed && !peer->lan_auth_direct_until);
}

static void check_cache_miss(time_t seen) {
	meshlink_handle_t *mesh = storage_open(DEV_CLASS_PORTABLE);
	node_t *peer = storage_peer(mesh);
	assert(peer->last_reachable == seen && peer->last_unreachable == storage_seen + 10);
	assert(!peer->recent[0].sa.sa_family && !peer->mtu_cache[0].family);
	meshlink_close(mesh);
}

/* Append an embedded NUL inside a short serialized string, retaining its
   previous C-string prefix and a structurally valid surrounding record. */
static void insert_string_nul(const config_t *record, uint8_t *damaged, unsigned field) {
	packmsg_input_t in = {damaged, record->len};
	packmsg_get_array(&in);
	for(unsigned i = 0; i < field; i++) {
		packmsg_skip_element(&in);
	}
	size_t header = in.ptr - damaged;
	const char *raw = NULL;
	unsigned len = packmsg_get_str_raw(&in, &raw);
	assert(packmsg_input_ok(&in) && len < 31 && damaged[header] == 0xa0 + len);
	size_t end = in.ptr - damaged;
	memmove(damaged + end + 1, damaged + end, record->len - end);
	damaged[end] = 0;
	damaged[header]++;
}

static void test_cache_damage(const config_t *cache, time_t seen) {
	assert(!unlink(storage_cache));
	check_cache_miss(seen);
	uint8_t *damaged = malloc(cache->len + 1);
	assert(damaged);

	for(unsigned corruption = 0; corruption < 11; corruption++) {
		memcpy(damaged, cache->buf, cache->len);
		config_t altered = {damaged, cache->len};

		if(corruption < 3) {
			if(corruption == 0) {
				damaged[1] = 2; // Unsupported local cache version.
			} else if(corruption == 1) {
				altered.len--;
			} else {
				damaged[cache->len] = 0;
				altered.len++;
			}
		} else if(corruption < 6) {
			packmsg_input_t in = {damaged, cache->len};
			packmsg_get_array(&in);
			packmsg_skip_element(&in);
			packmsg_skip_element(&in);
			const void *binding = NULL;

			for(unsigned field = 2; field < corruption; field++) {
				packmsg_get_bin_raw(&in, &binding);
			}

			assert(binding);
			damaged[(const uint8_t *)binding - damaged] ^= 1; // Incarnation, local key, peer key.
		} else if(corruption == 6) {
			damaged[0] = 0x98; // Extra top-level array element.
		} else if(corruption == 10) {
			insert_string_nul(cache, damaged, 1);
			altered.len++;
		} else if(corruption >= 8) {
			packmsg_input_t in = {damaged, cache->len};
			packmsg_get_array(&in);

			for(unsigned field = 0; field < 5; field++) {
				packmsg_skip_element(&in);
			}

			if(corruption == 9) {
				packmsg_skip_object(&in); // Skip the complete endpoint collection.
			}

			assert(packmsg_input_ok(&in));
			damaged[in.ptr - damaged] = corruption == 8 ? 0x96 : 0x95; // Exceed the 5/4 bounds.
		}

		const uint8_t wrong_key[CHACHA_POLY1305_KEYLEN] = {7};
		assert(config_write_path(storage_cache, &altered, corruption == 7 ? wrong_key : NULL));
		check_cache_miss(seen);
	}

	free(damaged);
	assert(config_write_path(storage_cache, cache, NULL));
}

static void test_core_damage(const config_t *core) {
	uint8_t *damaged = malloc(core->len + 1);
	assert(damaged);

	for(unsigned corruption = 0; corruption < 7; corruption++) {
		memcpy(damaged, core->buf, core->len);
		config_t altered = {damaged, core->len};

		switch(corruption) {
		case 0: damaged[1] = 2; break;
		case 1: altered.len--; break;
		case 2: damaged[0] = 0x9b; break;
		case 3: damaged[core->len] = 0; altered.len++; break;
		default: insert_string_nul(core, damaged, corruption == 4 ? 1 : corruption == 5 ? 3 : 7); altered.len++; break;
		}

		assert(config_write_path(storage_core, &altered, NULL));
		assert(!meshlink_open(storage_conf, "owner", "node-storage", DEV_CLASS_PORTABLE));
		assert(meshlink_errno == MESHLINK_ESTORAGE);
	}

	free(damaged);
	assert(config_write_path(storage_core, core, NULL));
}

static meshlink_handle_t *regression_open(const char *conf, const char *exported) {
	assert(meshlink_destroy(conf));
	meshlink_handle_t *mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh && meshlink_import(mesh, exported));
	node_t *peer = storage_peer(mesh);
	peer->last_reachable = storage_seen;
	node_storage_mark(peer, NODE_STORAGE_EDGE);
	seed_cache(peer);
	assert(node_storage_flush(mesh));
	return mesh;
}

static void check_disk_canonical(meshlink_handle_t *mesh, const char *expected) {
	config_t config = {0};
	assert(config_read(mesh, "current", "peer", &config, NULL));
	packmsg_input_t in = {config.buf, config.len};
	assert(packmsg_get_array(&in) == 10);

	for(unsigned field = 0; field < 7; field++) {
		packmsg_skip_element(&in);
	}

	char *canonical = packmsg_get_str_dup(&in);
	assert(canonical && !strcmp(canonical, expected));
	free(canonical);
	config_free(&config);
}

static void test_identical_config_retry(const char *exported) {
	const char *conf = "node_storage_identical_retry";
	meshlink_handle_t *mesh = regression_open(conf, exported);
	node_t *peer = storage_peer(mesh);

	for(unsigned operation = 0; operation < 4; operation++) {
		if(operation == 1) {
			assert(meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.8", "1234"));
		}
		config_fault_inject(CONFIG_FAULT_WRITE, 1);
		meshlink_errno = MESHLINK_OK;
		bool result;
		switch(operation) {
		case 0: result = meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.7", "1234"); break;
		case 1: result = meshlink_clear_canonical_address(mesh, (meshlink_node_t *)peer); break;
		case 2: result = meshlink_blacklist(mesh, (meshlink_node_t *)peer); break;
		default: result = meshlink_whitelist(mesh, (meshlink_node_t *)peer); break;
		}
		assert(!result && meshlink_errno == MESHLINK_ESTORAGE);
		config_fault_inject(CONFIG_FAULT_NONE, 0);
		switch(operation) {
		case 0: result = meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.7", "1234"); break;
		case 1: result = meshlink_clear_canonical_address(mesh, (meshlink_node_t *)peer); break;
		case 2: result = meshlink_blacklist(mesh, (meshlink_node_t *)peer); break;
		default: result = meshlink_whitelist(mesh, (meshlink_node_t *)peer); break;
		}
		assert(result);
		/* Prevent close from hiding an ineffective explicit retry. */
		meshlink_set_storage_policy(mesh, MESHLINK_STORAGE_DISABLED);
		meshlink_close(mesh);
		mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
		assert(mesh);
		peer = storage_peer(mesh);
		assert(peer->status.blacklisted == (operation == 2));
		assert(operation ? !peer->canonical_address : !strcmp(peer->canonical_address, "203.0.113.7 1234"));
	}

	/* Repeated config calls cannot turn a new observation into a checkpoint. */
	peer->last_reachable += 120;
	node_storage_mark(peer, NODE_STORAGE_OBSERVATION);
	node_storage_stats_t before, after;
	node_storage_get_stats(mesh, &before);
	assert(meshlink_clear_canonical_address(mesh, (meshlink_node_t *)peer));
	assert(meshlink_whitelist(mesh, (meshlink_node_t *)peer));
	node_storage_get_stats(mesh, &after);
	assert(before.core_writes == after.core_writes);

	/* A background acknowledgment must not discard deferred self publication. */
	config_fault_inject(CONFIG_FAULT_WRITE, 1);
	assert(!meshlink_set_canonical_address(mesh, meshlink_get_self(mesh), "203.0.113.9", "1234"));
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	assert(mesh->canonical_update_pending);
	assert(node_storage_flush(mesh));
	assert(mesh->canonical_update_pending);
	node_storage_get_stats(mesh, &before);
	assert(meshlink_set_canonical_address(mesh, meshlink_get_self(mesh), "203.0.113.9", "1234"));
	assert(!mesh->canonical_update_pending);
	node_storage_get_stats(mesh, &after);
	assert(before.core_writes == after.core_writes);
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
}

static void test_suppressed_configuration(const char *exported) {
	const char *conf = "node_storage_suppressed";
	meshlink_handle_t *remote = meshlink_open_ephemeral("suppressed", "node-storage", DEV_CLASS_PORTABLE);
	assert(remote);
	char *additional = meshlink_export(remote);
	assert(additional);
	meshlink_close(remote);
	for(unsigned keys_only = 0; keys_only < 2; keys_only++) {
		meshlink_handle_t *mesh = regression_open(conf, exported);
		node_t *peer = storage_peer(mesh);
		meshlink_set_storage_policy(mesh, keys_only ? MESHLINK_STORAGE_KEYS_ONLY : MESHLINK_STORAGE_DISABLED);
		node_storage_stats_t before, after;
		node_storage_get_stats(mesh, &before);
		assert(meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.44", "443"));
		assert(meshlink_import(mesh, additional));
		node_storage_get_stats(mesh, &after);
		assert(after.core_writes == before.core_writes + keys_only);
		assert(after.cache_writes == before.cache_writes);
		meshlink_set_storage_policy(mesh, MESHLINK_STORAGE_ENABLED);
		assert(node_storage_flush(mesh));
		meshlink_set_storage_policy(mesh, MESHLINK_STORAGE_DISABLED);
		meshlink_close(mesh);
		mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
		assert(mesh && meshlink_get_node(mesh, "suppressed"));
		peer = storage_peer(mesh);
		assert(peer->canonical_address && !strcmp(peer->canonical_address, "203.0.113.44 443"));
		meshlink_close(mesh);
		assert(meshlink_destroy(conf));
	}
	free(additional);
}

static void test_uncertain_writes(const char *exported) {
	const char *conf = "node_storage_uncertain";
	const char *cache_path = "node_storage_uncertain/current/path-cache/peer";
	meshlink_handle_t *mesh = regression_open(conf, exported);
	node_t *peer = storage_peer(mesh);
	assert(meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.1", "1234"));
	time_t checkpoint = node_storage_checkpoint_deadline(peer);
	node_storage_stats_t before, after;
	node_storage_get_stats(mesh, &before);
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	assert(!meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.2", "1234"));
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	check_disk_canonical(mesh, "203.0.113.2 1234");
	node_storage_get_stats(mesh, &after);
	assert(after.errors == before.errors + 1 && after.core_writes == before.core_writes);
	assert(node_storage_checkpoint_deadline(peer) == checkpoint);
	assert(meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.1", "1234"));
	check_disk_canonical(mesh, "203.0.113.1 1234");

	config_t original = storage_read(cache_path);
	checkpoint = node_storage_checkpoint_deadline(peer);
	node_storage_get_stats(mesh, &before);
	peer->mtu_cache[0].keepalive_ms++;
	node_storage_mark(peer, NODE_STORAGE_PATH_HISTORY);
	mesh->loop.now.tv_sec += 6;
	config_fault_inject(CONFIG_FAULT_DIR_SYNC, 1);
	node_storage_tick(mesh, storage_seen);
	node_storage_wait(mesh);
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	node_storage_get_stats(mesh, &after);
	assert(after.errors == before.errors + 1 && after.cache_writes == before.cache_writes);
	assert(after.core_writes == before.core_writes && node_storage_checkpoint_deadline(peer) == checkpoint);
	config_t visible = storage_read(cache_path);
	assert(visible.len != original.len || memcmp(visible.buf, original.buf, visible.len));
	config_free(&visible);
	peer->mtu_cache[0].keepalive_ms--;
	node_storage_mark(peer, NODE_STORAGE_PATH_HISTORY);
	assert(node_storage_flush(mesh));
	visible = storage_read(cache_path);
	assert(visible.len == original.len && !memcmp(visible.buf, original.buf, visible.len));
	config_free(&visible);
	config_free(&original);
	meshlink_close(mesh);
	mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh);
	peer = storage_peer(mesh);
	assert(peer->canonical_address && !strcmp(peer->canonical_address, "203.0.113.1 1234"));
	assert(peer->mtu_cache[0].keepalive_ms == 15000 && peer->last_reachable == storage_seen);
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
}

static void test_parent_path_classification(const char *exported) {
	const char *conf = "node_storage_parent/path-cache/owner_conf";
	assert(!mkdir("node_storage_parent", 0700) || errno == EEXIST);
	assert(!mkdir("node_storage_parent/path-cache", 0700) || errno == EEXIST);
	meshlink_handle_t *mesh = regression_open(conf, exported);
	node_t *peer = storage_peer(mesh);
	node_storage_stats_t before, after;
	node_storage_get_stats(mesh, &before);
	peer->last_reachable += 60;
	node_storage_mark(peer, NODE_STORAGE_CONFIG);
	node_storage_tick(mesh, storage_seen + 60);
	node_storage_wait(mesh);
	node_storage_get_stats(mesh, &after);
	assert(after.core_writes == before.core_writes + 1 && after.cache_writes == before.cache_writes);
	meshlink_close(mesh);
	mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh && storage_peer(mesh)->last_reachable == storage_seen + 60);
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
	assert(!rmdir(conf));
	assert(!rmdir("node_storage_parent/path-cache"));
	assert(!rmdir("node_storage_parent"));
}

static void test_missing_cache_directory(const char *exported) {
	const char *conf = "node_storage_missing_cache";
	meshlink_handle_t *mesh = regression_open(conf, exported);
	meshlink_close(mesh);
	assert(!unlink("node_storage_missing_cache/current/path-cache/peer"));
	assert(!rmdir("node_storage_missing_cache/current/path-cache"));
	mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh);
	node_t *peer = storage_peer(mesh);
	assert(peer->last_reachable == storage_seen && !peer->mtu_cache[0].family);
	assert(meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.3", "1234"));
	seed_cache(peer);
	assert(node_storage_flush(mesh));
	meshlink_close(mesh);
	mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh);
	peer = storage_peer(mesh);
	assert(peer->last_reachable == storage_seen && peer->mtu_cache[0].keepalive_ms == 15000);
	assert(peer->recent[0].in.sin_port == htons(9000));
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
}

static void test_future_cache_stamp(void) {
	const char *conf = "node_storage_future_cache";
	assert(meshlink_destroy(conf));
	meshlink_handle_t *mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh);
	node_t *n = new_node();
	n->name = strdup("peer");
	assert(n->name);
	node_add(mesh, n);
	assert(node_storage_write(mesh, n, false));
	n->mtu_cache[0] = (path_mtu_cache_entry_t) {
		.family = AF_INET, .addr = {203, 0, 113, 9}, .size = 1280, .updated_at = time(NULL) + 86400,
	};
	node_storage_mark(n, NODE_STORAGE_PATH_HISTORY);
	assert(node_storage_flush(mesh));
	meshlink_close(mesh);
	mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh);
	n = (node_t *)meshlink_get_node(mesh, "peer");
	assert(n && !n->mtu_cache[0].family);
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
}

static void test_trust_read_skips_submesh(void) {
	const char *conf = "node_storage_trust_submesh";
	assert(meshlink_destroy(conf));
	meshlink_handle_t *mesh = meshlink_open(conf, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh);
	node_t *n = new_node();
	n->name = strdup("peer");
	assert(n->name);
	node_add(mesh, n);
	char ghost[] = "ghost";
	submesh_t detached = {.name = ghost};
	n->submesh = &detached;
	n->ecdsa = ecdsa_set_public_key(ecdsa_get_public_key(mesh->private_key));
	assert(node_storage_write(mesh, n, true));
	n->submesh = NULL;
	unsigned before = mesh->submeshes->count;
	node_t *probe = new_node();
	probe->name = strdup("peer");
	assert(probe->name);
	assert(node_storage_read_trust(mesh, probe));
	assert(mesh->submeshes->count == before);
	assert(!lookup_submesh(mesh, "ghost"));
	assert(ecdsa_active(probe->ecdsa));
	free_node(probe);
	meshlink_close(mesh);
	assert(meshlink_destroy(conf));
}

static void test_wire_history(meshlink_handle_t *mesh, meshlink_handle_t *remote) {
	remote->self->mtu_cache[0] = (path_mtu_cache_entry_t) {.family = AF_INET, .addr = {203, 0, 113, 90}, .size = 1280, .updated_at = 1700000000};
	config_t wire = {0};
	assert(node_storage_wire_encode(remote, remote->self, &wire));
	node_t *decoded = new_node();
	assert(node_read_from_config(mesh, decoded, &wire));
	assert(!decoded->mtu_cache[0].family && !decoded->last_reachable && !decoded->last_unreachable);
	free_node(decoded);

	// An old-style performance trailer is rejected by the shared import/join
	// decoder, and cannot install path history through a real import.
	uint8_t with_history[8192];
	assert(wire.len < sizeof with_history);
	memcpy(with_history, wire.buf, wire.len);
	packmsg_output_t tail = {with_history + wire.len, sizeof with_history - wire.len};
	path_mtu_cache_pack(remote->self, &tail);
	assert(packmsg_output_ok(&tail));
	config_t malformed = {with_history, wire.len + packmsg_output_size(&tail, with_history + wire.len)};
	decoded = new_node();
	assert(!node_read_from_config(mesh, decoded, &malformed));
	assert(!decoded->mtu_cache[0].family);
	free_node(decoded);
	uint8_t outer[9000];
	packmsg_output_t out = {outer, sizeof outer};
	packmsg_add_array(&out, 1);
	packmsg_add_bin(&out, malformed.buf, malformed.len);
	assert(packmsg_output_ok(&out));
	char exported[12004];
	b64encode_urlsafe(outer, exported, packmsg_output_size(&out, outer));
	assert(!meshlink_import(mesh, exported));
	assert(!meshlink_get_node(mesh, "peer"));
	config_free(&wire);
}

static void test_self_key(void) {
	const char *base = "node_storage_self_key_conf";
	const char *path = "node_storage_self_key_conf/current/hosts/owner";
	assert(meshlink_destroy(base));
	meshlink_handle_t *mesh = meshlink_open(base, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh);
	assert(meshlink_whitelist_by_name(mesh, "keyless"));
	assert(node_storage_write(mesh, (node_t *)meshlink_get_node(mesh, "keyless"), true));
	meshlink_close(mesh);
	config_t original = storage_read(path);
	packmsg_input_t in = {original.buf, original.len};
	assert(packmsg_get_array(&in) == 10);
	for(unsigned i = 0; i < 6; i++) {
		packmsg_skip_element(&in);
	}
	const uint8_t *key_start = in.ptr;
	const void *key = NULL;
	assert(packmsg_get_bin_raw(&in, &key) == 32);
	uint8_t wrong_key[32];
	memcpy(wrong_key, key, sizeof wrong_key);
	wrong_key[0] ^= 1;
	for(unsigned mutation = 0; mutation < 2; mutation++) {
		uint8_t bytes[8192];
		size_t prefix = key_start - original.buf;
		memcpy(bytes, original.buf, prefix);
		packmsg_output_t out = {bytes + prefix, sizeof bytes - prefix};
		packmsg_add_bin(&out, wrong_key, mutation ? 32 : 0);
		size_t key_size = packmsg_output_size(&out, bytes + prefix);
		memcpy(bytes + prefix + key_size, in.ptr, in.len);
		config_t damaged = {bytes, prefix + key_size + in.len};
		assert(config_write_path(path, &damaged, NULL));
		assert(!meshlink_open(base, "owner", "node-storage", DEV_CLASS_PORTABLE));
		assert(meshlink_errno == MESHLINK_ESTORAGE);
	}
	assert(config_write_path(path, &original, NULL));
	config_free(&original);
	mesh = meshlink_open(base, "owner", "node-storage", DEV_CLASS_PORTABLE);
	assert(mesh && meshlink_get_node(mesh, "keyless"));
	assert(!ecdsa_active(((node_t *)meshlink_get_node(mesh, "keyless"))->ecdsa));
	meshlink_close(mesh);
	assert(meshlink_destroy(base));
}

void test_node_storage(void) {
	test_self_key();
	assert(meshlink_destroy(storage_conf));
	meshlink_handle_t *mesh = storage_open(DEV_CLASS_PORTABLE);
	meshlink_handle_t *remote = meshlink_open_ephemeral("peer", "node-storage", DEV_CLASS_BACKBONE);
	assert(remote);
	test_wire_history(mesh, remote);
	/* Import just identity so orphan-rejection assertions have no fresh wire hints. */
	memset(remote->self->recent, 0, sizeof remote->self->recent);
	char *exported = meshlink_export(remote);
	assert(exported && meshlink_import(mesh, exported));
	node_t *peer = storage_peer(mesh);
	peer->last_reachable = storage_seen;
	peer->last_unreachable = storage_seen + 10;
	node_storage_mark(peer, NODE_STORAGE_EDGE);
	seed_cache(peer);
	assert(node_storage_flush(mesh));
	cached_values_t expected;
	memcpy(expected.recent, peer->recent, sizeof expected.recent);
	memcpy(expected.sources, peer->recent_source, sizeof expected.sources);
	memcpy(expected.caps, peer->recent_cap, sizeof expected.caps);
	memcpy(expected.mtu, peer->mtu_cache, sizeof expected.mtu);
	config_t core = storage_read(storage_core), cache = storage_read(storage_cache);
	uint8_t incarnation[16];
	check_core(&core, storage_seen, incarnation);
	check_cache_schema(&cache, MAX_RECENT);
	assert(access("node_storage_conf/current/path-cache/owner", F_OK) && errno == ENOENT);

	node_storage_stats_t before, after;
	node_storage_get_stats(mesh, &before);
	peer->mtu_cache[0].updated_at++;
	node_storage_mark(peer, NODE_STORAGE_PATH_HISTORY);
	assert(node_storage_flush(mesh));
	node_storage_get_stats(mesh, &after);
	assert(after.cache_writes == before.cache_writes && after.core_writes == before.core_writes);
	peer->mtu_cache[0].updated_at--;
	peer->mtu_cache[0].keepalive_ms++;
	node_storage_mark(peer, NODE_STORAGE_PATH_HISTORY);
	assert(node_storage_flush(mesh));
	node_storage_get_stats(mesh, &after);
	assert(after.cache_writes == before.cache_writes + 1 && after.core_writes == before.core_writes);
	expected.mtu[0].keepalive_ms++;
	peer->last_reachable += 120;
	node_storage_mark(peer, NODE_STORAGE_OBSERVATION);
	assert(meshlink_set_canonical_address(mesh, (meshlink_node_t *)peer, "203.0.113.250", "1234"));
	node_storage_get_stats(mesh, &before);
	assert(before.core_writes == after.core_writes + 1 && before.cache_writes == after.cache_writes);
	config_free(&core);
	core = storage_read(storage_core);
	check_core(&core, storage_seen + 120, incarnation);
	config_free(&cache);
	cache = storage_read(storage_cache);
	meshlink_close(mesh);

	mesh = storage_open(DEV_CLASS_PORTABLE);
	peer = storage_peer(mesh);
	check_cache_roundtrip(peer, &expected, true);
	mesh->self->devclass = DEV_CLASS_BACKBONE;
	node_storage_profile_changed(mesh);
	assert(node_storage_flush(mesh));
	/* A storage profile change leaves the useful runtime endpoint order intact. */
	check_cache_roundtrip(peer, &expected, true);
	config_t backbone_cache = storage_read(storage_cache);
	check_cache_schema(&backbone_cache, 0);
	config_free(&backbone_cache);
	meshlink_close(mesh);
	mesh = storage_open(DEV_CLASS_BACKBONE);
	check_cache_roundtrip(storage_peer(mesh), &expected, false);
	meshlink_close(mesh);

	test_cache_damage(&cache, storage_seen + 120);
	test_core_damage(&core);
	mesh = storage_open(DEV_CLASS_PORTABLE);
	assert(meshlink_forget_node(mesh, (meshlink_node_t *)storage_peer(mesh)));
	assert(meshlink_import(mesh, exported));
	/* Simulate an optional cache orphan that survived the authoritative unlink. */
	assert(config_write_path(storage_cache, &cache, NULL));
	meshlink_close(mesh);
	mesh = storage_open(DEV_CLASS_PORTABLE);
	peer = storage_peer(mesh);
	assert(!peer->last_reachable && !peer->last_unreachable);
	assert(!peer->recent[0].sa.sa_family && !peer->mtu_cache[0].family);
	config_t recreated = storage_read(storage_core);
	uint8_t new_incarnation[16];
	check_core(&recreated, 0, new_incarnation);
	assert(memcmp(incarnation, new_incarnation, 16));
	config_free(&recreated);
	meshlink_close(mesh);
	meshlink_close(remote);
	test_uncertain_writes(exported);
	test_identical_config_retry(exported);
	test_suppressed_configuration(exported);
	config_fault_inject(CONFIG_FAULT_SCAN, 1);
	assert(!meshlink_open(storage_conf, "owner", "node-storage", DEV_CLASS_PORTABLE));
	assert(meshlink_errno == MESHLINK_ESTORAGE);
	config_fault_inject(CONFIG_FAULT_NONE, 0);
	test_parent_path_classification(exported);
	test_missing_cache_directory(exported);
	test_future_cache_stamp();
	test_trust_read_skips_submesh();
	free(exported);
	config_free(&cache);
	config_free(&core);
	assert(meshlink_destroy(storage_conf));
}
