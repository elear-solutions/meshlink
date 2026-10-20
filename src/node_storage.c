/*
    node_storage.c -- role-aware local node persistence
    Copyright (C) 2026 Elear Solutions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

/* Local node persistence. Disk records deliberately do not share the wire codec.
   The mesh mutex owns all state here; the writer owns only immutable snapshots. */
#include "system.h"
#include "node_storage.h"
#include "meshlink_internal.h"
#include "node.h"
#include "storage_writer.h"
#include "crypto.h"
#include "chacha-poly1305/chacha-poly1305.h"
#include "ecdsa.h"
#include "logger.h"
#include "netutl.h"
#include "packmsg.h"
#include "path_policy.h"
#include "splay_tree.h"
#include "submesh.h"
#include "utils.h"
#include "xalloc.h"

#define NODE_HOST_VERSION 1
#define NODE_CACHE_VERSION 1
#define NODE_RECORD_SIZE 8192
#define NODE_OBSERVATION_INTERVAL 60
#define NODE_CHECKPOINT_INTERVAL 86400
#define NODE_CHECKPOINT_SPREAD 3600

struct storage_record {
	uint64_t generation, acknowledged, submitted;
	config_t durable;
	time_t retry_at;
	unsigned failures;
	bool uncertain; /* A failed rename/sync may have changed visible bytes. */
};

struct node_storage_state {
	uint8_t incarnation[16];
	struct storage_record core, cache;
	unsigned reasons;
	uint64_t reason_generation[7]; /* Latest mutation of each classified reason. */
	time_t durable_seen, checkpoint_at, cache_at;
	bool retired;
};

struct node_storage_owner {
	storage_writer_owner_t *writer;
	signal_t signal;
	timeout_t retry;
	node_storage_stats_t stats;
	time_t (*clock)(void *);
	void *clock_context;
};

static void owner_init(meshlink_handle_t *mesh);

static time_t wall_now(meshlink_handle_t *mesh) {
	return mesh->storage && mesh->storage->clock ? mesh->storage->clock(mesh->storage->clock_context) : time(NULL);
}

static bool same_config(const config_t *a, const config_t *b) {
	return a->len == b->len && (!a->len || !memcmp(a->buf, b->buf, a->len));
}

static void replace_config(config_t *dest, const config_t *src) {
	config_free(dest);
	if(src->len) {
		uint8_t *buf = xmalloc(src->len);
		memcpy(buf, src->buf, src->len);
		dest->buf = buf;
		dest->len = src->len;
	}
}

void node_storage_init(node_t *n) {

	if(n->storage) {
		return;
	}

	n->storage = xzalloc(sizeof(*n->storage));
	/* The identifier is local to this record lifetime, including name/key reuse. */
	do {
		randomize(n->storage->incarnation, sizeof n->storage->incarnation);
	} while(!memcmp(n->storage->incarnation, (uint8_t[16]) {0}, 16));
}

void node_storage_free(node_t *n) {
	if(!n->storage) {
		return;
	}
	config_free(&n->storage->core.durable);
	config_free(&n->storage->cache.durable);
	free(n->storage);
	n->storage = NULL;
}

void node_storage_mark(node_t *n, node_storage_reason_t reason) {
	if(!n || !n->storage) {
		return;
	}
	struct node_storage_state *s = n->storage;
	if(s->retired) {
		return;
	}
	s->reasons |= reason;
	if(reason & (NODE_STORAGE_KEY_POLICY | NODE_STORAGE_CONFIG | NODE_STORAGE_EDGE | NODE_STORAGE_OBSERVATION)) {
		s->core.generation++;
	}
	if(reason & (NODE_STORAGE_KEY_POLICY | NODE_STORAGE_ENDPOINTS | NODE_STORAGE_PATH_HISTORY | NODE_STORAGE_PROFILE)) {
		bool new_batch = s->cache.generation == s->cache.acknowledged || s->cache.generation == s->cache.submitted;
		s->cache.generation++;
		if(new_batch) {
			s->cache_at = n->mesh ? n->mesh->loop.now.tv_sec + 5 : 0;
		}
	}
	for(unsigned i = 0; i < 7; i++) {
		unsigned bit = 1U << i;
		if(reason & bit) {
			s->reason_generation[i] = bit <= NODE_STORAGE_OBSERVATION ? s->core.generation : s->cache.generation;
		}
	}
}

static bool finish_config(config_t *config, uint8_t *buf, packmsg_output_t *out) {
	if(!packmsg_output_ok(out)) {
		meshlink_errno = MESHLINK_EINTERNAL;
		return false;
	}
	config_t value = {buf, packmsg_output_size(out, buf)};
	replace_config(config, &value);
	return true;
}

static bool core_encode(const node_t *n, config_t *config) {
	uint8_t buf[NODE_RECORD_SIZE];
	packmsg_output_t out = {buf, sizeof buf};
	packmsg_add_array(&out, 10);
	packmsg_add_uint32(&out, NODE_HOST_VERSION);
	packmsg_add_str(&out, n->name);
	packmsg_add_bin(&out, n->storage->incarnation, 16);
	packmsg_add_str(&out, n->submesh ? n->submesh->name : CORE_MESH);
	packmsg_add_int32(&out, n->devclass);
	packmsg_add_bool(&out, n->status.blacklisted);
	packmsg_add_bin(&out, ecdsa_active(n->ecdsa) ? ecdsa_get_public_key(n->ecdsa) : (const void *)"", ecdsa_active(n->ecdsa) ? 32 : 0);
	packmsg_add_str(&out, n->canonical_address ? n->canonical_address : "");
	packmsg_add_int64(&out, n->last_reachable);
	packmsg_add_int64(&out, n->last_unreachable);
	return finish_config(config, buf, &out);
}

static char *get_c_string(packmsg_input_t *in) {
	const char *raw = NULL;
	uint32_t len = packmsg_get_str_raw(in, &raw);
	if(!packmsg_input_ok(in) || (len && memchr(raw, 0, len))) {
		packmsg_input_invalidate(in);
		return NULL;
	}
	char *value = xmalloc((size_t)len + 1);
	memcpy(value, raw, len);
	value[len] = 0;
	return value;
}

static bool core_decode(meshlink_handle_t *mesh, node_t *n, const config_t *config, bool create_submesh) {
	packmsg_input_t in = {config->buf, config->len};
	uint32_t fields = packmsg_get_array(&in);
	uint32_t version = packmsg_get_uint32(&in);
	char *name = get_c_string(&in);
	const void *incarnation = NULL, *key = NULL;
	uint32_t incarnation_len = packmsg_get_bin_raw(&in, &incarnation);
	char *submesh = get_c_string(&in);
	int32_t devclass = packmsg_get_int32(&in);
	bool blacklisted = packmsg_get_bool(&in);
	uint32_t key_len = packmsg_get_bin_raw(&in, &key);
	char *canonical = get_c_string(&in);
	int64_t seen = packmsg_get_int64(&in), unreachable = packmsg_get_int64(&in);
	bool valid = packmsg_done(&in) && fields == 10 && version == NODE_HOST_VERSION && name && n->name && !strcmp(name, n->name)
	             && incarnation_len == 16 && memcmp(incarnation, (uint8_t[16]) {0}, 16) && submesh && canonical
	             && devclass >= 0 && devclass <= DEV_CLASS_UNKNOWN && (key_len == 0 || key_len == 32) && seen >= 0 && unreachable >= 0
	             && (int64_t)(time_t)seen == seen && (int64_t)(time_t)unreachable == unreachable;
	if(valid && n == mesh->self) {
		valid = key_len == 32 && !memcmp(key, ecdsa_get_public_key(mesh->private_key), 32);
	}
	if(!valid) {
		free(name);
		free(submesh);
		free(canonical);
		return false;
	}
	submesh_t *sub = NULL;

	if(strcmp(submesh, CORE_MESH)) {
		sub = create_submesh ? lookup_or_create_submesh(mesh, submesh) : lookup_submesh(mesh, submesh);

		if(create_submesh && !sub) {
			free(name);
			free(submesh);
			free(canonical);
			return false;
		}
	}
	node_storage_init(n);
	memcpy(n->storage->incarnation, incarnation, 16);
	n->submesh = sub;
	/* The configured local role remains authoritative, as in open/join today. */
	if(n != mesh->self) {
		n->devclass = devclass;
	}
	n->status.blacklisted = blacklisted;
	ecdsa_free(n->ecdsa);
	n->ecdsa = key_len ? ecdsa_set_public_key(key) : NULL;
	free(n->canonical_address);
	n->canonical_address = *canonical ? canonical : NULL;
	if(!*canonical) {
		free(canonical);
	}
	n->last_reachable = seen;
	n->last_unreachable = unreachable;
	n->storage->durable_seen = seen;
	replace_config(&n->storage->core.durable, config);
	path_refresh_canonical_endpoint(n);
	free(name);
	free(submesh);
	return true;
}

static bool persist_endpoints(const meshlink_handle_t *mesh) {
	return mesh->self && mesh->self->devclass != DEV_CLASS_BACKBONE;
}

static void cache_pack(const meshlink_handle_t *mesh, const node_t *n, packmsg_output_t *out, bool material, bool endpoints) {
	packmsg_add_array(out, 7);
	packmsg_add_uint32(out, NODE_CACHE_VERSION);
	packmsg_add_str(out, n->name);
	packmsg_add_bin(out, n->storage->incarnation, 16);
	packmsg_add_bin(out, ecdsa_get_public_key(mesh->private_key), 32);
	packmsg_add_bin(out, ecdsa_active(n->ecdsa) ? ecdsa_get_public_key(n->ecdsa) : (const void *)"", ecdsa_active(n->ecdsa) ? 32 : 0);
	unsigned count = 0;
	if(endpoints) {
		while(count < MAX_RECENT && n->recent[count].sa.sa_family) {
			count++;
		}
	}
	packmsg_add_array(out, count);
	for(unsigned i = 0; i < count; i++) {
		packmsg_add_array(out, 3);
		packmsg_add_sockaddr(out, &n->recent[i]);
		packmsg_add_uint8(out, n->recent_source[i]);
		packmsg_add_uint8(out, n->recent_cap[i]);
	}
	count = 0;
	for(unsigned i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		count += n->mtu_cache[i].family != 0;
	}
	packmsg_add_array(out, count);
	for(unsigned i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
		const path_mtu_cache_entry_t *e = &n->mtu_cache[i];
		if(!e->family) {
			continue;
		}
		packmsg_add_array(out, 8);
		packmsg_add_bin(out, e->addr, e->family == AF_INET6 ? 16 : 4);
		packmsg_add_uint16(out, e->size);
		packmsg_add_uint16(out, e->largest_failed);
		packmsg_add_uint8(out, e->flags);
		packmsg_add_uint8(out, e->raise_backoff);
		packmsg_add_uint32(out, e->keepalive_ms);
		packmsg_add_int64(out, material ? 0 : e->updated_at);
		packmsg_add_uint32(out, e->net_fp);
	}
}

static bool cache_encode_projection(const meshlink_handle_t *mesh, const node_t *n, config_t *config, bool material, bool endpoints) {
	uint8_t buf[NODE_RECORD_SIZE];
	packmsg_output_t out = {buf, sizeof buf};
	cache_pack(mesh, n, &out, material, endpoints);
	return finish_config(config, buf, &out);
}

static bool cache_encode(const meshlink_handle_t *mesh, const node_t *n, config_t *config, bool material) {
	return cache_encode_projection(mesh, n, config, material, persist_endpoints(mesh));
}

/* Decode transactionally. Invalid optional data never changes runtime state. */
static bool cache_decode(const meshlink_handle_t *mesh, node_t *n, const config_t *config, bool apply) {
	packmsg_input_t in = {config->buf, config->len};
	uint32_t fields = packmsg_get_array(&in), version = packmsg_get_uint32(&in);
	char *name = get_c_string(&in);
	const void *incarnation = NULL, *local = NULL, *peer = NULL;
	uint32_t ilen = packmsg_get_bin_raw(&in, &incarnation), llen = packmsg_get_bin_raw(&in, &local), plen = packmsg_get_bin_raw(&in, &peer);
	bool valid = fields == 7 && version == NODE_CACHE_VERSION && name && !strcmp(name, n->name)
	             && ilen == 16 && !memcmp(incarnation, n->storage->incarnation, 16)
	             && llen == 32 && !memcmp(local, ecdsa_get_public_key(mesh->private_key), 32)
	             && plen == (ecdsa_active(n->ecdsa) ? 32u : 0u) && (!plen || !memcmp(peer, ecdsa_get_public_key(n->ecdsa), 32));
	free(name);
	if(!valid) {
		return false;
	}
	sockaddr_t recent[MAX_RECENT] = {0};
	address_source_t sources[MAX_RECENT] = {0};
	path_cap_t caps[MAX_RECENT] = {0};
	path_mtu_cache_entry_t entries[PATH_MTU_CACHE_ENTRIES] = {{0}};
	unsigned count = packmsg_get_array(&in);
	if(count > MAX_RECENT) {
		return false;
	}
	for(unsigned i = 0; i < count; i++) {
		valid &= packmsg_get_array(&in) == 3;
		recent[i] = packmsg_get_sockaddr(&in);
		sources[i] = packmsg_get_uint8(&in);
		caps[i] = packmsg_get_uint8(&in);
		valid &= sources[i] <= ADDR_SRC_BACKBONE_PRIVATE && !(caps[i] & ~PATH_CAP_BOTH);
	}
	count = packmsg_get_array(&in);
	if(count > PATH_MTU_CACHE_ENTRIES) {
		return false;
	}
	for(unsigned i = 0; i < count; i++) {
		valid &= packmsg_get_array(&in) == 8;
		const void *addr = NULL;
		unsigned len = packmsg_get_bin_raw(&in, &addr);
		path_mtu_cache_entry_t *e = &entries[i];
		e->family = len == 4 ? AF_INET : len == 16 ? AF_INET6 : 0;
		if(e->family) {
			memcpy(e->addr, addr, len);
		}
		e->size = packmsg_get_uint16(&in);
		e->largest_failed = packmsg_get_uint16(&in);
		e->flags = packmsg_get_uint8(&in);
		e->raise_backoff = packmsg_get_uint8(&in);
		e->keepalive_ms = packmsg_get_uint32(&in);
		e->updated_at = packmsg_get_int64(&in);
		e->net_fp = packmsg_get_uint32(&in);
		time_t decoded_now = time(NULL);
		valid &= e->family && e->size >= MINMTU && e->size <= MTU
		         && (!e->largest_failed || (e->largest_failed > e->size && e->largest_failed <= MTU)) && e->updated_at >= 0
		         && (decoded_now == (time_t)-1 || e->updated_at <= decoded_now);
	}
	if(!valid || !packmsg_done(&in)) {
		return false;
	}
	if(apply) {
		memcpy(n->recent, recent, sizeof recent);
		memcpy(n->recent_source, sources, sizeof sources);
		memcpy(n->recent_cap, caps, sizeof caps);
		memcpy(n->mtu_cache, entries, sizeof entries);

	}
	return true;
}

static bool cache_same_material(meshlink_handle_t *mesh, node_t *n, const config_t *config) {
	if(!config->len) {
		return false;
	}
	node_t saved = {0};
	saved.name = n->name;
	saved.storage = n->storage;
	saved.ecdsa = n->ecdsa;
	if(!cache_decode(mesh, &saved, config, true)) {
		return false;
	}
	config_t old = {0}, current = {0};
	bool result = cache_encode_projection(mesh, &saved, &old, true, true) && cache_encode(mesh, n, &current, true) && same_config(&old, &current);
	config_free(&old);
	config_free(&current);
	return result;
}

time_t node_storage_checkpoint_interval(const node_t *n) {
	uint32_t hash = 2166136261u;
	for(unsigned i = 0; i < 16; i++) {
		hash = (hash ^ n->storage->incarnation[i]) * 16777619u;
	}
	return NODE_CHECKPOINT_INTERVAL - hash % (NODE_CHECKPOINT_SPREAD + 1);
}

static void checkpoint_reset(meshlink_handle_t *mesh, node_t *n, time_t wall_now) {
	struct node_storage_state *s = n->storage;
	time_t interval = node_storage_checkpoint_interval(n);
	double age = s->durable_seen && wall_now != (time_t)-1 ? difftime(wall_now, s->durable_seen) : 0;
	if(age < 0) {
		age = 0;
	}
	s->checkpoint_at = mesh->loop.now.tv_sec + (age >= interval ? 0 : interval - (time_t)age);
}

bool node_storage_read(meshlink_handle_t *mesh, node_t *n) {
	owner_init(mesh);
	/* The local host record is read before setup_network() on open and restart.
	   It can restore a submesh, so make the registry available first. */
	init_submeshes(mesh);
	config_t config = {0};
	if(!config_read(mesh, "current", n->name, &config, mesh->config_key)) {
		mesh->storage_error = true;
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}
	bool result = core_decode(mesh, n, &config, true);
	config_free(&config);
	if(!result) {
		mesh->storage_error = true;
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}
	checkpoint_reset(mesh, n, wall_now(mesh));
	if(n == mesh->self || mesh->storage_policy != MESHLINK_STORAGE_ENABLED) {
		return true;
	}
	if(config_cache_read(mesh, "current", n->name, &config, mesh->config_key) && cache_decode(mesh, n, &config, true)) {
		replace_config(&n->storage->cache.durable, &config);
		if(!persist_endpoints(mesh)) {
			memset(n->recent, 0, sizeof n->recent);
			memset(n->recent_source, 0, sizeof n->recent_source);
			memset(n->recent_cap, 0, sizeof n->recent_cap);
			node_storage_mark(n, NODE_STORAGE_PROFILE);
		}
		path_sanitize_recent(mesh, n);
		if(mesh->storage) {
			mesh->storage->stats.cache_hits++;
		}
	} else if(mesh->storage) {
		mesh->storage->stats.cache_misses++;
	}
	config_free(&config);
	return true;
}

bool node_storage_wire_encode(meshlink_handle_t *mesh, const node_t *n, config_t *config) {
	uint8_t buf[NODE_RECORD_SIZE];
	packmsg_output_t out = {buf, sizeof buf};
	packmsg_add_uint32(&out, MESHLINK_CONFIG_VERSION);
	packmsg_add_str(&out, n->name);
	packmsg_add_str(&out, n->submesh ? n->submesh->name : CORE_MESH);
	packmsg_add_int32(&out, n->devclass);
	packmsg_add_bool(&out, n->status.blacklisted);
	packmsg_add_bin(&out, ecdsa_active(n->ecdsa) ? ecdsa_get_public_key(n->ecdsa) : (const void *)"", ecdsa_active(n->ecdsa) ? 32 : 0);
	if(n == mesh->self && n->canonical_address && !strchr(n->canonical_address, ' ')) {
		char *canonical;
		xasprintf(&canonical, "%s %s", n->canonical_address, mesh->myport);
		packmsg_add_str(&out, canonical);
		free(canonical);
	} else {
		packmsg_add_str(&out, n->canonical_address ? n->canonical_address : "");
	}
	unsigned count = 0;
	while(count < MAX_RECENT && n->recent[count].sa.sa_family) {
		count++;
	}
	packmsg_add_array(&out, count);
	for(unsigned i = 0; i < count; i++) {
		packmsg_add_sockaddr(&out, &n->recent[i]);
	}
	packmsg_add_int64(&out, 0);
	packmsg_add_int64(&out, 0);
	packmsg_add_array(&out, count);
	for(unsigned i = 0; i < count; i++) {
		packmsg_add_uint8(&out, n->recent_source[i]);
	}
	packmsg_add_array(&out, count);
	for(unsigned i = 0; i < count; i++) {
		packmsg_add_uint8(&out, n->recent_cap[i]);
	}
	return finish_config(config, buf, &out);
}

static bool native_write(const char *path, const void *data, size_t len, const void *key, size_t keylen, void *context) {
	(void)context;
	assert(!key || keylen == CHACHA_POLY1305_KEYLEN);
	config_t config = {data, len};
	return config_write_path(path, &config, key);
}

static void writer_notify(void *data) {
	meshlink_handle_t *mesh = data;
	signal_trigger(&mesh->loop, &mesh->storage->signal);
}

static void writer_complete(const storage_writer_completion_t *completion, void *data);

static void writer_signal(event_loop_t *loop, void *data) {
	(void)loop;
	meshlink_handle_t *mesh = data;
	storage_writer_collect(mesh->storage->writer, writer_complete, mesh);
	/* Queue pressure can clear without another five-second timer. */
	node_storage_tick(mesh, wall_now(mesh));
}

static void owner_init(meshlink_handle_t *mesh) {
	if(mesh->storage || !mesh->confbase) {
		return;
	}
	mesh->storage = xzalloc(sizeof(*mesh->storage));
	signal_add(&mesh->loop, &mesh->storage->signal, writer_signal, mesh, 2);
	mesh->storage->writer = storage_writer_owner_open(writer_notify, mesh, native_write, NULL);
}

static bool record_path(meshlink_handle_t *mesh, node_t *n, bool cache, char path[PATH_MAX]) {
	int len = snprintf(path, PATH_MAX, "%s/%s/%s/%s", mesh->confbase, mesh_conf_write_subdir(mesh), cache ? "path-cache" : "hosts", n->name);
	if(len < 0 || len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}
	return true;
}

static unsigned reason_mask(bool cache) {
	return cache ? NODE_STORAGE_ENDPOINTS | NODE_STORAGE_PATH_HISTORY | NODE_STORAGE_PROFILE : NODE_STORAGE_KEY_POLICY | NODE_STORAGE_CONFIG | NODE_STORAGE_EDGE | NODE_STORAGE_OBSERVATION;
}

static void acknowledge(meshlink_handle_t *mesh, node_t *n, bool cache, uint64_t generation, const config_t *config) {
	struct node_storage_state *s = n->storage;
	struct storage_record *r = cache ? &s->cache : &s->core;
	if(generation < r->acknowledged) {
		return;
	}
	r->acknowledged = generation;
	r->failures = 0;
	r->retry_at = 0;
	r->uncertain = false;
	replace_config(&r->durable, config);
	if(!cache) {
		/* Parse only the immutable successful snapshot, never current memory. */
		packmsg_input_t in = {config->buf, config->len};
		packmsg_get_array(&in);
		for(unsigned i = 0; i < 8; i++) {
			packmsg_skip_element(&in);
		}
		s->durable_seen = packmsg_get_int64(&in);
		checkpoint_reset(mesh, n, wall_now(mesh));
	}
	/* A newer observation must not retain already-committed urgent reasons;
	   a newer mutation of the same reason must remain pending. */
	for(unsigned i = 0; i < 7; i++) {
		unsigned bit = 1U << i;
		if((reason_mask(cache) & bit) && s->reason_generation[i] <= generation) {
			s->reasons &= ~bit;
		}
	}
	if(cache) {
		mesh->storage->stats.cache_writes++;
	} else {
		mesh->storage->stats.core_writes++;
	}
}

static void record_failed(meshlink_handle_t *mesh, struct storage_record *r) {
	r->uncertain = true;
	static const unsigned delay[] = {1, 2, 5, 10, 30, 60, 300};
	unsigned i = r->failures < 6 ? r->failures : 6;
	r->retry_at = mesh->loop.now.tv_sec + delay[i];
	if(r->failures < 6) {
		r->failures++;
	}
	if(!mesh->storage->retry.node.data || mesh->storage->retry.tv.tv_sec > r->retry_at) {
		timeout_add(&mesh->loop, &mesh->storage->retry, writer_signal, mesh, &(struct timespec) {delay[i], 0});
	}
	mesh->storage->stats.errors++;
}

static void writer_complete(const storage_writer_completion_t *completion, void *data) {
	meshlink_handle_t *mesh = data;
	const char *name = strrchr(completion->path, '/');
	if(!name || !mesh->nodes) {
		return;
	}
	node_t *n = lookup_node(mesh, name + 1);
	if(!n || !n->storage || n->storage->retired) {
		return;
	}
	const char *parent = name;
	while(parent > completion->path && parent[-1] != '/') {
		parent--;
	}
	bool cache = name - parent == 10 && !memcmp(parent, "path-cache", 10);
	struct storage_record *r = cache ? &n->storage->cache : &n->storage->core;
	/* Name reuse and stale completions cannot acknowledge a new incarnation. */
	config_t config = {completion->data, completion->len};
	packmsg_input_t in = {config.buf, config.len};
	packmsg_get_array(&in);
	packmsg_skip_element(&in);
	packmsg_skip_element(&in);
	const void *incarnation = NULL;
	unsigned ilen = packmsg_get_bin_raw(&in, &incarnation);
	if(ilen != 16 || memcmp(incarnation, n->storage->incarnation, 16) || completion->generation <= r->acknowledged) {
		return;
	}
	if(completion->success) {
		/* A newer failed commit stays uncertain until that generation is rewritten. */
		if(r->uncertain && completion->generation < r->generation) {
			return;
		}

		acknowledge(mesh, n, cache, completion->generation, &config);
	} else {
		r->submitted = 0;
		record_failed(mesh, r);
	}
}

static bool write_record(meshlink_handle_t *mesh, node_t *n, bool cache, bool synchronous) {
	struct node_storage_state *s = n->storage;
	struct storage_record *r = cache ? &s->cache : &s->core;
	if(s->retired || (cache && n == mesh->self)) {
		return true;
	}
	owner_init(mesh);
	config_t config = {0};
	bool encoded = cache ? cache_encode(mesh, n, &config, false) : core_encode(n, &config);
	if(!encoded) {
		return false;
	}
	bool identical = !r->uncertain && (cache ? cache_same_material(mesh, n, &r->durable) : same_config(&config, &r->durable));
	if(cache && !r->durable.len && !r->uncertain) {
		bool useful = persist_endpoints(mesh) && n->recent[0].sa.sa_family;
		for(unsigned i = 0; i < PATH_MTU_CACHE_ENTRIES; i++) {
			useful |= n->mtu_cache[i].family != 0;
		}
		identical = !useful;
	}
	char path[PATH_MAX];
	if(!record_path(mesh, n, cache, path)) {
		config_free(&config);
		return false;
	}
	/* An older queued snapshot must not overwrite a reverted durable value. */
	if(identical && r->submitted <= r->acknowledged) {
		r->acknowledged = r->generation;
		s->reasons &= ~reason_mask(cache);
		mesh->storage->stats.noops++;
		config_free(&config);
		return true;
	}

	if(!synchronous && r->submitted == r->generation) {
		config_free(&config);
		return true;
	}
	bool result;
	if(synchronous) {
		result = storage_writer_commit(mesh->storage->writer, path, config.buf, config.len, mesh->config_key, mesh->config_key ? CHACHA_POLY1305_KEYLEN : 0, r->generation);
		if(result) {
			acknowledge(mesh, n, cache, r->generation, &config);
		} else {
			record_failed(mesh, r);
			meshlink_errno = MESHLINK_ESTORAGE;
		}
	} else {
		result = storage_writer_submit(mesh->storage->writer, path, config.buf, config.len, mesh->config_key, mesh->config_key ? CHACHA_POLY1305_KEYLEN : 0, r->generation);
		if(result) {
			r->submitted = r->generation;
		} else {
			mesh->storage->stats.admission_failures++;
		}
	}
	config_free(&config);
	return result;
}

bool node_storage_retry_config(meshlink_handle_t *mesh, node_t *n, bool new_key) {
	if(mesh->storage_unavailable) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}
	struct storage_record *r = &n->storage->core;
	if(!r->durable.len) {
		return node_storage_write(mesh, n, new_key);
	}
	if(!mesh->confbase || mesh->storage_policy == MESHLINK_STORAGE_DISABLED || (mesh->storage_policy == MESHLINK_STORAGE_KEYS_ONLY && !new_key)) {
		return true;
	}
	config_t current = {0};
	if(!core_encode(n, &current)) {
		return false;
	}
	packmsg_input_t a = {current.buf, current.len};
	packmsg_input_t b = {r->durable.buf, r->durable.len};
	packmsg_get_array(&a);
	packmsg_get_array(&b);
	/* History is deliberately excluded from this explicit-configuration test. */
	for(unsigned i = 0; i < (new_key ? 7U : 8U); i++) {
		packmsg_skip_element(&a);
		packmsg_skip_element(&b);
	}
	size_t alen = current.len - a.len, blen = r->durable.len - b.len;
	bool same = packmsg_input_ok(&b) && alen == blen && !memcmp(current.buf, r->durable.buf, alen);
	config_free(&current);
	unsigned config_reasons = NODE_STORAGE_KEY_POLICY | (new_key ? 0 : NODE_STORAGE_CONFIG);
	bool pending_config = r->submitted > r->acknowledged && (n->storage->reasons & config_reasons);
	if(same && !r->uncertain && !pending_config) {
		return true;
	}
	return node_storage_write(mesh, n, new_key);
}

bool node_storage_write(meshlink_handle_t *mesh, node_t *n, bool new_key) {
	if(mesh->storage_unavailable) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}
	/* A replacement established peer key invalidates history learned under
	   the previous identity before any further path use. */
	if(new_key && n->storage->core.durable.len && ecdsa_active(n->ecdsa)) {
		packmsg_input_t in = {n->storage->core.durable.buf, n->storage->core.durable.len};
		packmsg_get_array(&in);
		for(unsigned i = 0; i < 6; i++) {
			packmsg_skip_element(&in);
		}
		const void *key = NULL;
		unsigned len = packmsg_get_bin_raw(&in, &key);
		if(len == 32 && memcmp(key, ecdsa_get_public_key(n->ecdsa), 32)) {
			memset(n->recent, 0, sizeof n->recent);
			memset(n->recent_source, 0, sizeof n->recent_source);
			memset(n->recent_cap, 0, sizeof n->recent_cap);
			memset(n->mtu_cache, 0, sizeof n->mtu_cache);
			node_storage_mark(n, NODE_STORAGE_PROFILE);
		}
	}
	node_storage_mark(n, new_key ? NODE_STORAGE_KEY_POLICY : NODE_STORAGE_CONFIG);
	if(!mesh->confbase || mesh->storage_policy == MESHLINK_STORAGE_DISABLED || (mesh->storage_policy == MESHLINK_STORAGE_KEYS_ONLY && !new_key)) {
		return true;
	}
	return write_record(mesh, n, false, true);
}

bool node_storage_note_edge(meshlink_handle_t *mesh, node_t *n, bool reachable, time_t now) {
	time_t previous = n->last_reachable;
	if(now >= 0 && now != (time_t)-1) {
		if(reachable) {
			if(now > previous) {
				n->last_reachable = now;
			}
		} else if(now > n->last_unreachable) {
			n->last_unreachable = now;
		}
	}
	node_storage_mark(n, NODE_STORAGE_EDGE);
	if(reachable && !previous && n->last_reachable) {
		return node_storage_write(mesh, n, false);
	}
	return true;
}

void node_storage_note_seen(meshlink_handle_t *mesh, node_t *n, time_t wall_now) {
	if(!mesh || !n || n == mesh->self || n->status.blacklisted || wall_now == (time_t)-1 || wall_now <= 0 || (n->last_reachable && difftime(wall_now, n->last_reachable) < NODE_OBSERVATION_INTERVAL)) {
		return;
	}
	bool first = !n->last_reachable;
	n->last_reachable = wall_now;
	node_storage_mark(n, NODE_STORAGE_OBSERVATION);
	if(first && !node_storage_write(mesh, n, false)) {
		logger(mesh, MESHLINK_WARNING, "Could not persist first observation of %s", n->name);
	}
}

void node_storage_tick(meshlink_handle_t *mesh, time_t wall_now) {
	if(!mesh->nodes) {
		return;
	}
	/* Observation is runtime state even with all disk writes disabled. */
	for splay_each(node_t, n, mesh->nodes) {
		if(n->status.reachable) {
			node_storage_note_seen(mesh, n, wall_now);
		}
	}
	if(!mesh->confbase || mesh->storage_policy != MESHLINK_STORAGE_ENABLED || mesh->storage_unavailable) {
		return;
	}
	owner_init(mesh);
	storage_writer_collect(mesh->storage->writer, writer_complete, mesh);
	for splay_each(node_t, n, mesh->nodes) {
		struct node_storage_state *s = n->storage;
		if(!s || s->retired) {
			continue;
		}
		bool urgent = s->reasons & (NODE_STORAGE_KEY_POLICY | NODE_STORAGE_CONFIG | NODE_STORAGE_EDGE);
		bool due = s->durable_seen != n->last_reachable && n->last_reachable && mesh->loop.now.tv_sec >= s->checkpoint_at;
		if(s->core.generation != s->core.acknowledged && (urgent || due) && mesh->loop.now.tv_sec >= s->core.retry_at) {
			(void)write_record(mesh, n, false, false);
		}
		if(n != mesh->self && s->cache.generation != s->cache.acknowledged) {
			if(!s->cache_at) {
				s->cache_at = mesh->loop.now.tv_sec + 5;
			}
			if(mesh->loop.now.tv_sec >= s->cache_at && mesh->loop.now.tv_sec >= s->cache.retry_at) {
				(void)write_record(mesh, n, true, false);
			}
		}
	}
}

bool node_storage_flush(meshlink_handle_t *mesh) {
	if(mesh->storage_unavailable) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}
	if(!mesh->confbase || !mesh->nodes || mesh->storage_policy != MESHLINK_STORAGE_ENABLED) {
		return true;
	}
	owner_init(mesh);
	/* Stop commits current snapshots directly; unrelated owners must not
	   make this lifecycle barrier wait for obsolete queued projections. */
	node_storage_barrier(mesh);
	bool success = true;
	for splay_each(node_t, n, mesh->nodes) {
		if(!n->storage || n->storage->retired) {
			continue;
		}
		struct node_storage_state *s = n->storage;
		if(s->core.generation != s->core.acknowledged) {
			success = write_record(mesh, n, false, true) && success;
		}
		if(n != mesh->self && s->cache.generation != s->cache.acknowledged) {
			success = write_record(mesh, n, true, true) && success;
		}
	}
	return success;
}

void node_storage_barrier(meshlink_handle_t *mesh) {
	if(mesh->storage) {
		storage_writer_barrier(mesh->storage->writer, NULL, true);
		storage_writer_collect(mesh->storage->writer, writer_complete, mesh);
		/* Cancelled snapshots remain pending and can be reprojected after a
		   storage epoch/policy/profile change. No worker dereferences nodes. */
		if(mesh->nodes) {
			for splay_each(node_t, n, mesh->nodes) {
				if(n->storage) {
					n->storage->core.submitted = n->storage->core.acknowledged;
					n->storage->cache.submitted = n->storage->cache.acknowledged;
				}
			}
		}
	}
}

void node_storage_close(meshlink_handle_t *mesh) {
	if(!mesh->storage) {
		return;
	}
	storage_writer_owner_close(mesh->storage->writer);
	timeout_del(&mesh->loop, &mesh->storage->retry);
	signal_del(&mesh->loop, &mesh->storage->signal);
	free(mesh->storage);
	mesh->storage = NULL;
}

bool node_storage_forget(meshlink_handle_t *mesh, node_t *n) {
	if(mesh->storage_unavailable) {
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}
	node_storage_init(n);
	n->storage->retired = true;
	if(mesh->storage) {
		char path[PATH_MAX];
		if(!record_path(mesh, n, false, path)) {
			n->storage->retired = false;
			return false;
		}
		storage_writer_barrier(mesh->storage->writer, path, true);
		if(!record_path(mesh, n, true, path)) {
			n->storage->retired = false;
			return false;
		}
		storage_writer_barrier(mesh->storage->writer, path, true);
		storage_writer_collect(mesh->storage->writer, writer_complete, mesh);
		n->storage->core.submitted = n->storage->core.acknowledged;
		n->storage->cache.submitted = n->storage->cache.acknowledged;
	}
	if(!config_delete(mesh, "current", n->name)) {
		n->storage->retired = false;
		/* unlink may precede a failed directory sync. Restore the previous
		   persisted record even when ordinary writes are disabled: this is
		   compensation for the failed explicit deletion, not a new update. */
		struct storage_record *core = &n->storage->core;
		char path[PATH_MAX];
		bool restored = core->durable.len && record_path(mesh, n, false, path)
		                && storage_writer_commit(mesh->storage->writer, path, core->durable.buf, core->durable.len, mesh->config_key, mesh->config_key ? CHACHA_POLY1305_KEYLEN : 0, core->acknowledged);
		if(restored) {
			core->uncertain = false;
		} else {
			config_free(&core->durable);
			node_storage_mark(n, NODE_STORAGE_CONFIG);
			logger(mesh, MESHLINK_ERROR, "Could not restore authoritative record after failed deletion of %s", n->name);
		}
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}
	if(!config_cache_delete(mesh, "current", n->name)) {
		logger(mesh, MESHLINK_DEBUG, "Could not remove optional path cache for %s", n->name);
	}
	return true;
}

void node_storage_policy_changed(meshlink_handle_t *mesh) {
	node_storage_barrier(mesh);
}

void node_storage_profile_changed(meshlink_handle_t *mesh) {
	node_storage_barrier(mesh);
	if(mesh->nodes) {
		for splay_each(node_t, n, mesh->nodes) {
			node_storage_mark(n, NODE_STORAGE_PROFILE);
		}
	}
}

void node_storage_get_stats(meshlink_handle_t *mesh, node_storage_stats_t *stats) {
	memset(stats, 0, sizeof(*stats));
	if(mesh->storage) {
		*stats = mesh->storage->stats;
	}
}

uint64_t node_storage_generation(const node_t *n, bool cache) {
	return n && n->storage ? (cache ? n->storage->cache.generation : n->storage->core.generation) : 0;
}

bool node_storage_read_trust(meshlink_handle_t *mesh, node_t *n) {
	config_t config = {0};
	node_t *stored = new_node();
	stored->name = xstrdup(n->name);
	bool ok = config_read(mesh, "current", n->name, &config, mesh->config_key) && core_decode(mesh, stored, &config, false) && ecdsa_active(stored->ecdsa);
	if(ok) {
		n->ecdsa = stored->ecdsa;
		stored->ecdsa = NULL;
	}
	config_free(&config);
	free_node(stored);
	return ok;
}

time_t node_storage_checkpoint_deadline(const node_t *n) {
	return n->storage ? n->storage->checkpoint_at : 0;
}

void node_storage_wait(meshlink_handle_t *mesh) {
	if(mesh->storage) {
		storage_writer_barrier(mesh->storage->writer, NULL, false);
		storage_writer_collect(mesh->storage->writer, writer_complete, mesh);
	}
}

void node_storage_set_backend(meshlink_handle_t *mesh, storage_writer_backend_t backend, void *context) {
	owner_init(mesh);
	assert(mesh->storage);
	node_storage_barrier(mesh);
	storage_writer_owner_close(mesh->storage->writer);
	mesh->storage->writer = storage_writer_owner_open(writer_notify, mesh, backend ? backend : native_write, context);
}

struct node_storage_state *node_storage_begin_join(node_t *n) {
	struct node_storage_state *previous = n->storage;
	n->storage = NULL;
	node_storage_init(n);
	return previous;
}

void node_storage_end_join(node_t *n, struct node_storage_state *previous, bool committed) {
	if(committed) {
		node_t retired = {.storage = previous};
		node_storage_free(&retired);
	} else {
		node_storage_free(n);
		n->storage = previous;
	}
}

void node_storage_set_clock(meshlink_handle_t *mesh, time_t (*clock)(void *), void *context) {
	owner_init(mesh);
	assert(mesh->storage);
	mesh->storage->clock = clock;
	mesh->storage->clock_context = context;
}
