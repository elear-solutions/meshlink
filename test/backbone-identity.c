#ifdef NDEBUG
#undef NDEBUG
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"
#include "packmsg.h"

static void unlink_sidecar(const char *confbase) {
	char path[256];

	snprintf(path, sizeof path, "%s/current/backbone", confbase);
	assert(unlink(path) == 0 || errno == ENOENT);
}

static void write_sidecar_name(const char *confbase, const char *name) {
	char path[256];
	uint8_t buf[512];
	packmsg_output_t out = {buf, sizeof buf};

	snprintf(path, sizeof path, "%s/current/backbone", confbase);
	packmsg_add_uint32(&out, 1);
	packmsg_add_str(&out, name);
	assert(packmsg_output_ok(&out));

	FILE *f = fopen(path, "w");
	assert(f);
	size_t len = packmsg_output_size(&out, buf);
	assert(fwrite(buf, 1, len, f) == len);
	assert(fclose(f) == 0);
}

static bool sidecar_exists(const char *confbase) {
	char path[256];

	snprintf(path, sizeof path, "%s/current/backbone", confbase);
	return access(path, F_OK) == 0;
}

static bool path_exists(const char *path) {
	return access(path, F_OK) == 0;
}

static char *find_invitation_file(const char *confbase) {
	char cmd[512];
	char name[256];
	char *found;
	FILE *p;
	size_t n;

	snprintf(cmd, sizeof cmd, "ls -1 %s/current/invitations", confbase);

	for(int attempt = 0; attempt < 50; attempt++) {
		p = popen(cmd, "r");
		assert(p);
		name[0] = 0;

		if(fgets(name, sizeof name, p)) {
			n = strlen(name);

			while(n && (name[n - 1] == '\n' || name[n - 1] == '\r')) {
				name[--n] = 0;
			}
		} else {
			n = 0;
		}

		assert(pclose(p) == 0);

		if(n > 0 && strcmp(name, ".") && strcmp(name, "..")) {
			found = malloc(strlen(confbase) + n + 32);
			assert(found);
			sprintf(found, "%s/current/invitations/%s", confbase, name);
			return found;
		}

		usleep(20000);
	}

	assert(0 && "invitation file not found");
	return NULL;
}

static uint8_t *read_file(const char *path, size_t *len) {
	FILE *f = fopen(path, "rb");
	long n;
	uint8_t *buf;

	assert(f);
	assert(fseek(f, 0, SEEK_END) == 0);
	n = ftell(f);
	assert(n > 0);
	assert(fseek(f, 0, SEEK_SET) == 0);
	buf = malloc((size_t)n);
	assert(buf);
	assert(fread(buf, 1, (size_t)n, f) == (size_t)n);
	assert(fclose(f) == 0);
	*len = (size_t)n;
	return buf;
}

static void write_file(const char *path, const uint8_t *buf, size_t len) {
	FILE *f = fopen(path, "wb");

	assert(f);
	assert(fwrite(buf, 1, len, f) == len);
	assert(fclose(f) == 0);
}

static void rewrite_invitation_first_host(const char *path, const void *blob, size_t blob_len) {
	size_t len;
	uint8_t *buf = read_file(path, &len);
	packmsg_input_t in = {buf, len};
	uint8_t *outbuf = malloc(len + blob_len + 64);
	packmsg_output_t out;
	uint32_t version;
	char *name;
	char *submesh;
	int32_t devclass;
	char *backbone;
	uint32_t count;
	uint32_t i;

	assert(outbuf);
	out.ptr = outbuf;
	out.len = (ptrdiff_t)(len + blob_len + 64);

	version = packmsg_get_uint32(&in);
	name = packmsg_get_str_dup(&in);
	submesh = packmsg_get_str_dup(&in);
	devclass = packmsg_get_int32(&in);
	backbone = packmsg_get_str_dup(&in);
	count = packmsg_get_array(&in);

	assert(packmsg_input_ok(&in));
	assert(name && submesh && backbone);
	assert(count >= 1);

	packmsg_add_uint32(&out, version);
	packmsg_add_str(&out, name);
	packmsg_add_str(&out, submesh);
	packmsg_add_int32(&out, devclass);
	packmsg_add_str(&out, backbone);
	packmsg_add_array(&out, count);

	for(i = 0; i < count; i++) {
		const void *data;
		uint32_t data_len = packmsg_get_bin_raw(&in, &data);

		assert(data && data_len);

		if(i == 0) {
			packmsg_add_bin(&out, blob, (uint32_t)blob_len);
		} else {
			packmsg_add_bin(&out, data, data_len);
		}
	}

	assert(packmsg_done(&in));
	assert(packmsg_output_ok(&out));
	write_file(path, outbuf, packmsg_output_size(&out, outbuf));

	free(name);
	free(submesh);
	free(backbone);
	free(buf);
	free(outbuf);
}

static void rewrite_invitation_version(const char *path, uint32_t version) {
	size_t len;
	uint8_t *buf = read_file(path, &len);
	packmsg_input_t in = {buf, len};
	uint8_t *outbuf = malloc(len + 64);
	packmsg_output_t out;
	char *name;
	char *submesh;
	int32_t devclass;
	char *backbone;
	uint32_t count;
	uint32_t i;

	assert(outbuf);
	out.ptr = outbuf;
	out.len = (ptrdiff_t)(len + 64);

	(void)packmsg_get_uint32(&in);
	name = packmsg_get_str_dup(&in);
	submesh = packmsg_get_str_dup(&in);
	devclass = packmsg_get_int32(&in);
	backbone = packmsg_get_str_dup(&in);
	count = packmsg_get_array(&in);

	assert(packmsg_input_ok(&in));
	assert(name && submesh && backbone);
	assert(count >= 1);

	packmsg_add_uint32(&out, version);
	packmsg_add_str(&out, name);
	packmsg_add_str(&out, submesh);
	packmsg_add_int32(&out, devclass);
	packmsg_add_str(&out, backbone);
	packmsg_add_array(&out, count);

	for(i = 0; i < count; i++) {
		const void *data;
		uint32_t data_len = packmsg_get_bin_raw(&in, &data);

		assert(data && data_len);
		packmsg_add_bin(&out, data, data_len);
	}

	assert(packmsg_done(&in));
	assert(packmsg_output_ok(&out));
	write_file(path, outbuf, packmsg_output_size(&out, outbuf));

	free(name);
	free(submesh);
	free(backbone);
	free(buf);
	free(outbuf);
}

static void assert_joiner_untouched(meshlink_handle_t *b, const char *confbase, const char *name, const char *fp, bool had_sidecar) {
	char host[256];
	char conf[256];
	char *fp2;

	assert(!strcmp(b->name, name));
	assert(!strcmp(meshlink_get_self(b)->name, name));
	fp2 = meshlink_get_fingerprint(b, meshlink_get_self(b));
	assert(fp2);
	assert(!strcmp(fp, fp2));
	free(fp2);
	snprintf(host, sizeof host, "%s/current/hosts/%s", confbase, name);
	assert(path_exists(host));
	snprintf(conf, sizeof conf, "%s/current/meshlink.conf", confbase);
	assert(path_exists(conf));
	assert(sidecar_exists(confbase) == had_sidecar);

	if(!had_sidecar) {
		assert(!devtool_get_backbone_name(b));
	}
}

static void test_creator_persists_self(void) {
	assert(meshlink_destroy("backbone_identity_t1_conf"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t1_conf", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	meshlink_enable_discovery(a, false);
	assert(!devtool_get_backbone_name(a));
	assert(meshlink_start(a));
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(devtool_get_backbone(a) == meshlink_get_self(a));
	assert(sidecar_exists("backbone_identity_t1_conf"));
	meshlink_close(a);

	a = meshlink_open("backbone_identity_t1_conf", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(devtool_get_backbone(a) == meshlink_get_self(a));
	meshlink_close(a);
	assert(meshlink_destroy("backbone_identity_t1_conf"));
}

static void test_join_persists_inviter_before_start(void) {
	assert(meshlink_destroy("backbone_identity_t2_conf.1"));
	assert(meshlink_destroy("backbone_identity_t2_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t2_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t2_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(meshlink_join(b, url));
	free(url);

	assert(!strcmp(devtool_get_backbone_name(b), "aaa"));
	assert(sidecar_exists("backbone_identity_t2_conf.2"));
	assert(devtool_get_backbone(b) == meshlink_get_node(b, "aaa"));

	meshlink_close(b);
	b = meshlink_open("backbone_identity_t2_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(b);
	assert(!strcmp(devtool_get_backbone_name(b), "aaa"));
	assert(devtool_get_backbone(b) == meshlink_get_node(b, "aaa"));

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t2_conf.1"));
	assert(meshlink_destroy("backbone_identity_t2_conf.2"));
}

static void test_join_rejects_stationary_inviter(void) {
	assert(meshlink_destroy("backbone_identity_t3_conf.1"));
	assert(meshlink_destroy("backbone_identity_t3_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t3_conf.1", "aaa", "backbone-identity", DEV_CLASS_STATIONARY);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t3_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	devtool_set_allow_peer_bootstrap(a, true);
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	char *fp = meshlink_get_fingerprint(b, meshlink_get_self(b));
	assert(fp);
	assert(path_exists("backbone_identity_t3_conf.2/current/hosts/bbb"));
	assert(path_exists("backbone_identity_t3_conf.2/current/meshlink.conf"));
	assert(!meshlink_join(b, url));
	assert(meshlink_errno == MESHLINK_EPEER);
	free(url);
	assert_joiner_untouched(b, "backbone_identity_t3_conf.2", "bbb", fp, false);
	assert(!meshlink_get_node(b, "aaa"));
	free(fp);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t3_conf.1"));
	assert(meshlink_destroy("backbone_identity_t3_conf.2"));
}

static void test_invite_rejects_stationary(void) {
	assert(meshlink_destroy("backbone_identity_t16_conf"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t16_conf", "aaa", "backbone-identity", DEV_CLASS_STATIONARY);
	assert(a);
	meshlink_enable_discovery(a, false);
	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_invite(a, NULL, "bbb"));
	assert(meshlink_errno == MESHLINK_ENOTSUP);
	assert(!sidecar_exists("backbone_identity_t16_conf"));
	assert(!devtool_get_backbone_name(a));

	meshlink_close(a);
	assert(meshlink_destroy("backbone_identity_t16_conf"));
}

static void test_invite_rejects_portable(void) {
	assert(meshlink_destroy("backbone_identity_t17_conf"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t17_conf", "aaa", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a);
	meshlink_enable_discovery(a, false);
	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_invite(a, NULL, "bbb"));
	assert(meshlink_errno == MESHLINK_ENOTSUP);
	assert(!sidecar_exists("backbone_identity_t17_conf"));
	assert(!devtool_get_backbone_name(a));

	meshlink_close(a);
	assert(meshlink_destroy("backbone_identity_t17_conf"));
}

static void test_invite_before_start_commits_self(void) {
	assert(meshlink_destroy("backbone_identity_t18_conf.1"));
	assert(meshlink_destroy("backbone_identity_t18_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t18_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	meshlink_enable_discovery(a, false);
	assert(!devtool_get_backbone_name(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	free(url);
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(devtool_get_backbone(a) == meshlink_get_self(a));
	assert(sidecar_exists("backbone_identity_t18_conf.1"));

	meshlink_close(a);
	assert(meshlink_destroy("backbone_identity_t18_conf.1"));
	assert(meshlink_destroy("backbone_identity_t18_conf.2"));
}

static void test_second_backbone_class_is_detected(void) {
	assert(meshlink_destroy("backbone_identity_t4_conf.1"));
	assert(meshlink_destroy("backbone_identity_t4_conf.2"));
	assert(meshlink_destroy("backbone_identity_t4_conf.3"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t4_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t4_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	meshlink_handle_t *c = meshlink_open("backbone_identity_t4_conf.3", "ccc", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a && b && c);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	meshlink_enable_discovery(c, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(meshlink_join(b, url));
	free(url);

	char *exp = meshlink_export(c);
	assert(exp);
	assert(meshlink_import(b, exp));
	free(exp);

	assert(!strcmp(devtool_get_backbone_name(b), "aaa"));
	assert(devtool_get_backbone(b) == meshlink_get_node(b, "aaa"));
	assert(!devtool_node_has_conflict_backbone(b, meshlink_get_node(b, "aaa")));
	assert(devtool_node_has_conflict_backbone(b, meshlink_get_node(b, "ccc")));
	assert(!meshlink_get_node_blacklisted(b, meshlink_get_node(b, "ccc")));

	meshlink_close(a);
	meshlink_close(b);
	meshlink_close(c);
	assert(meshlink_destroy("backbone_identity_t4_conf.1"));
	assert(meshlink_destroy("backbone_identity_t4_conf.2"));
	assert(meshlink_destroy("backbone_identity_t4_conf.3"));
}

static void test_forget_clears_pointer_keeps_name(void) {
	assert(meshlink_destroy("backbone_identity_t5_conf.1"));
	assert(meshlink_destroy("backbone_identity_t5_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t5_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t5_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(meshlink_join(b, url));
	free(url);

	meshlink_node_t *inviter = meshlink_get_node(b, "aaa");
	assert(inviter);
	assert(meshlink_forget_node(b, inviter));
	assert(!devtool_get_backbone(b));
	assert(!strcmp(devtool_get_backbone_name(b), "aaa"));

	meshlink_close(b);
	b = meshlink_open("backbone_identity_t5_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(b);
	assert(!strcmp(devtool_get_backbone_name(b), "aaa"));
	assert(!devtool_get_backbone(b));

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t5_conf.1"));
	assert(meshlink_destroy("backbone_identity_t5_conf.2"));
}

static void test_migrate_one_other_backbone(void) {
	assert(meshlink_destroy("backbone_identity_t6a_conf.1"));
	assert(meshlink_destroy("backbone_identity_t6a_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t6a_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t6a_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(meshlink_join(b, url));
	free(url);
	meshlink_close(b);

	unlink_sidecar("backbone_identity_t6a_conf.2");
	b = meshlink_open("backbone_identity_t6a_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(b);
	assert(!strcmp(devtool_get_backbone_name(b), "aaa"));
	assert(sidecar_exists("backbone_identity_t6a_conf.2"));

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t6a_conf.1"));
	assert(meshlink_destroy("backbone_identity_t6a_conf.2"));
}

static void test_migrate_refuses_two_backbones(void) {
	assert(meshlink_destroy("backbone_identity_t6b_conf.1"));
	assert(meshlink_destroy("backbone_identity_t6b_conf.2"));
	assert(meshlink_destroy("backbone_identity_t6b_conf.3"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t6b_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t6b_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	meshlink_handle_t *c = meshlink_open("backbone_identity_t6b_conf.3", "ccc", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a && b && c);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	meshlink_enable_discovery(c, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(meshlink_join(b, url));
	free(url);

	char *exp = meshlink_export(c);
	assert(exp);
	assert(meshlink_import(b, exp));
	free(exp);
	meshlink_close(b);

	unlink_sidecar("backbone_identity_t6b_conf.2");
	b = meshlink_open("backbone_identity_t6b_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(b);
	assert(!devtool_get_backbone_name(b));
	assert(devtool_node_has_conflict_backbone(b, meshlink_get_node(b, "aaa")));
	assert(devtool_node_has_conflict_backbone(b, meshlink_get_node(b, "ccc")));

	meshlink_close(a);
	meshlink_close(b);
	meshlink_close(c);
	assert(meshlink_destroy("backbone_identity_t6b_conf.1"));
	assert(meshlink_destroy("backbone_identity_t6b_conf.2"));
	assert(meshlink_destroy("backbone_identity_t6b_conf.3"));
}

static void test_ephemeral_backbone(void) {
	meshlink_handle_t *a = meshlink_open_ephemeral("aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	assert(!devtool_get_backbone_name(a));
	assert(meshlink_start(a));
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(devtool_get_backbone(a) == meshlink_get_self(a));
	meshlink_close(a);
}

static void test_two_backbone_invite_join(void) {
	/* A BACKBONE invitee may still join. The extra backbone-class node is
	   marked conflict_backbone, not blacklisted, and cannot create invitations.
	   It is excluded from META pools (no outgoing on either side) and relay-hop
	   selection. */
	assert(meshlink_destroy("backbone_identity_t8_conf.1"));
	assert(meshlink_destroy("backbone_identity_t8_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t8_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t8_conf.2", "bbb", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(meshlink_join(b, url));
	free(url);

	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(meshlink_start(b));
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(!strcmp(devtool_get_backbone_name(b), "aaa"));
	assert(devtool_node_has_conflict_backbone(b, meshlink_get_self(b)));
	assert(!meshlink_get_node_blacklisted(b, meshlink_get_self(b)));
	sleep(2);
	assert(devtool_outgoing_count(a) == 0);
	assert(devtool_outgoing_count(b) == 0);
	assert(!devtool_backbone_intent_name(a));
	assert(!devtool_backbone_intent_name(b));
	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_invite(b, NULL, "ccc"));
	assert(meshlink_errno == MESHLINK_ENOTSUP);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t8_conf.1"));
	assert(meshlink_destroy("backbone_identity_t8_conf.2"));
}

static void test_portable_start_leaves_unset(void) {
	assert(meshlink_destroy("backbone_identity_t9_conf"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t9_conf", "aaa", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a);
	assert(meshlink_start(a));
	assert(!devtool_get_backbone_name(a));
	assert(!sidecar_exists("backbone_identity_t9_conf"));
	meshlink_close(a);
	assert(meshlink_destroy("backbone_identity_t9_conf"));
}

static void test_migrate_self_only(void) {
	assert(meshlink_destroy("backbone_identity_t10_conf"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t10_conf", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	assert(meshlink_start(a));
	meshlink_close(a);

	unlink_sidecar("backbone_identity_t10_conf");
	a = meshlink_open("backbone_identity_t10_conf", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(devtool_get_backbone(a) == meshlink_get_self(a));
	assert(sidecar_exists("backbone_identity_t10_conf"));
	meshlink_close(a);
	assert(meshlink_destroy("backbone_identity_t10_conf"));
}

static void test_creator_import_keeps_self(void) {
	assert(meshlink_destroy("backbone_identity_t11_conf.1"));
	assert(meshlink_destroy("backbone_identity_t11_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t11_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *c = meshlink_open("backbone_identity_t11_conf.2", "ccc", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a && c);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(c, false);

	assert(meshlink_start(a));
	char *exp = meshlink_export(c);
	assert(exp);
	assert(meshlink_import(a, exp));
	free(exp);

	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(devtool_get_backbone(a) == meshlink_get_self(a));
	assert(devtool_node_has_conflict_backbone(a, meshlink_get_node(a, "ccc")));
	assert(!devtool_node_has_conflict_backbone(a, meshlink_get_self(a)));

	meshlink_close(a);
	meshlink_close(c);
	assert(meshlink_destroy("backbone_identity_t11_conf.1"));
	assert(meshlink_destroy("backbone_identity_t11_conf.2"));
}

static void test_corrupt_sidecar_fails_open(void) {
	assert(meshlink_destroy("backbone_identity_t12_conf"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t12_conf", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	assert(meshlink_start(a));
	meshlink_close(a);

	FILE *f = fopen("backbone_identity_t12_conf/current/backbone", "w");
	assert(f);
	assert(fwrite("garbage", 1, 7, f) == 7);
	assert(fclose(f) == 0);

	a = meshlink_open("backbone_identity_t12_conf", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(!a);
	assert(meshlink_destroy("backbone_identity_t12_conf"));
}

static void test_same_name_reopen_is_idempotent(void) {
	assert(meshlink_destroy("backbone_identity_t13_conf"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t13_conf", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	assert(meshlink_start(a));
	meshlink_close(a);

	a = meshlink_open("backbone_identity_t13_conf", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(meshlink_start(a));
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(devtool_get_backbone(a) == meshlink_get_self(a));
	meshlink_close(a);
	assert(meshlink_destroy("backbone_identity_t13_conf"));
}

static void test_start_then_join_takes_inviter(void) {
	assert(meshlink_destroy("backbone_identity_t14_conf.1"));
	assert(meshlink_destroy("backbone_identity_t14_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t14_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t14_conf.2", "bbb", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	assert(meshlink_start(b));
	assert(!strcmp(devtool_get_backbone_name(b), "bbb"));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(!meshlink_join(b, url));
	meshlink_stop(b);
	assert(meshlink_join(b, url));
	free(url);
	assert(!strcmp(devtool_get_backbone_name(b), "aaa"));
	assert(sidecar_exists("backbone_identity_t14_conf.2"));
	assert(devtool_node_has_conflict_backbone(b, meshlink_get_self(b)));

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t14_conf.1"));
	assert(meshlink_destroy("backbone_identity_t14_conf.2"));
}

static void test_named_backbone_wrong_class(void) {
	assert(meshlink_destroy("backbone_identity_t15_conf"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t15_conf", "aaa", "backbone-identity", DEV_CLASS_STATIONARY);
	assert(a);
	meshlink_close(a);

	write_sidecar_name("backbone_identity_t15_conf", "aaa");
	a = meshlink_open("backbone_identity_t15_conf", "aaa", "backbone-identity", DEV_CLASS_STATIONARY);
	assert(a);
	assert(!strcmp(devtool_get_backbone_name(a), "aaa"));
	assert(devtool_get_backbone(a) == meshlink_get_self(a));
	assert(devtool_node_has_conflict_backbone(a, meshlink_get_self(a)));

	meshlink_close(a);
	assert(meshlink_destroy("backbone_identity_t15_conf"));
}

static void test_join_rejects_extra_backbone_inviter(void) {
	assert(meshlink_destroy("backbone_identity_t19_conf.1"));
	assert(meshlink_destroy("backbone_identity_t19_conf.2"));
	assert(meshlink_destroy("backbone_identity_t19_conf.3"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t19_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t19_conf.2", "bbb", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *c = meshlink_open("backbone_identity_t19_conf.3", "ccc", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b && c);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	meshlink_enable_discovery(c, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(meshlink_join(b, url));
	free(url);
	assert(meshlink_start(b));
	assert(devtool_node_has_conflict_backbone(b, meshlink_get_self(b)));

	devtool_set_allow_peer_bootstrap(b, true);
	url = meshlink_invite(b, NULL, "ccc");
	assert(url);
	assert(!meshlink_join(c, url));
	assert(meshlink_errno == MESHLINK_EPEER);
	free(url);
	assert(!sidecar_exists("backbone_identity_t19_conf.3"));
	assert(!devtool_get_backbone_name(c));

	meshlink_close(a);
	meshlink_close(b);
	meshlink_close(c);
	assert(meshlink_destroy("backbone_identity_t19_conf.1"));
	assert(meshlink_destroy("backbone_identity_t19_conf.2"));
	assert(meshlink_destroy("backbone_identity_t19_conf.3"));
}

static void test_join_malformed_first_host(void) {
	assert(meshlink_destroy("backbone_identity_t20_conf.1"));
	assert(meshlink_destroy("backbone_identity_t20_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t20_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t20_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	char *inv = find_invitation_file("backbone_identity_t20_conf.1");
	rewrite_invitation_first_host(inv, "not-a-host-config", 17);
	free(inv);

	char *fp = meshlink_get_fingerprint(b, meshlink_get_self(b));
	assert(fp);
	assert(!meshlink_join(b, url));
	assert(meshlink_errno == MESHLINK_EPEER);
	free(url);
	assert_joiner_untouched(b, "backbone_identity_t20_conf.2", "bbb", fp, false);
	assert(!meshlink_get_node(b, "aaa"));
	free(fp);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t20_conf.1"));
	assert(meshlink_destroy("backbone_identity_t20_conf.2"));
}

static void test_join_rejects_invitation_v2(void) {
	assert(meshlink_destroy("backbone_identity_t20b_conf.1"));
	assert(meshlink_destroy("backbone_identity_t20b_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t20b_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t20b_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	char *inv = find_invitation_file("backbone_identity_t20b_conf.1");
	rewrite_invitation_version(inv, 2);
	free(inv);

	char *fp = meshlink_get_fingerprint(b, meshlink_get_self(b));
	assert(fp);
	assert(!meshlink_join(b, url));
	assert(meshlink_errno == MESHLINK_EPEER);
	free(url);
	assert_joiner_untouched(b, "backbone_identity_t20b_conf.2", "bbb", fp, false);
	assert(!meshlink_get_node(b, "aaa"));
	free(fp);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t20b_conf.1"));
	assert(meshlink_destroy("backbone_identity_t20b_conf.2"));
}

static void test_join_trailing_invitation(void) {
	assert(meshlink_destroy("backbone_identity_t21_conf.1"));
	assert(meshlink_destroy("backbone_identity_t21_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t21_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t21_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	char *inv = find_invitation_file("backbone_identity_t21_conf.1");
	FILE *f = fopen(inv, "ab");
	assert(f);
	assert(fwrite("xxxx", 1, 4, f) == 4);
	assert(fclose(f) == 0);
	free(inv);

	char *fp = meshlink_get_fingerprint(b, meshlink_get_self(b));
	assert(fp);
	assert(!meshlink_join(b, url));
	assert(meshlink_errno == MESHLINK_EPEER);
	free(url);
	assert_joiner_untouched(b, "backbone_identity_t21_conf.2", "bbb", fp, false);
	free(fp);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t21_conf.1"));
	assert(meshlink_destroy("backbone_identity_t21_conf.2"));
}

static void test_join_truncated_invitation(void) {
	assert(meshlink_destroy("backbone_identity_t22_conf.1"));
	assert(meshlink_destroy("backbone_identity_t22_conf.2"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t22_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *b = meshlink_open("backbone_identity_t22_conf.2", "bbb", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && b);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	char *inv = find_invitation_file("backbone_identity_t22_conf.1");
	struct stat st;
	assert(stat(inv, &st) == 0);
	assert(st.st_size > 1);
	assert(truncate(inv, st.st_size - 1) == 0);
	free(inv);

	char *fp = meshlink_get_fingerprint(b, meshlink_get_self(b));
	assert(fp);
	assert(!meshlink_join(b, url));
	assert(meshlink_errno == MESHLINK_EPEER);
	free(url);
	assert_joiner_untouched(b, "backbone_identity_t22_conf.2", "bbb", fp, false);
	free(fp);

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t22_conf.1"));
	assert(meshlink_destroy("backbone_identity_t22_conf.2"));
}

static void test_ambiguous_legacy_cannot_invite_or_serve(void) {
	assert(meshlink_destroy("backbone_identity_t23_conf.1"));
	assert(meshlink_destroy("backbone_identity_t23_conf.2"));
	assert(meshlink_destroy("backbone_identity_t23_conf.3"));

	meshlink_handle_t *a = meshlink_open("backbone_identity_t23_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *c = meshlink_open("backbone_identity_t23_conf.2", "ccc", "backbone-identity", DEV_CLASS_BACKBONE);
	meshlink_handle_t *d = meshlink_open("backbone_identity_t23_conf.3", "ddd", "backbone-identity", DEV_CLASS_PORTABLE);
	assert(a && c && d);
	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(c, false);
	meshlink_enable_discovery(d, false);

	assert(meshlink_start(a));
	char *url = meshlink_invite(a, NULL, "ddd");
	assert(url);
	char *exp = meshlink_export(c);
	assert(exp);
	assert(meshlink_import(a, exp));
	free(exp);
	meshlink_close(a);

	unlink_sidecar("backbone_identity_t23_conf.1");
	a = meshlink_open("backbone_identity_t23_conf.1", "aaa", "backbone-identity", DEV_CLASS_BACKBONE);
	assert(a);
	meshlink_enable_discovery(a, false);
	assert(!devtool_get_backbone_name(a));
	assert(devtool_node_has_conflict_backbone(a, meshlink_get_self(a)));
	assert(devtool_node_has_conflict_backbone(a, meshlink_get_node(a, "ccc")));

	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_invite(a, NULL, "eee"));
	assert(meshlink_errno == MESHLINK_ENOTSUP);
	assert(!sidecar_exists("backbone_identity_t23_conf.1"));
	assert(!devtool_get_backbone_name(a));

	assert(meshlink_start(a));
	assert(!devtool_get_backbone_name(a));
	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_invite(a, NULL, "eee"));
	assert(meshlink_errno == MESHLINK_ENOTSUP);

	char *fp = meshlink_get_fingerprint(d, meshlink_get_self(d));
	assert(fp);
	assert(!meshlink_join(d, url));
	free(url);
	assert_joiner_untouched(d, "backbone_identity_t23_conf.3", "ddd", fp, false);
	assert(!devtool_get_backbone_name(a));
	free(fp);

	meshlink_close(a);
	meshlink_close(c);
	meshlink_close(d);
	assert(meshlink_destroy("backbone_identity_t23_conf.1"));
	assert(meshlink_destroy("backbone_identity_t23_conf.2"));
	assert(meshlink_destroy("backbone_identity_t23_conf.3"));
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	test_creator_persists_self();
	test_join_persists_inviter_before_start();
	test_join_rejects_stationary_inviter();
	test_invite_rejects_stationary();
	test_invite_rejects_portable();
	test_invite_before_start_commits_self();
	test_second_backbone_class_is_detected();
	test_forget_clears_pointer_keeps_name();
	test_migrate_one_other_backbone();
	test_migrate_refuses_two_backbones();
	test_ephemeral_backbone();
	test_two_backbone_invite_join();
	test_portable_start_leaves_unset();
	test_migrate_self_only();
	test_creator_import_keeps_self();
	test_corrupt_sidecar_fails_open();
	test_same_name_reopen_is_idempotent();
	test_start_then_join_takes_inviter();
	test_named_backbone_wrong_class();
	test_join_rejects_extra_backbone_inviter();
	test_join_malformed_first_host();
	test_join_rejects_invitation_v2();
	test_join_trailing_invitation();
	test_join_truncated_invitation();
	test_ambiguous_legacy_cannot_invite_or_serve();

	return 0;
}
