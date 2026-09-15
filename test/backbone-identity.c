#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

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
	char *url = meshlink_invite(a, NULL, "bbb");
	assert(url);
	assert(!meshlink_join(b, url));
	assert(meshlink_errno == MESHLINK_EPEER);
	free(url);
	assert(!sidecar_exists("backbone_identity_t3_conf.2"));
	assert(!devtool_get_backbone_name(b));

	meshlink_close(a);
	meshlink_close(b);
	assert(meshlink_destroy("backbone_identity_t3_conf.1"));
	assert(meshlink_destroy("backbone_identity_t3_conf.2"));
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
	/* Finding 4 still allows a BACKBONE invitee. Join succeeds; the extra
	   backbone-class node is marked conflict_backbone, not blacklisted.
	   Findings 5 and 10 exclude it from autoconnect and relay. */
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

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	test_creator_persists_self();
	test_join_persists_inviter_before_start();
	test_join_rejects_stationary_inviter();
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

	return 0;
}
