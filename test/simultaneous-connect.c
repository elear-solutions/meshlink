#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "meshlink.h"
#include "utils.h"

/* bar < foo, so both sides must keep the session initiated by bar. */
static const char *smaller_name = "bar";
static const char *larger_name = "foo";

static pthread_mutex_t drop_lock = PTHREAD_MUTEX_INITIALIZER;
static int drop_count;
static char last_initiator[256];

static void collision_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	log_cb(mesh, level, text);

	const char *keep = strstr(text, "keeping the one initiated by ");

	if(!keep) {
		return;
	}

	keep += strlen("keeping the one initiated by ");

	assert(pthread_mutex_lock(&drop_lock) == 0);
	snprintf(last_initiator, sizeof last_initiator, "%s", keep);
	drop_count++;
	assert(pthread_mutex_unlock(&drop_lock) == 0);
}

static void run_pair(void) {
	meshlink_handle_t *a;
	meshlink_handle_t *b;

	assert(meshlink_destroy("simultaneous-connect_conf.1"));
	assert(meshlink_destroy("simultaneous-connect_conf.2"));

	a = meshlink_open("simultaneous-connect_conf.1", smaller_name, "simultaneous-connect", DEV_CLASS_BACKBONE);
	b = meshlink_open("simultaneous-connect_conf.2", larger_name, "simultaneous-connect", DEV_CLASS_BACKBONE);
	assert(a);
	assert(b);

	meshlink_enable_discovery(a, false);
	meshlink_enable_discovery(b, false);
	link_meshlink_pair(a, b);

	start_meshlink_pair(a, b);

	meshlink_node_t *peer_a = meshlink_get_node(a, larger_name);
	meshlink_node_t *peer_b = meshlink_get_node(b, smaller_name);
	assert(peer_a);
	assert(peer_b);
	assert(meshlink_get_node_reachability(a, peer_a, NULL, NULL));
	assert(meshlink_get_node_reachability(b, peer_b, NULL, NULL));

	close_meshlink_pair(a, b);
	assert(meshlink_destroy("simultaneous-connect_conf.1"));
	assert(meshlink_destroy("simultaneous-connect_conf.2"));
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, collision_log_cb);

	/* Several start/stop cycles: pair must come up inside start_meshlink_pair's 5s
	   budget (the old last-ACK-wins flake). When a duplicate is dropped, the kept
	   initiator must be the lexicographically smaller name. */
	for(int i = 0; i < 5; i++) {
		run_pair();
	}

	assert(pthread_mutex_lock(&drop_lock) == 0);
	int seen = drop_count;
	char initiator[sizeof last_initiator];
	snprintf(initiator, sizeof initiator, "%s", last_initiator);
	assert(pthread_mutex_unlock(&drop_lock) == 0);

	if(seen) {
		assert(!strcmp(initiator, smaller_name));
	}

	fprintf(stderr, "simultaneous-connect: %d drop log(s), last initiator '%s'\n", seen, initiator);
}
