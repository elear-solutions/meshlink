/* A stop waiting for another caller's join still owns cleanup. Delay that
   waiter's mutex reacquisition to exercise a fresh start at this boundary. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include "meshlink_internal.h"
#include <assert.h>

static meshlink_handle_t *observed;
static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static bool release_worker;
static bool stopper_paused;
static bool release_stopper;
static bool join_paused;
static bool release_join;
static bool startup_waiting;
static bool stop_waiting;
static unsigned worker_calls;
static unsigned joins;
static _Thread_local bool late_stopper;
static _Thread_local bool failed_start_owner;

int __real_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int __real_pthread_join(pthread_t thread, void **result);
int __wrap_pthread_join(pthread_t thread, void **result);
int __wrap_setns(int fd, int kind);

static struct timespec deadline(void) {
	struct timespec limit;
	assert(clock_gettime(CLOCK_REALTIME, &limit) == 0);
	limit.tv_sec += 10;
	return limit;
}

static void wait_gate(bool *ready) {
	struct timespec limit = deadline();
	while(!*ready) {
		assert(pthread_cond_timedwait(&gate_cond, &gate_mutex, &limit) == 0);
	}
}

int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
	if(observed && cond == &observed->cond) {
		pthread_mutex_lock(&gate_mutex);
		if(late_stopper) {
			stop_waiting = true;
		} else {
			startup_waiting = true;
		}
		pthread_cond_broadcast(&gate_cond);
		pthread_mutex_unlock(&gate_mutex);
	}

	int result = __real_pthread_cond_wait(cond, mutex);
	if(late_stopper && observed && cond == &observed->cond) {
		/* Releasing the reacquired mutex models a woken waiter losing the
		   mutex race. The real predicate and cleanup execute after the gate. */
		pthread_mutex_unlock(mutex);
		pthread_mutex_lock(&gate_mutex);
		stopper_paused = true;
		pthread_cond_broadcast(&gate_cond);
		wait_gate(&release_stopper);
		pthread_mutex_unlock(&gate_mutex);
		pthread_mutex_lock(mutex);
		late_stopper = false;
	}
	return result;
}

int __wrap_pthread_join(pthread_t thread, void **result) {
	bool worker = observed && pthread_equal(thread, observed->thread);
	int status = __real_pthread_join(thread, result);
	if(worker) {
		pthread_mutex_lock(&gate_mutex);
		joins++;
		if(failed_start_owner) {
			join_paused = true;
			pthread_cond_broadcast(&gate_cond);
			wait_gate(&release_join);
		}
		pthread_mutex_unlock(&gate_mutex);
	}
	return status;
}

int __wrap_setns(int fd, int kind) {
	(void)fd;
	(void)kind;
	/* Only the mesh worker fails; inventory helpers never change namespace. */
	if(!observed || !pthread_equal(pthread_self(), observed->thread)) {
		return 0;
	}
	pthread_mutex_lock(&gate_mutex);
	worker_calls++;
	pthread_cond_broadcast(&gate_cond);
	wait_gate(&release_worker);
	pthread_mutex_unlock(&gate_mutex);
	errno = EPERM;
	return -1;
}

static void await_flag(bool *flag) {
	pthread_mutex_lock(&gate_mutex);
	wait_gate(flag);
	pthread_mutex_unlock(&gate_mutex);
}

static void release_flag(bool *flag) {
	pthread_mutex_lock(&gate_mutex);
	*flag = true;
	pthread_cond_broadcast(&gate_cond);
	pthread_mutex_unlock(&gate_mutex);
}

static void join_bounded(pthread_t thread) {
	struct timespec limit = deadline();
	assert(pthread_timedjoin_np(thread, NULL, &limit) == 0);
}

typedef struct {
	meshlink_handle_t *mesh;
	bool fails;
	bool result;
} start_call_t;

static void *start_call(void *arg) {
	start_call_t *call = arg;
	failed_start_owner = call->fails;
	call->result = meshlink_start(call->mesh);
	return NULL;
}

static void *stop_call(void *arg) {
	meshlink_stop(arg);
	return NULL;
}

static void *late_stop_call(void *arg) {
	late_stopper = true;
	meshlink_stop(arg);
	return NULL;
}

static void check_idle(meshlink_handle_t *mesh) {
	pthread_mutex_lock(&mesh->mutex);
	assert(!mesh->threadstarted && !mesh->thread_in_loop && !mesh->thread_join_claimed);
	assert(!mesh->loop.running && !mesh->adns_signal.cb && !mesh->outgoings);
	pthread_mutex_unlock(&mesh->mutex);
}

static void check_running(meshlink_handle_t *mesh) {
	pthread_mutex_lock(&mesh->mutex);
	assert(mesh->threadstarted && mesh->thread_in_loop && !mesh->thread_join_claimed);
	assert(mesh->loop.running && mesh->adns_signal.cb && mesh->outgoings);
	pthread_mutex_unlock(&mesh->mutex);
}

static void lifecycle_case(bool failed_owner) {
	meshlink_handle_t *mesh = meshlink_open_ephemeral("lifecycle", "lifecycle-start-stop", DEV_CLASS_STATIONARY);
	assert(mesh);
	meshlink_enable_discovery(mesh, false);
	observed = mesh;
	release_worker = false;
	stopper_paused = false;
	release_stopper = false;
	join_paused = false;
	release_join = false;
	startup_waiting = false;
	stop_waiting = false;
	worker_calls = 0;
	joins = 0;
	mesh->netns = 12345; /* setns is wrapped, no namespace changes */
	start_call_t owner = {mesh, failed_owner, true};
	pthread_t starting, first_stop, second_stop;
	assert(pthread_create(&starting, NULL, start_call, &owner) == 0);
	await_flag(&startup_waiting);

	if(failed_owner) {
		release_flag(&release_worker);
		await_flag(&join_paused);
	} else {
		assert(pthread_create(&first_stop, NULL, stop_call, mesh) == 0);
		/* The worker is gated, so the join owner cannot complete yet. */
		struct timespec limit = deadline(), now;
		bool claimed;
		do {
			pthread_mutex_lock(&mesh->mutex);
			claimed = mesh->thread_join_claimed;
			pthread_mutex_unlock(&mesh->mutex);
			assert(clock_gettime(CLOCK_REALTIME, &now) == 0 && now.tv_sec < limit.tv_sec);
			if(!claimed) {
				usleep(1000);
			}
		} while(!claimed);
	}

	assert(pthread_create(&second_stop, NULL, late_stop_call, mesh) == 0);
	await_flag(&stop_waiting);
	release_flag(failed_owner ? &release_join : &release_worker);
	if(!failed_owner) {
		join_bounded(first_stop);
	}
	join_bounded(starting);
	await_flag(&stopper_paused);
	assert(!owner.result && worker_calls == 1 && joins == 1);
	check_idle(mesh);
	pthread_mutex_lock(&mesh->mutex);
	mesh->bb_private.query_id = 42;
	mesh->bb_private.query_hold = true;
	mesh->bb_private.ever_proven = true;
	pthread_mutex_unlock(&mesh->mutex);
	mesh->netns = -1;

	/* Cleanup is still owed by the delayed stop. It must not tear down a
	   new worker's ADNS, outgoings or private-member state. */
	assert(!meshlink_start(mesh));
	release_flag(&release_stopper);
	join_bounded(second_stop);
	check_idle(mesh);
	assert(!mesh->bb_private.query_id && !mesh->bb_private.query_hold && !mesh->bb_private.ever_proven);
	for(unsigned retry = 0; retry < 2; retry++) {
		assert(meshlink_start(mesh));
		assert(meshlink_start(mesh));
		check_running(mesh);
		meshlink_stop(mesh);
		check_idle(mesh);
	}
	observed = NULL;
	meshlink_close(mesh);
	printf("PASS join owner=%s: one join, pending stop blocks start, full cleanup, two healthy restarts\n", failed_owner ? "failed start" : "first stop");
}

int main(void) {
	alarm(120);
	const char *only = getenv("MESHLINK_LIFECYCLE_JOIN_OWNER");
	for(unsigned repeat = 0; repeat < 8; repeat++) {
		if(!only || strcmp(only, "failed-start")) {
			lifecycle_case(false);
		}
		if(!only || !strcmp(only, "failed-start")) {
			lifecycle_case(true);
		}
	}
	return 0;
}
