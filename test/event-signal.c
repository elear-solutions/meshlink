/* A failed pipe write must neither lose EINTR retries nor permanently coalesce
   later triggers. Exercise the real signal owner with deterministic write faults. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "system.h"
#include "event.h"
#include <assert.h>

static int fail_errno;
static unsigned writes;
static unsigned callbacks;

ssize_t __real_write(int fd, const void *buf, size_t size);
ssize_t __wrap_write(int fd, const void *buf, size_t size);

ssize_t __wrap_write(int fd, const void *buf, size_t size) {
	writes++;
	if(fail_errno) {
		errno = fail_errno;
		fail_errno = 0;
		return -1;
	}
	return __real_write(fd, buf, size);
}

static void received(event_loop_t *loop, void *data) {
	(void)loop;
	(void)data;
	callbacks++;
}

int main(void) {
	event_loop_t loop = {0};
	signal_t sig = {0};
	event_loop_init(&loop);
	signal_add(&loop, &sig, received, NULL, 1);

	fail_errno = EINTR;
	errno = EDOM;
	signal_trigger(&loop, &sig);
	assert(errno == EDOM && writes == 2);
	loop.signalio.cb(&loop, NULL, IO_READ);
	assert(callbacks == 1);

	fail_errno = EAGAIN;
	errno = ERANGE;
	signal_trigger(&loop, &sig);
	assert(errno == ERANGE && writes == 3);
	loop.signalio.cb(&loop, NULL, IO_READ);
	assert(callbacks == 1);
	signal_trigger(&loop, &sig);
	assert(writes == 4);
#ifdef HAVE_STDATOMIC_H
	signal_trigger(&loop, &sig);
	assert(writes == 4); /* Successful triggers still coalesce. */
#endif
	loop.signalio.cb(&loop, NULL, IO_READ);
	assert(callbacks == 2);
	/* Exactly one billion nanoseconds must carry into the seconds field;
	   otherwise a later pselect can receive an invalid timeout. */
	timeout_t timer = {0};
	loop.now = (struct timespec) {100, 500000000};
	struct timespec delay = {0, 500000000};
	timeout_add(&loop, &timer, received, NULL, &delay);
	assert(timer.tv.tv_sec == 101 && timer.tv.tv_nsec == 0);
	timeout_del(&loop, &timer);

	delay = (struct timespec) {0, 1};
	timeout_add(&loop, &timer, received, NULL, &delay);
	timeout_del(&loop, &timer);
	assert(timer.tv.tv_sec == 0 && timer.tv.tv_nsec == 0);
	signal_del(&loop, &sig);
	event_loop_exit(&loop);
	return 0;
}
