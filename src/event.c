/*
    event.c -- I/O, timeout and signal event handling
    Copyright (C) 2014-2017 Guus Sliepen <guus@meshlink.io>

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

#include "dropin.h"
#include "event.h"
#include "net.h"
#include "splay_tree.h"
#include "utils.h"
#include "xalloc.h"
#include "logger.h"

static int io_compare(const io_t *a, const io_t *b) {
	return a->fd - b->fd;
}

static int timeout_compare(const timeout_t *a, const timeout_t *b) {
	struct timeval diff;
	timersub(&a->tv, &b->tv, &diff);

	if(diff.tv_sec < 0) {
		return -1;
	}

	if(diff.tv_sec > 0) {
		return 1;
	}

	if(diff.tv_usec < 0) {
		return -1;
	}

	if(diff.tv_usec > 0) {
		return 1;
	}

	if(a < b) {
		return -1;
	}

	if(a > b) {
		return 1;
	}

	return 0;
}

void io_add(event_loop_t *loop, io_t *io, io_cb_t cb, void *data, int fd, int flags) {
	assert(!io->cb);

	io->fd = fd;
	io->cb = cb;
	io->data = data;
	io->node.data = io;

	io_set(loop, io, flags);

	splay_node_t *node = splay_insert_node(&loop->ios, &io->node);
	assert(node);
	(void)node;
}

void io_set(event_loop_t *loop, io_t *io, int flags) {
	assert(io->cb);

	io->flags = flags;

	if(flags & IO_READ) {
		FD_SET(io->fd, &loop->readfds);
	} else {
		FD_CLR(io->fd, &loop->readfds);
	}

	if(flags & IO_WRITE) {
		FD_SET(io->fd, &loop->writefds);
	} else {
		FD_CLR(io->fd, &loop->writefds);
	}
}

void io_del(event_loop_t *loop, io_t *io) {
	assert(io->cb);

	loop->deletion = true;

	io_set(loop, io, 0);

	splay_unlink_node(&loop->ios, &io->node);
	io->cb = NULL;
}

void timeout_add(event_loop_t *loop, timeout_t *timeout, timeout_cb_t cb, void *data, struct timeval *tv) {
	timeout->cb = cb;
	timeout->data = data;
	timeout->node.data = timeout;

	timeout_set(loop, timeout, tv);
}

void timeout_set(event_loop_t *loop, timeout_t *timeout, struct timeval *tv) {
	assert(timeout->cb);

	if(timerisset(&timeout->tv)) {
		splay_unlink_node(&loop->timeouts, &timeout->node);
	}

	if(!loop->now.tv_sec) {
		gettimeofday(&loop->now, NULL);
	}

	timeradd(&loop->now, tv, &timeout->tv);

	if(!splay_insert_node(&loop->timeouts, &timeout->node)) {
		abort();
	}

	loop->deletion = true;
}

static void timeout_disable(event_loop_t *loop, timeout_t *timeout) {
	splay_unlink_node(&loop->timeouts, &timeout->node);
	timeout->tv = (struct timeval) {
		0, 0
	};
}

void timeout_del(event_loop_t *loop, timeout_t *timeout) {
	if(!timeout->cb) {
		return;
	}

	if(timerisset(&timeout->tv)) {
		timeout_disable(loop, timeout);
	}

	timeout->cb = NULL;
	loop->deletion = true;
}

static int signal_compare(const signal_t *a, const signal_t *b) {
	return (int)a->signum - (int)b->signum;
}

static void signalio_handler(event_loop_t *loop, void *data, int flags) {
	(void)data;
	(void)flags;
	unsigned char signum;

	if(read(loop->pipefd[0], &signum, 1) != 1) {
		return;
	}

	signal_t *sig = splay_search(&loop->signals, &(signal_t) {
		.signum = signum
	});

	if(sig) {
		sig->cb(loop, sig->data);
	}
}

static void pipe_init(event_loop_t *loop) {
	int result = pipe(loop->pipefd);
	assert(result == 0);

	if(result == 0) {
		io_add(loop, &loop->signalio, signalio_handler, NULL, loop->pipefd[0], IO_READ);
	}
}

static void pipe_exit(event_loop_t *loop) {
	io_del(loop, &loop->signalio);

	close(loop->pipefd[0]);
	close(loop->pipefd[1]);

	loop->pipefd[0] = -1;
	loop->pipefd[1] = -1;
}

void signal_trigger(event_loop_t *loop, signal_t *sig) {
	uint8_t signum = sig->signum;
	write(loop->pipefd[1], &signum, 1);
	return;
}

void signal_add(event_loop_t *loop, signal_t *sig, signal_cb_t cb, void *data, uint8_t signum) {
	assert(!sig->cb);

	sig->cb = cb;
	sig->data = data;
	sig->signum = signum;
	sig->node.data = sig;

	if(loop->pipefd[0] == -1) {
		pipe_init(loop);
	}

	if(!splay_insert_node(&loop->signals, &sig->node)) {
		abort();
	}
}

void signal_del(event_loop_t *loop, signal_t *sig) {
	assert(sig->cb);

	loop->deletion = true;

	splay_unlink_node(&loop->signals, &sig->node);
	sig->cb = NULL;

	if(!loop->signals.count && loop->pipefd[0] != -1) {
		pipe_exit(loop);
	}
}

void idle_set(event_loop_t *loop, idle_cb_t cb, void *data) {
	loop->idle_cb = cb;
	loop->idle_data = data;
}

bool event_loop_run(event_loop_t *loop, pthread_mutex_t *mutex) {
	assert(mutex);

	fd_set readable;
	fd_set writable;

	logger(NULL, MESHLINK_INFO, "%s.%d before entering while loop\n", __func__, __LINE__);
	while(loop->running) {
	logger(NULL, MESHLINK_INFO, "%s.%d gettimeoftheday\n", __func__, __LINE__);
		gettimeofday(&loop->now, NULL);
		struct timeval diff, it, *tv = NULL;

	logger(NULL, MESHLINK_INFO, "%s.%d while loop->timeouts.head\n", __func__, __LINE__);
		while(loop->timeouts.head) {
	logger(NULL, MESHLINK_INFO, "%s.%d timeout = loop->timeouts.head->data\n", __func__, __LINE__);
			timeout_t *timeout = loop->timeouts.head->data;
	logger(NULL, MESHLINK_INFO, "%s.%d timersub\n", __func__, __LINE__);
			timersub(&timeout->tv, &loop->now, &diff);

	logger(NULL, MESHLINK_INFO, "%s.%d if diff.tv_sec < 0\n", __func__, __LINE__);
			if(diff.tv_sec < 0) {
	logger(NULL, MESHLINK_INFO, "%s.%d timeout_disable\n", __func__, __LINE__);
				timeout_disable(loop, timeout);
	logger(NULL, MESHLINK_INFO, "%s.%d invoking timeout callback\n", __func__, __LINE__);
				timeout->cb(loop, timeout->data);
	logger(NULL, MESHLINK_INFO, "%s.%d invoked timeout callback\n", __func__, __LINE__);
			} else {
				tv = &diff;
				break;
			}
	logger(NULL, MESHLINK_INFO, "%s.%d end of the timeouts while loop\n", __func__, __LINE__);
		}

	logger(NULL, MESHLINK_INFO, "%s.%d if loop->idle_cb\n", __func__, __LINE__);
		if(loop->idle_cb) {
	logger(NULL, MESHLINK_INFO, "%s.%d it = loop->idle_cb\n", __func__, __LINE__);
			it = loop->idle_cb(loop, loop->idle_data);

	logger(NULL, MESHLINK_INFO, "%s.%dit.tv_sec >= 0\n", __func__, __LINE__);
			if(it.tv_sec >= 0 && (!tv || timercmp(&it, tv, <))) {
				tv = &it;
			}
		}

	logger(NULL, MESHLINK_INFO, "%s.%d memcpy readble\n", __func__, __LINE__);
		memcpy(&readable, &loop->readfds, sizeof(readable));
	logger(NULL, MESHLINK_INFO, "%s.%d memcpy writedble\n", __func__, __LINE__);
		memcpy(&writable, &loop->writefds, sizeof(writable));

		int fds = 0;

	logger(NULL, MESHLINK_INFO, "%s.%d if loop->ios.tail\n", __func__, __LINE__);
		if(loop->ios.tail) {
	logger(NULL, MESHLINK_INFO, "%s.%d last = loop->ios.tail\n", __func__, __LINE__);
			io_t *last = loop->ios.tail->data;
	logger(NULL, MESHLINK_INFO, "%s.%d last->fd + 1\n", __func__, __LINE__);
			fds = last->fd + 1;
		}

		// release mesh mutex during select
	logger(NULL, MESHLINK_INFO, "%s.%d pthread_mutex_unlock\n", __func__, __LINE__);
		pthread_mutex_unlock(mutex);

	logger(NULL, MESHLINK_INFO, "%s.%d select\n", __func__, __LINE__);
		int n = select(fds, &readable, &writable, NULL, tv);

	logger(NULL, MESHLINK_INFO, "%s.%d pthread_mutex_lock\n", __func__, __LINE__);
		pthread_mutex_lock(mutex);

	logger(NULL, MESHLINK_INFO, "%s.%d gettimeofday\n", __func__, __LINE__);
		gettimeofday(&loop->now, NULL);

	logger(NULL, MESHLINK_INFO, "%s.%d if n < 0\n", __func__, __LINE__);
		if(n < 0) {
	logger(NULL, MESHLINK_INFO, "%s.%d if sockwouldblock\n", __func__, __LINE__);
			if(sockwouldblock(errno)) {
				continue;
			} else {
				return false;
			}
		}

		if(!n) {
			continue;
		}

		// Normally, splay_each allows the current node to be deleted. However,
		// it can be that one io callback triggers the deletion of another io,
		// so we have to detect this and break the loop.

	logger(NULL, MESHLINK_INFO, "%s.%d loop->deletion = false\n", __func__, __LINE__);
		loop->deletion = false;

	logger(NULL, MESHLINK_INFO, "%s.%d spley each io\n", __func__, __LINE__);
		for splay_each(io_t, io, &loop->ios) {
	logger(NULL, MESHLINK_INFO, "%s.%d if FD_ISSET\n", __func__, __LINE__);
			if(FD_ISSET(io->fd, &writable) && io->cb) {
	logger(NULL, MESHLINK_INFO, "%s.%d before io->cb\n", __func__, __LINE__);
				io->cb(loop, io->data, IO_WRITE);
	logger(NULL, MESHLINK_INFO, "%s.%d io->cb done\n", __func__, __LINE__);
			}

	logger(NULL, MESHLINK_INFO, "%s.%d loop->deletion\n", __func__, __LINE__);
			if(loop->deletion) {
	logger(NULL, MESHLINK_INFO, "%s.%d break\n", __func__, __LINE__);
				break;
			}

	logger(NULL, MESHLINK_INFO, "%s.%d if FD_ISSET\n", __func__, __LINE__);
			if(FD_ISSET(io->fd, &readable) && io->cb) {
	logger(NULL, MESHLINK_INFO, "%s.%d before io->cb\n", __func__, __LINE__);
				io->cb(loop, io->data, IO_READ);
	logger(NULL, MESHLINK_INFO, "%s.%d io->cb done\n", __func__, __LINE__);
			}

	logger(NULL, MESHLINK_INFO, "%s.%d loop->deletion\n", __func__, __LINE__);
			if(loop->deletion) {
	logger(NULL, MESHLINK_INFO, "%s.%d break\n", __func__, __LINE__);
				break;
			}
		}
	}

	logger(NULL, MESHLINK_INFO, "%s.%d returnig event\n", __func__, __LINE__);
	return true;
}

void event_flush_output(event_loop_t *loop) {
	for splay_each(io_t, io, &loop->ios)
		if(FD_ISSET(io->fd, &loop->writefds)) {
			io->cb(loop, io->data, IO_WRITE);
		}
}

void event_loop_start(event_loop_t *loop) {
	loop->running = true;
}

void event_loop_stop(event_loop_t *loop) {
	loop->running = false;
}

void event_loop_init(event_loop_t *loop) {
	loop->ios.compare = (splay_compare_t)io_compare;
	loop->timeouts.compare = (splay_compare_t)timeout_compare;
	loop->signals.compare = (splay_compare_t)signal_compare;
	loop->pipefd[0] = -1;
	loop->pipefd[1] = -1;
	gettimeofday(&loop->now, NULL);
}

void event_loop_exit(event_loop_t *loop) {
	assert(!loop->ios.count);
	assert(!loop->timeouts.count);
	assert(!loop->signals.count);

	for splay_each(io_t, io, &loop->ios) {
		splay_unlink_node(&loop->ios, node);
	}

	for splay_each(timeout_t, timeout, &loop->timeouts) {
		splay_unlink_node(&loop->timeouts, node);
	}

	for splay_each(signal_t, signal, &loop->signals) {
		splay_unlink_node(&loop->signals, node);
	}
}
