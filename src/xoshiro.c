/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

#include <stdint.h>
#include "xoshiro.h"
#include "logger.h"

/* This is xoshiro256** 1.0, one of our all-purpose, rock-solid
   generators. It has excellent (sub-ns) speed, a state (256 bits) that is
   large enough for any parallel application, and it passes all tests we
   are aware of.

   For generating just floating-point numbers, xoshiro256+ is even faster.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s. */

static inline uint64_t rotl(const uint64_t x, int k) {
	logger(NULL, MESHLINK_INFO, "%s.%d in rotl\n", __func__, __LINE__);
	return (x << k) | (x >> (64 - k));
}

uint64_t xoshiro(uint64_t s[4]) {
	logger(NULL, MESHLINK_INFO, "%s.%d in xoshrio\n", __func__, __LINE__);
	const uint64_t result = rotl(s[1] * 5, 7) * 9;
	logger(NULL, MESHLINK_INFO, "%s.%d << 17\n", __func__, __LINE__);

	const uint64_t t = s[1] << 17;
	logger(NULL, MESHLINK_INFO, "%s.%d some operation\n", __func__, __LINE__);

	s[2] ^= s[0];
	logger(NULL, MESHLINK_INFO, "%s.%d some operation\n", __func__, __LINE__);
	s[3] ^= s[1];
	logger(NULL, MESHLINK_INFO, "%s.%d some operation\n", __func__, __LINE__);
	s[1] ^= s[2];
	logger(NULL, MESHLINK_INFO, "%s.%d some operation\n", __func__, __LINE__);
	s[0] ^= s[3];
	logger(NULL, MESHLINK_INFO, "%s.%d some operation\n", __func__, __LINE__);

	s[2] ^= t;

	logger(NULL, MESHLINK_INFO, "%s.%d s3 before rotl\n", __func__, __LINE__);
	s[3] = rotl(s[3], 45);

	logger(NULL, MESHLINK_INFO, "%s.%d done\n", __func__, __LINE__);
	return result;
}
