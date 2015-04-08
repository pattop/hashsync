#include "sha1.h"

#include <string.h>

#define min(a, b) ({ \
	__typeof__(a) _a = (a); \
	__typeof__(b) _b = (b); \
	_a < _b ? _a : _b; \
})

#ifndef UINT32_C
#define UINT32_C(c) c##UL
#endif

void sha1_start(sha1_state *s)
{
	s->index = 0;
	s->hash[0] = UINT32_C(0x67452301);
	s->hash[1] = UINT32_C(0xEFCDAB89);
	s->hash[2] = UINT32_C(0x98BADCFE);
	s->hash[3] = UINT32_C(0x10325476);
	s->hash[4] = UINT32_C(0xC3D2E1F0);
	s->total = 0;
}

void sha1_process(sha1_state *s, const void *vp, size_t len)
{
	const uint8_t *p = static_cast<const uint8_t *>(vp);

	if (s->index != 0) {
		const size_t blkrem = min(64 - s->index, len);
		memcpy(s->block + s->index, p, blkrem);
		s->index += blkrem;
		s->total += blkrem;
		len -= blkrem;
		p += blkrem;
		if (s->index == 64) {
			sha1_compress(s->hash, s->block);
			s->index = 0;
		}
	}

	if (len == 0)
		return;

	size_t i;
	for (i = 0; len - i >= 64; i += 64)
		sha1_compress(s->hash, p + i);

	const size_t rem = len - i;
	if (rem > 0) {
		memcpy(s->block, p + i, rem);
		s->index = rem;
	}

	s->total += len;
}

void sha1_finish(sha1_state *s, uint32_t hash[5])
{
	s->block[s->index] = 0x80;
	++s->index;
	if (64 - s->index >= 8)
		memset(s->block + s->index, 0, 56 - s->index);
	else {
		memset(s->block + s->index, 0, 64 - s->index);
		sha1_compress(s->hash, s->block);
		memset(s->block, 0, 56);
	}

	uint64_t len = s->total << 3;
	for (unsigned i = 0; i < 8; i++)
		s->block[64 - 1 - i] = (uint8_t)(len >> (i * 8));
	sha1_compress(s->hash, s->block);

	memcpy(hash, s->hash, sizeof(s->hash));
}

