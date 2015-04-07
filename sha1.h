#ifndef sha1_h
#define sha1_h

#include <stddef.h>
#include <stdint.h>

typedef struct {
	size_t index;
	uint32_t hash[5];
	uint64_t total;
	uint8_t block[64];
} sha1_state;

void sha1_start(sha1_state *s);
void sha1_process(sha1_state *s, const void *p, size_t len);
void sha1_finish(sha1_state *s, uint32_t hash[5]);

extern "C" {
	void sha1_compress(uint32_t state[5], const uint8_t block[64]);
}

#endif // sha1_h

