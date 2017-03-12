#ifndef _CRYPTO_SHA256_H
#define _CRYPTO_SHA256_H

#include <sys/compiler.h>
#include <sys/cpu.h>

#define SHA256_SIZE       32
#define SHA256_HEX_SIZE   65
#define SHA256_BLOCK_SIZE 64

struct sha256 {
	byte data[SHA256_BLOCK_SIZE];
	unsigned int len;
	unsigned int bitlen[2];
	unsigned int state[8];
};

void
sha256_init(struct sha256 *sha256);

void
sha256_update(struct sha256 *sha256, byte data[], unsigned int len);

void
sha256_transform(struct sha256 *sha256, byte data[]);

void
sha256_final(struct sha256 *sha256, byte hash[]);

#endif
