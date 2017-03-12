/*
 * SHA-1 Hash Function (FIPS 180-1, RFC 3174)
 */

#ifndef __CRYPTO_SHA1_H__
#define __CRYPTO_SHA1_H__

#include <sys/compiler.h>
#include <sys/cpu.h>

#define SHA1_SIZE  20
#define SHA1_BLOCK 64

struct sha1 {
	u32 h0,h1,h2,h3,h4;
	u32 nblocks;
	byte buf[SHA1_BLOCK];
	int count;
};

struct sha1_digest {
	byte hash[SHA1_SIZE];
};

void
sha1_init(struct sha1 *sha1); 

void
sha1_update(struct sha1 *sha1, const byte *buf, unsigned int len);

byte *
sha1_final(struct sha1 *sha1);

void
sha1_hash(struct sha1_digest *digest, const byte *buf, unsigned int len);

#endif
