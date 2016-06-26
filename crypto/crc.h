/*
 * CRC32 (Castagnoli 1993) -- Tables
 *
 * Based on Michael E. Kounavis and Frank L. Berry: A Systematic Approach
 * to Building High Performance Software-based CRC Generators
 * (Proceedings of the 10th IEEE Symposium on Computers and Communications 2005)
 *
 * Includes code from http://sourceforge.net/projects/slicing-by-8/,
 * which carried the following copyright notice:
 *
 * Copyright (c) 2004-2006 Intel Corporation - All Rights Reserved
 *
 * This software program is licensed subject to the BSD License,
 * available at http://www.opensource.org/licenses/bsd-license.html
 */

#ifndef __CRYPTO_CRC_H__
#define __CRYPTO_CRC_H__

enum crc32_mode {
	CRC_MODE_DEFAULT,/* Default algorithm (4K table) */
	CRC_MODE_SMALL,  /* Optimize for small data (1K table) */
	CRC_MODE_BIG,    /* Optimize for large data (8K table) */
	CRC_MODE_MAX,
};

struct crc32 {
	unsigned int state;
	void (*update)(struct crc32 *, const byte *, unsigned int);
};

void
crc32_init(struct crc32 *crc32, unsigned int mode);

void
crc32_update(struct crc32 *crc32, const byte *buf, unsigned int len);

u32
crc32_final(struct crc32 *crc32);

u32
crc32_hash(const byte *buf, unsigned int len);

#endif
