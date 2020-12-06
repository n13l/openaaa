/*
 * The MIT License (MIT)         Copyright (c) 2016 Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"),to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#ifndef __CRYPTO_ECC_H__
#define __CRYPTO_ECC_H__

#include <sys/compiler.h>

__BEGIN_DECLS

enum {
	ECC_GROUP_NONE        = 0,
	ECC_GROUP_T163K1      = 1,
	ECC_GROUP_SECP192K1   = 18,
	ECC_GROUP_SECP192R1   = 19,
	ECC_GROUP_SECP224R1   = 20,
	ECC_GROUP_SECP256R1   = 23,
	ECC_GROUP_SECP384R1   = 24,
	ECC_GROUP_SECP521R1   = 25,
	ECC_GROUP_X25519      = 29,
	ECC_GROUP_X448        = 30,
	ECC_GROUP_LAST
};

typedef void (*fn_ecc_key_pair)(u8 *public_key, u8 *private_key);
typedef void (*fn_ecc_key_exchange)(const u8 *peer, const u8 *sec, u8 *shared);

struct ecc_group {
	const char *name;
	unsigned int id;
	unsigned int pub_key_len;
	unsigned int prv_key_len;
	unsigned int size;
	void (*key_pair)(u8 *public_key, u8 *private_key);
	void (*key_exchange)(const u8 *peer, const u8 *secret, u8 *shared);
	void (*derive)(const u8* pubkey, const u8 *secret, u8 *shared);
	void (*public_from_private)(const u8* public_key, u8 *private_key);
};

void crypto_ecc_group_register(struct ecc_group *);

/**
 * crypto_ecc_group_by_id()
 *
 * O(1) time branchless memory access
 *
 * @id:             the unique identifier of group.
 *
 */

struct ecc_group *crypto_ecc_group_by_id(unsigned int id);

__END_DECLS

#endif
