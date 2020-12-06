/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015                               Daniel Kubec <niel@rtfm.cz>
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
 */

#include <sys/compiler.h>
#include <bsd/array.h>
#include <crypto/ecc.h>
#include <stdio.h>

static void none_key_pair(u8 *public_key, u8 *private_key) {}
static void none_key_exch(const u8 *peer_key, const u8 *secret, u8* shared) {}
static void none_derive(const u8* seed, const u8 *public, u8 *shared) {}

struct ecc_group none_ecc = {
	.name = "none_ecc",
	.id = ECC_GROUP_NONE,
	.pub_key_len = 0,
	.prv_key_len = 0,
	.size = 0,
	.key_pair = none_key_pair,
	.key_exchange = none_key_exch,
	.derive = none_derive,
};

/* O(1) time branchless memory access. */
DEFINE_STATIC_ARRAY_ALIGNED_8BIT(struct ecc_group *, ecc_group, &none_ecc);

void
crypto_ecc_group_register(struct ecc_group *group)
{
	unsigned int index = ecc_group_index(group->id);
	if (ecc_group[index] != NULL && ecc_group[index] != &none_ecc)
		return;
	ecc_group[index] = group;
}

struct ecc_group *
crypto_ecc_group_by_id(unsigned int id)
{
	return ecc_group_fetch(id);
}

void ecc_x25519_init(void);
void ecc_secp256r1_init(void);
void ecc_secp384r1_init(void);

void
crypto_init_ecc_groups(void)
{
	ecc_x25519_init();
	ecc_secp256r1_init();
	ecc_secp384r1_init();
}
