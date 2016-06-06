/*
 * The MIT License (MIT)                MD5 message-digest algorithm [RFC-1351]
 *                               Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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

#ifndef __CRYPTO_MD5_H__
#define __CRYPTO_MD5_H__

#define MD5_SIZE       16
#define MD5_HEX_SIZE   33
#define MD5_BLOCK_SIZE 64

struct md5 {
	u32 buf[4];
	u32 bits[2];
	byte in[64];
};

void
md5_init(struct md5 *md5);

void
md5_update(struct md5 *md5, const byte *buf, unsigned int len);

byte *
md5_final(struct md5 *md5);

void
md5_hash(byte *out, const byte *buf, unsigned int len);

byte *                                                                          
md5_hmac(byte *buf, unsigned int len, byte *key, unsigned int klen);

#endif/*__CRYPTO_MD5_H__*/
