/*
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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
 * SHA-1 Hash Function (FIPS 180-1, RFC 3174) 
 * SHA-1 HMAC Message Authentication Code (RFC 2202)
 */

#ifndef _CRYPTO_SHA1_H
#define _CRYPTO_SHA1_H

#include <sys/compiler.h>
#include <sys/cpu.h>

#define SHA1_SIZE       20
#define SHA1_HEX_SIZE   41
#define SHA1_BLOCK_SIZE 64

struct sha1;
struct sha1_hmac;

void
sha1_init(struct sha1 *sha1); 

void
sha1_update(struct sha1 *sha1, const byte *buf, unsigned int len);

byte *
sha1_final(struct sha1 *sha1);

void
sha1_hash(byte *outbuf, const byte *buf, unsigned int len);

void
sha1_hmac(byte *buf, const byte *key, unsigned int klen, 
          const byte *data, unsigned int dlen);

void
sha1_hmac_init(struct sha1_hmac *hmac, const byte *key, unsigned int len);

void
sha1_hmac_update(struct sha1_hmac *hmac, const byte *data, unsigned int len);

byte *
sha1_hmac_final(struct sha1_hmac *hmac);

#endif
