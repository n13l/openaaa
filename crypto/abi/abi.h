/*
 * The MIT License (MIT)                                ABI SSL Runtime Support 
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
 *
 * Pseudorandom functions are deterministic functions which return pseudorandom
 * output indistinguishable from random sequences.
 *
 * They are made based on pseudorandom generators but contrary to them, in 
 * addition to the internal state, they can accept any input data. The input 
 * may be arbitrary but the output must always look completely random.
 *
 * A pseudorandom function, which output is indistinguishable from random 
 * sequences, is called a secure one.
 */

#ifndef __ABI_SSL_PLATFORM_H__
#define __ABI_SSL_PLATFORM_H__

#include <sys/compiler.h>
#include <sys/abi.h>

struct abi_crypto_openssl {
	struct abi_version version;
	defn_abi_call(long,         SSLeay, void);
	defn_abi_call(const char *, SSLeay_version, int);
};

extern struct abi_crypto_openssl abi_crypto_openssl;

#endif/*__ABI_SSL_PLATFORM_H__*/
