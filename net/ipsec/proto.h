/*
 * The MIT License (MIT)                (IPSEC) IP Security Protocol [RFC-4301]
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

#ifndef __NET_PROTO_IPSEC_H__
#define __NET_PROTO_IPSEC_H__

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/unaligned.h>

enum ipsec_alg_type {
	IPSEC_ALG_NONE                 = 0,
	IPSEC_ALG_MD5                  = 1,
	IPSEC_ALG_SHA1                 = 2,
	IPSEC_ALG_SHA256               = 3,
	IPSEC_ALG_SHA384               = 4,
	IPSEC_ALG_SHA512               = 5,
};

enum ipsec_enc_type {	
	IPSEC_ENC_NONE                 = 1,
	IPSEC_ENC_HMAC_MD5             = 2,
	IPSEC_ENC_HMAC_SHA1            = 3,
	IPSEC_ENC_HMAC_SHA256          = 4,
	IPSEC_ENC_HMAC_SHA384          = 5,
	IPSEC_ENC_HMAC_SHA512          = 6,
};

enum ipsec_esp_type {
	IPSEC_ESP_NONE                 = 1,
	IPSEC_ESP_DES                  = 2,
	IPSEC_ESP_3DES                 = 3,
	IPSEC_ESP_RC5                  = 4,
	IPSEC_ESP_CAST128              = 5,
	IPSEC_ESP_BLOWFISH             = 6,
	IPSEC_ESP_RIJNDAEL             = 7,
};

#endif
