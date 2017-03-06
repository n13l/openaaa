/*
 * The MIT License (MIT)                     (TLS) The Transport Layer Security 
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

#ifndef __NET_PROTO_TLS_EXT_H__
#define __NET_PROTO_TLS_EXT_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/unaligned.h>

enum tls_ext_e {
	TLS_EXT_SERVER_NAME            = 0,
	TLS_EXT_MAX_FRAGMENT_LENGTH    = 1,
	TLS_EXT_CLIENT_CERTIFICATE_URL = 2,
	TLS_EXT_TRUSTED_CA_KEYS        = 3,
	TLS_EXT_TRUNCATED_HMAC         = 4,
	TLS_EXT_STATUS_REQUEST         = 5,
	TLS_EXT_USER_MAPPING           = 6,
	TLS_EXT_CLIENT_AUTHZ           = 7,
	TLS_EXT_SERVER_AUTHZ           = 8,
	TLS_EXT_CERT_TYPE              = 9,
	TLS_EXT_ELLIPTIC_CURVES        = 10,
	TLS_EXT_EC_POINT_FORMATS       = 11,
	TLS_EXT_SRP                    = 12,
	TLS_EXT_SIGNATURE_ALGORITHMS   = 13,
	TLS_EXT_USE_SRTP               = 14,
	TLS_EXT_HEARTBEAT              = 15,
	TLS_EXT_PADDING                = 21,
	TLS_EXT_SESSION_TICKET         = 35,
	TLS_EXT_OPAQUE_PRF_INPUT       = 38183,
	TLS_EXT_RENEGOTIATE            = 0xff01,
	TLS_EXT_NEXT_PROTO_NEG         = 13172,
	TLS_EXT_SUPPLEMENTAL_DATA      = 1000,
	TLS_EXT_CHANNEL_ID             = 30032,
	TLS_EXT_ALPN                   = 16,
	TLS_EXT_EXTENDED_MASTER_SECRET = 23,
};

const char *
tls_strext(enum tls_ext_e type);

#endif
