/*
 * The MIT License (MIT)                                         TLS Extensions
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

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <net/tls/ext.h>

static const char *__tls_ext_names[] = {
	[TLS_EXT_RENEGOTIATE]            = "renegotiate",
	[TLS_EXT_HEARTBEAT]              = "heartbeat",      
	[TLS_EXT_EC_POINT_FORMATS]       = "ec_point_formats",
	[TLS_EXT_SERVER_NAME]            = "server_name",
	[TLS_EXT_MAX_FRAGMENT_LENGTH]    = "max_fragmet_length",
	[TLS_EXT_CLIENT_CERTIFICATE_URL] = "client_certificate_url",
	[TLS_EXT_TRUSTED_CA_KEYS]        = "trusted_ca_keys",
	[TLS_EXT_TRUNCATED_HMAC]         = "truncated_hmac",
	[TLS_EXT_STATUS_REQUEST]         = "status_request",
	[TLS_EXT_USER_MAPPING]           = "user_mapping",
	[TLS_EXT_CLIENT_AUTHZ]           = "client_authz",
	[TLS_EXT_SERVER_AUTHZ]           = "server_authz",
	[TLS_EXT_CERT_TYPE]              = "cert_type",
	[TLS_EXT_ELLIPTIC_CURVES]        = "elliptic_curves",
	[TLS_EXT_SRP]                    = "srp",
	[TLS_EXT_SIGNATURE_ALGORITHMS]   = "signature_algorithms",
	[TLS_EXT_USE_SRTP]               = "use_srtp",
	[TLS_EXT_SESSION_TICKET]         = "session_ticket",
	[TLS_EXT_NEXT_PROTO_NEG]         = "next_proto_neg"
};

const char *                                                                    
tls_strext(enum tls_ext_e type)
{
	return __tls_ext_names[type];
}
