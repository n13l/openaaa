/*
 * The MIT License (MIT)                                    IANA Considerations
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
 */



#ifndef __CRYPTO_IANA_H__
#define __CRYPTO_IANA_H__

/* IANA Considerations */
enum iana_sha2_alg_assignments {
/* IANA has made the following IKE hash algorithm attribute assignments: */
   SHA2_256               = 4,
   SHA2_384               = 5,
   SHA2_512               = 6,
/*
 * For IKE Phase 2 negotiations, IANA has assigned the following
 * authentication algorithm identifiers:
 */
   HMAC_SHA2_256          = 5,
   HMAC_SHA2_384          = 6,
   HMAC_SHA2_512          = 7,
/*
 * For use of HMAC-SHA-256+ as a PRF in IKEv2, IANA has assigned the
 * following IKEv2 Pseudo-random function (type 2) transform
 * identifiers:
 */
   PRF_HMAC_SHA2_256      = 5,
   PRF_HMAC_SHA2_384      = 6,
   PRF_HMAC_SHA2_512      = 7,
/*
 * For the use of HMAC-SHA-256+ algorithms for data origin
 * authentication and integrity verification in IKEv2, ESP, or AH, IANA
 * has assigned the following IKEv2 integrity (type 3) transform
 * identifiers:
*/
   AUTH_HMAC_SHA2_256_128 = 12,
   AUTH_HMAC_SHA2_384_192 = 13,
   AUTH_HMAC_SHA2_512_256 = 14   
};

#endif/*__CRYPTO_HMAC_H__*/
