/*
 * $id: ssl.c                               Daniel Kubec <niel@rtfm.cz>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#undef HAVE_STRING_H
#undef PACKAGE_NAME
#undef PACKAGE_VERSION

#include <stdlib.h>
#include <unistd.h>
#include <httpd/ap_config.h>
#include <httpd/ap_socache.h>
#include <apr_strings.h>
#include <httpd/httpd.h>
#include <httpd/http_config.h>
#include <httpd/http_connection.h>
#include <httpd/http_core.h>
#include <httpd/http_log.h>
#include <httpd/http_main.h>
#include <httpd/http_request.h>
#include <httpd/http_protocol.h>
#include <httpd/util_filter.h>
#include <httpd/util_script.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>

#ifdef PACKAGE_VERSION
#undef PACKAGE_VERSION
#endif

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <list.h>
#include <mem/map.h>
#include <mem/page.h>
#include <mem/stack.h>
#include <crypto/sha1.h>
#include <aaa/lib.h>

#include "mod_openaaa.h"
#include "private.h"
#include "optional.h"

#define BASE64_ENC_LENGTH(x) (((x)+2)/3 *4)

#define SHA1_SIZE 20 /** Size of the SHA1 hash in its binary representation **/
#define SHA1_HEX_SIZE 41 /** Buffer length for a string containing SHA1 in hexadecimal format. **/
#define SHA1_BLOCK_SIZE 64 /** SHA1 splits input to blocks of this size. **/

#include <stdlib.h>
#include <openssl/bn.h>
   
char *
BN_to_binary(BIGNUM *b, unsigned int *outsz) 
{
	char *ret = NULL;
/*	    
	*outsz = BN_num_bytes(b);
	if (BN_is_negative(b)) {
		(*outsz)++;
		if (!(ret = (char *)malloc(*outsz))) return 0;
		BN_bn2bin(b, (unsigned char *)ret + 1);
		ret[0] = 0x80;
	} else {
		if (!(ret = (char *)malloc(*outsz))) return 0;
		BN_bn2bin(b, (unsigned char *)ret);
		printf("positive\n");
	}
*/	
	return ret;
}

char *
base64(const byte *input, int length)
{
	char *buff = NULL;
/*
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);
*/
	return buff;
}

char *
ap_x509_pubkey_from_cert(apr_pool_t *p, const char *b, unsigned int size)
{
	char *pub = NULL;
/*
	BIO *bio = BIO_new(BIO_s_mem()); 
	BIO_puts(bio,b); 
	X509 *x = PEM_read_bio_X509(bio, NULL, 0, NULL);

	if (!x)
		goto cleanup;

	EVP_PKEY *key = X509_get_pubkey(x);
	if (!key)
		goto cleanup;

	char *pub = NULL;

#define PEM_BEGIN "-----BEGIN PUBLIC KEY-----"
#define PEM_END   "-----END PUBLIC KEY-----"

#ifndef OPENSSL_NO_RSA
	if (key->type == EVP_PKEY_RSA && key->pkey.rsa != NULL && 
	    key->pkey.rsa->n != NULL) {
		BIO *brsa = BIO_new(BIO_s_mem());
		PEM_write_bio_RSA_PUBKEY(brsa, key->pkey.rsa);

		BUF_MEM *bptr;
		BIO_get_mem_ptr(brsa, &bptr);
		pub = apr_palloc(p, bptr->length + 1);
		memcpy(pub, bptr->data, bptr->length);
		pub[bptr->length] = 0;

		if (!strncasecmp(pub, PEM_BEGIN, strlen(PEM_BEGIN)))
			pub += strlen(PEM_BEGIN);
#define KEY_LENGTH 2048
		int l = BASE64_ENC_LENGTH(((KEY_LENGTH / 8)) + 
		                          strlen(PEM_BEGIN)) + 23;
		pub[l] = 0;
		pub++;
		BIO_free(brsa);
		goto cleanup;
	}
#endif
#ifndef OPENSSL_NO_DSA
	if (key->type == EVP_PKEY_DSA && key->pkey.dsa != NULL && 
	    key->pkey.dsa->p != NULL) {
		char *bn = BN_bn2hex(key->pkey.dsa->p);
		pub = apr_pstrdup(p, bn);
		OPENSSL_free(bn);
		goto cleanup;
	}
#endif

cleanup:
	if (key)
		EVP_PKEY_free(key);
	if (x)
		X509_free(x);

	BIO_free(bio);
*/	
	return pub;
}

char *
ap_keying_material_pubkey_derivate(apr_pool_t *p, const char *key, const char *pub)
{
	struct sha1 sha1;
	sha1_init(&sha1);

	sha1_update(&sha1, (byte *)key, strlen(key));
	sha1_update(&sha1, (byte *)pub, strlen(pub));

	char *hash = (char *)sha1_final(&sha1);
	char *sec  = apr_palloc(p, SHA1_HEX_SIZE);
	//mem_to_hex(sec, hash, SHA1_SIZE, 0);
	return sec;
}
