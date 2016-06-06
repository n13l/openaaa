/*                                                                              
 * The MIT License (MIT)            (SCTP) Stream Control Transmission Protocol 
 *                                                  Daniel Kubec <niel@rtfm.cz> 
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
#include <net/ipsec/proto.h>

_unused static const char * const ipsec_alg_names[] = {
	[IPSEC_ALG_NONE]               = "none",
	[IPSEC_ALG_MD5]                = "md5",
	[IPSEC_ALG_SHA1]               = "sha1",
	[IPSEC_ALG_SHA256]             = "sha256",
	[IPSEC_ALG_SHA384]             = "sha384",
	[IPSEC_ALG_SHA512]             = "sha512",

};

_unused static const char * const ipsec_esp_names[] = {
	[IPSEC_ESP_NONE]               = "none",
	[IPSEC_ESP_DES]                = "des-cbc",
	[IPSEC_ESP_3DES]               = "3des-cbc",
	[IPSEC_ESP_RC5]                = "rc5-cbc",
	[IPSEC_ESP_CAST128]            = "cast128-cbc",
	[IPSEC_ESP_BLOWFISH]           = "blowfish-cbc",
	[IPSEC_ESP_RIJNDAEL]           = "rijndael-cbc",
};

_unused static const char * const ipsec_cmp_names[] = {
	"none",
	"oui",
	"deflate",
	"lzs", 
};

_unused static const char *ipsec_msg_names[] = {
	"reserved", "getspi", "update", "add", "delete",
	"get", "acquire", "register", "expire", "flush",
	"dump", "x_promisc", "x_pchange", "x_spdupdate", "x_spdadd",
	"x_spddelete", "x_spdget", "x_spdacquire", "x_spddump", "x_spdflush",
	"x_spdsetidx", "x_spdexpire", "x_spddelete2"
};
