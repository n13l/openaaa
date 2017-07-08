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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN    
 * THE SOFTWARE.                                                                
 */

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <sys/dll.h>
#include <mem/stack.h>
#include <crypto/hex.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <crypto/pkcs11.h>

#include <crypto/abi/lib.h>

#define PKCS11_MAJOR 2
#define PKCS11_MINOR 20
/* #define PKCS11_MINOR 22 */

#define CK_VERSION(X, Y) \
	(struct ck_version) { .major = X, .minor = Y };

#define CK_STRING(str, value) \
	strpadl(str,  sizeof(str),  ' ', value)
 
#define LIBRARY_DESC "OpenAAA PKCS11 Module"
#define MANUFACTURER "OpenAAA"
#define SLOT_DESC    "OpenAAA PKCS11 Slot"

#undef KBUILD_MODNAME
#define KBUILD_MODNAME "pkcs11"

/* __attribute__((__stdcall__)) */
static unsigned long  
C_Initialize(void *args)
{
	printf("initialize\n");
	fflush(stdout);

	crypto_lookup();
	return CKR_OK;
}
                                                                                
static unsigned long
finalize(void *args)
{
	return CKR_OK;
}

int
spadr(char *buf, size_t size, int pad, char *str)
{
	int len = size - strlen(str);
	if(len < 0) len = 0;

	char *padding = alloca(size);
	memset(padding, pad, size);
	return snprintf(buf, size, "%*.*s%s", len, len, padding, str);
}

int
strpadl(char *buf, size_t size, int pad, char *str)
{
	int len = size - strlen(str);
	if(len < 0) len = 0;

	char *padding = alloca(size);
	memset(padding, pad, size);
	return snprintf(buf, size, "%s%*.*s", str, len, len, padding);
}

static unsigned long
get_info(struct ck_info *info)
{
	/* 
	 * PKCS #11: CRYPTOGRAPHIC TOKEN INTERFACE STANDARD
	 *
	 * Character-string must be padded with the blank character (‘ ‘). 
	 * Should not be null-terminated
	 */

	CK_STRING(info->description,  LIBRARY_DESC);
	CK_STRING(info->manufacturer, MANUFACTURER);

	info->library = CK_VERSION(1, 0);
	info->crypto  = CK_VERSION(PKCS11_MAJOR, PKCS11_MINOR);
	info->flags = 0;

	debug("crypto version=%d.%d", info->crypto.major, info->crypto.minor);

	return CKR_OK;
}
                                                                                
static unsigned long
get_slot_list(bool present, ck_slot_id *id, ck_ulong *count)
{
	*count = present ? 0 : 1;
	if (!id) 
		return CKR_OK;

	*id = (ck_slot_id)0x1234;
	return CKR_OK;
}
                                                                                
static unsigned long
get_slot_info(ck_ulong id, struct ck_slot_info *slot)
{
	char *v = evala(memhex, (byte *)&id, sizeof(id));
	debug("id=%s", v);

	CK_STRING(slot->description,  LIBRARY_DESC);
	CK_STRING(slot->manufacturer, MANUFACTURER);

	slot->firmware = CK_VERSION(1, 0);
	slot->hardware = CK_VERSION(1, 0);
	slot->flags    = CKF_REMOVABLE_DEVICE;

	return CKR_OK;
}
                                                                                
static unsigned long
get_token_info(ck_ulong id, struct ck_token_info *token)
{
	char *v = evala(memhex, (byte *)&id, sizeof(id));
	debug("id=%s", v);
	return CKR_OK;
}
                                                                                
static unsigned long
get_mechanism_list(ck_ulong id, ck_ulong *type, ck_ulong *count)
{
	debug("pkcs11");
	return CKR_OK;
}
                                                                                
static unsigned long
get_mechanism_info(ck_ulong id, ck_ulong type, struct ck_mechanism_info *info)
{
	debug("pkcs11");
	return CKR_OK;
}

static unsigned long
init_token(ck_ulong id, byte *pin, ck_ulong len, byte *label)
{
	debug("pkcs11");
	return CKR_OK;
}

static unsigned long
open_session(ck_ulong id, ck_flags flags, void *app, ck_notify fn, ck_ulong *s)
{
	debug("pkcs11");
	return CKR_TOKEN_NOT_PRESENT;
}

static unsigned long
close_session(ck_ulong session)
{
	debug("pkcs11");
	return CKR_TOKEN_NOT_PRESENT;
}

static unsigned long
close_all_sessions(ck_ulong id)
{
	debug("pkcs11");
	return CKR_TOKEN_NOT_PRESENT;
}

static unsigned long
get_function_status(ck_ulong id)
{
	debug("pkcs11");
	return CKR_OK;
}

static unsigned long
cancel_function(ck_ulong id)
{
	debug("pkcs11");
	return CKR_OK;
}

static unsigned long
wait_for_slot_event(ck_flags flags, ck_ulong *slot, void *a)
{
	debug("pkcs11");
	return CKR_NO_EVENT;
}

struct ck_function_list {
	struct ck_version version;
	__typeof__(C_Initialize) *C_Initialize;
	void *finalize;
	void *get_info;
	void *get_function_list;
	void *get_slot_list;
	void *get_slot_info;
	void *get_token_info;
	void *get_mechanism_list;
	void *get_mechanism_info;
	void *init_token;
	void *open_session;
	void *close_session;
	void *close_all_sessions;
	void *get_function_status;
	void *cancel_function;
	void *wait_for_slot_event;
}  __attribute__((gcc_struct, packed)); 

struct ck_function_list ck_function_list = {
	.version             = {.major = PKCS11_MAJOR, .minor = PKCS11_MINOR},
	.C_Initialize        = C_Initialize,
	.finalize            = finalize,
	.get_info            = get_info,
	.get_slot_list       = get_slot_list,
	.get_slot_info       = get_slot_info,
	.get_token_info      = get_token_info,
	.get_mechanism_list  = get_mechanism_list,
	.get_mechanism_info  = get_mechanism_info,
	.init_token          = init_token,
	.open_session        = open_session,
	.close_session       = close_session,
	.close_all_sessions  = close_all_sessions,
	.get_function_status = get_function_status,
	.cancel_function     = cancel_function,
	.wait_for_slot_event = wait_for_slot_event,
}; 

EXPORT(unsigned long) 
C_GetFunctionList(struct ck_function_list **vtbl) 
{
	*vtbl = &ck_function_list;
	return CKR_OK;                                                          
}
