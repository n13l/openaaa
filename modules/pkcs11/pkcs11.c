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
#include <sys/link.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <crypto/pkcs11.h>

#define CK_VERSION_MAJOR 2
#define CK_VERSION_MINOR 22

#define LIBRARY_DESC    "OpenAAA PKCS11 Module"
#define MANUFACTURER_ID "OpenAAA"
#define SLOT_DESC       "OpenAAA PKCS11 Slot"

static unsigned long
pkcs11_initialize(void *args)
{
	return CKR_OK;
}
                                                                                
static unsigned long
pkcs11_finalize(void *args)
{
	return CKR_OK;
}
                                                                                
static unsigned long
pkcs11_get_info(struct ck_info *info)
{
	return CKR_OK;
}
                                                                                
static unsigned long
pkcs11_get_slot_list(bool present, ck_slot_id *id, ck_ulong *count)
{
	*count = 0;
	return 0;
}
                                                                                
static unsigned long
pkcs11_get_slot_info(ck_ulong id, struct ck_slot_info *slot)
{
	return 0;
}
                                                                                
static unsigned long
pkcs11_get_token_info(ck_ulong id, struct ck_token_info *token)
{
	return 0;
}
                                                                                
static unsigned long
pkcs11_get_mechanism_list(ck_ulong id, ck_ulong *type, ck_ulong *count)
{
	return 0;
}
                                                                                
static unsigned long
pkcs11_get_mechanism_info(ck_ulong id, ck_ulong type, struct ck_mechanism_info *info)
{
	return 0;
}

static unsigned long
pkcs11_init_token(ck_ulong id, byte *pin, ck_ulong len, byte *label)
{
	return 0;
}

static unsigned long
pkcs11_open_session(ck_ulong id, ck_flags flags, void *app, ck_notify fn, ck_ulong *s)
{
	return CKR_TOKEN_NOT_PRESENT;
}

static unsigned long
pkcs11_close_session(ck_ulong session)
{
	return CKR_TOKEN_NOT_PRESENT;
}

static unsigned long
pkcs11_close_all_sessions(ck_ulong id)
{
	return CKR_TOKEN_NOT_PRESENT;
}

static unsigned long
pkcs11_get_function_status(ck_ulong id)
{
	return CKR_OK;
}

static unsigned long
pkcs11_cancel_function(ck_ulong id)
{
	return CKR_OK;
}

static unsigned long
pkcs11_wait_for_slot_event(ck_flags flags, ck_ulong *slot, void *a)
{
	return CKR_NO_EVENT;
}

struct pkcs11_entry {
	struct ck_version version;
	void *initialize;
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
};

static struct pkcs11_entry pkcs11_entry = {
	.version             = { 
		.major = CK_VERSION_MAJOR, 
		.minor = CK_VERSION_MINOR
	},
	.initialize          = pkcs11_initialize,
	.finalize            = pkcs11_finalize,
	.get_info            = pkcs11_get_info,
	.get_slot_list       = pkcs11_get_slot_list,
	.get_slot_info       = pkcs11_get_slot_info,
	.get_token_info      = pkcs11_get_token_info,
	.get_mechanism_list  = pkcs11_get_mechanism_list,
	.get_mechanism_info  = pkcs11_get_mechanism_info,
	.init_token          = pkcs11_init_token,
	.open_session        = pkcs11_open_session,
	.close_session       = pkcs11_close_session,
	.close_all_sessions  = pkcs11_close_all_sessions,
	.get_function_status = pkcs11_get_function_status,
	.cancel_function     = pkcs11_cancel_function,
	.wait_for_slot_event = pkcs11_wait_for_slot_event,
};

EXPORT(unsigned long)
C_GetFunctionList(void **list)
{                                                                               
	*list = (void **)&pkcs11_entry;
	return CKR_OK;                                                          
}
