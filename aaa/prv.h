/*
 * (AAA) Autentication, Authorisation and Accounting) Library
 *
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
 */

#ifndef __AAA_PRV_H__
#define __AAA_PRV_H__

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <mem/pool.h>

#include <dict.h>

struct aaa {
	struct mm_pool *mp;
	struct mm_pool *mp_attrs;
	struct dict attrs;
	const char *config;
};

struct msg {
	struct aaa *aaa;
	int status;
	const char *id;
	const char *op;
	const char *sid;
	const char *uid;
};

void aaa_config_load(struct aaa *c);
int session_init(void);
int session_fini(void);
int session_bind(struct aaa *aaa, const char *id, int type);
int session_select(struct aaa *aaa, const char *id);
int session_commit(struct aaa *aaa, const char *id);
int session_touch(struct aaa *aaa, const char *id);

int
udp_bind(struct aaa *aaa, int type, const char *id);

int
udp_commit(struct aaa *aaa);

extern int (*aaa_server)(int argc, char *argv[]);

#endif
