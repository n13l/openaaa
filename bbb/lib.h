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

#ifndef __HTTP2_LIB_PUBLIC_H__
#define __HTTP2_LIB_PUBLIC_H__

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <limits.h>

/* A private structures containing the aaa context */
struct http2;
typedef void (*callback_t)(int arg, void *userdata);

/* public api functions */

struct http2 *
http2_new(void);

void
http2_free(struct http2 *);

int
http2_connect(struct http2 *http2, const char *uri);

int
http2_disconnect(struct http2 *http2);

int
http2_read(struct http2 *http2, char *buf, int size);
	
int
http2_write(struct http2 *http2, char *buf, int size);

int 
http2_attr_set(struct http2 *, const char *attr, const char *value);

const char *
http2_attr_get(struct http2 *, const char *attr);

#endif
