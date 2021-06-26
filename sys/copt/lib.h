/*
 * The MIT License (MIT)         
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

#ifndef __COPT_LIB_H__
#define __COPT_LIB_H__

#include <list.h>

#define DECLARE_SECTION_PROLOGUE(name)
#define DECLARE_SECTION_EPILOGUE(name)

#define OPTION_ITEMS(ns) 
#define OPTION_STRING(NAME, REF) (struct option_item) \
	{.name = NAME, .type = TYPE_STRING, .addr = REF }

enum option_type {
	TYPE_S8      = 1,   /* signed   8bit  interger type: s8   */
	TYPE_S16     = 2,   /* signed   8bit  interger type: s16  */
	TYPE_S32     = 3,   /* signed   8bit  interger type: s32  */
	TYPE_S64     = 4,   /* signed   8bit  interger type: s64  */
	TYPE_U8      = 5,   /* unsigned 8bit  interger type: u8   */
	TYPE_U16     = 6,   /* unsigned 8bit  interger type: u16  */
	TYPE_U32     = 7,   /* unsigned 8bit  interger type: u32  */
	TYPE_U64     = 8,   /* Unsigned 64bit integer  type: u64  */
	TYPE_INT     = 9,   /* signed interger type: int */
	TYPE_UINT    = 10,  /* unsigned 8bit interger type: unsigned int */
	TYPE_STRING  = 11,  /* String        */
	TYPE_IP      = 12,  /* IP4/6 Address */
	TYPE_HOST    = 13,  /* IP4/6 Address and port host:port */
};

enum option_attr {
	ATTR_SECTION = 1,
	ATTR_ARY     = 2,
};

enum option_cap {
	OPTION_OVERRIDE_ENV = 1 << 1,
	OPTION_OVERRIDE_ARG = 1 << 2,
};

struct option_item;

struct option_section {
	//struct option_item *items;
	struct dlist items;
};

struct option_item {
	const char *name;
	enum option_type type;
	enum option_attr attr;
	struct node node;
	void *addr;
};

struct options {
	int unused;
};

int
copt_init(int argc, const char *argv[]);

int
copt_load(const char *file);

int
copt_set(const char *path, const char *value);

const char *
copt_get(const char *path);

int
copt_commit(void);

int
copt_rollback(void);

#endif/*__COPT_LIB_H__*/
