/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016, 2017 Daniel Kubec <niel@rtfm.cz>
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

#ifndef __GENERIC_ATTR_H__
#define __GENERIC_ATTR_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <buffer.h>
#include <list.h>

#include <stdarg.h>
#include <stdint.h>

enum xattr_type {
	TYPE_S8      = 1,   /* signed   8bit  interger type: s8   */
	TYPE_S16     = 2,   /* signed   8bit  interger type: s16  */
	TYPE_S32     = 3,   /* signed   8bit  interger type: s32  */
	TYPE_S64     = 4,   /* signed   8bit  interger type: s64  */
	TYPE_U8      = 5,   /* unsigned 8bit  interger type: u8   */
	TYPE_U16     = 6,   /* unsigned 8bit  interger type: u16  */
	TYPE_U32     = 7,   /* unsigned 8bit  interger type: u32  */
	TYPE_U64     = 8,   /* Unsigned 64bit integer  type: u64  */
	TYPE_INT     = 9,   /* signed interger type: int */
	TYPE_UINT    = 10,  /* unsigned interger type: unsigned int */
	TYPE_STRING  = 11,  /* null terminated string        */
	TYPE_BLOB    = 12,  /* byte buffer */
	TYPE_IP      = 13,  /* IP4/6 Address */
	TYPE_HOST    = 14,  /* Hostname */
};

struct xattr {
	enum xattr_type type;
	struct bb key;
	union {
		u8 u8;
		u16 u16;
		u32 u32;
		u64 u64;
		s8 s8;
		s16 s16;
		s32 s32;
		s64 s64;
		unsigned int u;
		int s;
		struct bb bb;
		char *str;
	} val;
};

struct xattr_node {
	struct node node;
	union { struct xattr; };
};

#endif
