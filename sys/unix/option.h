/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Daniel Kubec <niel@rtfm.cz>
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

#ifndef __GENERIC_GETOPT_H__
#define __GENERIC_GETOPT_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/unaligned.h>

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

enum c_types {
	C_U8     = 1,
	C_U16    = 2,
	C_U32    = 3,
	C_U64    = 4,
	C_S8     = 5,
	C_S16    = 6,
	C_S32    = 7,
	C_S64    = 8,
	C_INT    = 9,
	C_UINT   = 10,
	C_STRING = 11,
};

enum c_rules {
	C_REQUIRED = 1,
	C_OPTIONAL = 2,
};

enum c_mapping {
	int env;
	int opt;
	int cfg;
};

struct c_section {
	int unused;
};

#define DEFINE_SECTION(name) 
#define DEFINE_OPTION(name)

#endif
