/*
 * The MIT License (MIT)                                 (IP) Internet Protocol
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
 */

#ifndef __NET_PROTO_IP_H__
#define __NET_PROTO_IP_H__

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/unaligned.h>

#ifndef IP4_HEADER_SIZE
#define IP4_HEADER_SIZE 20
#endif

#ifndef IP6_HEADER_SIZE
#define IP6_HEADER_SIZE 40
#endif

struct ip_peer {
	struct sockaddr_in6 sa;
	socklen_t len;
	char name[INET6_ADDRSTRLEN];
	int fd;
};

#endif
