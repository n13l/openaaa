/*
 * HOTPLUG Interface for CPU, Memory and other devices
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

#ifndef __HOTPLUG_PRV_H__
#define __HOTPLUG_PRV_H__

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>

#include <sys/compiler.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <mem/page.h>

#include <hotplug/lib.h>

struct plugable_cpu;
struct plugable_mem;
struct plugable_usb;

/* A private structures containing the aaa context */
struct hotplug {
	struct mempool *mp;
	hotplug_event event;
	struct plugable_usb *cpu;
	struct plugable_usb *mem;
	struct plugable_usb *usb;
	const char *jclass;
};

int
plugable_usb_init(struct hotplug *hotplug);

int                                                                             
plugable_usb_wait(struct hotplug *hotplug);

int
plugable_usb_fini(struct hotplug *hotplug);

#endif
