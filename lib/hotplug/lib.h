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

#ifndef __HOTPLUG_LIB_H__
#define __HOTPLUG_LIB_H__

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>

#define HOTPLUG_TYPE_CPU      1 
#define HOTPLUG_TYPE_MEM      2
#define HOTPLUG_TYPE_USB      4

#define HOTPLUG_EVENT_ARRIVED 1
#define HOTPLUG_EVENT_LEFT    2

/* API version, they compare as integers */
#define API_VERSION PACKAGE_VERSION

/* A private structures containing the aaa context */
struct hotplug;

typedef int (*hotplug_event)(int type, int msg, const char *info);

/* Generic HOTPLUG Interface */
struct hotplug *
hotplug_init(void);

int
hotplug_wait(struct hotplug *hotplug);

void 
hotplug_fini(struct hotplug *hotplug);

#endif
