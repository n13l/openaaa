/*                                                                              
 * The MIT License (MIT)                       Memory Management debug facility
 *
 * Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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

#ifndef __MM_DEBUG_H__
#define __MM_DEBUG_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <unix/timespec.h>

#define MM_ADDR_POISON1  ((void *) 0x00100100)
#define MM_ADDR_POISON2  ((void *) 0x00200200)

#ifdef CONFIG_DEBUG_MEMPOOL
#define mem_pool_dbg(fmt, ...) debug(fmt, __VA_ARGS__);
#define mem_dbg(fmt, ...) debug(fmt, __VA_ARGS__);
#else
#define mem_pool_dbg(fmt, ...) do { } while(0)
#define mem_dbg(fmt, ...) do { } while(0)
#endif

#ifdef CONFIG_DEBUG_MEMSTACK
#define mem_stack_dbg(fmt, ...) debug(fmt, __VA_ARGS__);
#else
#define mem_stack_dbg(fmt, ...) do { } while(0)
#endif

#endif
