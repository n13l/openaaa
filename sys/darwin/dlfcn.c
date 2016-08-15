/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 Daniel Kubec <niel@rtfm.cz>
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

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <posix/list.h>
#include <link.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

int
dl_iterate_phdr(int (*cb)(struct dl_phdr_info *info, 
                size_t size, void *data), void *data)
{

	for (int i = 0; i < _dyld_image_count(); i++) {
		const struct mach_header *hdr = _dyld_get_image_header(i);
		/* hdr->magic MH_MAGIC: MH_MAGIC_64: */
		intptr_t addr = _dyld_get_image_vmaddr_slide(i);
		Dl_info dl_info;
		if (!dladdr(hdr, &dl_info))
			continue;

		struct dl_phdr_info info = { 
			.dlpi_addr = (void *)addr,
			.dlpi_name = dl_info.dli_fname,
			.dlpi_phdr = hdr,
		};

		cb(&info, 0, data);
	}

	return 1;
}
