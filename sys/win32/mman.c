/*
 * The MIT License (MIT)                            Daniel Kubec <niel@rtfm.cz>
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

#include <windows.h>
#include <errno.h>
#include <io.h>
#include <sys/mman.h>

#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE 0x0020
#endif/*FILE_MAP_EXECUTE*/

static int
__map_mman_error(const u32 err, const int deferr)
{
	if (err == 0)
		return 0;
	return err;
}

static u32
__map_mmap_prot_page(const int prot)
{
	u32 protect = 0;

	if (prot == PROT_NONE)
		return protect;

	if ((prot & PROT_EXEC) != 0) {
		protect = ((prot & PROT_WRITE) != 0) ? 
		PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
	} else {
		protect = ((prot & PROT_WRITE) != 0) ?
		PAGE_READWRITE : PAGE_READONLY;
	}

	return protect;
}

static u32
__map_mmap_prot_file(const int prt)
{
	u32 acc = 0;

	if (prt == PROT_NONE)
		return acc;
	if ((prt & PROT_READ) != 0)
		acc |= FILE_MAP_READ;
	if ((prt & PROT_WRITE) != 0)
		acc |= FILE_MAP_WRITE;
	if ((prt & PROT_EXEC) != 0)
		acc |= FILE_MAP_EXECUTE;

	return acc;
}

void *
mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
	HANDLE fm, h;

	void *map = MAP_FAILED;
	const u32 offlow    = (sizeof(off_t) <= sizeof(u32)) ? 
	                      (u32)off : (u32)(off & 0xFFFFFFFFL);
	const u32 offhigh   = (sizeof(off_t) <= sizeof(u32)) ?
	                      (u32)0 : (u32)((off >> 32) & 0xFFFFFFFFL);
	const u32 protect   = __map_mmap_prot_page(prot);
	const u32 acc       = __map_mmap_prot_file(prot);
	const off_t maxSize = off + (off_t)len;

	const u32 msizelow  = (sizeof(off_t) <= sizeof(u32)) ? 
	                      (u32)maxSize : (u32)(maxSize & 0xFFFFFFFFL);
	const u32 msizehi   = (sizeof(off_t) <= sizeof(u32)) ?
	                      (u32)0 : (u32)((maxSize >> 32) & 0xFFFFFFFFL);

	errno = 0;

	if (len == 0 || (flags & MAP_FIXED) != 0 || prot == PROT_EXEC) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	h = ((flags & MAP_ANONYMOUS) == 0) ? 
	(HANDLE)_get_osfhandle(fildes) : INVALID_HANDLE_VALUE;

	if ((flags & MAP_ANONYMOUS) == 0 && h == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return MAP_FAILED;
	}

	fm = CreateFileMapping(h, NULL, protect, msizehi, msizelow, NULL);

	if (fm == NULL) {
		errno = __map_mman_error(GetLastError(), EPERM);
		return MAP_FAILED;
	}

	map = MapViewOfFile(fm, acc, offhigh, offlow, len);
	CloseHandle(fm);

	if (map == NULL) {
		errno = __map_mman_error(GetLastError(), EPERM);
		return MAP_FAILED;
	}

	return map;
}

int
munmap(void *addr, size_t len)
{
	if (UnmapViewOfFile(addr))
		return 0;

	errno =  __map_mman_error(GetLastError(), EPERM);
	return -1;
}

void *
mremap(void *addr, size_t size, size_t nsize, int mode)
{
	return NULL;
}

int
mprotect(void *addr, size_t len, int prot)
{
	u32 n = __map_mmap_prot_page(prot);
	DWORD o = 0;

	if (VirtualProtect(addr, len, n, &o))
		return 0;

	errno =  __map_mman_error(GetLastError(), EPERM);
	return -1;
}

int
msync(void *addr, size_t len, int flags)
{
	if (FlushViewOfFile(addr, len))
		return 0;
	errno =  __map_mman_error(GetLastError(), EPERM);
	return -1;
}

int
mlock(const void *addr, size_t len)
{
	if (VirtualLock((LPVOID)addr, len))
		return 0;
	errno =  __map_mman_error(GetLastError(), EPERM);
    
	return -1;
}

int
munlock(const void *addr, size_t len)
{
	if (VirtualUnlock((void *)addr, len))
		return 0;
        
	errno =  __map_mman_error(GetLastError(), EPERM);
	return -1;
}
