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
#include <sys/compiler.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/locking.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

int
lockf(int fd, int cmd, off_t len)
{
	int stat;
	switch (cmd) {
	case F_LOCK:
		do     stat = _locking(fd, _LK_LOCK, len);
		while (stat == -1 && errno == EDEADLOCK);
		return stat;
	case F_TLOCK:
		return _locking(fd, _LK_NBLCK, len);
	case F_ULOCK:
		return _locking(fd, _LK_UNLCK, len);
	default:
		errno = EINVAL;
		return -1;
	}
}
