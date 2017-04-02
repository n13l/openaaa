/*
 *                                                  Daniel Kubec <niel@rtfm.cz>
 * The MIT License (MIT)
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
#include <mem/page.h>
#include <mem/pool.h>
#include <mem/stack.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#ifdef KBUILD_STR
#undef KBUILD_STR
#endif

#define KBUILD_STR(s) #s


_unused static struct option long_options[] = {
	{"cpu-caps", no_argument, 0, 0  },
	{"cpu-info", no_argument, 0, 0  },
	{"sys-info", no_argument, 0, 0  },
	{"mem-test", no_argument, 0, 0  },
	{"version",  no_argument, 0, 'v'},
	{0,          0,           0,  0 }
};

static void 
info_cpu(void)
{
	_unused const char *vendor = cpu_vendor();
	cpu_dump_extension();

}

static void 
info_sys(void)
{
	info("sys.platform=%s", CONFIG_PLATFORM);
	info("sys.stack.avail=%d", 0);
	info("sys.sizeof int=%d", (int)sizeof(int));
	info("sys.sizeof long=%d", (int)sizeof(long));
	info("sys.sizeof long long int=%d", (int)sizeof(long long int));
	info("sys.sizeof ptr=%d", (int)sizeof(void *));
}

int
main(int argc, char *argv[])
{
	printf("sysconfig v%s %s/%s %s " __TIME__ " " __DATE__  "\n", 
	       PACKAGE_VERSION, CONFIG_PLATFORM, CONFIG_SRCARCH, CONFIG_ARCH);

	info_cpu();
	info_sys();

	return 0;
}
