/*
 * The MIT License (MIT)
 *                               Copyright (c) 2017 Daniel Kubec <niel@rtfm.cz> 
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
#include <list.h>

#include <copt/lib.h>
#include <getopt.h>

static char *string = "string";

struct section_example1 {
	char *host;
	int port;
};
/*
#define OPTION_ITEM(T) \
        (struct node*) ({ struct option_item o = {.node = INIT_NODE, .type = T }; &o.node; })

static struct option_section section = {
	.items.head = OPTION_ITEM(1)
};
*/
/*
static struct option_section section = {
	.items = &OPTION_STRING("value", &string)
};
*/
static const char *options = "V";

static struct option long_options[] = {
        {"version",  no_argument, 0, 'V'},
        {0,          0,           0,  0 }
};

static void
usage(void)
{
	struct node *node = OPTION_ITEM(1);
}

int
main(int argc, char *argv[])
{
/*	
	copt_setcap(OPTION_OVERRIDE_ENV | OPTION_OVERRIDE_ARG);
*/	
        do {
		int index = 0;
                int c = getopt_long(argc, argv, options, long_options, &index);
                if (c == -1)
                        break;
                switch (c) {
                case 'V':
			break;
		default:
			break;
		}
	} while(1);

	return 0;
}
