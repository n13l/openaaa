#include <sys/compiler.h>
#include <sys/log.h>
#include <getopt.h>
#include <bbb/prv.h>
#include <bbb/lib.h>

#ifdef KBUILD_STR
#undef KBUILD_STR
#endif
#define KBUILD_STR(s) #s

static const char *options = "scvVl:o:";

static struct option long_options[] = {
	{"verbose",  no_argument, 0, 'v'},
	{"help",     no_argument, 0, 'h'},
	{"version",  no_argument, 0, 'V'},
        {0,          0,           0,  0 }
};

static void
usage(void)
{
	printf("usage: http2 [options] <cmd>\n");
	printf("\noptions: \n");

	exit(0);
}

int
main(int argc, char *argv[])
{
        int c, index;
	do {
		c = getopt_long (argc, argv, options, long_options, &index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			if (long_options[index].flag != 0)
				break;
			printf ("option %s", long_options[index].name);
			if (optarg)
				printf (" with arg %s", optarg);
			printf ("\n");
			break;
		case 'v': log_verbose++; break;
		case 'V': printf("version: %s", PACKAGE_VERSION); break;
		case '?':
		case 'h':
			usage();
			break;
		default:
			die("wrong arguments");
		}
	} while(1);

	usage();
	return 0;
}
