#include <sys/compiler.h>
#include <sys/log.h>
#include <getopt.h>

#include <aaa/prv.h>
#include <aaa/lib.h>

#ifdef KBUILD_STR
#undef KBUILD_STR
#endif

#define KBUILD_STR(s) #s

static const char *options = "scvV";

static struct option long_options[] = {
        {"server",   no_argument, 0, 's'},
        {"client",   no_argument, 0, 'c'},
        {"verbose",  no_argument, 0, 'v'},
        {"help",     no_argument, 0, 'h'},
        {"version",  no_argument, 0, 'V'},
        {0,          0,           0,  0 }
};

static void
usage(void)
{
	printf("aaa utility v%s\n", PACKAGE_VERSION);
}

int
main(int argc, char *argv[])
{
        int endpoint = 0, c, index = 0;

        do {
                c = getopt_long (argc, argv, options, long_options, &index);
                /* the end of the options. */
                if (c == -1)
                        break;
                switch (c) {
                case 0:
                        /* If this option set a flag, do nothing else now. */
                        if (long_options[index].flag != 0)
                                break;
                        printf ("option %s", long_options[index].name);
                        if (optarg)
                                printf (" with arg %s", optarg);
                        printf ("\n");
                        break;
                case 's': endpoint = 1; break;
                case 'c': endpoint = 0; break;
                case 'v': log_verbose++; break;
                case 'V': info("version: %s", PACKAGE_VERSION); break;
                case '?':
		case 'h':
                        usage();
                        break;
                default:
                        die("wrong arguments");
                }
        } while(1);

        if (endpoint == 1 && aaa_server)
                return aaa_server(argc, argv);

        return 0;
}
