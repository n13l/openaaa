#include <sys/compiler.h>
#include <sys/log.h>
#include <getopt.h>
#include <list.h>
#include <aaa/prv.h>
#include <aaa/lib.h>

#ifdef KBUILD_STR
#undef KBUILD_STR
#endif

#define KBUILD_STR(s) #s

const char *pid_file = "/var/run/aaa/daemon.pid";
const char *log_file = "syslog";

int caps = 0;

static const char *options = "scvVl:o:";

static struct option long_options[] = {
	{"server",   no_argument, 0, 's'},
	{"client",   no_argument, 0, 'c'},
	{"verbose",  no_argument, 0, 'v'},
	{"help",     no_argument, 0, 'h'},
	{"version",  no_argument, 0, 'V'},
	{"log-file", 0, 0, 'l'},
	{"pid-file", 0, 0, 'p'},
	{"log-caps", 0, 0, 'o'},
        {0,          0,           0,  0 }
};

static void
usage(void)
{
	printf("usage: aaa [options] <cmd>\n");
	printf("\noptions: \n");
	printf("\t-s, --server        Server \n");
	printf("\t-c, --client        Client \n");
	printf("\t-v, --verbose       Make the operation more talkative. " 
	                              "(such as: -v, -vv, -vvv, -vvvv)\n");
	printf("\t-S, --silent        Silent mode (don't output anything)\n");
	printf("\t-f, --cfg-file      Configuration file. (default: /etc/aaa ~/.aaa/default)\n");
	printf("\t-p, --pid-file      PID file. (default: /var/run/aaa/daemon.pid)\n");
	printf("\t-l, --log-file      Values: stdout, stderr, syslog or filename (default: syslog)\n");
	printf("\t-o, --log-caps      Bit mask of loggin capabilities\n");
	printf("\t-h, --help          This Usage\n");
	printf("\t-V, --version       Show version number and quit\n");
	printf("\nserver options:\n");
	printf("\t-a, --accept        Listener's parameters\n");
	printf("\nserver commands: \n");

	exit(0);
}

int
main(int argc, char *argv[])
{
	int endpoint = 0, c, index = 0;

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
		case 's': endpoint = 1; break;
		case 'c': endpoint = 0; break;
		case 'v': log_verbose++; break;
		case 'V': printf("version: %s", PACKAGE_VERSION); break;
		case 'l': log_file = optarg; break;
		case 'o': caps = atoi(optarg); break;
		case '?':
		case 'h':
			usage();
			break;
		default:
			die("wrong arguments");
		}
	} while(1);

/*
	log_open(log_file, LOG_AUTHPRIV);
	log_setcaps(caps);
*/
	if (endpoint == 1 && aaa_server)
		return aaa_server(argc, argv);

	usage();
	return 0;
}
