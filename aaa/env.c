#include <sys/compiler.h>
#include <sys/log.h>
#include <aaa/lib.h>
#include <aaa/prv.h>

#ifndef CONFIG_WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

const char *aaad_ip = "127.0.0.1";
const char *aaad_host;

void
aaa_env_init(void)
{
        aaad_host = getenv("OPENAAA_SERVICE");
/*
#ifndef CONFIG_WIN32
        struct hostent *hostent = gethostbyname(aaad_host);
        if (!hostent)
                return;

        struct in_addr addr = *(struct in_addr*) hostent->h_addr_list[0];
        char *ip = inet_ntoa(addr);
        if (!ip)
                return;
#endif
*/
	const char *logf = getenv("OPENAAA_LOG_FILE");
	const char *logc = getenv("OPENAAA_LOG_CAPS");
	const char *logv = getenv("OPENAAA_VERBOSE");

	logf = logf ? logf: "syslog";

	if (logc)
		log_setcaps(atoi(logc));
	if (logv)
		log_verbose = atoi(logv);

	log_open(logf, LOG_AUTHPRIV);

	if (aaad_host) {
		debug1("aaa.service.ip=%s", aaad_host);
        	aaad_ip = strdup(aaad_host);
	}
}

void
aaa_env_fini(void)
{
	log_close();
}
