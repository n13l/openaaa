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
        if (!(aaad_host = getenv("OPENAAA_SERVICE")))
                return;

#ifndef CONFIG_WIN32
        struct hostent *hostent = gethostbyname(aaad_host);
        if (!hostent)
                return;

        struct in_addr addr = *(struct in_addr*) hostent->h_addr_list[0];
        char *ip = inet_ntoa(addr);
        if (!ip)
                return;

        info("aaa.service.ip=%s", ip);
        aaad_ip = strdup(ip);

#endif
}

void
aaa_env_fini(void)
{
}
