#include <sys/compiler.h>
#include <sys/log.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

void 
socket_blocking(int sd)
{
#ifndef CONFIG_WIN32	
	int opts;
	if ((opts = fcntl(sd, F_GETFL)) < 0)
		die("fcntl(F_GETFL)");
	if (fcntl(sd, F_SETFL, (opts & (~O_NONBLOCK))) < 0)
		die("fcntl(F_SETFL)");
	return;
#endif	
}

void 
socket_nblocking(int sd)
{
#ifndef CONFIG_WIN32	
	int opts;
	if ((opts = fcntl(sd, F_GETFL)) < 0)
		die("fcntl(F_GETFL)");
	if (fcntl(sd, F_SETFL, (opts & O_NONBLOCK)) < 0)
		die("fcntl(F_SETFL)");
	return;
#endif	
}

void
socket_reuseaddr(int sd)
{
#ifndef CONFIG_WIN32
	int opts;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opts,sizeof(opts)) < 0)
		die("setsockopt(SO_REUSEADDR) failed");
#endif	
}


