#include <sys/compiler.h>
#include <sys/log.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <net/tls/conf.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

void
aaa_config_load(struct aaa *c)
{
	const char *file = getenv("OPENAAA_CONF");
	debug("config file load(%s):%d", file, 0);

}
