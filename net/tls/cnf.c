
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <mem/list.h>

#include <net/tls/proto.h>
#include <net/tls/conf.h>

struct cf_tls_rfc5705 cf_tls_rfc5705 = {
	.context = "OpenAAA",
	.label   = "EXPORTER_AAA",
	.length  = 8
};

