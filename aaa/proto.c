#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/stack.h>
#include <mem/pool.h>
#include <list.h>
#include <dict.h>
#include <hash.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h> 
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>                                                         
#include <netinet/in.h>                                                         
#include <arpa/inet.h>

static int port = 8888;

static int
attr_enc(byte *buf, int len, int maxlen, const char *key, const char *val)
{
	if (len < 0)
		return len;

	int klen = strlen(key), vlen = strlen(val);
	int linelen = klen + 1 + vlen + 1;

	if (len + linelen > maxlen)
		return -1;
	buf += len;
	memcpy(buf, key, klen);
	buf += klen;
	*buf++ = ':';
	memcpy(buf, val, vlen);
	buf += vlen;
	*buf = '\n';
	return linelen;
}

static int
udp_build(struct aaa *aaa, const char *op, byte *buf, int size)
{
	int len = 0;
	len += attr_enc(buf, len, size, "msg.op", op);
	len += attr_enc(buf, len, size, "msg.id", "1");

	dict_for_each(a, aaa->attrs.list) {
		len += attr_enc(buf, len, size, a->key, a->val);
	}

	return len;
}

static int 
udp_parse(struct aaa *aaa, byte *packet, unsigned int len)
{
        debug2("\n%s", packet);
	byte *ptr = packet, *end = packet + len;
	while (packet < end) {
		byte *key = packet;
		while (packet < end && *packet != ':' && *packet != '\n')
			packet++;
		if (packet >= end)
			return -1;
		if (*packet != ':')
			return packet - ptr;
		*packet++ = 0;
		byte *value = packet;
		while (packet < end && *packet != '\n')
			packet++;
		if (packet >= end)
			return -1;
		*packet++ = 0;

		debug2("%s:%s", key, value);
/*
		if (!strncasecmp(key, "sess.id", 4))
			msg->sid = value;
		if (!strncasecmp(key, "user.id", 4))
			msg->uid = value;
*/
		if (strncasecmp(key, "msg.", 4)) {
			aaa_attr_set(aaa, key, value);
			continue;
		}
/*
		if (!strcasecmp(key, "msg.op"))
			msg->op = value;
		else if (!strcasecmp(key, "msg.id"))
			msg->id = value;
*/		
	}
	return len;
}


int
udp_bind(struct aaa *aaa, int type, const char *id)
{
        int fd = 1;
        byte packet[8192];
        memset(packet, 0, sizeof(packet));

        int size = udp_build(aaa, "bind", packet, sizeof(packet) - 1);

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		die("Cannot create UDP socket: %s", strerror(errno));

	int one = 1;
	if (setsockopt(fd , SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("Cannot set SO_REUSEADDR: %s", strerror(errno));

	struct timeval tv = {.tv_sec = 10, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv,sizeof(tv)) < 0)
		die("SO_RCVTIMEO");

	struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = inet_addr("127.0.0.1")
	};

	socklen_t len = sizeof(in);
	
        int sent = sendto(fd, packet, size, 0, &in, len);
	if (sent < 0)
	        error("sendto failed: reason=%s ", strerror(errno));
	else if (sent < size)
		error("sendto sent partial packet (%d of %d bytes)", sent, (int)size);

        char *v = printfa("%s:%d", inet_ntoa(in.sin_addr), ntohs(in.sin_port));
        debug2("%s sent %d byte(s)", v, sent);

        memset(packet, 0, sizeof(packet));
	ssize_t recved = recvfrom(fd, packet, sizeof(packet) - 1, MSG_TRUNC, &in, &len);
	if (recved < 0) {
	        error("recvfrom failed: reason=%s ", strerror(errno));
                goto cleanup;
        }

        debug2("%s recv %jd byte(s)", v, (intmax_t)recved);
        udp_parse(aaa, packet, (unsigned int)recved);

cleanup:        
        if (fd != -1)
                close(fd);

        return 0;
}
