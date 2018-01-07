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

#ifndef CONFIG_WIN32
#include <sys/socket.h>                                                         
#include <netinet/in.h>                                                         
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

static int port = 8888;
static int sched_workers = 4;

static int
attr_enc(byte *buf, int len, int maxlen, char *key, char *val)
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
udp_build(struct aaa *aaa, char *op, byte *buf, int size)
{
	int len = 0;
	len += attr_enc(buf, len, size, "msg.op", op);
	len += attr_enc(buf, len, size, "msg.id", "1");

	dict_for_each(a, aaa->attrs.list) {
                /* debug4("attr %s %s", a->key, a->flags & ATTR_CHANGED ? "changed" : ""); */
                if (!(a->flags & ATTR_CHANGED))
                        continue;
		len += attr_enc(buf, len, size, a->key, a->val);
	}

	return len;
}

static int 
udp_parse(struct aaa *aaa, byte *packet, unsigned int len)
{
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

		if (!strncmp(key, "msg.", 4))
                        continue;

                dict_set_nf(&aaa->attrs, key, value);
	}
	return len;
}

int
udp_bind(struct aaa *aaa)
{
        int fd = 1;
        byte packet[8192];
        memset(packet, 0, sizeof(packet));

        int size = udp_build(aaa, "bind", packet, sizeof(packet) - 1);
	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		die("Cannot create UDP socket: %s", strerror(errno));

	int one = 1;
	if (setsockopt(fd , SOL_SOCKET, SO_REUSEADDR, (const void *)&one, sizeof(one)) < 0)
		die("Cannot set SO_REUSEADDR: %s", strerror(errno));

	struct timeval tv = {.tv_sec = 10, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv,sizeof(tv)) < 0)
		die("SO_RCVTIMEO");

	u32 hash = hash_string(aaa->sid);
	int index = hash % sched_workers;
	debug4("id=%s hash=%d index=%d", aaa->sid, (int)hash, index);

	struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(port + index),
		.sin_addr.s_addr = inet_addr(aaad_ip)
	};

	socklen_t len = sizeof(in);
	
        int sent = sendto(fd, packet, size, 0, (struct sockaddr * )&in, len);
	if (sent < 0)
	        error("sendto failed: reason=%s ", strerror(errno));
	else if (sent < size)
		error("sendto sent partial packet (%d of %d bytes)", sent, (int)size);

        char *v = printfa("%s:%d", inet_ntoa(in.sin_addr), ntohs(in.sin_port));
        debug2("%s sent %d byte(s)", v, sent);

        memset(packet, 0, sizeof(packet));
	ssize_t recved = recvfrom(fd, packet, sizeof(packet) - 1, MSG_TRUNC, 
                                  (struct sockaddr *)&in, &len);
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

int
udp_commit(struct aaa *aaa)
{
        int fd = 1;
        byte packet[8192];
        memset(packet, 0, sizeof(packet));

        int size = udp_build(aaa, "commit", packet, sizeof(packet) - 1);
	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		die("Cannot create UDP socket: %s", strerror(errno));

	int one = 1;
	if (setsockopt(fd , SOL_SOCKET, SO_REUSEADDR, (const void *)&one, sizeof(one)) < 0)
		die("Cannot set SO_REUSEADDR: %s", strerror(errno));

	struct timeval tv = {.tv_sec = 10, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv,sizeof(tv)) < 0)
		die("SO_RCVTIMEO");

	u32 hash = hash_string(aaa->sid);
	int index = hash % sched_workers;
	debug4("id=%s hash=%d index=%d", aaa->sid, (int)hash, index);

	struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(port + index),
		.sin_addr.s_addr = inet_addr(aaad_ip)
	};

	socklen_t len = sizeof(in);
        int sent = sendto(fd, packet, size, 0, (struct sockaddr *)&in, len);
	if (sent < 0)
	        error("sendto failed: reason=%s ", strerror(errno));
	else if (sent < size)
		error("sendto sent partial packet (%d of %d bytes)", sent, (int)size);

        char *v = printfa("%s:%d", inet_ntoa(in.sin_addr), ntohs(in.sin_port));
        debug2("%s sent %d byte(s)", v, sent);

        memset(packet, 0, sizeof(packet));
	ssize_t recved = recvfrom(fd, packet, sizeof(packet) - 1, MSG_TRUNC, 
                                  (struct sockaddr *)&in, &len);
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
