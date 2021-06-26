#include <sys/compiler.h>
#include <sys/log.h>
#include <list.h>
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
		goto cleanup;

	int klen = strlen(key), vlen = strlen(val);
	int linelen = klen + 1 + vlen + 1;

	if (len + linelen + 1 > maxlen)
		goto cleanup;
	buf += len;
	memcpy(buf, key, klen);
	buf += klen;
	*buf++ = ':';
	memcpy(buf, val, vlen);
	buf += vlen;
	*buf = '\n';
	buf++;
	*buf = 0;
	return linelen;
cleanup:
	error("attr encode key: %s val: <%s> len: %d failed", key, val, len);
	return 0;
}

int
udp_validate(u8 *packet, int size)
{
/*
	if (size < 6 || strncmp(packet, "msg.op", 5)) {
		error("expected payload header");
		return -1;
	}
*/
	if (size >= aaa_packet_max) {
		error("payload overflow size: %d max: %d", size, aaa_packet_max);
		return -1;
	}

	return 0;
}

static inline int
validate_key(char *key)
{
	size_t len = strlen(key);
	if (len < 5)
		return -1;
	if (!strncmp(key, "sess.", 5))
		return 0;
	if (!strncmp(key, "user.", 5))
		return 0;
	if (!strncmp(key, "auth.", 5))
		return 0;
	if (!strncmp(key, "acct.", 5))
		return 0;
	if (!strncmp(key, "msg.", 4))
		return 0;

	error("invalid attr name: %s", key);
	return -1;
}

static int
udp_build(struct aaa *aaa, char *op, byte *buf, int size)
{
	int len = 0, rv = 0;
	len += attr_enc(buf, len, size, "msg.op", op);
	len += attr_enc(buf, len, size, "msg.id", "1");

	dict_for_each(a, aaa->attrs.list) {
		debug4("udp build %s:%s %s ", a->key, a->val, 
		       a->flags & ATTR_CHANGED ? "changed" : ""); 
		if (validate_key(a->key))
			return -1;
                if (!(a->flags & ATTR_CHANGED))
                        continue;
		if ((rv = attr_enc(buf, len, size, a->key, a->val)) < 5)
			return -1;
		len += rv;
	}

	return len;
}

static int 
udp_parse(struct aaa *aaa, byte *packet, unsigned int len)
{
	char *sid = NULL;
	byte *end = packet + len;
	while (packet < end) {
		byte *key = packet;
		while (packet < end && *packet != ':' && *packet != '\n')
			packet++;
		if (packet >= end)
			return -1;
		if (*packet != ':')
			return -1;
		*packet++ = 0;
		byte *value = packet;
		while (packet < end && *packet != '\n')
			packet++;
		if (packet >= end)
			return -1;
		*packet++ = 0;

		if (!strncmp(key, "msg.", 4))
			continue;
		if (!strncmp(key, "sess.id", 7))
			sid = value;
		if (*key == '.')
			return -1;

		dict_set_nf(&aaa->attrs, key, value);
	}

	size_t sess_id_len = sid ? strlen(sid): 0;
	if (sess_id_len < 8 || sess_id_len > 64) {
		error("invalid sess_id attribute");
		return -1;
	}

	return 0;
}

int
udp_bind(struct aaa *aaa)
{
        int fd = -1, rc = -1;
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
	debug4("udp commit id=%s index=%d", aaa->sid, index);

	struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(port + index),
		.sin_addr.s_addr = inet_addr(aaad_ip)
	};

	socklen_t len = sizeof(in);
	if (len >= aaa_packet_max) {
		error("packet_size overflow max: %d", aaa_packet_max);
		goto cleanup;
	}

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

	if (udp_validate(packet, (int)recved))
		goto cleanup;

	if (size >= aaa_packet_max) {
		error("packet_size overflow max: %d", aaa_packet_max);
		goto cleanup;
	}

        if (!udp_parse(aaa, packet, (unsigned int)recved))
		rc = 0;

cleanup:        
        if (fd != -1)
                close(fd);

        return rc;
}

int
udp_commit(struct aaa *aaa)
{
        int fd = -1;
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
	debug4("udp commit id=%s index=%d", aaa->sid, index);

	struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(port + index),
		.sin_addr.s_addr = inet_addr(aaad_ip)
	};

	socklen_t len = sizeof(in);
	if (len >= aaa_packet_max) {
		error("packet_size overflow max: %d", aaa_packet_max);
		goto cleanup;
	}

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
	if (recved >= aaa_packet_max) {
		error("packet_size overflow max: %d", aaa_packet_max);
		goto cleanup;
	}

        udp_parse(aaa, packet, (unsigned int)recved);

cleanup:        
        if (fd != -1)
                close(fd);

        return 0;
}
