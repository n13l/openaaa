/*
 *                       (SCTP) Stream Control Transmission Protocol [RFC-2960]
 * The MIT License (MIT)                            Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __NET_PROTO_SCTP_H__
#define __NET_PROTO_SCTP_H__

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/unaligned.h>
#include <net/ip/proto.h>
#include <net/eth/proto.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP                             132
#endif

#define SCTP_CHUNK_ALIGN                         4

#define SCTP_CHUNK_DATA                          0x00
#define SCTP_CHUNK_INIT                          0x01
#define SCTP_CHUNK_INIT_ACK                      0x02
#define SCTP_CHUNK_SACK                          0x03
#define SCTP_CHUNK_HBREQ                         0x04
#define SCTP_CHUNK_HBACK                         0x05
#define SCTP_CHUNK_ABORT                         0x06
#define SCTP_CHUNK_SHUTDOWN                      0x07
#define SCTP_CHUNK_SHUTDOWN_ACK                  0x08
#define SCTP_CHUNK_ERROR                         0x09
#define SCTP_CHUNK_COOKIE_ECHO                   0x0A
#define SCTP_CHUNK_COOKIE_ACK                    0x0B
#define SCTP_CHUNK_ECNE                          0x0C
#define SCTP_CHUNK_CWR                           0x0D
#define SCTP_CHUNK_SHUTDOWN_COMPLETE             0x0E
#define SCTP_CHUNK_IETF_EXTENSION                0xFF

#define SCTP_CHUNK_FORWARD_TSN                   0xC0
#define SCTP_CHUNK_ASCONF                        0xC1
#define SCTP_CHUNK_ASCONF_ACK                    0x80

#define SCTP_CHUNK_HDR_FLAG_NONE                 0x00
#define SCTP_CHUNK_HDR_FLAG_DESTROYED_TCB        0x00
#define SCTP_CHUNK_HDR_FLAG_NO_TCB               0x01

#define SCTP_DATA_BEGIN_SEGMENT                  0x02
#define SCTP_DATA_MIDDLE_SEGMENT                 0x00
#define SCTP_DATA_END_SEGMENT                    0x01
#define SCTP_DATA_UNORDERED                      0x04

#define SCTP_HDR_SIZE       (sizeof(struct sctp_hdr))

#ifndef sctp_dbg
#define sctp_dbg(fmt, ...)
#endif

struct sctp_hdr {
	be16 src_port;
	be16 dst_port;
	be32 verify;
	be32 checksum;
} __attribute__ ((packed));

struct sctp_packet {
	struct sctp_hdr hdr;
	byte pdu[];
} __attribute__ ((packed));

struct sctp_hdr_chunk {
	u8 id;
	u8 flags;
	be16 len;
} __attribute__ ((packed));

struct sctp_chunk {
	struct sctp_hdr_chunk hdr;
	be32 tsn;
	be16 stream_id;
	be16 stream_sn;
	be32 proto_id;
	byte payload[];
} __attribute__ ((packed));

struct sctp {
	struct sctp_packet *packet;
	u16 len;
};

void
sctp_checksum(struct sctp_packet *msg, unsigned int len);

int
sctp_validate(struct sctp_packet *msg, unsigned int len);

void
sctp_init(struct sctp *sctp, byte *pdu, u16 len);

int
sctp_decode(struct sctp_packet *msg, unsigned int len);

const char *
sctp_chunk_print_type(u8 id);

static inline u8
sctp_chunk_type(struct sctp_chunk *sctp_chunk)
{
	return sctp_chunk->hdr.id;
}

static inline u16
sctp_chunk_size_aligned(struct sctp_chunk *sctp_chunk)
{
	return align_to(get_u16_be(&sctp_chunk->hdr.len), SCTP_CHUNK_ALIGN);
}

static inline struct sctp_chunk *
sctp_chunk_first(struct sctp *sctp)
{
	return (struct sctp_chunk *)(((byte *)sctp->packet) + SCTP_HDR_SIZE);
}

static inline struct sctp_chunk *
sctp_chunk_next(struct sctp *sctp, struct sctp_chunk *chunk)
{
	u16 size = sctp_chunk_size_aligned(chunk);
	u16 rest = sctp->len - SCTP_HDR_SIZE;

	if (rest <= ((((byte *)chunk) - ((byte*)sctp->packet)) + size))
		return NULL;

	return (struct sctp_chunk *)(((byte *)chunk) + size);
}

#endif
