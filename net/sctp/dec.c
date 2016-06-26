/*
 * The MIT License (MIT)            (SCTP) Stream Control Transmission Protocol
 *
 * Copyright (c) 2013 Daniel Kubec <niel@rtfm.cz>
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

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <crypto/crc.h>
#include <net/sctp/proto.h>

static const char * const sctp_chunk_type_names[] = {
	[SCTP_CHUNK_DATA]           = "data",
	[SCTP_CHUNK_INIT]           = "init",
	[SCTP_CHUNK_INIT_ACK]       = "init ack",
	[SCTP_CHUNK_SACK]           = "sack",
	[SCTP_CHUNK_HBREQ]          = "heartbeat req",
	[SCTP_CHUNK_HBACK]          = "heartbeat ack",
	[SCTP_CHUNK_ABORT]          = "abort",
	[SCTP_CHUNK_SHUTDOWN]       = "shutdown",
	[SCTP_CHUNK_SHUTDOWN_ACK]   = "shutdown ack",
	[SCTP_CHUNK_ERROR]          = "error",
	[SCTP_CHUNK_COOKIE_ECHO]    = "cookie echo",
	[SCTP_CHUNK_COOKIE_ACK]     = "cookie ack",
	[SCTP_CHUNK_ECNE]           = "ecne",
	[SCTP_CHUNK_CWR]            = "cwr",
	[SCTP_CHUNK_IETF_EXTENSION] = "ietf extension"
};

void
sctp_checksum(struct sctp_packet *msg, unsigned int len)
{
	msg->hdr.checksum = cpu_be32(crc32_hash((byte *)msg, len));
}

int
sctp_validate(struct sctp_packet *msg, unsigned int len)
{
	unsigned long crc32 = be32_cpu(msg->hdr.checksum);
	msg->hdr.checksum = 0L;
	return ((crc32 == crc32_hash((byte *)msg, len)) ? 1 : -1);
}

const char *
sctp_chunk_print_type(u8 id)
{
	if (id > (u8)array_size(sctp_chunk_type_names))
		return "undefined";
			
	return sctp_chunk_type_names[id];
}

void
sctp_init(struct sctp *sctp, byte *pdu, u16 len)
{
	(*sctp) = (struct sctp) { 
		.packet = (struct sctp_packet *)pdu, .len = len, 
	};

}

int
sctp_decode(struct sctp_packet *msg, unsigned int len)
{
	sctp_dbg("pdu len=%d, spost=%d, dport=%d", len, 
	         get_u16_be(&msg->hdr.src_port),
	         get_u16_be(&msg->hdr.dst_port));

	struct sctp_chunk *c = (struct sctp_chunk *)msg + sizeof(*msg);

	_unused u8 type = sctp_chunk_type(c);

	sctp_dbg("chunk id=%d, flags=%d, len=%d",
	       c->hdr.id, c->hdr.flags, c->hdr.len);
	sctp_dbg("tsn=%d, stream_id=%d, stream_sn=%d proto_id=%d",
	       c->tsn, c->stream_id, c->stream_sn, c->proto_id);

	return 0;
}
