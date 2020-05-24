/* KLV (Key-Length-Value) format */
/* TLV (Type-Length-Value) format */
/* LV (Length-Value) format */

#ifndef __KLV_FORMAT_H__
#define __KLV_FORMAT_H__

#include <sys/compiler.h>
#include <mem/unaligned.h>

/* Run block on fixed size string */
#define VISIT_KLV_STR_U8(payload, avail, lv, block)

/* Run block on fixed size string in native order */
#define VISIT_KLV_STR_U16(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_KLV_STR_BE16(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_KLV_STR_LE16(payload, avail, lv, block) \

/* Run block on fixed size string in native order */
#define VISIT_KLV_STR_U32(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_KLV_STR_BE32(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_KLV_STR_LE32(payload, avail, lv, block) \

/* Run block on fixed size string in native order */
#define VISIT_KLV_STR_U64(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_KLV_STR_BE64(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_KLV_STR_LE64(payload, avail, lv, block) \

/* Run block on fixed size buffer */
#define VISIT_KLV_BUF_U8(payload, avail, lv, block)

/* Run block on fixed size buffer in native order */
#define VISIT_KLV_BUF_U16(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_KLV_BUF_BE16(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_KLV_BUF_LE16(payload, avail, lv, block) \

/* Run block on fixed size buffer in native order */
#define VISIT_KLV_BUF_U32(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_KLV_BUF_BE32(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_KLV_BUF_LE32(payload, avail, lv, block) \

/* Run block on fixed size buffer in native order */
#define VISIT_KLV_BUF_U64(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_KLV_BUF_BE64(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_KLV_BUF_LE64(payload, avail, lv, block) \

#endif
