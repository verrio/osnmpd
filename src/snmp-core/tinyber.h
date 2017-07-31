/*
 * Copyright (C) 2015 Sam Rushing
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#ifndef _TINYBER_H_
#define _TINYBER_H_

#include <stdint.h>

typedef int64_t asn1int_t;
typedef uint8_t asn1bool_t;

typedef enum {
  FLAG_UNIVERSAL   = 0x00,
  FLAG_STRUCTURED  = 0x20,
  FLAG_APPLICATION = 0x40,
  FLAG_CONTEXT     = 0x80,
} asn1flag;

typedef enum {
  TAG_BOOLEAN     = 0x01,
  TAG_INTEGER     = 0x02,
  TAG_BITSTRING   = 0x03,
  TAG_OCTETSTRING = 0x04,
  TAG_NULLTAG     = 0x05,
  TAG_OID         = 0x06,
  TAG_ENUMERATED  = 0x0A,
  TAG_UTF8STRING  = 0x0C,
  TAG_SEQUENCE    = 0x10,
  TAG_SET         = 0x11,
  TAG_SMI_IP_ADDRESS = 0x40,
  TAG_SMI_COUNTER32 = 0x41,
  TAG_SMI_COUNTER64 = 0x46,
  TAG_SMI_GAUGE32 = 0x42,
  TAG_SMI_TIME_TICKS = 0x43,
  TAG_SMI_OPAQUE = 0x44
} asn1type;

typedef struct {
  uint32_t type;
  uint8_t flags;
  unsigned int length;
  uint8_t * value;
} asn1raw_t;

typedef struct {
  uint8_t * buffer;
  unsigned int pos;
  unsigned int size;
} buf_t;

// buffer interface

static inline void init_obuf (buf_t * self, uint8_t * buffer, unsigned int size)
{
  self->buffer = buffer;
  self->pos = size;
  self->size = size;
}

static inline void init_ibuf (buf_t * self, uint8_t * buffer, unsigned int size)
{
  self->buffer = buffer;
  self->pos = 0;
  self->size = size;
}

// decoder
__attribute__((visibility("default")))
int decode_BOOLEAN (asn1raw_t * src);
__attribute__((visibility("default")))
asn1int_t decode_INTEGER (asn1raw_t * src);
__attribute__((visibility("default")))
uint8_t decode_BITSTRING (asn1raw_t * src);
__attribute__((visibility("default")))
int decode_TLV (asn1raw_t * dst, buf_t * src);
__attribute__((visibility("default")))
int decode_length (buf_t * src, uint32_t * length);

// encoder
__attribute__((visibility("default")))
int encode_TLV (buf_t * o, unsigned int mark, uint32_t tag, uint8_t flags);
__attribute__((visibility("default")))
int encode_BITSTRING (buf_t * o, const uint8_t * n);
__attribute__((visibility("default")))
int encode_INTEGER (buf_t * o, const asn1int_t * n, uint32_t tag, uint8_t flags);
__attribute__((visibility("default")))
int encode_UNSIGNED64 (buf_t *o, uint64_t n, uint32_t tag, uint8_t flags);
__attribute__((visibility("default")))
int encode_BOOLEAN (buf_t * o, const asn1bool_t * value);
__attribute__((visibility("default")))
int encode_OCTET_STRING (buf_t * o, const uint8_t * src, int src_len);
__attribute__((visibility("default")))
int encode_NULL (buf_t * o);

#define TYB_FAILIF(x) do { if (x) { return -1; } } while(0)
#define TYB_CHECK(x) TYB_FAILIF(-1 == (x))

#endif // _TINYBER_H_
