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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "tinyber.h"

// --------------------------------------------------------------------------------
//  buffer interface
// --------------------------------------------------------------------------------

// output buffers are written in reverse, using predecrement.
// [this is the most efficient way to render BER - you write
//  a sub-object first, then prepend its length and type byte].

// emit data <src> (of length <n>) into output buffer <dst>.
static int emit(buf_t * dst, const uint8_t * src, int n)
{
  if (dst->pos < n) {
    return -1;
  } else {
    dst->pos -= n;
    memcpy (dst->buffer + dst->pos, src, n);
    return 0;
  }
}

// emit a single byte into an output stream.
static int emit_byte (buf_t * self, uint8_t b)
{
  if (self->pos < 1) {
    return -1;
  } else {
    self->buffer[--self->pos] = b;
    return 0;
  }
}

// ensure there are at least <n> bytes of input available.
static int ensure_input (const buf_t * self, unsigned int n)
{
  if ((self->pos + n) <= self->size) {
    return 0;
  } else {
    return -1;
  }
}

// ensure there are at least <n> bytes of output available.
static int ensure_output (const buf_t * self, unsigned int n)
{
  if (self->pos >= n) {
    return 0;
  } else {
    return -1;
  }
}

// --------------------------------------------------------------------------------
//  encoder
// --------------------------------------------------------------------------------

// how many bytes to represent length <n> (the 'L' in TLV).
static int length_of_length (asn1int_t n)
{
  if (n < 0x80) {
    return 1;
  } else {
    int r = 1;
    while (n) {
      n >>= 8;
      r += 1;
    }
    return r;
  }
}

// encode length into a byte buffer.
static void encode_length (asn1int_t len, int n, uint8_t * buffer)
{
  // caller must ensure room.  see length_of_length above.
  if (len < 0x80) {
    buffer[0] = (uint8_t) len;
  } else {
    int i;
    buffer[0] = 0x80 | ((n-1) & 0x7f);
    for (i=1; i < n; i++) {
      buffer[n-i] = len & 0xff;
      len >>= 8;
    }
  }
}

// encode an integer, ASN1 style.
// two's complement with the minimum number of bytes.
static int encode_integer (buf_t * o, asn1int_t n)
{
  asn1int_t n0 = n;
  asn1int_t i = 0;
  uint8_t byte = 0x80; // for n==0
  uint8_t result[16]; // plenty of room up to uint128_t
  while (1) {
    n >>= 8;
    if (n0 == n) {
      if ((n == -1) && (!(byte & 0x80) || (i == 0))) {
	// negative, but high bit clear
	result[15-i] = 0xff;
	i += 1;
      } else if ((n == 0) && (byte & 0x80)) {
	// positive, but high bit set
	result[15-i] = 0x00;
	i += 1;
      }
      break;
    } else {
      byte = n0 & 0xff;
      result[15-i] = byte;
      i += 1;
      n0 = n;
    }
  }
  // for machine-sized ints, lol is one byte, tag is one byte.
  // Note: emit() works in reverse.
  TYB_CHECK (emit (o, result + (16 - i), i));  // V
  return 0;
}

int encode_UNSIGNED64 (buf_t * o, const uint64_t n, uint32_t tag, uint8_t flags)
{
  unsigned int mark = o->pos;

  if (n >= 0x8000000000000000L) {
    TYB_CHECK (emit_byte(o, 0xff & n));
    TYB_CHECK (emit_byte(o, 0xff & (n >> 8)));
    TYB_CHECK (emit_byte(o, 0xff & (n >> 16)));
    TYB_CHECK (emit_byte(o, 0xff & (n >> 24)));
    TYB_CHECK (emit_byte(o, 0xff & (n >> 32)));
    TYB_CHECK (emit_byte(o, 0xff & (n >> 40)));
    TYB_CHECK (emit_byte(o, 0xff & (n >> 48)));
    TYB_CHECK (emit_byte(o, 0xff & (n >> 56)));
    TYB_CHECK (emit_byte(o, 0x00));
  } else {
    encode_integer (o, n);
  }

  TYB_CHECK (encode_TLV (o, mark, tag, flags));
  return 0;
}

int encode_INTEGER (buf_t * o, const asn1int_t * n, uint32_t tag, uint8_t flags)
{
  unsigned int mark = o->pos;
  encode_integer (o, *n);
  TYB_CHECK (encode_TLV (o, mark, tag, flags));
  return 0;
}

int encode_BITSTRING (buf_t * o, const uint8_t * n)
{
  unsigned int mark = o->pos;
  emit_byte (o, *n);
  emit_byte (o, 0); // number of unused bits
  TYB_CHECK (encode_TLV (o, mark, TAG_BITSTRING, FLAG_UNIVERSAL));
  return 0;
}

int encode_BOOLEAN (buf_t * o, const asn1bool_t * value)
{
  static const uint8_t encoded_bool_true[3]  = {0x01, 0x01, 0xff};
  static const uint8_t encoded_bool_false[3] = {0x01, 0x01, 0x00};
  if (*value) {
    TYB_CHECK (emit (o, encoded_bool_true, sizeof(encoded_bool_true)));
  } else {
    TYB_CHECK (emit (o, encoded_bool_false, sizeof(encoded_bool_false)));
  }
  return 0;
}

int encode_NULL (buf_t * o)
{
  static const uint8_t encoded_null[2] = {0x05, 0x00};
  TYB_CHECK (emit (o, encoded_null, sizeof(encoded_null)));
  return 0;
}

int encode_OCTET_STRING (buf_t * o, const uint8_t * src, int src_len)
{
  int mark = o->pos;
  TYB_CHECK (emit (o, src, src_len));
  TYB_CHECK (encode_TLV (o, mark, TAG_OCTETSTRING, FLAG_UNIVERSAL));
  return 0;
}

// assuming the encoded value has already been emitted (starting at position <mark>),
//  emit the length and tag for that value.
int encode_TLV (buf_t * o, unsigned int mark, uint32_t tag, uint8_t flags)
{
  int length = mark - o->pos;
  uint8_t encoded_length[6];
  uint8_t lol;
  // compute length of length
  lol = length_of_length (length);
  // ensure room for length
  TYB_CHECK (ensure_output (o, lol));
  // encode & emit the length
  encode_length (length, lol, encoded_length);
  TYB_CHECK (emit (o, encoded_length, lol));
  // emit tag|flags
  TYB_CHECK (emit_byte (o, tag | flags));
  return 0;
}

// --------------------------------------------------------------------------------
//  decoder
// --------------------------------------------------------------------------------

int decode_length (buf_t * src, uint32_t * length)
{
  uint8_t lol;
  // assure at least one byte [valid for length == 0]
  TYB_CHECK (ensure_input (src, 1));
  // 2) get length
  if (src->buffer[src->pos] < 0x80) {
    // one-byte length
    *length = src->buffer[src->pos++];
    return 0;
  } else if (src->buffer[src->pos] == 0x80) {
    // indefinite length
    return -1;
  } else {
    // long definite length from, lower 7 bits
    // give us the number of bytes of length.
    lol = src->buffer[src->pos++] & 0x7f;
    if (lol > 4) {
      // we don't support lengths > 32 bits
      return -1;
    } else {
      TYB_CHECK (ensure_input (src, lol));
      uint8_t i;
      uint32_t n=0;
      for (i=0; i < lol; i++) {
	n = (n << 8) | src->buffer[src->pos++];
      }
      *length = n;
      return 0;
    }
  }
}

int decode_tag (buf_t * src, uint32_t * tag, uint8_t * flags)
{
  uint32_t r = 0;
  uint8_t b = 0;
  TYB_CHECK (ensure_input (src, 1));
  b = src->buffer[src->pos++];
  *flags = b & 0xe0;
  if ((b & 0x1f) < 0x1f) {
    // single-byte tag
    *tag = b & 0x1f;
    return 0;
  } else {
    // multi-byte tag
    while (1) {
      // tag is in base128, high bit is continuation flag.
      TYB_CHECK (ensure_input (src, 1));
      b = src->buffer[src->pos++];
      if (!(b & 0x80)) {
	break;
      } else {
	r = (r << 7) | (b & 0x7f);
      }
    }
    r = (r << 7) | b;
    *tag = r;
    return 0;
  }
}

int decode_TLV (asn1raw_t * dst, buf_t * src)
{
  uint32_t tag;
  uint8_t flags;
  uint32_t length;
  TYB_CHECK (decode_tag (src, &tag, &flags));
  TYB_CHECK (decode_length (src, &length));
  TYB_CHECK (ensure_input (src, length));
  dst->type = tag;
  dst->flags = flags;
  dst->length = length;
  dst->value = src->buffer + src->pos;
  src->pos += length;
  if (src->pos > src->size) { return -1; }
  return 0;
}

asn1int_t decode_INTEGER (asn1raw_t * src)
{
  uint8_t length = src->length;
  if (length == 0) {
    return 0;
  } else {
    asn1int_t n;
    uint8_t pos = 0;
    n = src->value[pos];
    if (n & 0x80) {
      // negative
      n = n - 0x100;
    }
    length -= 1;
    while (length) {
      pos += 1;
      n = (n << 8) | src->value[pos];
      length -= 1;
    }
    return n;
  }
}

uint8_t decode_BITSTRING (asn1raw_t * src)
{
  uint8_t length = src->length;
  if (length == 0) {
    return 0;
  } else if (length == 2) {
	  return src->value[1];
  } else {
	  return -1;
  }
}

int decode_BOOLEAN (asn1raw_t * src)
{
  if (src->length == 0) {
    return 0;
  } else {
    return (src->value[0] == 0xff);
  }
}
