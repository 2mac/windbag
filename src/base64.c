/*
 *  windbag - AX.25 packet radio chat with cryptographic signature verification
 *  Copyright (C) 2024 David McMackins II
 *
 *  Redistributions, modified or unmodified, in whole or in part, must retain
 *  applicable notices of copyright or other legal privilege, these conditions,
 *  and the following license terms and disclaimer.  Subject to these
 *  conditions, each holder of copyright or other legal privileges, author or
 *  assembler, and contributor of this work, henceforth "licensor", hereby
 *  grants to any person who obtains a copy of this work in any form:
 *
 *  1. Permission to reproduce, modify, distribute, publish, sell, sublicense,
 *  use, and/or otherwise deal in the licensed material without restriction.
 *
 *  2. A perpetual, worldwide, non-exclusive, royalty-free, gratis, irrevocable
 *  patent license to make, have made, provide, transfer, import, use, and/or
 *  otherwise deal in the licensed material without restriction, for any and
 *  all patents held by such licensor and necessarily infringed by the form of
 *  the work upon distribution of that licensor's contribution to the work
 *  under the terms of this license.
 *
 *  NO WARRANTY OF ANY KIND IS IMPLIED BY, OR SHOULD BE INFERRED FROM, THIS
 *  LICENSE OR THE ACT OF DISTRIBUTION UNDER THE TERMS OF THIS LICENSE,
 *  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 *  A PARTICULAR PURPOSE, AND NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS,
 *  ASSEMBLERS, OR HOLDERS OF COPYRIGHT OR OTHER LEGAL PRIVILEGE BE LIABLE FOR
 *  ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN ACTION OF CONTRACT,
 *  TORT, OR OTHERWISE ARISING FROM, OUT OF, OR IN CONNECTION WITH THE WORK OR
 *  THE USE OF OR OTHER DEALINGS IN THE WORK.
 */

#include <string.h>
#include <sys/param.h>

#include "base64.h"

static const char * const TABLE =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

#define PAD '='

char *
base64_encode(const uint8_t *src, size_t src_size)
{
	size_t i, max_dest;
	char *dest, *p;

	max_dest = (src_size / 3 * 4) + ((src_size % 3) ? 4 : 0) + 1;
	dest = malloc(max_dest);
	if (!dest)
		return NULL;

	p = dest;
	for (i = 0; i < src_size; i += 3)
	{
		uint32_t quantum = 0, mask6 = 0x3F;
		unsigned int j, in_count, out_count, bits, shift;

		in_count = MIN(3, src_size - i);
		bits = in_count * 8;
		out_count = (bits / 6) + ((bits % 6) ? 1 : 0);

		for (j = 0; j < in_count; ++j)
			quantum |= src[i + j] << (8 * j);

		shift = bits - 6;
		mask6 <<= shift;
		for (j = 0; j < out_count; ++j)
		{
			unsigned int index;

			index = ((quantum << (6 * j)) & mask6) >> shift;
			*(p++) = TABLE[index];
		}

		for (; j < 4; ++j)
			*(p++) = PAD;
	}

	*p = '\0';
	return dest;
}

uint8_t *
base64_decode(size_t *dest_size, const char *src)
{
	size_t i, max_dest, src_len;
	uint8_t *p, *dest;

	src_len = strlen(src);
	if ((src_len % 4) != 0)
		return NULL;

	max_dest = src_len / 4 * 3;
	dest = malloc(max_dest);
	if (!dest)
		return NULL;

	p = dest;
	for (i = 0; i < src_len; i += 4)
	{
		uint8_t decoded[4];
		unsigned int j, in_count;

		for (in_count = 0; in_count < 4; ++in_count)
			if (src[i + in_count] == PAD)
				break;

		if (in_count < 2)
			goto fail;

		for (j = 0; j < in_count; ++j)
		{
			char *lookup;
			unsigned int index;

			lookup = strchr(TABLE, src[i + j]);
			if (!lookup)
				goto fail;

			index = lookup - TABLE;
			decoded[j] = index;
		}

		for (j = 0; j < in_count - 1; ++j)
		{
			unsigned int j2 = j * 2;
			*(p++) = (decoded[j] << j2) | (decoded[j+1] >> (4 - j2));
		}
	}

	*dest_size = p - dest;
	return dest;

fail:
	free(dest);
	return NULL;
}
