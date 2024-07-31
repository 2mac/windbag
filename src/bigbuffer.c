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

#include <stdlib.h>
#include <string.h>

#include "bigbuffer.h"

#define STEP_SIZE 1024
#define UTF8_MASK 0xC0
#define UTF8_IN_CHAR 0x80

struct bigbuffer *
bigbuffer_new(unsigned int init_size)
{
	struct bigbuffer *b = malloc(sizeof (struct bigbuffer));
	if (!b)
		return NULL;

	b->data = malloc(init_size);
	if (!b->data)
	{
		free(b);
		return NULL;
	}

	b->length = 0;
	b->bufsize = init_size;
	return b;
}

void
bigbuffer_free(struct bigbuffer *b)
{
	free(b->data);
	free(b);
}

int
bigbuffer_expand(struct bigbuffer *b, unsigned int chunks)
{
	unsigned int new_bufsize = b->bufsize + chunks * STEP_SIZE;
	uint8_t *temp = realloc(b->data, new_bufsize);
	if (!temp)
		return -1;

	b->data = temp;
	b->bufsize = new_bufsize;
	return 0;
}

int
bigbuffer_append(struct bigbuffer *b, const uint8_t *data, unsigned int length)
{
	unsigned int new_length = length + b->length;

	if (new_length >= b->bufsize)
	{
		unsigned int chunks = (new_length - b->bufsize) / STEP_SIZE + 1;
		if (bigbuffer_expand(b, chunks))
			return -1;
	}

	memcpy(b->data + b->length, data, length);
	b->length = new_length;
	return 0;
}

void
bigbuffer_terminate(struct bigbuffer *b)
{
	/* We are guaranteed to have at least 1 byte available by the append logic */
	b->data[b->length] = '\0';
}

struct bigbuffer *
bigbuffer_truncate(const struct bigbuffer *b, unsigned int max_length)
{
	struct bigbuffer *new;

	new = bigbuffer_new(max_length + 1);
	if (!new)
		return NULL;

	if (max_length >= b->length)
	{
		new->length = b->length;
		memcpy(new->data, b->data, b->length);
		return new;
	}

	while ((b->data[max_length] & UTF8_MASK) == UTF8_IN_CHAR)
		--max_length; /* don't split unicode character */

	new->length = max_length;
	memcpy(new->data, b->data, max_length);
	return new;
}

struct bigbuffer **
bigbuffer_split(const struct bigbuffer *src, unsigned int max_length, unsigned int *n_buffers)
{
	unsigned int max_leftover, num_splits, max_buffers, written;
	struct bigbuffer **buffers;
	int index;

	num_splits = src->length / max_length;
	max_leftover = (3 * num_splits) + (src->length % max_length);
	max_buffers = num_splits + 1 + (max_leftover / max_length);

	buffers = malloc(max_buffers * sizeof src);
	if (!buffers)
		return NULL;

	index = 0;
	written = 0;

	do
	{
		struct bigbuffer temp;
		temp.length = src->length - written;
		temp.data = src->data + written;

		buffers[index] = bigbuffer_truncate(&temp, max_length);
		if (!buffers[index])
		{
			--index;
			goto fail;
		}

		if (buffers[index]->length == 0) /* max_length is too small */
			goto fail;

		written += buffers[index++]->length;
	} while (written < src->length);

	*n_buffers = index;
	return buffers;

fail:
	for (; index >= 0; --index)
		bigbuffer_free(buffers[index]);
	free(buffers);
	return NULL;
}