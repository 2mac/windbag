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
#include <strings.h>
#include <time.h>

#include "os.h"
#include "windbag.h"

#ifdef OS_WINDOWS
# define htole32(N) ((uint32_t) N)
#else
# include <endian.h>
#endif

const uint8_t MAGIC_NUMBER[2] = { 0xA4, 0x55 };
#define MIN_PAYLOAD_LENGTH 8

#define HEADER_INDEX 2
#define FLAGS_INDEX 3
#define TIMESTAMP_INDEX (-4)
#define MULTIPART_INDEX (TIMESTAMP_INDEX - 2)

#define FLAG_MULTIPART 0x01
#define FLAG_SIGNED 0x02

int
windbag_packet_init(struct windbag_packet *packet)
{
	bzero(packet, sizeof (struct windbag_packet));
	packet->payload = bigbuffer_new(AX25_INFO_MAX * 8);
	return !packet->payload;
}

void
windbag_packet_cleanup(struct windbag_packet *packet)
{
	bigbuffer_free(packet->payload);
}

struct windbag_packet *
windbag_read_packet(struct windbag_packet *dest, const struct ax25_io *io)
{
	struct ax25_packet *src;
	unsigned int header_length, flags, content_length;
	const uint8_t *content;
	int need_free = !dest;

	src = ax25_read_packet(io);
	if (!src)
		return NULL;

	if (src->payload_length < MIN_PAYLOAD_LENGTH || memcmp(src->payload, MAGIC_NUMBER, sizeof MAGIC_NUMBER) != 0)
		goto fail1;

	if (!dest)
	{
		dest = malloc(sizeof (struct windbag_packet));
		if (!dest)
			goto fail1;

		if (windbag_packet_init(dest))
			goto fail2;
	}

	memcpy(&dest->header, &src->header, sizeof src->header);

	header_length = src->payload[HEADER_INDEX];
	flags = src->payload[FLAGS_INDEX];
	content = src->payload + header_length;
	dest->timestamp = le32toh(*((uint32_t *) &content[TIMESTAMP_INDEX]));

	/* TODO check compression flag */

	content_length = src->payload_length - header_length;
	dest->payload->length = 0;
	bigbuffer_append(dest->payload, content, content_length);
	bigbuffer_terminate(dest->payload);

	free(src);
	return dest;

fail2:
	if (need_free)
		free(dest);
fail1:
	free(src);
	return NULL;
}

ssize_t
windbag_send_message(const struct ax25_io *io, const struct ax25_header *header,
		const struct bigbuffer *message)
{
	struct ax25_packet packet;
	unsigned int header_length, content_length, flags = 0, max_content;
	uint32_t timestamp;
	ssize_t written = 0;

	max_content = sizeof packet.payload - MIN_PAYLOAD_LENGTH;
	header_length = MIN_PAYLOAD_LENGTH;
	content_length = message->length;

	memcpy(&packet.header, header, sizeof packet.header);
	memcpy(&packet.payload, MAGIC_NUMBER, sizeof MAGIC_NUMBER);

	timestamp = htole32((uint32_t) time(NULL));

	if (content_length > max_content)
	{
		struct bigbuffer **buffers;
		unsigned int part_index, final_index;
		/* adding indices to header */
		max_content -= 2;
		header_length += 2;
		flags |= FLAG_MULTIPART;

		buffers = bigbuffer_split(message, max_content, &final_index);
		if (!buffers)
		{
			written = -1;
			goto end;
		}

		--final_index;
		for (part_index = 0; part_index <= final_index; ++part_index)
		{
			struct bigbuffer *buf = buffers[part_index];
			ssize_t rc;
			
			packet.payload[HEADER_INDEX] = header_length;
			packet.payload[FLAGS_INDEX] = flags;
			packet.payload[header_length + MULTIPART_INDEX] = part_index;
			packet.payload[header_length + MULTIPART_INDEX + 1] = final_index;
			*((uint32_t *) &packet.payload[header_length + TIMESTAMP_INDEX]) = timestamp;

			memcpy(packet.payload + header_length, buf->data, buf->length);
			packet.payload_length = header_length + buf->length;
			rc = ax25_write_packet(io, &packet);
			if (rc < 0)
			{
				written = rc;
				break;
			}

			written += rc;
		}

		for (part_index = 0; part_index <= final_index; ++part_index)
			bigbuffer_free(buffers[part_index]);

		free(buffers);
	}
	else /* can fit in one packet */
	{
		*((uint32_t *) &packet.payload[header_length + TIMESTAMP_INDEX]) = timestamp;
		
		packet.payload[HEADER_INDEX] = header_length;
		packet.payload[FLAGS_INDEX] = flags;

		memcpy(packet.payload + header_length, message->data, content_length);
		packet.payload_length = header_length + content_length;

		written = ax25_write_packet(io, &packet);
	}

end:
	return written;
}