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

#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "endian.h"
#include "keyring.h"
#include "windbag.h"

const uint8_t MAGIC_NUMBER[2] = { 0xA4, 0x55 };
#define MIN_PAYLOAD_LENGTH 8

#define MAX_SIGNATURE_LENGTH crypto_sign_BYTES

#define HEADER_INDEX 2
#define FLAGS_INDEX 3
#define SIGLENGTH_INDEX 4
#define SIG_INDEX (SIGLENGTH_INDEX + 1)
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
windbag_read_packet(struct windbag_packet *dest,
		const struct windbag_config *config, const struct ax25_io *io)
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
	content_length = src->payload_length - header_length;
	dest->timestamp = le32toh(*((uint32_t *) &content[TIMESTAMP_INDEX]));

	if (flags & FLAG_MULTIPART)
	{
		dest->multipart_index = content[MULTIPART_INDEX];
		dest->multipart_final = content[MULTIPART_INDEX + 1];
	}
	else
	{
		dest->multipart_final = 0;
	}

	if (flags & FLAG_SIGNED)
	{
		struct keyring *keyring = config->keyring;
		struct identity *identity;

		if (!keyring || !(identity = keyring_search(keyring, src->header.src_addr)))
		{
			dest->signature_status = UNKNOWN_SIGNATURE;
		}
		else
		{
			unsigned char *sig = src->payload + SIG_INDEX;
			unsigned char *msg = (unsigned char *) content + TIMESTAMP_INDEX;
			unsigned long long mlen;

			if (dest->multipart_final)
				msg -= 2;

			mlen = content_length + (content - msg);
			if (crypto_sign_verify_detached(sig, msg, mlen, identity->pubkey))
				dest->signature_status = BAD_SIGNATURE;
			else
				dest->signature_status = GOOD_SIGNATURE;
		}
	}
	else
	{
		dest->signature_status = NO_SIGNATURE;
	}

	/* TODO check compression flag */

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

struct msg_param
{
	unsigned int content_length;
	int sign;
	int multi;
	unsigned int multi_index;
	unsigned int multi_final;
	uint32_t timestamp;
	const uint8_t *content;
	const unsigned char *seckey;
};

static int
sign_message(const struct msg_param *params, unsigned char *sig,
	unsigned long long *sig_length)
{
	unsigned char *buf, *p;
	unsigned int bufsize;
	int rc;

	bufsize = params->content_length + sizeof params->timestamp;
	if (params->multi)
		bufsize += 2;

	buf = malloc(bufsize);
	if (!buf)
		return -1;

	p = buf;

	if (params->multi)
	{
		*(p++) = params->multi_index;
		*(p++) = params->multi_final;
	}

	*((uint32_t *) p) = params->timestamp;
	p += sizeof params->timestamp;
	memcpy(p, params->content, params->content_length);

	rc = crypto_sign_detached(sig, sig_length, buf, bufsize,
				params->seckey);
	free(buf);
	return rc;
}

static ssize_t
write_message(const struct ax25_io *io, struct ax25_packet *packet,
	const struct msg_param *params)
{
	unsigned char sig[MAX_SIGNATURE_LENGTH];
	unsigned long long sig_length = 0;
	unsigned int header_length, flags = 0;
	uint8_t *payload = packet->payload;

	header_length = 4;

	if (params->sign)
	{
		int rc;

		flags |= FLAG_SIGNED;

		rc = sign_message(params, sig, &sig_length);
		if (rc < 0)
			return rc;

		payload[SIGLENGTH_INDEX] = sig_length;
		memcpy(payload + SIG_INDEX, sig, sig_length);
		header_length += sig_length + 1;
	}

	if (params->multi)
	{
		flags |= FLAG_MULTIPART;
		payload[header_length++] = params->multi_index;
		payload[header_length++] = params->multi_final;
	}

	*((uint32_t *) &payload[header_length]) = params->timestamp;
	header_length += sizeof params->timestamp;

	payload[HEADER_INDEX] = header_length;
	payload[FLAGS_INDEX] = flags;

	memcpy(payload + header_length, params->content, params->content_length);
	packet->payload_length = header_length + params->content_length;

	return ax25_write_packet(io, packet);
}

ssize_t
windbag_send_message(const struct windbag_config *config,
		const struct ax25_io *io, const struct ax25_header *header,
		const struct bigbuffer *message)
{
	struct ax25_packet packet;
	struct msg_param params;
	unsigned int content_length, max_content;
	ssize_t written = 0;

	max_content = sizeof packet.payload - MIN_PAYLOAD_LENGTH;
	content_length = message->length;

	if (config->sign_messages)
		max_content -= MAX_SIGNATURE_LENGTH + 1;

	memcpy(&packet.header, header, sizeof packet.header);
	memcpy(&packet.payload, MAGIC_NUMBER, sizeof MAGIC_NUMBER);

	params.timestamp = htole32((uint32_t) time(NULL));
	params.sign = config->sign_messages;
	params.seckey = config->seckey;

	if (content_length > max_content)
	{
		struct bigbuffer **buffers;
		unsigned int part_index, final_index;
		/* adding indices to header */
		max_content -= 2;
		params.multi = 1;

		buffers = bigbuffer_split(message, max_content, &final_index);
		if (!buffers)
		{
			written = -1;
			goto end;
		}

		--final_index;
		params.multi_final = final_index;
		for (part_index = 0; part_index <= final_index; ++part_index)
		{
			struct bigbuffer *buf = buffers[part_index];
			ssize_t rc;

			params.content_length = buf->length;
			params.multi_index = part_index;
			params.content = buf->data;

			rc = write_message(io, &packet, &params);
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
		params.content_length = content_length;
		params.multi = 0;
		params.content = message->data;

		written = write_message(io, &packet, &params);
	}

end:
	return written;
}
