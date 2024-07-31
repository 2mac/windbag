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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ax25.h"

#define ADDR_END_MASK 0x01
#define FRAME_TYPE_MASK 0x03
#define SSID_MASK 0x1E
#define SSID_SHIFT 1

#define FRAME_TYPE_UI 0x03

static int
addrlen(const struct ax25_frame *frame)
{
	int i;
	int found = 0;

	for (i = 0; i < (int) frame->length; ++i)
	{
		if (frame->data[i] & ADDR_END_MASK)
		{
			found = 1;
			break;
		}
	}

	if (!found)
		return -1;

	return i + 1;
}

static void
addr_decode(const uint8_t *src, char *dest)
{
	int i, ssid;
	char temp[AX25_ADDR_MAX];

	for (i = 0; i < 6; ++i)
	{
		if (src[i] == (' ' << 1))
			break;

		dest[i] = src[i] >> 1;
	}

	dest[i] = '\0';

	ssid = (src[6] & SSID_MASK) >> SSID_SHIFT;
	if (ssid)
	{
		sprintf(temp, "%s-%d", dest, ssid);
		strcpy(dest, temp);
	}
}

struct ax25_packet *
ax25_read_packet(const struct ax25_io *io)
{
	struct ax25_frame *frame;
	struct ax25_packet *packet;
	struct ax25_header *header;
	int addr_len, control_code, pid, i;

	frame = io->read_frame(io->tnc);
	if (!frame)
		return NULL;

	if (frame->length < AX25_FRAME_MIN)
		return NULL;

	addr_len = addrlen(frame);
	if (addr_len < 14 || addr_len % AX25_ADDR_SIZE != 0)
		return NULL;

	control_code = frame->data[addr_len];
	if ((control_code & FRAME_TYPE_MASK) != FRAME_TYPE_UI)
		return NULL;

	pid = frame->data[addr_len + 1];
	if (pid != AX25_PID_NO_L3)
		return NULL;

	packet = malloc(sizeof (struct ax25_packet));
	if (!packet)
		return NULL;

	header = &packet->header;
	addr_decode(frame->data, header->dest_addr);
	addr_decode(frame->data + AX25_ADDR_SIZE, header->src_addr);

	for (i = 2; i < addr_len / AX25_ADDR_SIZE; ++i)
		addr_decode(frame->data + (i * AX25_ADDR_SIZE), header->digi_path[i-2]);

	for (; i < AX25_MAX_ADDRS; ++i)
		header->digi_path[i-2][0] = '\0';

	header->control = control_code;
	header->pid = pid;

	packet->payload_length = frame->length - (addr_len + 2);
	memcpy(packet->payload, frame->data + addr_len + 2, packet->payload_length);

	return packet;
}

static void
addr_encode(const char *src, uint8_t *dest)
{
	unsigned int ssid;
	const char *hyphen;
	uint8_t *p;

	hyphen = strchr(src, '-');
	if (hyphen)
	{
		sscanf(hyphen, "-%u", &ssid);
		dest[6] = ssid << SSID_SHIFT;
	}
	else
	{
		hyphen = src + strlen(src);
		dest[6] = 0;
	}

	memset(dest, ' ' << 1, 6);

	p = dest;
	while (src < hyphen)
		*(p++) = *(src++) << 1;
}

ssize_t
ax25_write_packet(const struct ax25_io *io, const struct ax25_packet *packet)
{
	struct ax25_frame frame;
	const struct ax25_header *header = &packet->header;
	unsigned int i;

	addr_encode(header->dest_addr, frame.data);
	addr_encode(header->src_addr, frame.data + AX25_ADDR_SIZE);
	frame.length = AX25_ADDR_SIZE * 2;
	
	for (i = 0; i < AX25_MAX_ADDRS - 2; ++i)
	{
		if (header->digi_path[i][0] == '\0')
			break;

		addr_encode(header->digi_path[i], frame.data + frame.length);
		frame.length += AX25_ADDR_SIZE;
	}

	frame.data[frame.length - 1] |= ADDR_END_MASK;

	frame.data[frame.length++] = FRAME_TYPE_UI; /* control field */
	frame.data[frame.length++] = AX25_PID_NO_L3; /* PID field */

	memcpy(frame.data + frame.length, packet->payload, packet->payload_length);
	frame.length += packet->payload_length;

	return io->write_frame(io->tnc, &frame);
}