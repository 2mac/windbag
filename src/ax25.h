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

#ifndef WB_AX25_H
#define WB_AX25_H

#include <stdint.h>
#include <sys/types.h>

#define AX25_ADDR_MAX 10
#define AX25_CALL_MAX 6
#define AX25_SSID_MAX 15
#define AX25_ADDR_SIZE 7
#define AX25_MAX_ADDRS 4
#define AX25_HEADER_MAX (3 + AX25_ADDR_SIZE * AX25_MAX_ADDRS)
#define AX25_INFO_MAX 256
#define AX25_FRAME_MIN 15
#define AX25_FRAME_MAX (AX25_HEADER_MAX + AX25_INFO_MAX)

#define AX25_PID_NO_L3 0xF0

struct ax25_frame
{
	unsigned int length;
	uint8_t data[AX25_FRAME_MAX];
};

struct ax25_header
{
	char dest_addr[AX25_ADDR_MAX];
	char src_addr[AX25_ADDR_MAX];
	char digi_path[AX25_MAX_ADDRS - 2][AX25_ADDR_MAX];
	uint16_t control;
	uint8_t pid;
};

struct ax25_packet
{
	struct ax25_header header;
	unsigned int payload_length;
	uint8_t payload[AX25_INFO_MAX];
};

typedef struct ax25_frame *(*ax25_frame_reader)(void *tnc);
typedef ssize_t (*ax25_frame_writer)(void *tnc, const struct ax25_frame *frame);

struct ax25_io
{
	ax25_frame_reader read_frame;
	ax25_frame_writer write_frame;
	void *tnc;
};

struct ax25_packet *
ax25_read_packet(const struct ax25_io *io);

ssize_t
ax25_write_packet(const struct ax25_io *io, const struct ax25_packet *packet);

#endif