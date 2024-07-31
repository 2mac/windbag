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

#ifndef WB_KISS_H
#define WB_KISS_H

#include <stdint.h>
#include <termios.h>

#include "io.h"
#include "ax25.h"

#define KISS_FRAME_MAX (AX25_FRAME_MAX * 2 + 3)

typedef struct
{
	struct io *io;
	unsigned int input_length;
	unsigned int input_index;
	int escape;
	int command;

	struct ax25_frame input_frame;

	uint8_t input_buf[KISS_FRAME_MAX];
	uint8_t output_buf[KISS_FRAME_MAX];
} KISS_TNC;

struct ax25_frame *
kiss_read_frame(KISS_TNC *tnc);

ssize_t
kiss_write_frame(KISS_TNC *tnc, const struct ax25_frame *frame);

KISS_TNC *
kiss_init(KISS_TNC *tnc, struct io *io);

KISS_TNC *
kiss_init_serial(KISS_TNC *tnc, struct io *io, const char *tty_path, speed_t speed);

#endif