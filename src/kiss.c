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

#include <errno.h>
#include <fcntl.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <strings.h>

#include "kiss.h"

#define FEND 0xC0
#define FESC 0xDB
#define TFEND 0xDC
#define TFESC 0xDD

#define NO_INPUT -1
#define IO_ERROR -2

enum kiss_command
{
	NO_COMMAND = -2,
	AWAITING_COMMAND = -1,
	DATA_FRAME = 0,
	TX_DELAY,
	PERSISTENCE,
	SLOT_TIME,
	TX_TAIL,
	FULL_DUPLEX,
	SET_HARDWARE,
	EXIT_KISS_MODE = 0xFF
};

static int
kiss_getchar(KISS_TNC *tnc)
{
	if (tnc->input_index >= tnc->input_length)
	{
		ssize_t bytes_read;

		bytes_read = tnc->io->read(tnc->io, tnc->input_buf, KISS_FRAME_MAX);
		if (bytes_read < 0)
			return IO_ERROR;

		if (bytes_read == 0)
			return NO_INPUT;

		tnc->input_index = 0;
		tnc->input_length = bytes_read;
	}

	return tnc->input_buf[tnc->input_index++];
}

static int
skip_frame(KISS_TNC *tnc)
{
	int c;

	while ((c = kiss_getchar(tnc)) != FEND)
		if (c < 0)
			return c;

	return c;
}

static void
append_input(KISS_TNC *tnc, int c)
{
	struct ax25_frame *frame = &tnc->input_frame;

	if (frame->length < sizeof frame->data)
		frame->data[frame->length++] = c;
}

struct ax25_frame *
kiss_read_frame(KISS_TNC *tnc)
{
	int c;

	while (tnc->command == NO_COMMAND)
	{
		c = skip_frame(tnc);
		if (c < 0)
			return NULL;

		tnc->command = AWAITING_COMMAND;
	}

	while (tnc->command == AWAITING_COMMAND)
	{
		c = kiss_getchar(tnc);
		if (c < 0)
			return NULL;

		if (c == DATA_FRAME)
		{
			tnc->command = DATA_FRAME;
			tnc->input_frame.length = 0;
		}
		else if (c != FEND)
		{
			c = skip_frame(tnc);
			if (c < 0)
			{
				tnc->command = NO_COMMAND;
				return NULL;
			}
		}
	}

	while ((c = kiss_getchar(tnc)) >= 0)
	{
		if (tnc->escape)
		{
			tnc->escape = 0;
			
			switch (c)
			{
			case TFEND:
				c = FEND;
				break;

			case TFESC:
				c = FESC;
				break;

			default:
				continue;
			}

			append_input(tnc, c);
		}
		else
		{
			switch (c)
			{
			case FEND:
				tnc->command = AWAITING_COMMAND;
				return &tnc->input_frame;

			case FESC:
				tnc->escape = 1;
				continue;

			default:
				append_input(tnc, c);
				break;
			}
		}
	}

	return NULL;
}

ssize_t
kiss_write_frame(KISS_TNC *tnc, const struct ax25_frame *frame)
{
	size_t out_length = 2;
	unsigned int i;
	uint8_t *buf = tnc->output_buf;

	buf[0] = FEND;
	buf[1] = DATA_FRAME;

	for (i = 0; i < frame->length; ++i)
	{
		uint8_t c = frame->data[i];

		switch (c)
		{
		case FEND:
			buf[out_length++] = FESC;
			buf[out_length++] = TFEND;
			break;

		case FESC:
			buf[out_length++] = FESC;
			buf[out_length++] = TFESC;
			break;

		default:
			buf[out_length++] = c;
			break;
		}
	}

	buf[out_length++] = FEND;
	return tnc->io->write(tnc->io, buf, out_length);
}

KISS_TNC *
kiss_init(KISS_TNC *tnc, struct io *io)
{
	bzero(tnc, sizeof (KISS_TNC));
	tnc->io = io;
	tnc->command = NO_COMMAND;

	return tnc;
}

ssize_t
serial_read(struct io *io, void *buf, size_t count)
{
	return read(io->meta.fd, buf, count);
}

ssize_t
serial_write(struct io *io, const void *buf, size_t count)
{
	return write(io->meta.fd, buf, count);
}

KISS_TNC *
kiss_init_serial(KISS_TNC *tnc, struct io *io, const char *path, speed_t speed)
{
	int fd;
	struct termios tty;

	fd = open(path, O_RDWR | O_NOCTTY | O_SYNC);
	if (fd < 0 || tcgetattr(fd, &tty) < 0)
		return NULL;

	cfsetospeed(&tty, speed);
	cfsetispeed(&tty, speed);

	tty.c_cflag |= (CLOCAL | CREAD);    /* ignore modem controls */
	tty.c_cflag &= ~CSIZE;
	tty.c_cflag |= CS8;         /* 8-bit characters */
	tty.c_cflag &= ~PARENB;     /* no parity bit */
	tty.c_cflag &= ~CSTOPB;     /* only need 1 stop bit */

	/* setup for non-canonical mode */
	tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	tty.c_oflag &= ~OPOST;

	/* fetch bytes as they become available */
	tty.c_cc[VMIN] = 1;
	tty.c_cc[VTIME] = 5;

	if (tcsetattr(fd, TCSANOW, &tty) != 0)
		return NULL;

	io->read = serial_read;
	io->write = serial_write;
	io->meta.fd = fd;

	return kiss_init(tnc, io);
}