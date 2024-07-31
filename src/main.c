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

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ax25.h"
#include "chat.h"
#include "config.h"
#include "kiss.h"
#include "windbag.h"

static const unsigned int speeds[][2] = {
	{ 300, B300 },
	{ 1200, B1200 },
	{ 2400, B2400 },
	{ 4800, B4800 },
	{ 9600, B9600 },
	{ 19200, B19200 },
	{ 38400, B38400 },
	{ 57600, B57600 },
	{ 115200, B115200 }
};

static const int num_speeds = sizeof speeds / sizeof speeds[0];

static speed_t
strtospeed(const char *s)
{
	unsigned int parsed;
	int rc, i;
	
	rc = sscanf(s, "%u", &parsed);
	if (rc != 1)
		return B0;

	for (i = 0; i < num_speeds; ++i)
		if (speeds[i][0] == parsed)
			return speeds[i][1];

	return B0;
}

int
main(int argc, char *argv[])
{
	struct windbag_config config;
	speed_t speed = B9600;
	char *tty = NULL, *p;
	struct io io;
	KISS_TNC tnc;
	struct ax25_io aio;
	int rc, opt;

	config.my_call[0] = '\0';

	while ((opt = getopt(argc, argv, "b:c:t:")) != -1)
	{
		switch (opt)
		{
		case 'b':
			speed = strtospeed(optarg);
			if (speed == B0)
			{
				fprintf(stderr, "Unknown baud rate %s. Defaulting to 9600.\n", optarg);
				speed = B9600;
			}
			break;
		
		case 'c':
			strcpy(config.my_call, optarg);
			break;

		case 't':
			tty = optarg;
			break;

		default:
			break;
		}
	}

	if (config.my_call[0] == '\0')
	{
		fprintf(stderr, "Set a call sign with -c\n");
		return 1;
	}

	if (!tty)
	{
		fprintf(stderr, "Set the TNC device with -t\n");
		return 1;
	}

	kiss_init_serial(&tnc, &io, tty, speed);

	aio.read_frame = (ax25_frame_reader) kiss_read_frame;
	aio.write_frame = (ax25_frame_writer) kiss_write_frame;
	aio.tnc = (void *) &tnc;

	config.digi_path[0][0] = '\0';

	p = config.my_call;
	while (*p != '\0')
		*(p++) = toupper(*p);

	rc = chat(&config, &aio);

	return rc;
}