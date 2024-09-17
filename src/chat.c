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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bigbuffer.h"
#include "chat.h"
#include "keygen.h"
#include "kiss.h"
#include "util.h"
#include "windbag.h"

struct chat_config
{
	struct windbag_config *config;
	struct ax25_io *aio;
};

static void *
chat_read(void *input)
{
	struct chat_config *cc = (struct chat_config *) input;
	struct ax25_io *aio = cc->aio;
	struct windbag_config *config = cc->config;
	struct windbag_packet packet;
	int rc;

	rc = windbag_packet_init(&packet);
	if (rc)
		return NULL;

	for (;;)
	{
		if (!windbag_read_packet(&packet, config, aio))
			continue;

		printf("\n%s: %s\n", packet.header.src_addr, (char *) packet.payload->data);
	}

	windbag_packet_cleanup(&packet);
	return NULL;
}

static int
chat_write(struct chat_config *cc)
{
	struct windbag_config *config = cc->config;
	struct ax25_io *aio = cc->aio;
	struct ax25_header header;
	struct bigbuffer *message;
	char buf[513];
	int rc = 0, done = 0;

	buf[0] = '\0';

	strcpy(header.dest_addr, "CQ");
	strcpy(header.src_addr, config->my_call);
	memcpy(header.digi_path, config->digi_path, sizeof header.digi_path);

	message = bigbuffer_new(sizeof buf);
	if (!message)
		return 1;

	while (!done)
	{
		size_t count;
		char *next = buf, *line_end = NULL;

		printf("> ");

		fgets(buf, sizeof buf, stdin);
		count = strlen(buf);

		while ((line_end = strchr(next, '\n')) != NULL)
		{
			unsigned int line_length = line_end - next;
			int written;

			*line_end = '\0';

			if (strcmp(next, "/exit") == 0)
			{
				done = 1;
				break;
			}

			bigbuffer_append(message, (uint8_t *) next, line_length);
			if (message->length > 0)
			{
				written = windbag_send_message(config, aio,
							&header, message);
				if (written < 0)
				{
					fprintf(stderr, "Error writing to TNC\n");
					done = 1;
					rc = 1;
					break;
				}

				printf("Wrote %d bytes\n", written);

				message->length = 0;
			}

			next = line_end + 1;
		}

		bigbuffer_append(message, (uint8_t *) next, count - (next - buf));
	}

	bigbuffer_free(message);
	return rc;
}

int
chat(struct windbag_config *config, int argc, char **argv)
{
	struct io io;
	struct ax25_io aio;
	KISS_TNC tnc;
	struct chat_config cc;
	pthread_t read_thread;
	int rc;

	UNUSED(argc);
	UNUSED(argv);

	if (config->my_call[0] == '\0')
	{
		fprintf(stderr, "Set a call sign with -c\n");
		return 1;
	}

	if (config->tty[0] == '\0')
	{
		fprintf(stderr, "Set the TNC device with -t\n");
		return 1;
	}

	if (config->sign_messages)
	{
		rc = load_keypair(config);
		if (rc)
			return rc;
	}

	kiss_init_serial(&tnc, &io, config->tty, config->tty_speed);

	aio.read_frame = (ax25_frame_reader) kiss_read_frame;
	aio.write_frame = (ax25_frame_writer) kiss_write_frame;
	aio.tnc = (void *) &tnc;

	cc.config = config;
	cc.aio = &aio;

	rc = pthread_create(&read_thread, NULL, chat_read, &cc);
	if (rc)
	{
		fprintf(stderr, "Error starting read thread\n");
		return rc;
	}

	rc = chat_write(&cc);
	pthread_cancel(read_thread);

	return rc;
}
