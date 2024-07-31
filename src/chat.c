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

#include "bigbuffer.h"
#include "chat.h"
#include "windbag.h"

static int
chat_write(struct windbag_config *config, struct ax25_io *aio)
{
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
			written = windbag_send_message(aio, &header, message);
			if (written < 0)
			{
				fprintf(stderr, "Error writing to TNC\n");
				done = 1;
				break;
			}
			
			printf("Wrote %d bytes\n", written);

			message->length = 0;
			next = line_end + 1;
		}

		bigbuffer_append(message, (uint8_t *) next, count - (next - buf));
	}

	return rc;
}

int
chat(struct windbag_config *config, struct ax25_io *aio)
{
	return chat_write(config, aio);
}