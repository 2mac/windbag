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
#include <errno.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "callsign.h"
#include "chat.h"
#include "config.h"
#include "keygen.h"
#include "keyring.h"
#include "os.h"
#include "tnc2.h"
#include "tty.h"
#include "windbag.h"

typedef struct
{
	const char *name;
	int (*run)(struct windbag_config *, int, char **);
} COMMAND;

static const COMMAND COMMANDS[] = {
	{ "chat", chat },
	{ "delete-key", delete_key },
	{ "export-key", export_key },
	{ "import-key", import_key },
	{ "keygen", keygen }
};

static int
read_config_file(const char *config_path, struct windbag_config *config)
{
	int rc;
	FILE *config_file;

	config_file = fopen(config_path, "r");
	if (!config_file)
	{
		if (errno != ENOENT)
			fprintf(stderr, "Error opening %s: %s\n", config_path,
				strerror(errno));

		return 1;
	}

	rc = read_config(config, config_file);
	fclose(config_file);
	return rc;
}

int
main(int argc, char *argv[])
{
	struct windbag_config config;
	const char *command = "chat";
	speed_t speed = 0;
	char *tty = NULL, *my_call = NULL, *config_path = NULL, *hbaud = NULL;
	int rc, opt, found, tnc2 = 0;
	unsigned int i;

	while ((opt = getopt(argc, argv, "2C:b:c:h:t:")) != -1)
	{
		switch (opt)
		{
		case '2':
			tnc2 = 1;
			break;

		case 'C':
			config_path = optarg;
			break;

		case 'b':
			speed = strtospeed(optarg);
			if (speed == B0)
			{
				fprintf(stderr,
					"Bad baud rate %s. Defaulting to 9600.\n",
					optarg);
			}
			break;

		case 'c':
			my_call = optarg;
			break;

		case 'h':
			hbaud = optarg;
			break;

		case 't':
			tty = optarg;
			break;

		default:
			break;
		}
	}

	if (config_path)
	{
		if (access(config_path, F_OK) != 0)
		{
			fprintf(stderr, "File '%s' does not exist\n",
				config_path);
			return 1;
		}

		rc = read_config_file(config_path, &config);
		strncpy(config.config_path, config_path, sizeof config.config_path - 1);
	}
	else
	{
		char buf[MAX_FILE_PATH];
		config_path = default_config_dir_path(buf, sizeof buf);
		strncat(config_path, FILE_SEPARATOR, sizeof buf - strlen(buf));
		strncat(config_path, CONFIG_FILE_NAME, sizeof buf - strlen(buf));

		if (access(config_path, F_OK) == 0)
		{
			rc = read_config_file(config_path, &config);
		}
		else
		{
			rc = 0;
			memset(&config, 0, sizeof config);
		}

		strncpy(config.config_path, config_path, sizeof config.config_path - 1);
	}

	if (rc)
		return rc;

	if (config.keyring_path[0] == '\0')
	{
		char buf[MAX_FILE_PATH];
		default_config_dir_path(buf, sizeof buf);
		strncat(buf, FILE_SEPARATOR, sizeof buf - strlen(buf));
		strncat(buf, DEFAULT_KEYRING, sizeof buf - strlen(buf));
		strcpy(config.keyring_path, buf);
	}
	else if (access(config.keyring_path, F_OK) == -1)
	{
		fprintf(stderr, "Error opening keyring file %s: %s\n",
			config.keyring_path, strerror(errno));
		return 1;
	}

	if (my_call)
	{
		rc = validate_callsign(my_call);
		if (rc)
		{
			fprintf(stderr, "Error in call sign '%s': %s\n",
				my_call, callsign_strerror(rc));
			return 1;
		}

		sanitize_callsign(my_call);
		strcpy(config.my_call, my_call);
	}

	if (tty)
		strncpy(config.tty, tty, sizeof config.tty - 1);

	if (speed)
		config.tty_speed = speed;

	if (hbaud)
		tnc2 = 1;
	else if (strlen(config.hbaud) > 0)
		hbaud = config.hbaud;

	if (tnc2 && strlen(config.tty) > 0
		&& tnc2_init(config.tty, speed, hbaud))
		return 1;

	if (optind < argc)
		command = argv[optind++];

	if (sodium_init() < 0)
	{
		fprintf(stderr, "Failed to initialize libsodium. Exiting.\n");
		return 1;
	}

	found = 0;
	for (i = 0; i < (sizeof COMMANDS / sizeof (COMMAND)); ++i)
	{
		if (strcmp(command, COMMANDS[i].name) == 0)
		{
			found = 1;
			rc = COMMANDS[i].run(&config, argc - optind,
					argv + optind);
			break;
		}
	}

	if (!found)
	{
		fprintf(stderr, "Command not found: %s\n", command);
		rc = 1;
	}

	return rc;
}
