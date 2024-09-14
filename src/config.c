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
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "os.h"

const char *
default_config_dir_path(char *buf, int bufsize)
{
	char *base_dir;

#ifdef OS_WINDOWS
	base_dir = getenv("APPDATA");
	strncpy(buf, base_dir, bufsize);
#else /* not Windows */
	if (strcmp(getenv("USER"), "root") == 0)
	{
		base_dir = "/etc";
		strncpy(buf, base_dir, bufsize);
	}
	else
	{
		base_dir = getenv("XDG_DATA_HOME");
		if (!base_dir)
		{
			char *home = getenv("HOME");
			strncpy(buf, home, bufsize);
			strncat(buf, "/.local/share", bufsize - strlen(buf));
		}
		else
		{
			strncpy(buf, base_dir, bufsize);
		}
	}
#endif

	strncat(buf, FILE_SEPARATOR "windbag", bufsize - strlen(buf));
	return buf;
}

enum callsign_error
{
	NO_ERROR,
	SYNTAX,
	TOO_LONG,
	SSID
};

static const char *
callsign_strerror(int error)
{
	switch (error)
	{
	case NO_ERROR:
		return "No error";

	case SYNTAX:
		return "Syntax error in call sign";

	case TOO_LONG:
		return "Call sign too long";

	case SSID:
		return "SSID must be between 0 and 15";
	}

	return NULL;
}

static int
validate_callsign(const char *callsign)
{
	const char *hyphen;
	size_t len;

	len = strlen(callsign);
	if (len == 0)
		return SYNTAX;

	if (len > AX25_ADDR_MAX)
		return TOO_LONG;

	hyphen = strchr(callsign, '-');
	if (hyphen)
	{
		unsigned int ssid;
		int read;

		if ((hyphen - callsign) > AX25_CALL_MAX)
			return TOO_LONG;

		read = sscanf(hyphen, "-%u", &ssid);
		if (read != 1)
			return SYNTAX;

		if (ssid > AX25_SSID_MAX)
			return SSID;
	}
	else
	{
		if (len > AX25_CALL_MAX)
			return TOO_LONG;
	}

	return 0;
}

static int
set_mycall(struct windbag_config *config, const char *args)
{
	int rc;

	rc = validate_callsign(args);
	if (rc)
		fprintf(stderr, "Error in mycall: %s\n", callsign_strerror(rc));
	else
		strcpy(config->my_call, args);
	
	return rc;
}

static int
set_digi_path(struct windbag_config *config, const char *args)
{
	char *path[2], *temp;
	char *comma;
	int i, rc = 0, path_len = 1;

	temp = malloc(strlen(args) + 1);
	if (!temp)
	{
		fprintf(stderr, "Failed to set digi-path: out of memory\n");
		return ENOMEM;
	}

	strcpy(temp, args);

	path[0] = temp;

	comma = strchr(temp, ',');
	if (comma)
	{
		*comma = '\0';
		++path_len;
		path[1] = comma + 1;

		while (isspace(*(path[1])))
			++(path[1]);
	}

	for (i = 0; i < path_len; ++i)
	{
		rc = validate_callsign(path[i]);
		if (rc)
		{
			fprintf(stderr, "Error in digi-path: %s\n", callsign_strerror(rc));
			break;
		}

		strcpy(config->digi_path[i], path[i]);
	}

	free(temp);
	return rc;
}

typedef struct config_setter
{
	const char *name;
	int (*process)(struct windbag_config *config, const char *args);
} SETTER;

static const SETTER SETTERS[] = {
	{ "mycall", set_mycall },
	{ "digi-path", set_digi_path }
};

#define NUM_SETTERS (sizeof SETTERS / sizeof SETTERS[0])

int
read_config(struct windbag_config *config, FILE *f)
{
	char *buf;
	size_t bufsize = 512;
	ssize_t line_len;
	int rc = 0;

	buf = malloc(bufsize);
	if (!buf)
	{
		fprintf(stderr, "Error reading config file: %s\n", strerror(ENOMEM));
		return ENOMEM;
	}

	while ((line_len = getline(&buf, &bufsize, f)) != -1)
	{
		char *line, *eol, *option_name, *args;
		const struct config_setter *setter;
		unsigned int i;

		line = buf;
		
		while (isspace(*line))
			++line;
		
		eol = strchr(line, '#');
		if (!eol)
			eol = line + line_len;
		
		while (eol > line && isspace(eol[-1]))
			--eol;

		*eol = '\0';
		if (strlen(line) == 0)
			continue;

		option_name = line;

		while (!isspace(*(++line)))
			;

		*line = '\0';
		setter = NULL;
		for (i = 0; i < NUM_SETTERS; ++i)
		{
			if (strcmp(option_name, SETTERS[i].name) == 0)
			{
				setter = &SETTERS[i];
				break;
			}
		}

		if (!setter)
		{
			fprintf(stderr, "Unknown config option '%s'", option_name);
			continue;
		}

		while (isspace(*(++line)))
			;

		args = line;
		rc = setter->process(config, args);
		if (rc)
			break;
	}

	if (ferror(f))
	{
		fprintf(stderr, "Error reading config file: %s\n", strerror(errno));
		rc = errno;
	}

	free(buf);
	return rc;
}