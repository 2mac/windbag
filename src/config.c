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
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include "callsign.h"
#include "config.h"
#include "os.h"
#include "tty.h"
#include "util.h"

const char * const CONFIG_FILE_NAME = "windbag.conf";
const char * const DEFAULT_PUBKEY = "ed25519.pub";
const char * const DEFAULT_SECKEY = "ed25519.sec";
const char * const DEFAULT_KEYRING = "keyring.dat";

char *
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

static int
set_mycall(struct windbag_config *config, const char *args)
{
	int rc;

	rc = validate_callsign(args);
	if (rc)
		fprintf(stderr, "Error in mycall: %s\n", callsign_strerror(rc));
	else
		strcpy(config->my_call, args);

	sanitize_callsign(config->my_call);
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

		sanitize_callsign(path[i]);
		strcpy(config->digi_path[i], path[i]);
	}

	free(temp);
	return rc;
}

static int
set_tty(struct windbag_config *config, const char *args)
{
	strncpy(config->tty, args, sizeof config->tty - 1);
	return 0;
}

static int
set_tty_speed(struct windbag_config *config, const char *args)
{
	speed_t speed = strtospeed(args);
	if (speed == B0)
	{
		fprintf(stderr, "Error parsing tty-speed '%s'\n", args);
		return 1;
	}

	config->tty_speed = speed;
	return 0;
}

static int
set_pubkey_path(struct windbag_config *config, const char *args)
{
	strncpy(config->pubkey_path, args, sizeof config->pubkey_path - 1);
	return 0;
}

static int
set_seckey_path(struct windbag_config *config, const char *args)
{
	strncpy(config->seckey_path, args, sizeof config->seckey_path - 1);
	return 0;
}

static int
set_keyring_path(struct windbag_config *config, const char *args)
{
	strncpy(config->keyring_path, args, sizeof config->keyring_path - 1);
	return 0;
}

typedef struct config_setter
{
	const char *name;
	int (*process)(struct windbag_config *config, const char *args);
} SETTER;

static const SETTER SETTERS[] = {
	{ "mycall", set_mycall },
	{ "digi-path", set_digi_path },
	{ "tty", set_tty },
	{ "tty-speed", set_tty_speed },
	{ "public-key", set_pubkey_path },
	{ "secret-key", set_seckey_path },
	{ "private-key", set_seckey_path },
	{ "keyring", set_keyring_path }
};

#define NUM_SETTERS (sizeof SETTERS / sizeof SETTERS[0])

int
read_config(struct windbag_config *config, FILE *f)
{
	char *buf;
	size_t bufsize = 1200;
	ssize_t line_len;
	int rc = 0;

	memset(config, 0, sizeof *config);
	config->tty_speed = B9600;

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

	free(buf);

	if (ferror(f))
	{
		fprintf(stderr, "Error reading config file: %s\n", strerror(errno));
		return errno;
	}

	if (!rc)
	{
		const char *missing = NULL;
		int have_pubkey = config->pubkey_path[0] != '\0';
		int have_seckey = config->seckey_path[0] != '\0';

		if (have_pubkey && have_seckey)
			config->sign_messages = 1;
		else if (have_pubkey && !have_seckey)
			missing = "secret";
		else if (have_seckey && !have_pubkey)
			missing = "public";

		if (missing)
			fprintf(stderr, "Warning: %s key not specified; message signing is disabled\n",
				missing);
	}

	return rc;
}

int
write_config_options(struct windbag_config *config,
		const struct windbag_option *options, size_t n)
{
	char *empty = "\n";
	FILE *f;
	char *orig = NULL, *line, *end;
	unsigned int i;
	long f_len;
	int *found = NULL, rc = 0;

	f = fopen(config->config_path, "r");
	if (!f)
	{
		char *dpath;

		if (errno != ENOENT)
		{
			rc = errno;
			goto end;
		}

		dpath = strdup(config->config_path);
		if (!dpath)
		{
			rc = ENOMEM;
			goto end;
		}

		rc = mkdir_recursive(dirname(dpath), 0755);
		free(dpath);
		if (rc)
			goto end;

		orig = empty;
	}
	else
	{
		fseek(f, 0L, SEEK_END);
		f_len = ftell(f);

		orig = malloc(f_len + 2);
		if (!orig)
		{
			rc = ENOMEM;
			goto end;
		}

		rewind(f);
		fread(orig, f_len, 1, f);
		if (ferror(f))
		{
			rc = EIO;
			goto end;
		}

		fclose(f);
		f = NULL;

		if (orig[f_len - 1] != '\n')
		{
			orig[f_len] = '\n';
			orig[f_len + 1] = '\0';
		}
	}

	found = calloc(n, sizeof (int));
	if (!found)
	{
		rc = ENOMEM;
		goto end;
	}

	f = fopen(config->config_path, "w");
	if (!f)
	{
		rc = errno;
		goto end;
	}

	line = orig;
	while ((end = strchr(line, '\n')) != NULL)
	{
		char *word, *p, temp;

		*end = '\0';

		p = line;
		while (isspace(*p))
			++p;

		if (p == end)
		{
			if (fprintf(f, "%s\n", line) < 0)
			{
				rc = EIO;
				goto end;
			}

			line = end + 1;
			continue;
		}

		word = p++;
		*end = '\n';

		while (!isspace(*p))
			++p;

		if (p == end)
		{
			*end = '\0';
			if (fprintf(f, "%s\n", line) < 0)
			{
				rc = EIO;
				goto end;
			}

			line = end + 1;
			continue;
		}

		temp = *p;
		*p = '\0';

		for (i = 0; i < n; ++i)
		{
			const struct windbag_option *option = options + i;
			if (strcmp(word, option->name) == 0)
			{
				if (found[i])
					break;

				found[i] = 1;
				if (fprintf(f, "%s\t%s\n", option->name,
						option->value) < 0)
				{
					rc = EIO;
					goto end;
				}

				break;
			}
		}

		if (i == n)
		{
			*p = temp;
			*end = '\0';
			if (fprintf(f, "%s\n", line) < 0)
			{
				rc = EIO;
				goto end;
			}
		}

		line = end + 1;
	}

	for (i = 0; i < n; ++i)
	{
		const struct windbag_option *option = options + i;
		if (!found[i])
		{
			if (fprintf(f, "%s\t%s\n", option->name,
					option->value) < 0)
			{
				rc = EIO;
				goto end;
			}
		}
	}

end:
	if (found)
		free(found);
	if (orig && orig != empty)
		free(orig);
	if (f)
		fclose(f);

	return rc;
}
