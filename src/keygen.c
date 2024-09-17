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
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base64.h"
#include "keygen.h"
#include "os.h"
#include "util.h"

static int
prompt_yn(const char *prompt, int default_result)
{
	char *line = NULL;
	size_t bufsize;
	ssize_t line_len;
	int rc;

	printf("%s", prompt);
	line_len = getline(&line, &bufsize, stdin);
	switch (line_len)
	{
	case -1:
	case 0:
		rc = -1;
		break;

	case 1:
		rc = default_result;
		break;

	default:
		rc = tolower(line[0]) == 'y';
		break;
	}

	free(line);
	return rc;
}

static int
prompt_and_set_path(char *dest, const char *key_type, const char *default_path,
		const char *default_file)
{
	const char * const prompt_fmt = "Enter location for the new %s key "
		"[%s" FILE_SEPARATOR "%s]: ";
	char *line = NULL, *p;
	size_t bufsize;
	ssize_t line_len;

	printf(prompt_fmt, key_type, default_path, default_file);
	line_len = getline(&line, &bufsize, stdin);
	if (line_len < 1)
	{
		free(line);
		return 1;
	}

	if (line_len == 1)
	{
		size_t len = strlen(default_path) + strlen(default_file) + 2;
		if (len > bufsize)
		{
			char *temp = realloc(line, len);
			if (!temp)
			{
				free(line);
				return 1;
			}

			line = temp;
		}

		sprintf(line, "%s" FILE_SEPARATOR "%s", default_path, default_file);
	}
	else
	{
		p = strrchr(line, '\n');
		if (p)
			*p = '\0';
	}

	strncpy(dest, line, MAX_FILE_PATH - 1);

	if (access(line, F_OK) == 0)
	{
		printf("%s exists. Overwrite? [y/N] ", line);
		line_len = getline(&line, &bufsize, stdin);
		if (line_len < 2 || tolower(line[0]) != 'y')
		{
			free(line);
			return 1;
		}
	}

	free(line);
	return 0;
}

static int
encode_and_save(const unsigned char *key, size_t key_size, const char *path)
{
	char *encoded, *dpath;
	FILE *f;
	int rc;

	dpath = strdup(path);
	if (!dpath)
	{
		fprintf(stderr, "Error saving key: %s\n", strerror(ENOMEM));
		return ENOMEM;
	}

	rc = mkdir_recursive(dirname(dpath), 0755);
	free(dpath);
	if (rc)
	{
		fprintf(stderr, "Error writing %s: %s\n", path,
			strerror(errno));
		return errno;
	}

	encoded = base64_encode(key, key_size);
	if (!encoded)
		return -1;

	f = fopen(path, "w");
	if (!f)
	{
		fprintf(stderr, "Error writing %s: %s\n", path,
			strerror(errno));
		free(encoded);
		return errno;
	}

	rc = fprintf(f, "%s\n", encoded);
	if (rc > 0)
		rc = 0;

	free(encoded);
	fclose(f);
	return rc;
}

int
keygen(struct windbag_config *config, int argc, char **argv)
{
	char default_path[MAX_FILE_PATH];
	int rc;

	UNUSED(argc);
	UNUSED(argv);

	default_config_dir_path(default_path, sizeof default_path);

	if (prompt_and_set_path(config->pubkey_path, "public", default_path,
					DEFAULT_PUBKEY))
		return 1;

	if (prompt_and_set_path(config->seckey_path, "secret", default_path,
					DEFAULT_SECKEY))
		return 1;

	rc = crypto_sign_keypair(config->pubkey, config->seckey);
	if (rc)
	{
		fprintf(stderr, "Error generating keypair.\n");
		return 1;
	}

	if (encode_and_save(config->pubkey, sizeof config->pubkey,
				config->pubkey_path))
		return 1;

	if (encode_and_save(config->seckey, sizeof config->seckey,
				config->seckey_path))
		return 1;

	rc = chmod(config->seckey_path, 0600);
	if (rc == -1)
		fprintf(stderr, "Warning: error setting permissions for the secret key file: %s\n",
			strerror(errno));

	rc = prompt_yn("Save to default config? [Y/n] ", 1);
	if (rc == 1)
	{
		struct windbag_option options[2];
		options[0].name = "public-key";
		options[0].value = config->pubkey_path;
		options[1].name = "secret-key";
		options[1].value = config->seckey_path;

		rc = write_config_options(config, options, 2);
		if (rc)
		{
			fprintf(stderr, "Error saving config: %s\n",
				strerror(rc));
			return rc;
		}
	}

	return 0;
}

static int
read_key_file(const char *path, const char *key_type, unsigned char *dest,
	size_t expected_size)
{
	FILE *f;
	char *buf = NULL, *eol;
	uint8_t *decoded;
	size_t bufsize, decoded_size;
	ssize_t line_len;

	f = fopen(path, "r");
	if (!f)
	{
		fprintf(stderr, "Error loading %s key file %s: %s\n", key_type,
			path, strerror(errno));
		return 1;
	}

	line_len = getline(&buf, &bufsize, f);
	fclose(f);
	if (line_len < 0)
	{
		free(buf);
		fprintf(stderr, "Error reading %s key file %s: %s\n", key_type,
			path, strerror(EIO));
		return 1;
	}

	if ((eol = strrchr(buf, '\n')) != NULL)
		*eol = '\0';

	decoded = base64_decode(&decoded_size, buf);
	free(buf);
	if (!decoded)
	{
		fprintf(stderr, "Error decoding %s key.\n", key_type);
		return 1;
	}

	if (decoded_size != expected_size)
	{
		fprintf(stderr, "Error in %s key file: unexpected data length\n",
			key_type);
		free(decoded);
		return 1;
	}

	memcpy(dest, decoded, decoded_size);
	free(decoded);

	return 0;
}

int
load_keypair(struct windbag_config *config)
{
	int rc;

	rc = read_key_file(config->pubkey_path, "public", config->pubkey,
				sizeof config->pubkey);
	if (rc)
		return rc;

	rc = read_key_file(config->seckey_path, "secret", config->seckey,
			sizeof config->seckey);

	return rc;
}
