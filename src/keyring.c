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
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "callsign.h"
#include "base64.h"
#include "keyring.h"
#include "os.h"
#include "util.h"

#define STEP 32
#define RECORD_LENGTH (AX25_CALL_MAX + 1 + crypto_sign_PUBLICKEYBYTES)

struct keyring *
keyring_new()
{
	struct keyring *keyring = malloc(sizeof (struct keyring));
	if (!keyring)
		return NULL;

	keyring->keys = malloc(STEP * sizeof (struct identity));
	if (!keyring->keys)
	{
		free(keyring);
		return NULL;
	}

	keyring->bufsize = STEP;
	keyring->length = 0;
	return keyring;
}

void
keyring_free(struct keyring *keyring)
{
	free(keyring->keys);
	free(keyring);
}

static int
add_identity(struct keyring *keyring, const char *callsign,
	unsigned char *pubkey)
{
	struct identity *identity;

	if (keyring->length == keyring->bufsize)
	{
		unsigned int new_bufsize = keyring->bufsize + STEP;
		struct identity *temp = realloc(keyring->keys,
						new_bufsize * sizeof (struct identity));
		if (!temp)
			return ENOMEM;

		keyring->keys = temp;
		keyring->bufsize = new_bufsize;
	}

	identity = keyring->keys + keyring->length++;
	strcpy(identity->callsign, callsign);
	memcpy(identity->pubkey, pubkey, crypto_sign_PUBLICKEYBYTES);
	return 0;
}

int
keyring_add(struct keyring *keyring, const char *callsign,
	const char *pubkey_base64)
{
	struct identity *existing;
	uint8_t *pubkey;
	size_t pubkey_length;
	int rc = 0;

	pubkey = base64_decode(&pubkey_length, pubkey_base64);
	if (!pubkey || pubkey_length != crypto_sign_PUBLICKEYBYTES)
		return -1;

	existing = keyring_search(keyring, callsign);
	if (existing)
		memcpy(existing->pubkey, pubkey, pubkey_length);
	else
		rc = add_identity(keyring, callsign, pubkey);

	free(pubkey);
	return rc;
}

void
keyring_delete(struct keyring *keyring, const char *callsign)
{
	struct identity *found = keyring_search(keyring, callsign);

	if (found)
	{
		unsigned int i = found - keyring->keys;

		--keyring->length;
		for (; i <= keyring->length; ++i)
			memcpy(keyring->keys + i, keyring->keys + i + 1,
				sizeof (struct identity));
	}
}

int
keyring_load(struct keyring *keyring, const char *path)
{
	FILE *f;
	long fsize;
	unsigned int i, n;
	int rc = 0;

	f = fopen(path, "rb");
	if (!f)
		return errno;

	fseek(f, 0L, SEEK_END);
	fsize = ftell(f);
	if (fsize % RECORD_LENGTH != 0)
	{
		fclose(f);
		return -1;
	}

	rewind(f);
	n = fsize / RECORD_LENGTH;
	for (i = 0; i < n; ++i)
	{
		unsigned char buf[RECORD_LENGTH];
		char callsign[AX25_ADDR_MAX];
		unsigned char *pubkey = buf + AX25_CALL_MAX + 1;
		int ssid;

		if (fread(buf, sizeof buf, 1, f) != 1)
		{
			rc = EIO;
			break;
		}

		ssid = buf[AX25_CALL_MAX];
		if (ssid > AX25_SSID_MAX)
		{
			rc = -1;
			break;
		}

		buf[AX25_CALL_MAX] = '\0';
		if (ssid)
			sprintf(callsign, "%s-%d", buf, ssid);
		else
			strcpy(callsign, (char *) buf);

		if ((rc = add_identity(keyring, callsign, pubkey)))
			break;
	}

	fclose(f);
	return rc;
}

int
keyring_save(struct keyring *keyring, const char *path)
{
	FILE *f;
	unsigned int i;
	char *dpath;
	int rc;

	dpath = strdup(path);
	if (!dpath)
		return ENOMEM;

	rc = mkdir_recursive(dirname(dpath), 0755);
	free(dpath);
	if (rc)
		return rc;

	f = fopen(path, "wb");
	if (!f)
		return errno;

	for (i = 0; i < keyring->length; ++i)
	{
		struct identity *key = keyring->keys + i;
		char *hyphen = strchr(key->callsign, '-');
		char callsign[AX25_CALL_MAX];
		int ssid;
		size_t written;

		memset(callsign, 0, sizeof callsign);

		if (hyphen)
		{
			*hyphen = '\0';
			memcpy(callsign, key->callsign, sizeof callsign);
			*hyphen = '-';

			sscanf(hyphen + 1, "%d", &ssid);
		}
		else
		{
			memcpy(callsign, key->callsign, sizeof callsign);
			ssid = 0;
		}

		written = fwrite(callsign, sizeof callsign, 1, f);
		if (written != 1)
		{
			rc = EIO;
			break;
		}

		rc = fputc(ssid, f);
		if (rc == EOF)
		{
			rc = EIO;
			break;
		}

		written = fwrite(key->pubkey, sizeof key->pubkey, 1, f);
		if (written != 1)
		{
			rc = EIO;
			break;
		}

		rc = 0;
	}

	fclose(f);
	return rc;
}

struct identity *
keyring_search(struct keyring *keyring, const char *callsign)
{
	unsigned int i;

	for (i = 0; i < keyring->length; ++i)
	{
		struct identity *key = keyring->keys + i;
		if (strcmp(key->callsign, callsign) == 0)
			return key;
	}

	return NULL;
}

static void
set_default_keyring_path(struct windbag_config *config)
{
	char dir[MAX_FILE_PATH - 2];
	default_config_dir_path(dir, sizeof dir);
	snprintf(config->keyring_path, MAX_FILE_PATH, "%s" FILE_SEPARATOR "%s",
		dir, DEFAULT_KEYRING);
}

int
import_key(struct windbag_config *config, int argc, char **argv)
{
	int rc = 0;
	char *callsign, *pubkey_base64;
	struct keyring *keyring;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: windbag import-key <callsign> <key>\n");
		return -1;
	}

	callsign = argv[0];
	rc = validate_callsign(callsign);
	if (rc)
	{
		fprintf(stderr, "Error in call sign: %s\n",
			callsign_strerror(rc));
		return -1;
	}

	sanitize_callsign(callsign);
	pubkey_base64 = argv[1];

	if (config->keyring_path[0] == '\0')
		set_default_keyring_path(config);

	keyring = keyring_new();
	if (!keyring)
	{
		fprintf(stderr, "Error importing key: %s\n", strerror(ENOMEM));
		return ENOMEM;
	}

	rc = keyring_load(keyring, config->keyring_path);
	if (rc && rc != ENOENT)
	{
		fprintf(stderr, "Error loading keyring: %s\n", strerror(errno));
		goto end;
	}

	rc = keyring_add(keyring, callsign, pubkey_base64);
	if (rc)
	{
		fprintf(stderr, "Error adding key: %s\n", strerror(errno));
		goto end;
	}

	rc = keyring_save(keyring, config->keyring_path);
	if (rc)
		fprintf(stderr, "Error saving keyring: %s\n", strerror(errno));
	else
		printf("Key successfully imported.\n");

end:
	free(keyring);
	return rc;
}

int
export_key(struct windbag_config *config, int argc, char **argv)
{
	int rc = 0;
	FILE *f;
	char *callsign, *pubkey_base64 = NULL;
	size_t bufsize;
	struct keyring *keyring = NULL;
	struct identity *found;

	switch (argc)
	{
	case 0:
		if (config->pubkey_path[0] == '\0')
		{
			fprintf(stderr, "No public key file specified in the config file.\n");
			return -1;
		}

		f = fopen(config->pubkey_path, "r");
		if (!f)
		{
			fprintf(stderr, "Error opening %s: %s\n",
				config->pubkey_path, strerror(errno));
			return errno;
		}

		if (getline(&pubkey_base64, &bufsize, f) == -1)
		{
			free(pubkey_base64);
			fclose(f);
			fprintf(stderr, "Error reading %s: %s\n",
				config->pubkey_path, strerror(ENOMEM));
			return ENOMEM;
		}

		fclose(f);
		printf("%s", pubkey_base64);
		free(pubkey_base64);
		break;

	case 1:
		callsign = argv[0];
		rc = validate_callsign(callsign);
		if (rc)
		{
			fprintf(stderr, "Error in call sign: %s\n",
				callsign_strerror(rc));
			return -1;
		}

		sanitize_callsign(callsign);

		if (config->keyring_path[0] == '\0')
			set_default_keyring_path(config);

		keyring = keyring_new();
		if (!keyring)
		{
			fprintf(stderr, "Error exporting key: %s\n",
				strerror(ENOMEM));
			return ENOMEM;
		}

		rc = keyring_load(keyring, config->keyring_path);
		if (rc)
		{
			fprintf(stderr, "Error loading keyring: %s\n",
				strerror(rc));
			goto end;
		}

		found = keyring_search(keyring, callsign);
		if (!found)
		{
			fprintf(stderr, "No key found for %s.\n", callsign);
			rc = -1;
			goto end;
		}

		pubkey_base64 = base64_encode(found->pubkey,
					sizeof found->pubkey);
		if (!pubkey_base64)
		{
			rc = ENOMEM;
			fprintf(stderr, "Error exporting key: %s\n",
				strerror(rc));
			goto end;
		}

		printf("%s\t%s\n", callsign, pubkey_base64);
		break;

	default:
		fprintf(stderr, "Usage: windbag export-key [callsign]\n");
		return -1;
	}


end:
	if (keyring)
		free(keyring);
	return rc;
}

int
delete_key(struct windbag_config *config, int argc, char **argv)
{
	int rc = 0;
	char *callsign;
	struct keyring *keyring;

	if (argc != 1)
	{
		fprintf(stderr, "Usage: windbag delete-key <callsign>\n");
		return -1;
	}

	callsign = argv[0];
	rc = validate_callsign(callsign);
	if (rc)
	{
		fprintf(stderr, "Error in call sign: %s\n",
			callsign_strerror(rc));
		return -1;
	}

	sanitize_callsign(callsign);

	if (config->keyring_path[0] == '\0')
		set_default_keyring_path(config);

	keyring = keyring_new();
	if (!keyring)
	{
		fprintf(stderr, "Error deleting key: %s\n", strerror(ENOMEM));
		return ENOMEM;
	}

	rc = keyring_load(keyring, config->keyring_path);
	if (rc)
	{
		fprintf(stderr, "Error loading keyring: %s\n", strerror(errno));
		goto end;
	}

	keyring_delete(keyring, callsign);

	rc = keyring_save(keyring, config->keyring_path);
	if (rc)
		fprintf(stderr, "Error saving keyring: %s\n", strerror(errno));
	else
		printf("Key successfully deleted.\n");

end:
	free(keyring);
	return rc;
}
