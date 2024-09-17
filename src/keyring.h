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

#ifndef WB_KEYRING_H
#define WB_KEYRING_H

#include <sodium.h>

#include "ax25.h"
#include "config.h"

struct identity
{
	char callsign[AX25_ADDR_MAX];
	unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
};

struct keyring
{
	unsigned int bufsize;
	unsigned int length;
	struct identity *keys;
};

struct keyring *
keyring_new(void);

void
keyring_free(struct keyring *keyring);

int
keyring_add(struct keyring *keyring, const char *callsign,
	const char *pubkey_base64);

void
keyring_delete(struct keyring *keyring, const char *callsign);

int
keyring_load(struct keyring *keyring, const char *path);

int
keyring_save(struct keyring *keyring, const char *path);

struct identity *
keyring_search(struct keyring *keyring, const char *callsign);

int
import_key(struct windbag_config *config, int argc, char **argv);

int
export_key(struct windbag_config *config, int argc, char **argv);

int
delete_key(struct windbag_config *config, int argc, char **argv);

#endif
