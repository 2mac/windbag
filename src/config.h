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

#ifndef WB_CONFIG_H
#define WB_CONFIG_H

#include <sodium.h>
#include <stdio.h>

#include "ax25.h"

#define MAX_FILE_PATH 1025

extern const char * const CONFIG_FILE_NAME;
extern const char * const DEFAULT_PUBKEY;
extern const char * const DEFAULT_SECKEY;
extern const char * const DEFAULT_KEYRING;

struct keyring;

struct windbag_config
{
	char config_path[MAX_FILE_PATH];

	char my_call[AX25_ADDR_MAX];
	char digi_path[AX25_MAX_ADDRS - 2][AX25_ADDR_MAX];
	char tty[MAX_FILE_PATH];
	unsigned int tty_speed;

	int sign_messages;
	char pubkey_path[MAX_FILE_PATH];
	char seckey_path[MAX_FILE_PATH];
	char keyring_path[MAX_FILE_PATH];
	unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
	unsigned char seckey[crypto_sign_SECRETKEYBYTES];
	struct keyring *keyring;
};

struct windbag_option
{
	char *name;
	char *value;
};

char *
default_config_dir_path(char *buf, int bufsize);

int
read_config(struct windbag_config *config, FILE *f);

int
write_config_options(struct windbag_config *config,
		const struct windbag_option *options, size_t n_options);

#endif
