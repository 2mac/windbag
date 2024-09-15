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
#include <stdlib.h>
#include <string.h>

#include "ax25.h"
#include "callsign.h"

const char *
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

int
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

void
sanitize_callsign(char *callsign)
{
	char *p = callsign;
	while (*p)
	{
		*p = toupper(*p);
		++p;
	}
}
