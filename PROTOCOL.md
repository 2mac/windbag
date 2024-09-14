Windbag Protocol
================

All Windbag packets are AX.25 UI packets of the following form:

|Magic number|Header length|Flags|Optional fields|Timestamp|Content|
|---|---|---|---|---|---|
| `0xA4` `0x55` | 8 bits | 8 bits | (see Optional Fields below) | 32 bits | Variable |

- The magic number designates this as a Windbag packet
- The header length field contains the offset at which the content begins
- The flags are described in the Flags section below
- The timestamp is a 32-bit unsigned integer representing the number of seconds since 1970-01-01 00:00:00 (UTC) in little endian encoding
- The content takes up the remainder of the packet

Flags
-----

The flags field takes this form (most significant bit on the left):

|Reserved|Signature|Multipart|
|---|---|---|
| 6 bits | 1 bit | 1 bit |

- The signature flag indicates that the header includes the signature field (see Optional Fields below).
- The multipart flag indicates the packet's payload is split into multiple parts to be sent in other packets. The optional multipart index header fields will be present (see Optional Fields below).

Optional Fields
---------------

The following optional fields are defined and always appear in the given order, when present:

- Signature
    - This field consists of one octet representing the length of the signature which follows, and
    - The Ed25519 signature of the SHA-256 hash of the payload (the multipart field, timestamp, and message content, in that order).
- Multipart
    - This field consists of two octets: the index of this packet and the index of the final packet in the series, respectively.