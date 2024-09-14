Windbag
=======

Portable AX.25 packet radio chat with cryptographic signature verification.

This program was inspired by [chattervox][1].

For protocol details, see [PROTOCOL.md](PROTOCOL.md).

Prerequisites
-------------

This software requires a PC with a Unix-like operating system (e.g. GNU/Linux, OpenBSD), a KISS TNC (or [Direwolf][2]), and a radio you can control from the TNC.

Build Instructions
------------------

To build Windbag, you need an ANSI C compiler, make, and libsodium.

### Debian

    sudo apt install build-essential libsodium-dev
    make

### Fedora

    sudo dnf install gcc make libsodium-devel
    make

[1]: https://github.com/brannondorsey/chattervox
[2]: https://github.com/wb2osz/direwolf