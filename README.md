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

To build Windbag, you need a C99 compiler, make, and libsodium.

### Debian

    sudo apt install build-essential libsodium-dev
    make
    sudo make install

### Fedora

    sudo dnf install gcc make libsodium-devel
    make
    sudo make install

Getting Started
---------------

To get the most out of Windbag, you'll need to generate a keypair:

    $ windbag keygen

You'll also want to exchange keys with your friends and load them into your keyring:

    $ windbag export-key # outputs your own public key for you to send to a friend
    $ windbag import-key <callsign> <key> # registers a key with a call sign

Finally, it's time to chat! Turn on your radio and TNC, then start Windbag:

    $ windbag -t <tty> -c <callsign> -b <baudrate>

Here, `<tty>` is the serial port for your TNC, `<callsign>` is your call sign, and `<baudrate>` is the serial port speed to use when talking to the TNC (it is NOT the baud rate that will be used over the air! see your TNC's manual for setting that.).

[1]: https://github.com/brannondorsey/chattervox
[2]: https://github.com/wb2osz/direwolf