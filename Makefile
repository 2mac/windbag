CC ?= cc
STND ?= -std=c99
CFLAGS += $(STND) -O2 -Wall -Wextra -Wunreachable-code -ftrapv \
        -Wno-format-overflow -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE
LDFLAGS = -lpthread -lsodium
PREFIX=/usr/local
CFLAGS += -I$(PREFIX)/include
LDFLAGS += -L$(PREFIX)/lib -Wl,-R$(PREFIX)/lib

all: windbag

windbag_deps=src/ax25.o src/base64.o src/bigbuffer.o src/callsign.o src/chat.o src/config.o src/keygen.o src/keyring.o src/kiss.o src/main.o src/tty.o src/util.o src/windbag.o
windbag: $(windbag_deps)
	./mvobjs.sh
	$(CC) -o $@ $(windbag_deps) $(LDFLAGS)

install: windbag
	install -m755 windbag $(PREFIX)/bin/windbag

clean:
	rm -rf src/*.o windbag
