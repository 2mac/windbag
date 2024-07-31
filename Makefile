CC ?= cc
STND ?= -ansi -pedantic
CFLAGS += $(STND) -O2 -Wall -Wextra -Wunreachable-code -ftrapv \
        -D_POSIX_C_SOURCE=2 -D_DEFAULT_SOURCE
PREFIX=/usr/local

all: windbag

windbag_deps=src/ax25.o src/bigbuffer.o src/chat.o src/kiss.o src/main.o src/windbag.o
windbag: $(windbag_deps)
	./mvobjs.sh
	$(CC) -o $@ $(windbag_deps)

clean:
	rm -rf src/*.o windbag