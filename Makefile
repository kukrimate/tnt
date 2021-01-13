# Default install prefix
PREFIX  := /usr/local

# Compiler flags
CFLAGS  := -std=c99 -D_GNU_SOURCE -Wall -Wpedantic -pthread \
	-Ilibkm -I/opt/libressl/include
LDFLAGS := -pthread
LIBS    := -L/opt/libressl/lib -l:libtls.a -l:libssl.a -l:libcrypto.a

# Object files
OBJ := src/url.o src/conn.o src/http.o src/tnt.o

.PHONY: all
all: tnt

tnt: $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: install
install: tnt
	install $^ $(PREFIX)/bin/

.PHONY: clean
clean:
	rm -f $(OBJ) tnt
