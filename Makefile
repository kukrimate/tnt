# Default install prefix
PREFIX  := /usr/local

# Compiler flags
CFLAGS  := -std=c99 -D_GNU_SOURCE -pthread -pedantic -Wall \
	-Wdeclaration-after-statement -Wno-parentheses \
	-I/opt/libressl/include
LDFLAGS := -pthread
LIBS    := -L/opt/libressl/lib -l:libtls.a -l:libssl.a -l:libcrypto.a

# Object files
OBJ := dynarr.o htab.o url.o conn.o http.o tnt.o

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
	find -name '*.o' -delete
	rm -f tnt
