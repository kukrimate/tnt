# Default install prefix
PREFIX  := /usr/local

# Compiler flags
CFLAGS  := -std=c99 -D_GNU_SOURCE -pthread -pedantic -Wall \
	-Wdeclaration-after-statement -Wno-parentheses
LDFLAGS := -pthread

# Object files
OBJ := url.o dynarr.o http.o tnt.o

.PHONY: all
all: tnt

tnt: $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: install
install: tnt
	install $^ $(PREFIX)/bin/

.PHONY: clean
clean:
	find -name '*.o' -delete
	rm -f tnt
