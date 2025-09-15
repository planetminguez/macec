APP=macsec
CC=clang
CFLAGS=-std=c11 -Wall -Wextra -Werror -O2
LDFLAGS=
PREFIX?=/usr/local
BINDIR?=$(PREFIX)/bin

SRC=src/macsec.c
OBJ=$(SRC:.c=.o)

.PHONY: all clean install uninstall

all: $(APP)

$(APP): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

install: $(APP)
	printf "Proceed? [y/N] "; read ans; case "$$ans" in y|Y) ;; *) echo "Aborted."; exit 1;; esac; \
	install -d $(BINDIR); \
	install -m 0755 $(APP) $(BINDIR)/$(APP)

uninstall:
	printf "Proceed? [y/N] "; read ans; case "$$ans" in y|Y) ;; *) echo "Aborted."; exit 1;; esac; \
	rm -f $(BINDIR)/$(APP)

clean:
	rm -f $(OBJ) $(APP)
