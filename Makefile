.PHONY: all install clean
CC=gcc
CFLAGS=-g -Wall
LDFLAGS=
MESSAGE = Un petit peu avancé
DEPS=dazibao.c rfc6234/sha224-256.c
EXEC=dazibao

all: $(EXEC)

dazibao : dazibao.c
	$(CC) $(CFLAGS) $(DEPS) -o $(EXEC)

clean:
	rm -f dazibao

push :
	git add dazibao.c
	git add Makefile
	git add dazibao.h
	git commit -m "$(MESSAGE)"
	git push
