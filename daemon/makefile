# Makefile for uniauth daemon project
.PHONY: debug clean

ifeq ($(MAKECMDGOALS),debug)
MAKE_DEBUG = yes
endif

OPTIONS = -O3 -std=gnu99 -Wno-unused-result
DEBUG_OPTIONS = -g -Wall -pedantic-errors -Werror -Wextra -Wshadow -Wfatal-errors \
	-Wno-unused-function -Wno-unused-parameter -Wno-unused-variable $(INCLUDE) \
	-std=gnu99

ifdef MAKE_DEBUG
COMPILE = gcc -c $(DEBUG_OPTIONS)
LINK = gcc
else
COMPILE = gcc -c $(OPTIONS)
LINK = gcc
endif

LIBS = -ldstructs

all: uniauthd
debug: uniauthd-debug

uniauthd: main.o clientbuf.o
	$(LINK) -o$@ $^ $(LIBS)
uniauthd-debug: main.o clientbuf.o
	$(LINK) -o$@ $^ $(LIBS)

main.o: main.c defs.h clientbuf.h
	$(COMPILE) -omain.o main.c

clientbuf.o: clientbuf.c defs.h
	$(COMPILE) -oclientbuf.o clientbuf.c
