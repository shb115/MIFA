# Textbook reference implementation of BAKSHEESH (non-attack).
#
#     make                         # builds  baksheesh  and  baksheesh_reduced
#     ./baksheesh                  # prints the shipped test-vector table
#     ./baksheesh_reduced 4 1000   # <round-count> <sample-count>
#     make clean
#
# This directory is not part of the attack pipeline; it is shipped as
# a specification-style cipher reference.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

TARGETS = baksheesh baksheesh_reduced

.PHONY: all clean
all: $(TARGETS)

baksheesh: baksheesh.c
	$(CC) $(CFLAGS) -o $@ $<

baksheesh_reduced: baksheesh_reduced.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o *.out
