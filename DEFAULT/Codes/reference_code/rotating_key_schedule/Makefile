# Textbook reference DEFAULT cipher under the rotating key schedule
# (non-attack).  Shipped as a specification-style reference.
#
#     make                                    # builds both binaries
#     ./default                               # prints shipped test-vector table
#     ./default_rotating_reduced              # small demo
#     make clean

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

TARGETS = default default_rotating_reduced

.PHONY: all clean
all: $(TARGETS)

default: default.c
	$(CC) $(CFLAGS) -o $@ $<

default_rotating_reduced: default_rotating_reduced.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o *.out
