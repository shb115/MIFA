# Textbook reference DEFAULT cipher under the simple key schedule
# (non-attack).  Shipped as a specification-style reference.
#
#     make                         # builds  default  and  default_reduced
#     ./default                    # prints the shipped test-vector table
#     ./default_reduced 6          # <round-count>
#     make clean

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

TARGETS = default default_reduced

.PHONY: all clean
all: $(TARGETS)

default: default.c
	$(CC) $(CFLAGS) -o $@ $<

default_reduced: default_reduced.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o *.out
