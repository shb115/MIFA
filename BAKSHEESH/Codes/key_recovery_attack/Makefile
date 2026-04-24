# Makefile for the C + OpenMP port of the BAKSHEESH key-recovery attack.
#
#     make                         # build baksheesh_attack
#     OMP_NUM_THREADS=20 \
#         ./baksheesh_attack 4     # 4-round attack  (reads trails_4r.txt)
#     ./baksheesh_attack 5         # 5-round attack  (reads trails_5r.txt)
#     make clean

CC      ?= gcc
CFLAGS  ?= -O3 -march=native -fopenmp -Wall -Wextra -std=c11 -MMD -MP
LDFLAGS ?= -fopenmp

TARGET   = baksheesh_attack
COMMON   = baksheesh_common.o
DRIVER   = key_recovery_Nr.c

.PHONY: all clean

all: $(TARGET)

$(COMMON): baksheesh_common.c baksheesh_common.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(DRIVER) $(COMMON) baksheesh_common.h
	$(CC) $(CFLAGS) -o $@ $(DRIVER) $(COMMON) $(LDFLAGS)

clean:
	rm -f $(COMMON) $(TARGET) *.o *.d *.partial

# Auto-generated header dependencies (via -MMD -MP).
# Wildcard-include every .d file emitted by the build (common object
# plus driver compile-and-link) so new headers are auto-tracked.
-include $(wildcard *.d)
