# Makefile for the C + OpenMP port of the DEFAULT simple-key-schedule
# key-recovery attack.
#
#     make                            # build default_simple_attack
#     OMP_NUM_THREADS=20 \
#         ./default_simple_attack 6   # 6-round attack  (reads trails_6r.txt)
#     ./default_simple_attack 7       # 7-round attack  (reads trails_7r.txt)
#     ./default_simple_attack 8       # 8-round attack  (reads trails_8r.txt)
#     make clean

CC      ?= gcc
CFLAGS  ?= -O3 -march=native -fopenmp -Wall -Wextra -std=c11 -MMD -MP
LDFLAGS ?= -fopenmp

TARGET   = default_simple_attack
COMMON   = default_common.o
DRIVER   = key_recovery_attack_Nr.c

.PHONY: all clean

all: $(TARGET)

$(COMMON): default_common.c default_common.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(DRIVER) $(COMMON) default_common.h
	$(CC) $(CFLAGS) -o $@ $(DRIVER) $(COMMON) $(LDFLAGS)

clean:
	rm -f $(COMMON) $(TARGET) *.o *.d *.partial

# Auto-generated header dependencies (via -MMD -MP).
-include $(wildcard *.d)
