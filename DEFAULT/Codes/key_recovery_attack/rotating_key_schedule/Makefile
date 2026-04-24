# Makefile for the C+OpenMP port of the rotating-key-schedule
# key-recovery attack on DEFAULT.
#
#     make                       # build rotating_attack
#     OMP_NUM_THREADS=20 \
#         ./rotating_attack 6    # run the 6-round attack (needs trails_6r.txt)
#     ./rotating_attack 7        # 7-round (needs trails_7r.txt)
#     ./rotating_attack 8        # 8-round
#     make clean

CC      ?= gcc
CFLAGS  ?= -O3 -march=native -fopenmp -Wall -Wextra -std=c11 -MMD -MP
LDFLAGS ?= -fopenmp

TARGET   = rotating_attack
COMMON   = rotating_common.o
DRIVER   = key_recovery_on_rotating_key_schedule_Nr.c

.PHONY: all clean

all: $(TARGET)

$(COMMON): rotating_common.c rotating_common.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(DRIVER) $(COMMON) rotating_common.h
	$(CC) $(CFLAGS) -o $@ $(DRIVER) $(COMMON) $(LDFLAGS)

clean:
	rm -f $(COMMON) $(TARGET) *.o *.d *.partial

# Auto-generated header dependencies (via -MMD -MP).
# Wildcard-include every .d file emitted by the build (common object
# plus driver compile-and-link) so new headers are auto-tracked.
-include $(wildcard *.d)
