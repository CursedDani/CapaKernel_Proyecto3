CC     ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror

all: bench_mmap_latency

bench_mmap_latency: bench_mmap_latency.c
	$(CC) $(CFLAGS) -o $@ $< -lm

clean:
	rm -f bench_mmap_latency

.PHONY: all clean
