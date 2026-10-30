obj-m += kmod_mmap.o

# Fuera de kbuild: KDIR, omitir si faltan headers y soporte de rutas con espacios
ifeq ($(KERNELRELEASE),)
include ../scripts/kbuild.mk
endif
PWD := $(shell pwd)

USER_TARGET = test_mmap
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g

all: modules $(USER_TARGET)

modules:
	$(call kbuild_run,modules)

$(USER_TARGET): test_mmap.c
	$(CC) $(CFLAGS) -o $@ test_mmap.c

clean:
	rm -f $(KBUILD_ARTIFACTS)
	rm -f $(USER_TARGET)

load:
	sudo insmod kmod_mmap.ko
	sudo chmod 666 /dev/demo_mmap

unload:
	sudo rmmod kmod_mmap

test: $(USER_TARGET)
	./$(USER_TARGET)

.PHONY: all modules clean load unload test
