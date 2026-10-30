obj-m += kmod_copy_user.o

# Fuera de kbuild: KDIR, omitir si faltan headers y soporte de rutas con espacios
ifeq ($(KERNELRELEASE),)
include ../scripts/kbuild.mk
endif
PWD := $(shell pwd)

USER_TARGET = test_copy_user
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g

all: modules $(USER_TARGET)

modules:
	$(call kbuild_run,modules)

$(USER_TARGET): test_copy_user.c
	$(CC) $(CFLAGS) -o $@ test_copy_user.c

clean:
	rm -f $(KBUILD_ARTIFACTS)
	rm -f $(USER_TARGET)

load:
	sudo insmod kmod_copy_user.ko
	sudo chmod 666 /dev/demo_copy_user

unload:
	sudo rmmod kmod_copy_user

test: $(USER_TARGET)
	./$(USER_TARGET)

.PHONY: all modules clean load unload test
