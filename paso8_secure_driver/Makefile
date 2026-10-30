obj-m += kmod_secure.o

# El parcial exige "clean build": cualquier warning rompe la compilacion
ccflags-y += -Wall -Wextra -Werror -Wno-unused-parameter

# Fuera de kbuild: KDIR, omitir si faltan headers y soporte de rutas con espacios
ifeq ($(KERNELRELEASE),)
include ../scripts/kbuild.mk
endif
PWD := $(shell pwd)

USER_TARGET = test_secure
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g

all: modules $(USER_TARGET)

modules:
	$(call kbuild_run,modules)

$(USER_TARGET): test_secure.c
	$(CC) $(CFLAGS) -o $@ test_secure.c

clean:
	rm -f $(KBUILD_ARTIFACTS)
	rm -f $(USER_TARGET)

# allowed_uid=0 (root) por defecto; sobreescriba con: make load ALLOWED_UID=<uid>
ALLOWED_UID ?= 1000

load:
	sudo insmod kmod_secure.ko allowed_uid=$(ALLOWED_UID)
	sudo chmod 666 /dev/secure_mmap

unload:
	sudo rmmod kmod_secure

test: $(USER_TARGET)
	./$(USER_TARGET)

attack: $(USER_TARGET)
	./attack_unauthorized_uid.sh

.PHONY: all modules clean load unload test attack
