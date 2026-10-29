obj-m += kmod_secure.o

# El parcial exige "clean build": cualquier warning rompe la compilacion
ccflags-y += -Wall -Wextra -Werror -Wno-unused-parameter

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

USER_TARGET = test_secure
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g

all: modules $(USER_TARGET)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

$(USER_TARGET): test_secure.c
	$(CC) $(CFLAGS) -o $@ test_secure.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
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
