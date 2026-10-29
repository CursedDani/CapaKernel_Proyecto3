# Solo h5 se carga (en la VM). El resto se verifica con ./verificar.sh (compilacion).
obj-m += h5_cr0_wp.o
KDIR ?= /lib/modules/$(shell uname -r)/build
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	-$(MAKE) -C $(KDIR) M=$(CURDIR) clean
.PHONY: modules clean
