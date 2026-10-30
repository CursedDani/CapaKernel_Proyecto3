# Paso 9 - Auditor global de mmap() con kprobes (Parcial 25%, Componente B)
#   make            # modulo kmod_auditor.ko (-Werror) + mmap_probe
#   make load       # sudo insmod kmod_auditor.ko
#   make demo       # genera mmaps sospechosos y muestra /proc/mmap_audit
#   make unload
# NOTA: kbuild no soporta rutas con espacios; use una ruta sin espacios.

obj-m += kmod_auditor.o
ccflags-y += -Wall -Wextra -Werror -Wno-unused-parameter

# Fuera de kbuild: KDIR, omitir si faltan headers y soporte de rutas con espacios
ifeq ($(KERNELRELEASE),)
include ../scripts/kbuild.mk
endif
PWD  := $(CURDIR)
CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror

all: modules mmap_probe

modules:
	$(call kbuild_run,modules)

mmap_probe: mmap_probe.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(KBUILD_ARTIFACTS)
	rm -f mmap_probe

load: modules
	sudo insmod kmod_auditor.ko watch_prefix=/tmp/secret

unload:
	sudo rmmod kmod_auditor

demo: mmap_probe
	./mmap_probe /tmp/secret.txt
	@echo "---- /proc/mmap_audit ----"
	@grep -E "^(total|anonimos|archivos|anomalos)|regla=[A-Z]" /proc/mmap_audit

.PHONY: all modules clean load unload demo
