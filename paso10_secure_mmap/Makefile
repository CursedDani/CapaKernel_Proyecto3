# ==============================================================================
# Paso 10 - Boveda segura (Parcial 25%): modulo de kernel + pruebas + benchmark
#
# Uso rapido (requiere kernel-devel / linux-headers del kernel en ejecucion):
#   make                # modulo secure_vault.ko + binarios de prueba (SIN warnings)
#   make load           # sudo insmod secure_vault.ko allowed_uid=$(ALLOWED_UID)
#   make test           # ejecuta tests/ contra /dev/secure_vault
#   make unload
#
# IMPORTANTE: kbuild NO soporta rutas con espacios. Si su carpeta contiene espacios
# (p. ej. "parcial 3") clone/copie el repo a una ruta sin espacios.
# ==============================================================================

obj-m += secure_vault.o
secure_vault-y := kmod_secure_mmap.o secure_crypto.o secure_audit.o

# -Werror: el parcial exige "clean build". Falla la compilacion ante cualquier warning.
ccflags-y += -Wall -Wextra -Werror -Wno-unused-parameter -Wno-missing-field-initializers

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(CURDIR)
ALLOWED_UID ?= 1000

.PHONY: all modules tests bench clean load unload test attack

all: modules tests bench

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

tests:
	$(MAKE) -C tests

bench:
	$(MAKE) -C bench

clean:
	-$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C tests clean
	$(MAKE) -C bench clean

load: modules
	sudo insmod secure_vault.ko allowed_uid=$(ALLOWED_UID)
	sudo chmod 666 /dev/secure_vault

unload:
	sudo rmmod secure_vault

test: tests
	./tests/run_tests.sh /dev/secure_vault

attack: tests
	./tests/run_tests.sh /dev/secure_vault
