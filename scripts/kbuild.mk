# ==============================================================================
# kbuild.mk - Logica comun para compilar/limpiar modulos de kernel desde cada paso.
# Se incluye SOLO en la invocacion externa (KERNELRELEASE vacio), nunca dentro de kbuild.
#
# Resuelve los dos problemas del entorno:
#   1. Sin headers (falta kernel-devel): se OMITE el modulo con un aviso claro y el resto
#      del proyecto (programas de usuario) sigue compilando.
#   2. Ruta con espacios (p. ej. "parcial 3"): kbuild no la soporta, asi que se compila en
#      una copia temporal sin espacios y se trae el .ko de vuelta.
# ==============================================================================

KDIR ?= /lib/modules/$(shell uname -r)/build

KBUILD_NO_HEADERS := $(if $(wildcard $(KDIR)/Makefile),,1)
KBUILD_SPACES     := $(if $(word 2,$(CURDIR)),1,)
KBUILD_NAME       := $(shell basename "$(CURDIR)")

define kbuild_no_headers_msg
	@echo "[!] Sin headers del kernel en $(KDIR): se OMITE el modulo de $(KBUILD_NAME)."
	@echo "    Solucion: sudo dnf install kernel-devel-$$(uname -r)   (Debian/Ubuntu: linux-headers-$$(uname -r))"
	@echo "    Si su version ya no esta en los repos: actualice el kernel y reinicie, o use"
	@echo "    KDIR=<ruta-headers> make   /   vm/run_vm_tests.sh  (ver RESUMEN_IMPLEMENTACION.md)"
endef

# $(call kbuild_run,modules|clean)
ifeq ($(KBUILD_NO_HEADERS),1)
define kbuild_run
	$(kbuild_no_headers_msg)
endef
else ifeq ($(KBUILD_SPACES),1)
define kbuild_run
	@tmp=$$(mktemp -d /tmp/kbuild.XXXXXX); \
	 echo "[i] Ruta con espacios: compilando $(KBUILD_NAME) en $$tmp"; \
	 cp -a . "$$tmp/" && $(MAKE) -C $(KDIR) M="$$tmp" $(1); rc=$$?; \
	 if [ $$rc -eq 0 ] && [ "$(1)" = modules ]; then cp "$$tmp"/*.ko . ; fi; \
	 rm -rf "$$tmp"; exit $$rc
endef
else
define kbuild_run
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(1)
endef
endif

# Limpieza local (no necesita headers)
KBUILD_ARTIFACTS = *.ko *.o *.mod *.mod.c .*.cmd .*.d Module.symvers modules.order .module-common.o
