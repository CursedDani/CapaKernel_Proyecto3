#!/usr/bin/env bash
# ==============================================================================
# check_compat.sh - Compila los modulos del repo contra uno o varios arboles de headers
# (kernel-devel) y reporta OK/FAIL y numero de warnings por modulo y version de kernel.
#
#   uso: vm/check_compat.sh /ruta/headers-A [/ruta/headers-B ...]
#        (sin argumentos usa /lib/modules/$(uname -r)/build)
#
# Para obtener headers de OTRA version sin root:
#   dnf download kernel-devel-<ver> && rpm2cpio kernel-devel-*.rpm | cpio -idm
#   -> usr/src/kernels/<ver>   (ese directorio es el KDIR)
# ==============================================================================
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KDIRS=("$@"); [ ${#KDIRS[@]} -eq 0 ] && KDIRS=("/lib/modules/$(uname -r)/build")
MODS=(paso3_driver_copy_user paso4_driver_mmap_kernel paso6_demand_paging_fault \
      paso8_secure_driver paso9_kprobe_auditor paso10_secure_mmap)

WORK="$(mktemp -d /tmp/vault-compat.XXXXXX)"; trap 'rm -rf "$WORK"' EXIT
tar -C "$ROOT" --exclude=.git --exclude=docs -cf - . | tar -C "$WORK" -xf -   # sin espacios en la ruta

printf "%-28s %-30s %s\n" "MODULO" "KERNEL (headers)" "RESULTADO"
rc=0
for K in "${KDIRS[@]}"; do
    [ -e "$K/Makefile" ] || { echo "sin headers en $K"; rc=1; continue; }
    KVER="$(basename "$K")"; [ "$KVER" = build ] && KVER="$(uname -r)"
    for m in "${MODS[@]}"; do
        make -C "$WORK/$m" clean KDIR="$K" >/dev/null 2>&1
        log="$WORK/$m.log"
        if make -C "$WORK/$m" modules KDIR="$K" >"$log" 2>&1; then
            # El aviso "compiler differs" es del toolchain, no del codigo del modulo
            w=$(grep "warning:" "$log" | grep -vc "compiler differs\|pahole")
            printf "%-28s %-30s OK (%s warnings de codigo)\n" "$m" "$KVER" "$w"
        else
            printf "%-28s %-30s FALLA\n" "$m" "$KVER"; grep -m3 "error" "$log" | sed 's/^/      /'; rc=1
        fi
    done
done
exit $rc
