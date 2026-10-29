#!/usr/bin/env bash
# ==============================================================================
# verificar.sh - Comprueba EMPIRICAMENTE las afirmaciones tipicas de una IA sobre APIs del
# kernel (parte "alucinaciones" del parcial). Intenta compilar cada hN_*.c contra los
# headers REALES y reporta si compila y enlaza.
#   uso: ./verificar.sh [KDIR ...]     (defecto: /lib/modules/$(uname -r)/build)
# kbuild no admite espacios en la ruta: se compila en un directorio temporal.
# ==============================================================================
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KDIRS=("$@"); [ ${#KDIRS[@]} -eq 0 ] && KDIRS=("/lib/modules/$(uname -r)/build")
W="$(mktemp -d /tmp/halluc.XXXXXX)"; trap 'rm -rf "$W"' EXIT
for K in "${KDIRS[@]}"; do
  V="$(basename "$K")"; [ "$V" = build ] && V="$(uname -r)"
  echo "================ headers $V ================"
  for f in "$HERE"/h[1-6]_*.c; do
    n="$(basename "$f" .c)"; [ "$n" = h5_cr0_wp ] && continue   # h5 es de ejecucion (VM)
    d="$W/$n"; mkdir -p "$d"; cp "$f" "$d/$n.c"; echo "obj-m := $n.o" > "$d/Makefile"
    if make -C "$K" M="$d" modules >"$d/log" 2>&1; then
      printf "%-26s COMPILA y ENLAZA\n" "$n"
    else
      printf "%-26s FALLA: %s\n" "$n" "$(grep -m1 -E 'error|ERROR|undefined' "$d/log" | sed 's|^.*/||' | cut -c1-150)"
    fi
  done
done
