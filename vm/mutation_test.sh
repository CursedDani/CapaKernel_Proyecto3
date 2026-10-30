#!/usr/bin/env bash
# ==============================================================================
# mutation_test.sh - Prueba de MUTACION de la boveda: elimina un control a la vez y
# comprueba que la bateria de pruebas lo DETECTA (alguna prueba pasa a FAIL).
# Un mutante que "sobrevive" indica un control redundante o una prueba que falta.
#
#   uso: vm/mutation_test.sh        (usa las mismas variables KVER/KDIR que run_vm_tests.sh)
# Cada mutante compila y arranca su propia VM (~15 s). Los textos a mutar estan en MUTATE.py.
# ==============================================================================
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="$(mktemp -d /tmp/vault-mut.XXXXXX)"; trap 'rm -rf "$W"' EXIT
cd /tmp   # no ejecutar desde un directorio que se vaya a borrar

declare -A DESC=(
  [M1]="sin validacion de pgoff/longitud (control 5)"
  [M2]="sin limpiar VM_MAYEXEC: mprotect(PROT_EXEC) posterior (control 2)"
  [M3]="mmap sin re-verificar identidad: fd heredado (control 1)"
  [M4]="permite MAP_PRIVATE: vector COW (control 4)"
  [M5]="sin VM_DONTCOPY/DONTDUMP/DONTEXPAND (control 6)"
  [M6]="fd solo-lectura sin limpiar VM_WRITE|VM_MAYWRITE (control 3)"
  [M7]="sin verificar el HMAC (control 9)"
  [M8]="VM_SHARED en vez de VM_MAYSHARE (indicacion original del plan)"
)

for name in M1 M2 M3 M4 M5 M6 M7 M8; do
    d="$W/$name"; mkdir -p "$d"; rsync -a --exclude .git --exclude docs "$ROOT/" "$d/"
    python3 "$ROOT/vm/MUTATE.py" "$d/paso10_secure_mmap/kmod_secure_mmap.c" "$name" || { echo "$name: mutacion no aplicable"; continue; }
    OUT="$d/ev" "$d/vm/run_vm_tests.sh" tests >"$d/out.txt" 2>&1
    if [ ! -f "$d/ev/tests.log" ]; then
        printf "%-3s %-66s NO COMPILA (-Werror lo rechazo)\n" "$name" "${DESC[$name]}"; continue
    fi
    p=$(grep -c '^\[PASS\]' "$d/ev/tests.log"); f=$(grep -c '^\[FAIL\]' "$d/ev/tests.log")
    est=SOBREVIVE; [ "$f" -gt 0 ] && est=DETECTADO
    printf "%-3s %-66s PASS=%-3s FAIL=%-2s %s\n" "$name" "${DESC[$name]}" "$p" "$f" "$est"
    grep '^\[FAIL\]' "$d/ev/tests.log" | head -3 | sed 's/^/        /'
done
