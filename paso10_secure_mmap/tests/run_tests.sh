#!/usr/bin/env bash
# ==============================================================================
# run_tests.sh - Ejecuta la bateria de pruebas de ataque/defensa contra la boveda.
#
#   uso: ./run_tests.sh [/dev/secure_vault]
#
# Requisitos: modulo cargado con  allowed_uid=1000  (make load ALLOWED_UID=1000),
# y sudo (para cambiar de UID con setpriv). Para ejecutar TODO sin riesgo en el host,
# use el harness de VM:  ../../vm/run_vm_tests.sh
# ==============================================================================
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV="${1:-/dev/secure_vault}"
PASS=0; FAIL=0

[ -e "$DEV" ] || { echo "No existe $DEV: cargue el modulo (make load)"; exit 2; }

while read -r prog uid gid; do
    case "$prog" in ''|'#'*) continue;; esac
    echo
    echo "################ $prog (uid=$uid) ################"
    if [ "$uid" = "$(id -u)" ]; then
        "$DIR/$prog" "$DEV"; rc=$?
    else
        sudo setpriv --reuid="$uid" --regid="$gid" --clear-groups \
             --inh-caps=-all --bounding-set=-all "$DIR/$prog" "$DEV"; rc=$?
    fi
    if [ $rc -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
done < "$DIR/manifest.txt"

echo
echo "================ RESUMEN: $PASS programas OK, $FAIL con fallos ================"
echo "Estadisticas del modulo:"; cat /proc/secure_vault/stats 2>/dev/null
[ $FAIL -eq 0 ]
