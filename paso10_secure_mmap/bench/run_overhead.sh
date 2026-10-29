#!/usr/bin/env bash
# ==============================================================================
# run_overhead.sh - Medicion de overhead EN EL HOST con perf / strace / ftrace.
#
# Requiere los modulos cargados (make -C .. load  y  sudo insmod ../../paso4_*/kmod_mmap.ko)
# y, opcionalmente: perf, strace. ftrace se usa via tracefs directo (sin trace-cmd).
#
# NOTA: la evidencia incluida en docs/evidencia/ se obtuvo DENTRO de la VM QEMU/KVM
# (vm/run_vm_tests.sh bench|trace), donde perf/strace no estan disponibles; este script
# es la version "de host" para quien tenga esas herramientas instaladas
# (sudo dnf install perf strace  /  sudo apt install linux-tools-$(uname -r) strace).
# ==============================================================================
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$DIR/bench_mmap_latency"
ITERS="${ITERS:-2000}"; RUNS="${RUNS:-30}"
BASE_DEV=/dev/demo_mmap
VAULT_DEV=/dev/secure_vault

[ -x "$BENCH" ] || { echo "compile primero: make -C $DIR"; exit 1; }

for dev in "$BASE_DEV" "$VAULT_DEV"; do
    [ -e "$dev" ] || { echo "falta $dev (cargue los modulos)"; continue; }
    echo; echo "################ $dev ################"

    echo "--- latencia (media +- sd sobre $RUNS corridas) ---"
    "$BENCH" "$dev" "$ITERS" "$RUNS"

    if command -v perf >/dev/null; then
        echo "--- perf stat: fallos de pagina y cambios de contexto ---"
        perf stat -e page-faults,minor-faults,major-faults,context-switches \
            "$BENCH" "$dev" 500 3 2>&1 | grep -E "page-faults|minor|major|context|elapsed"
    else
        echo "[i] perf no instalado: se omite (usa getrusage/minflt del benchmark)"
    fi

    if command -v strace >/dev/null; then
        echo "--- strace -c: syscalls (los accesos posteriores al mmap NO generan ninguna) ---"
        strace -c -f "$BENCH" "$dev" 200 1 2>&1 | head -15
    else
        echo "[i] strace no instalado: se omite"
    fi
done

# ftrace: duracion de vault_fault por page fault (requiere root + tracefs)
T=/sys/kernel/tracing
if [ -e "$VAULT_DEV" ] && [ -w "$T/current_tracer" ] 2>/dev/null; then
    echo; echo "################ ftrace function_graph: vault_fault ################"
    echo vault_fault > "$T/set_graph_function"
    echo function_graph > "$T/current_tracer"
    echo 1 > "$T/tracing_on"
    "$BENCH" "$VAULT_DEV" 4 1 >/dev/null
    echo 0 > "$T/tracing_on"
    grep -E "vault_fault|us +\|  \}" "$T/trace" | head -40
    echo nop > "$T/current_tracer"
else
    echo "[i] ftrace: ejecute como root con tracefs montado (sudo ./run_overhead.sh)"
fi
