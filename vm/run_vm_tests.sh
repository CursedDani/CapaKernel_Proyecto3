#!/usr/bin/env bash
# ==============================================================================
# run_vm_tests.sh - Ejecuta los modulos de kernel y las pruebas de ataque DENTRO de
# una maquina virtual QEMU/KVM desechable (arranca en ~1 s con el kernel del host).
#
# POR QUE: cargar un modulo puede provocar un kernel panic. En la VM un panic solo
# apaga la VM; el host jamas carga nada y NO se necesita root.
#
#   uso:  vm/run_vm_tests.sh [suite ...]        (por defecto: all)
#   suites:  tests   bateria PASS/FAIL contra /dev/secure_vault (paso10)
#            matrix  matriz de ataques ANTES (Paso 4) / DESPUES (paso10)
#            bench   benchmark de overhead (Paso 4 vs paso10) + estadisticas del kernel
#            kprobe  auditor global de mmap() (paso9)
#            halluc  experimento de ejecucion de "practicas inseguras de IA" (CR0.WP) en la VM
#            trace   ftrace function_graph sobre vault_fault (duracion por page fault)
#            all     todas las anteriores
#
#   variables:  KVER  version de kernel a arrancar     (def. $(uname -r))
#               KDIR  arbol de headers para compilar   (def. /lib/modules/$KVER/build)
#               OUT   carpeta de evidencia             (def. docs/evidencia)
#               SMP / MEM  vCPUs y MiB de la VM        (def. 2 / 512)
#
# Requisitos: qemu-system-x86_64, /dev/kvm accesible, /boot/vmlinuz-$KVER legible,
# kernel-devel del MISMO $KVER (el modulo debe coincidir en vermagic), gcc, make, cpio.
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KVER="${KVER:-$(uname -r)}"
KDIR="${KDIR:-/lib/modules/$KVER/build}"
OUT="${OUT:-$ROOT/docs/evidencia}"
SMP="${SMP:-2}"
MEM="${MEM:-512}"
SUITES=("$@"); [ ${#SUITES[@]} -eq 0 ] && SUITES=(all)

die() { echo "ERROR: $*" >&2; exit 1; }

# ---- comprobaciones previas ---------------------------------------------------
command -v qemu-system-x86_64 >/dev/null || die "falta qemu-system-x86_64 (sudo dnf install qemu-system-x86)"
[ -r "/boot/vmlinuz-$KVER" ] || die "no se puede leer /boot/vmlinuz-$KVER (defina KVER con un kernel instalado)"
[ -e "$KDIR/Makefile" ] || die "no hay headers en $KDIR: instale kernel-devel-$KVER (sudo dnf install kernel-devel-$KVER) o defina KDIR"
[ -w /dev/kvm ] || echo "AVISO: /dev/kvm no es escribible; la VM correra sin aceleracion (lento)" >&2

# ---- kbuild NO soporta espacios en la ruta: compilar en un espejo sin espacios ----
WORK="$(mktemp -d /tmp/vault-vm.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
if [[ "$ROOT" == *" "* ]]; then
    echo "[*] La ruta contiene espacios (kbuild no los soporta): compilando en un espejo temporal"
    BUILD="$WORK/src"; mkdir -p "$BUILD"
    tar -C "$ROOT" --exclude=.git --exclude=docs -cf - . | tar -C "$BUILD" -xf -
else
    BUILD="$ROOT"
fi
mkdir -p "$OUT"

echo "[*] Compilando modulos contra $KDIR (kernel de la VM: $KVER)"
build_ko() { make -C "$BUILD/$1" KDIR="$KDIR" modules >"$WORK/build-${1////_}.log" 2>&1 || { cat "$WORK/build-${1////_}.log"; die "fallo la compilacion de $1"; }; }
build_ko paso4_driver_mmap_kernel
build_ko paso10_secure_mmap
build_ko paso10_secure_mmap/verificacion_ia
if [ -d "$BUILD/paso9_kprobe_auditor" ]; then
    build_ko paso9_kprobe_auditor
    make -C "$BUILD/paso9_kprobe_auditor" mmap_probe >"$WORK/build-probe.log" 2>&1 || { cat "$WORK/build-probe.log"; die "fallo mmap_probe"; }
fi
make -C "$BUILD/paso10_secure_mmap" tests bench >"$WORK/build-user.log" 2>&1 || { cat "$WORK/build-user.log"; die "fallo la compilacion de las pruebas"; }
gcc -O2 -Wall -Wextra -Werror -o "$WORK/init" "$ROOT/vm/init.c"
echo "[+] Compilacion limpia (modulos con -Werror, pruebas con -Werror)"

# ---- utilidades de initramfs ----------------------------------------------------
IR="$WORK/root"
add_file() { # origen destino
    mkdir -p "$IR$(dirname "$2")"; cp "$1" "$IR$2"
    if file -L "$1" | grep -q "dynamically linked"; then
        ldd "$1" | awk '/=>/ {print $3} /ld-linux/ {print $1}' | sort -u | while read -r l; do
            [ -e "$l" ] && { mkdir -p "$IR$(dirname "$l")"; cp -L "$l" "$IR$l"; }
        done
    fi
}

boot_vm() { # nombre-del-log ; usa $IR y $WORK/plan.txt
    local name="$1"
    cp "$WORK/plan.txt" "$IR/plan.txt"
    add_file "$WORK/init" /init     # incluye libc/ld.so que necesita el propio init
    mkdir -p "$IR"/{proc,sys,dev,tmp}
    (cd "$IR" && find . | cpio -o -H newc --quiet | gzip -1 > "$WORK/initrd.gz")
    echo "[*] Arrancando VM ($KVER) -> $OUT/$name.log"
    # -nic none evita el arranque PXE; panic=-1 reinicia (y -no-reboot apaga) ante un panic
    timeout 600 qemu-system-x86_64 -enable-kvm -cpu host -smp "$SMP" -m "$MEM" \
        -nographic -nic none -no-reboot \
        -kernel "/boot/vmlinuz-$KVER" -initrd "$WORK/initrd.gz" \
        -append "console=ttyS0 panic=-1 quiet loglevel=0" 2>&1 \
        | tr -d '\r' | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\x1bc//g' \
        | grep -v "^$" | grep -v "iPXE\|Booting from ROM\|Press Ctrl-B" > "$OUT/$name.log" || true
}

fresh_root() { rm -rf "$IR"; mkdir -p "$IR"; : > "$WORK/plan.txt"; }
plan() { echo "$*" >> "$WORK/plan.txt"; }

TESTS="$BUILD/paso10_secure_mmap/tests"
BENCH="$BUILD/paso10_secure_mmap/bench"
add_tests() {
    local p
    for p in $(grep -v '^#' "$TESTS/manifest.txt" | awk 'NF{print $1}') attack_matrix; do
        add_file "$TESTS/$p" "/tests/$p"
    done
}

# ---- suites ----------------------------------------------------------------------
suite_tests() {
    fresh_root; add_tests
    add_file "$BUILD/paso10_secure_mmap/secure_vault.ko" /secure_vault.ko
    plan "echo ===== SUITE tests: bateria de ataque/defensa contra /dev/secure_vault ====="
    plan "insmod /secure_vault.ko allowed_uid=1000"
    plan "chmod 666 /dev/secure_vault"
    while read -r prog uid gid; do
        case "$prog" in ''|'#'*) continue;; esac
        plan "echo"; plan "echo ################ $prog uid=$uid ################"
        plan "run $uid $gid /tests/$prog /dev/secure_vault"
    done < "$TESTS/manifest.txt"
    plan "echo"; plan "echo ===== /proc/secure_vault/stats ====="
    plan "cat /proc/secure_vault/stats"
    plan "echo"; plan "echo ===== dmesg (auditoria del kernel) ====="
    plan "dmesg secure_vault"
    plan "rmmod secure_vault"
    plan "dmesg descargado"
    boot_vm tests
}

suite_matrix() {
    fresh_root; add_tests
    add_file "$BUILD/paso4_driver_mmap_kernel/kmod_mmap.ko" /kmod_mmap.ko
    add_file "$BUILD/paso10_secure_mmap/secure_vault.ko" /secure_vault.ko
    plan "echo ===== ANTES: Paso 4 (kmod_mmap, sin endurecer) atacado por 'nobody' ====="
    plan "insmod /kmod_mmap.ko"
    plan "chmod 666 /dev/demo_mmap"
    plan "run 65534 65534 /tests/attack_matrix /dev/demo_mmap"
    plan "rmmod kmod_mmap"
    plan "echo"; plan "echo ===== DESPUES: boveda atacada por 'nobody' (UID no autorizado) ====="
    plan "insmod /secure_vault.ko allowed_uid=1000"
    plan "chmod 666 /dev/secure_vault"
    plan "run 65534 65534 /tests/attack_matrix /dev/secure_vault"
    plan "echo"; plan "echo ===== DESPUES: boveda atacada por UID 1000 AUTORIZADO (cada control por separado) ====="
    plan "run 1000 1000 /tests/attack_matrix /dev/secure_vault"
    plan "rmmod secure_vault"
    boot_vm matrix
}

suite_bench() {
    fresh_root
    add_file "$BENCH/bench_mmap_latency" /bench_mmap_latency
    add_file "$BUILD/paso4_driver_mmap_kernel/kmod_mmap.ko" /kmod_mmap.ko
    add_file "$BUILD/paso10_secure_mmap/secure_vault.ko" /secure_vault.ko
    plan "echo ===== BENCH linea base: Paso 4 (remap_pfn_range, sin proteccion) ====="
    plan "insmod /kmod_mmap.ko"
    plan "chmod 666 /dev/demo_mmap"
    plan "run 1000 1000 /bench_mmap_latency /dev/demo_mmap 2000 30"
    plan "rmmod kmod_mmap"
    plan "echo"; plan "echo ===== BENCH solucion: paso10 secure_vault ====="
    plan "insmod /secure_vault.ko allowed_uid=1000"
    plan "chmod 666 /dev/secure_vault"
    plan "run 1000 1000 /bench_mmap_latency /dev/secure_vault 2000 30"
    plan "echo"; plan "echo ===== estadisticas del modulo (fault_ns_avg medido DENTRO del kernel) ====="
    plan "cat /proc/secure_vault/stats"
    plan "rmmod secure_vault"
    boot_vm bench
}

suite_kprobe() {
    [ -d "$BUILD/paso9_kprobe_auditor" ] || { echo "[i] paso9_kprobe_auditor no existe, se omite"; return; }
    fresh_root; add_tests
    add_file "$BUILD/paso9_kprobe_auditor/kmod_auditor.ko" /kmod_auditor.ko
    add_file "$BUILD/paso9_kprobe_auditor/mmap_probe" /mmap_probe
    add_file "$BUILD/paso10_secure_mmap/secure_vault.ko" /secure_vault.ko
    plan "echo ===== SUITE kprobe: auditor global de mmap() (paso9) ====="
    plan "insmod /kmod_auditor.ko watch_prefix=/tmp/secret"
    plan "insmod /secure_vault.ko allowed_uid=1000"
    plan "chmod 666 /dev/secure_vault"
    plan "echo"; plan "echo --- mmap_probe: mmaps sospechosos CONTROLADOS (archivo de prueba propio) ---"
    plan "run 1000 1000 /mmap_probe /tmp/secret.txt /dev/secure_vault"
    plan "run 1000 1000 /tests/test_prot_exec /dev/secure_vault"
    plan "echo"; plan "echo ===== /proc/mmap_audit ====="
    plan "cat /proc/mmap_audit"
    plan "echo"; plan "echo ===== dmesg del auditor ====="
    plan "dmesg mmap_auditor"
    plan "rmmod secure_vault"
    plan "rmmod kmod_auditor"
    plan "dmesg descargado"
    boot_vm kprobe
}

suite_halluc() {
    fresh_root
    add_file "$BUILD/paso10_secure_mmap/verificacion_ia/h5_cr0_wp.ko" /h5_cr0_wp.ko
    plan "echo ===== SUITE halluc: practica insegura sugerida por IA: apagar CR0.WP (se ejecuta SOLO en la VM) ====="
    plan "insmod /h5_cr0_wp.ko"
    plan "dmesg h5:"
    plan "dmesg CR0"
    plan "rmmod h5_cr0_wp"
    boot_vm halluc
}

suite_trace() {
    fresh_root
    add_file "$BENCH/bench_mmap_latency" /bench_mmap_latency
    add_file "$BUILD/paso10_secure_mmap/secure_vault.ko" /secure_vault.ko
    local T=/sys/kernel/tracing
    plan "echo ===== SUITE trace: ftrace function_graph de vault_fault (duracion por page fault) ====="
    plan "mount tracefs $T"
    plan "insmod /secure_vault.ko allowed_uid=1000"
    plan "chmod 666 /dev/secure_vault"
    plan "write $T/set_graph_function vault_fault"
    plan "write $T/current_tracer function_graph"
    plan "write $T/tracing_on 1"
    plan "run 1000 1000 /bench_mmap_latency /dev/secure_vault 4 1"
    plan "write $T/tracing_on 0"
    plan "cat $T/trace"
    plan "write $T/current_tracer nop"
    plan "rmmod secure_vault"
    boot_vm trace
}

for s in "${SUITES[@]}"; do
    case "$s" in
        tests)  suite_tests ;;
        matrix) suite_matrix ;;
        bench)  suite_bench ;;
        kprobe) suite_kprobe ;;
        trace)  suite_trace ;;
        halluc) suite_halluc ;;
        all)    suite_tests; suite_matrix; suite_bench; suite_kprobe; suite_trace; suite_halluc ;;
        *)      die "suite desconocida: $s" ;;
    esac
done
echo "[+] Listo. Evidencia en $OUT"
