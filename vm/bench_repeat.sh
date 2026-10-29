#!/usr/bin/env bash
# ==============================================================================
# bench_repeat.sh - Repite la suite "bench" en N arranques independientes de la VM y
# resume con la MEDIANA entre arranques (el ruido del host entre arranques puede ser ~2x,
# por eso una sola corrida no es defendible). Cada arranque ya trae 30 corridas internas.
#   uso: vm/bench_repeat.sh [N=7]      (mismas variables KVER/KDIR que run_vm_tests.sh)
# ==============================================================================
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N="${1:-7}"; W="$(mktemp -d /tmp/vault-benchrep.XXXXXX)"; trap 'rm -rf "$W"' EXIT
for i in $(seq 1 "$N"); do
    OUT="$W/b$i" "$ROOT/vm/run_vm_tests.sh" bench >/dev/null 2>&1 || true
    [ -f "$W/b$i/bench.log" ] || { echo "arranque $i fallo"; continue; }
done
python3 - "$W" "$N" <<'PY'
import sys,re,statistics as st,glob
W,N=sys.argv[1],int(sys.argv[2])
data={'baseline':{}, 'vault':{}}
for f in sorted(glob.glob(W+'/b*/bench.log')):
    sect=None
    for l in open(f):
        if 'linea base' in l: sect='baseline'
        elif 'solucion' in l: sect='vault'
        m=re.match(r'METRIC (\S+)\s+mean=([\d.]+)',l)
        if m and sect: data[sect].setdefault(m.group(1),[]).append(float(m.group(2)))
n=len(data['baseline'].get('mmap_ns',[]))
print("# Benchmark: mediana entre %d arranques de VM (rango min..max entre arranques); cada arranque = 30 corridas x 2000 iteraciones"%n)
print("# baseline = Paso 4 (remap_pfn_range, sin proteccion) | vault = paso10 secure_vault")
print("%-11s %24s %24s %9s"%("metrica","baseline (ns)","vault (ns)","vault/base"))
for k in ['mmap_ns','touch_ns','fault_ns','munmap_ns','total_ns','session_ns','access_ns','minflt']:
    b=data['baseline'][k]; v=data['vault'][k]
    mb,mv=st.median(b),st.median(v)
    ratio=(mv/mb) if mb else float('nan')
    print("%-11s %10.1f (%7.1f..%7.1f) %10.1f (%7.1f..%7.1f) %8.2fx"%(k,mb,min(b),max(b),mv,min(v),max(v),ratio))
PY
