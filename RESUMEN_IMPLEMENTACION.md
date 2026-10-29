# Resumen de lo implementado y paso a paso para ejecutarlo todo

**Parcial 25 % — Seguridad de archivos en capa Kernel y `mmap`** · Sistemas Operativos 2026-2
Este documento resume **qué se implementó, dónde está, qué se verificó y cómo reproducirlo**. El informe académico (Partes I–III) está en [`docs/`](./docs/).

---

## 1. Qué se implementó (en una página)

Se ejecutó el [plan de acción](../PLAN_DE_ACCION_P3.md) sobre el repositorio `CapaKernel` y se organizó por carpetas:

| Carpeta | Qué es | Estado |
|---|---|---|
| [`paso10_secure_mmap/`](./paso10_secure_mmap/) | **Bóveda segura** `/dev/secure_vault` (módulo de kernel, ~1 000 líneas entre `.c` y `.h`, en 3 unidades de compilación). 10 controles: UID/`CAP_SYS_ADMIN` re-verificado en `open`/`mmap`/`ioctl`, W^X, solo `MAP_SHARED`, límites de `pgoff`, aislamiento (`VM_DONTCOPY/DONTDUMP/DONTEXPAND`), auditoría, **cifrado AES-128-CTR en reposo**, **integridad HMAC-SHA256**, detección de escrituras con `page_mkwrite`. Incluye `tests/` (10 programas de ataque/defensa), `bench/` y `verificacion_ia/` | ✅ compila `-Werror` en 6.19 y 7.2; 72/72 pruebas en VM |
| [`paso9_kprobe_auditor/`](./paso9_kprobe_auditor/) | **Auditor global** de `mmap()` con `kprobe` sobre `security_mmap_file` + reglas de anomalía + `/proc/mmap_audit` (Componente B que el README marcaba "pendiente") | ✅ |
| [`paso8_secure_driver/`](./paso8_secure_driver/) | Componente A previo (corregido: warning `-Wformat`, `class_create` portable, `-Werror`) | ✅ corregido |
| [`vm/`](./vm/) | **Harness QEMU/KVM**: carga los módulos y ejecuta los ataques en una VM desechable **sin root y sin riesgo de panic en el host**; compatibilidad multi-kernel; prueba de mutación; benchmark repetido | ✅ |
| [`docs/`](./docs/) | `PARTE_I_respuestas.md`, `PARTE_II_estrategia_IA.md`, `PARTE_III_implementacion_resultados.md` y `evidencia/` (logs reales) | ✅ (ver §6: pendientes del equipo) |
| `Makefile`, `run.sh`, `scripts/` | Integración: `SUBDIRS` con pasos 9-10, `make run-vm`, opción `[9]` en `./run.sh`, carga/descarga de los módulos nuevos | ✅ |

### Resultados clave (reales, en [`docs/evidencia/`](./docs/evidencia/))

- **72/72 comprobaciones PASS**, repetidas 3 veces, en el kernel **6.19.10** dentro de una VM KVM.
- **12/12 compilaciones OK, 0 warnings** de los 6 módulos del repo contra **6.19.10 y 7.2.13**.
- **Antes/después** frente al Paso 4: de 7 ataques que el Paso 4 *permite* (UID cualquiera, `PROT_EXEC`, `mprotect(EXEC)`, `MAP_PRIVATE`, offset ignorado, offset fuera del dispositivo, herencia por `fork`) la bóveda bloquea **todos**.
- **Prueba de mutación: 7/8 mutantes detectados**; el que sobrevive (M6) demuestra que un control es redundante con el core.
- **Overhead**: acceso con PTE instalada **1,00×** (0,5 ns); `munmap` 1,08×; ciclo `mmap`+toque+`munmap` 1,23×; primer fallo por página ≈ 1,7 µs (11,6× una PTE preinstalada); sesión completa con descifrado 2,14×.
- **Hallazgos que corrigen el plan/borrador** (detalle en `docs/PARTE_II_estrategia_IA.md` §3): hay que usar `VM_MAYSHARE`, no `VM_SHARED` (el plan lo decía al revés); el Paso 4 ignora el offset pero **no** lee fuera de su buffer; `CR0.WP` ya no se puede apagar (*pinning*); `kmap_atomic` aún compila; `mm_rb` ya no existe; kbuild no admite rutas con espacios.

---

## 2. Requisitos

| Necesito | Para qué | Fedora | Debian/Ubuntu |
|---|---|---|---|
| `gcc`, `make`, `cpio`, `rsync`, `file`, `python3` | compilar y empaquetar | `sudo dnf install gcc make cpio rsync file python3` | `sudo apt install build-essential cpio rsync file python3` |
| **Headers del kernel** (`kernel-devel`) | compilar los `.ko` | `sudo dnf install kernel-devel-$(uname -r)` | `sudo apt install linux-headers-$(uname -r)` |
| `qemu-system-x86_64` + `/dev/kvm` | VM de pruebas (recomendado) | `sudo dnf install qemu-system-x86` | `sudo apt install qemu-system-x86` |
| `/boot/vmlinuz-<KVER>` legible | kernel de la VM | (por defecto) | `sudo chmod +r /boot/vmlinuz-*` si hace falta |

> ⚠ **Ruta sin espacios.** kbuild no soporta espacios en la ruta del módulo. Si su carpeta contiene espacios (como `parcial 3`), `vm/run_vm_tests.sh` compila automáticamente en un espejo temporal; para compilar a mano con `make`, copie el repo a una ruta sin espacios.
> ⚠ **Nunca** cargue módulos propios en una máquina que no sea desechable sin antes pasar las pruebas en la VM: un bug puede dar *kernel panic*.

---

## 3. Paso a paso — ruta recomendada (VM, sin root)

```bash
cd CapaKernel_Proyecto3

# 3.1  Obtener los headers (si NO tiene kernel-devel instalado y NO tiene root).
#      Es lo que se hizo en esta sesión; sustituya la versión por la de un kernel instalado en /boot.
mkdir -p ~/kdevel && cd ~/kdevel
dnf download kernel-devel-6.19.10-300.fc44          # o la version que ofrezcan sus repos
rpm2cpio kernel-devel-*.rpm | cpio -idm
cd - >/dev/null
export KVER=6.19.10-300.fc44.x86_64                 # kernel que arrancara la VM (debe existir /boot/vmlinuz-$KVER)
export KDIR=$HOME/kdevel/usr/src/kernels/$KVER      # headers de ESA misma version
#      (si instalo kernel-devel del kernel en ejecucion, no hace falta exportar nada)

# 3.2  Ejecutar TODA la evidencia (compila con -Werror, arranca la VM, carga modulos, ataca, apaga)
vm/run_vm_tests.sh all            # ~1-2 minutos. Tambien: make run-vm   |   ./run.sh vm
#      o una suite concreta:  tests | matrix | bench | kprobe | trace | halluc

# 3.3  Ver los resultados
cat docs/evidencia/tests.log      # [PASS]/[FAIL] de los 10 programas + /proc/secure_vault/stats + dmesg
cat docs/evidencia/matrix.log     # matriz ANTES (Paso 4) / DESPUES (bóveda)
cat docs/evidencia/kprobe.log     # auditor global: eventos y anomalías
```

### Suites disponibles

| Comando | Qué hace | Salida |
|---|---|---|
| `vm/run_vm_tests.sh tests` | 10 programas de ataque/defensa contra `/dev/secure_vault` (uid autorizado 1000, `nobody`, root) | `evidencia/tests.log` |
| `vm/run_vm_tests.sh matrix` | Mismos ataques contra el **Paso 4** y contra la **bóveda** | `evidencia/matrix.log` |
| `vm/run_vm_tests.sh bench` | Latencia de `mmap`/fault/`munmap`/acceso, 30 corridas × 2000 iteraciones | `evidencia/bench.log` |
| `vm/run_vm_tests.sh kprobe` | Carga el auditor global y genera `mmap` sospechosos controlados | `evidencia/kprobe.log` |
| `vm/run_vm_tests.sh trace` | `ftrace function_graph` de `vault_fault` | `evidencia/trace.log` |
| `vm/run_vm_tests.sh halluc` | Experimento de la "práctica insegura" `CR0.WP` | `evidencia/halluc.log` |

### Extras de verificación

```bash
vm/check_compat.sh $KDIR [otro-KDIR ...]   # compila los 6 modulos del repo contra varios kernels (0 warnings)
paso10_secure_mmap/verificacion_ia/verificar.sh $KDIR   # comprueba "afirmaciones tipicas de IA" contra los headers reales
vm/mutation_test.sh                         # elimina un control por vez y exige que alguna prueba falle (8 mutantes)
vm/bench_repeat.sh 7                        # repite el benchmark en 7 arranques y resume con la mediana
```

---

## 4. Paso a paso — carga en el sistema real (requiere `sudo` y headers del kernel en ejecución)

> Hágalo **solo después** de que la VM pase 72/72, en una máquina que pueda reiniciar sin consecuencias.

```bash
cd <ruta-sin-espacios>/CapaKernel_Proyecto3

# 4.1 Compilar (modulos con -Wall -Wextra -Werror; pruebas con -Werror)
make -C paso10_secure_mmap            # secure_vault.ko + tests + bench
make -C paso9_kprobe_auditor          # kmod_auditor.ko + mmap_probe

# 4.2 Cargar la boveda. allowed_uid=1000 es lo que esperan las pruebas del manifiesto.
make -C paso10_secure_mmap load ALLOWED_UID=1000     # sudo insmod ... + chmod 666 /dev/secure_vault
sudo insmod paso9_kprobe_auditor/kmod_auditor.ko watch_prefix=/tmp/secret   # ruta 'sensible' de la demo
#     (alternativa a lo anterior: sudo ./scripts/load_modules.sh  carga TODOS los modulos del repo)

# 4.3 Probar
paso10_secure_mmap/tests/run_tests.sh /dev/secure_vault   # usa 'sudo setpriv' para cambiar de UID
cat /proc/secure_vault/stats                               # contadores de auditoria
paso9_kprobe_auditor/mmap_probe /tmp/secret.txt; grep 'regla=[A-Z]' /proc/mmap_audit | tail
sudo dmesg | grep -E "secure_vault|mmap_auditor" | tail -30

# 4.4 Medir con las herramientas del host (si estan instaladas: perf, strace; ftrace via tracefs)
sudo paso10_secure_mmap/bench/run_overhead.sh

# 4.5 Descargar
make -C paso10_secure_mmap unload
sudo rmmod kmod_auditor        # (o: sudo ./scripts/unload_modules.sh)
```

---

## 5. Cómo está organizado el código (para estudiarlo y defenderlo)

```
paso10_secure_mmap/
├── kmod_secure_mmap.c     # open / mmap (controles 1-6) / fault / page_mkwrite / close / ioctl
├── secure_policy.h        # politica (flags prohibidos/impuestos) + compatibilidad 5.x/6.x/7.x
├── secure_crypto.{c,h}    # AES-128-CTR (skcipher) + HMAC-SHA256 (shash); IV=(pagina,generacion)
├── secure_audit.{c,h}     # contadores atomicos + /proc/secure_vault/stats
├── secure_vault_uapi.h    # ioctl de laboratorio: VERIFY / TAMPER / PEEK
├── tests/                 # test_*.c, attack_matrix.c, manifest.txt, run_tests.sh
├── bench/                 # bench_mmap_latency.c, run_overhead.sh (perf/strace/ftrace)
└── verificacion_ia/       # h1..h6: comprobacion empirica de afirmaciones de IA
paso9_kprobe_auditor/      # kmod_auditor.c (kprobe security_mmap_file), mmap_probe.c
vm/                        # run_vm_tests.sh, init.c (PID 1 de la VM), check_compat.sh,
                           # mutation_test.sh (+MUTATE.py), bench_repeat.sh
docs/                      # PARTE_I, PARTE_II, PARTE_III + evidencia/
```

Flujo de una operación legítima: `open` (autoriza y crea la *sesión* privada) → `mmap` (valida y fija flags) → **#PF** → `vault_fault` (descifra la página en la copia privada y verifica HMAC) → escritura → `page_mkwrite` (audita, marca sucia) → `munmap/close` → `vault_commit_session` (si hubo escrituras: re-cifra con generación+1 y nuevo HMAC).

---

## 6. Qué NO se hizo / qué debe completar el equipo (importante)

| Pendiente | Detalle |
|---|---|
| **Carga en el host real** | No había `sudo` en esta sesión: los módulos se cargaron **solo en la VM** (kernel real 6.19.10). El §4 está listo para ejecutarse. |
| **Kernels 5.x y arm64** | Las ramas de compatibilidad (`LINUX_VERSION_CODE`, `__has_include`, `class_create` de 2 args, registros arm64 del kprobe) están escritas pero **no se compilaron** (solo 6.19.10 y 7.2.13, x86-64). |
| **`perf` / `strace` / `bpftrace`** | No estaban instalados. Se midió con `clock_gettime`, `getrusage`, `ktime` en kernel y **ftrace**. `bench/run_overhead.sh` usa `perf`/`strace` si existen (no ejecutado). |
| **Tabla de prompts propios (Parte II)** | La rúbrica exige *sus* ≥ 4 prompts. `docs/PARTE_II_estrategia_IA.md` §2.3 trae la plantilla **vacía a propósito**: no se inventan prompts. |
| **Informe en PDF** | Solo hay Markdown (no hay `pandoc`/LaTeX en el entorno). Conviértalos en su equipo (`pandoc docs/*.md -o informe.pdf`). |
| **Commit y evidencia por integrante** | No se hizo `git commit` (no se pidió). Cada integrante debe subir su evidencia al buzón de Interactiva EAFIT. Todo lo nuevo está **sin versionar** (`git status`). |
| **Informe previo** | `Parcial_CapaKernel_Solucion.md` se conserva sin reescribir; `docs/PARTE_I_respuestas.md` lo corrige (tabla de correcciones C1–C8). |
| **Verificación en VM limpia** (plan §6.4) | Se hizo en una VM desechable por ejecución; falta el `git clone` desde GitHub en otra máquina. |

---

## 7. Cumplimiento del plan de acción

| Fase del plan | Estado |
|---|---|
| 0 Entorno (línea base, snapshot) | ✅ VM desechable en lugar de snapshot; headers obtenidos sin root; línea base = Paso 4 medido |
| 1 Parte I (10 preguntas) | ✅ `docs/PARTE_I_respuestas.md` con marcas `[H]/[E]/[F]` y correcciones al borrador |
| 2 Módulo (controles 1-10) | ✅ (control 3 redundante; control 10 verificado empíricamente) |
| 3 Medición (≥ 30 corridas, media ± sd) | ✅ 30 corridas × 6 arranques; mediana entre arranques; `ftrace`; ⚠ sin `perf`/`strace` |
| 4 Parte II (IA, alucinaciones, trade-offs) | ✅ hallazgos reales F1–F15; ⚠ tabla de prompts propios por completar |
| 5 Argumentación y limitaciones | ✅ `docs/PARTE_III…` §3 y §5 |
| 6 Empaquetado | ✅ README, Makefile, este resumen; ⚠ PDF, commit y buzón pendientes |
| Opcional: eBPF/bpftrace, BPF-LSM | ➡ sustituido por kprobe LKM (Paso 9); BPF-LSM como trabajo futuro (la config lo permite) |
