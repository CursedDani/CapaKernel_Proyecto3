# Parte III — Implementación, presentación y argumentación (40 %)

> Todos los números provienen de [`evidencia/`](./evidencia/) (VM QEMU/KVM, kernel **6.19.10-300.fc44**, CPU AMD Ryzen 7 8840HS, `-smp 2 -m 512 -cpu host`). Los módulos además se compilan contra **7.2.13**.

## 1. Qué se entrega (mapa de código)

| Carpeta | Contenido | Papel en el parcial |
|---|---|---|
| [`paso10_secure_mmap/`](../paso10_secure_mmap/) | `kmod_secure_mmap.c` (módulo), `secure_policy.h`, `secure_crypto.{c,h}`, `secure_audit.{c,h}`, `secure_vault_uapi.h`, `tests/`, `bench/`, `verificacion_ia/` | **Solución principal**: `/dev/secure_vault` (profundidad) |
| [`paso9_kprobe_auditor/`](../paso9_kprobe_auditor/) | `kmod_auditor.c` (kprobe sobre `security_mmap_file`), `mmap_probe.c` | **Componente B**: auditoría global (amplitud) |
| [`paso8_secure_driver/`](../paso8_secure_driver/) | Componente A previo (CRC32 + ACL por UID) | Línea intermedia; corregido: warning `-Wformat`, `class_create` portable, `-Werror` |
| [`vm/`](../vm/) | `run_vm_tests.sh`, `init.c`, `check_compat.sh`, `mutation_test.sh`, `bench_repeat.sh` | Infraestructura: ejecutar todo **sin riesgo y sin root** |
| [`docs/`](./) | Partes I-III + `evidencia/` | Informe |

### Controles del módulo `secure_vault` y dónde se prueban

| # | Control | Mecanismo en kernel | Prueba (todas `[PASS]` en `evidencia/tests.log`) |
|---|---|---|---|
| 1 | Control de acceso | `vault_caller_authorized()` (UID o `CAP_SYS_ADMIN`) en `open`, **y re-verificado en `mmap` e `ioctl`** | `test_unauthorized`, `test_fd_inherit` |
| 2 | W^X | `VM_EXEC` ⇒ `-EACCES`; se limpia `VM_MAYEXEC` | `test_prot_exec` |
| 3 | Solo lectura real | `VM_WRITE\|VM_MAYWRITE` limpios si el fd no es `FMODE_WRITE` | `test_ro_write` *(redundante con el core; mutante M6 sobrevive)* |
| 4 | Solo `MAP_SHARED` | `!(VM_MAYSHARE)` ⇒ `-EACCES` | `test_private_map` |
| 5 | Límites estrictos | `pgoff` + longitud ≤ bóveda, sin desbordes | `test_oob_pgoff` |
| 6 | Aislamiento | `VM_DONTCOPY\|VM_DONTDUMP\|VM_DONTEXPAND` | `test_oob_pgoff` (`/proc/self/smaps`, `fork`, `mremap`) |
| 7 | Auditoría | contadores atómicos, `/proc/secure_vault/stats`, `dmesg` limitado en tasa | todas (verifican los contadores) |
| 8 | Cifrado en reposo | AES-128-CTR, IV = `(página, generación)`, copia en claro privada por `open()` | `test_crypto_rest`, `test_authorized` |
| 9 | Integridad | HMAC-SHA256 por página, `crypto_memneq`, `SIGBUS` si falla | `test_tamper`, `test_race_madvise` (`VERIFY`) |
| 10 | Detección de escrituras | `vm_ops->page_mkwrite` (**verificado que se invoca**) + `dirty_mask` | `test_authorized` (`mkwrite 0→1`) |

## 2. Demostración (qué se ve al ejecutar)

`vm/run_vm_tests.sh tests` → **10 programas, 72 comprobaciones, 0 fallos**, repetido 3 veces con resultado idéntico. Extractos:

```
[PASS] open(O_RDWR) por UID no autorizado -> EPERM (errno=1)              (test_unauthorized, uid=65534)
[PASS] hijo con fd heredado y UID 65534: mmap -> EPERM e ioctl -> EPERM   (test_fd_inherit)
[PASS] mmap(PROT_READ|PROT_EXEC) -> EACCES ; mprotect(PROT_EXEC) posterior -> EACCES
[PASS] REGRESION Paso 4: offset=1 pagina + longitud completa -> EINVAL
[PASS] NINGUNA escritura forzada tuvo exito durante la carrera (exitos=0)   (1 175 841 intentos)
cifrado en reposo (pagina 0, 32 B): 27a4c9c89484e000e3f161cadae2193812bc9aea6a6450397b0386f7870af912
[PASS] leer la pagina manipulada produce SIGBUS, NO datos corruptos
```

`dmesg` (auditoría del kernel): `open DENEGADO … [pid=158 comm=test_unauthoriz uid=65534]`, `ALERTA DE INTEGRIDAD: pagina 2 del respaldo fue MANIPULADA`, `PRIMERA ESCRITURA pagina=1 …`.

### Antes / después (matriz de ataques, `evidencia/matrix.log`)

| Ataque (proceso sin privilegios o autorizado, según el caso) | Paso 4 (sin endurecer) | `secure_vault` |
|---|---|---|
| A1 abrir el dispositivo como usuario cualquiera | **PERMITIDO** | **BLOQUEADO** (`EPERM`) |
| A2 `mmap(PROT_EXEC)` sobre datos | **PERMITIDO** | **BLOQUEADO** (`EACCES`) |
| A3 `mprotect(PROT_EXEC)` posterior | **PERMITIDO** | **BLOQUEADO** (`EACCES`) |
| A4 `MAP_PRIVATE\|PROT_WRITE` (vector COW) | **PERMITIDO** | **BLOQUEADO** (`EACCES`) |
| A5 offset de `mmap` ignorado (alias de la página 0) | **PERMITIDO (bug)** | **BLOQUEADO** (offset respetado) |
| A6 offset 1 MiB más allá del dispositivo | **PERMITIDO (bug)** | **BLOQUEADO** (`EINVAL`) |
| A9 longitud 1 MiB > buffer | BLOQUEADO (el Paso 4 sí valida tamaño) | BLOQUEADO |
| A7 el hijo de `fork()` lee la región | **PERMITIDO** | **BLOQUEADO** (`SIGSEGV`, `VM_DONTCOPY`) |
| A8 escritura forzada `FOLL_FORCE` en mapeo RO | BLOQUEADO (`VM_PFNMAP` ya lo impide) | BLOQUEADO |

(Los ataques A2–A8 sobre la bóveda se ejecutan como UID **autorizado** para probar cada control por separado; como UID no autorizado el kernel corta en A1.)

## 3. Justificación: por qué la capa de kernel y no el espacio de usuario

1. **Tras instalar la PTE no hay punto de control en usuario.** Medido: el acceso en régimen estacionario cuesta **0,5 ns** (igual en el Paso 4 y en la bóveda): ninguna syscall, ningún *hook* de usuario. Un `LD_PRELOAD` sobre `mmap()` solo ve el alta del mapeo y se evade con `syscall(SYS_mmap,…)`, binarios estáticos o `ptrace`.
2. **Solo el kernel posee las palancas que importan:** `vm_flags` (`VM_MAYEXEC`, `VM_MAYWRITE`, `VM_DONTCOPY`…), el manejador de fallos (`vm_ops->fault`: descifrar/verificar bajo demanda), `page_mkwrite` (primera escritura) y las credenciales (`current_euid()`, `capable()`), que un proceso hostil no puede falsificar.
3. **Segunda línea de defensa que usuario no puede dar:** `test_fd_inherit` — un descriptor **ya abierto** cae en manos de un UID sin autorización y aun así `mmap` e `ioctl` fallan, porque `.mmap` re-verifica la identidad.
4. **Confidencialidad en memoria:** el respaldo en RAM es texto cifrado; el texto plano existe solo en la copia privada de cada `open()` y se pone a cero al cerrar. Ninguna biblioteca de usuario puede garantizar eso frente a otro proceso o a `/proc/pid/mem`.
5. **Defensa en profundidad:** además de validar en `.mmap`, `vault_fault` rechaza índices fuera de rango con `SIGBUS` (`fault_oob`), de modo que un fallo en una capa no abre toda la bóveda *(por diseño; el mutante M1 solo comprueba que la capa de `.mmap` es detectada, no se probó el `SIGBUS` con el mutante)*.

## 4. Medición de impacto (overhead)

Herramientas usadas: **`clock_gettime`** (medición en usuario), **`getrusage().ru_minflt`**, **`ktime_get_ns()` dentro de `vault_fault`** (exportado en `/proc/secure_vault/stats`) y **ftrace `function_graph`** sobre `vault_fault` (`vm/run_vm_tests.sh trace`). `perf` y `strace` **no están instalados** en este entorno (no hay root); `paso10_secure_mmap/bench/run_overhead.sh` los usa automáticamente cuando existen — **no se ejecutó aquí**.

### 4.1 Latencias (mediana de 6 arranques de VM; 30 corridas × 2000 iteraciones por arranque) — `evidencia/bench_resumen.txt`

| Métrica | Paso 4 (base) | `secure_vault` | Razón | Lectura |
|---|---:|---:|---:|---|
| `mmap()` (4 páginas) | 6 835 ns | 2 836 ns | **0,41×** | La bóveda no precarga PTEs (`remap_pfn_range` sí) |
| Tocar las 4 páginas (1.er acceso) | 580 ns | 6 717 ns | 11,6× | Aquí está el coste: 4 *page faults* con auditoría |
| …por página (`fault`) | 145 ns | 1 679 ns | 11,6× | `vault_fault` con página ya cargada en la sesión |
| `munmap()` | 3 076 ns | 3 324 ns | **1,08×** | `commit` solo si hubo escrituras (`dirty_mask`) |
| `mmap`+toque+`munmap` | 10 491 ns | 12 894 ns | **1,23×** | Coste de usar un mapeo nuevo |
| Sesión completa (`open`+…+`close`, fd nuevo) | 15 535 ns | 33 175 ns | 2,14× | Incluye descifrar + HMAC de 4 páginas por sesión |
| **Acceso con PTE instalada** | **0,5 ns** | **0,5 ns** | **1,00×** | **Sin overhead tras el primer fallo** |
| Fallos menores por mapeo | 0 | 4 | — | Paginación por demanda real |

El archivo incluye también el rango mín–máx entre arranques. El ruido del host entre arranques llegó a ~2× en una medición aislada (valores absolutos distintos entre `bench.log` y la mediana), por eso se reporta la **mediana entre arranques** y no una sola corrida; las **razones** son más estables que los valores absolutos. 6 de 7 arranques produjeron datos válidos.

### 4.2 Dentro del kernel (`ktime`) y con `ftrace`

- `fault_ns_avg` ≈ **0,9 µs** por *page fault* medio (300 120 faults, de los cuales 60 004 requirieron descifrar), `fault_ns_max` ≈ 80 µs (`bench.log`).
- `function_graph` (`trace_resumen.txt`): `vault_fault` con página ya cargada ≈ 2–3 µs; con descifrado AES-CTR (`ctr_crypt_vaes_avx512`) + HMAC ≈ 30–50 µs (varía entre ejecuciones). **Estas duraciones están infladas por la propia instrumentación** de `function_graph`; sirven para ver el *camino* (`alloc_pages → vault_decrypt_verify → crypto_skcipher_encrypt → …`), no el coste real, que es el de §4.1.

### 4.3 Por qué hay overhead y por qué es aceptable

El coste se **concentra en eventos de baja frecuencia** (alta de VMA, primer fallo por página, cierre) y es **proporcional a las páginas tocadas**, no a los accesos: una vez instalada la PTE, el acceso es idéntico al de un `mmap` sin protección. Dentro del coste del fallo, lo dominante es la criptografía (descifrar + HMAC) y la reserva de la copia privada; el resto (mutex, `get_page`, contadores) es del orden de cientos de ns. La optimización medida de `dirty_mask` redujo el `munmap` de ~11 µs a ~2 µs en una corrida comparable al evitar recalcular HMAC en cierres sin escritura.

## 5. Limitaciones y trabajo futuro

**Limitaciones del diseño (obligatorias en el parcial).**

1. **Cobertura:** el módulo protege **su** dispositivo, no archivos arbitrarios del sistema. El Paso 9 da visibilidad global pero **solo observa** (un kprobe no puede vetar).
2. **Privilegios:** un atacante con `root`/`CAP_SYS_ADMIN` (autorizado por diseño), `CAP_SYS_MODULE` (descarga el módulo), `/dev/mem`/`/proc/kcore` o `kexec` supera el esquema.
3. **Claves:** se generan al cargar con `get_random_bytes` y nunca salen del kernel; **se pierden al descargar** (no hay persistencia ni *key management*). Clave y respaldo están en la misma RAM: un atacante con lectura de memoria del kernel obtiene ambas.
4. **Integridad no es autenticidad de origen:** HMAC con clave en el mismo kernel detecta manipulación del respaldo, pero un atacante con **escritura** de memoria del kernel puede recalcular cifrado y HMAC.
5. **Coherencia:** cada `open()` tiene su copia en claro; con varios escritores concurrentes gana el **último commit** (sin fusión).
6. **Verificación en el cierre**, no en cada *store* (el commit compara el HMAC al cerrar la VMA/fd).
7. **Control 3 redundante** (mutante M6) y **`page_mkwrite` sin `LOCKED` no probado** (solo se probó la variante correcta).
8. **Cobertura de pruebas:** x86-64, kernels 6.19.10/7.2.13; las ramas para 5.x/arm64 están escritas pero **no compiladas**.
9. **Canales laterales** (Spectre/Meltdown/Rowhammer, *cache timing* sobre AES por software) no cubiertos; con AES-NI el riesgo de tiempo por tablas es menor, pero no se midió.
10. **Denegación de servicio:** un usuario autorizado puede abrir muchos `open()` y consumir 4 páginas × N sesiones; no hay cuotas (`RLIMIT`/cgroup).

**Trabajo futuro (mitigaciones de hardware/hipervisor/kernel).**

- **BPF-LSM** (`SEC("lsm/mmap_file")`): *bloquear* globalmente en vez de solo observar; esta config ya incluye `bpf` en `CONFIG_LSM` `[H]`. **Landlock** y **IMA/EVM** para integridad de archivos.
- **`memfd_secret`**/`mlock` para sacar el texto plano del mapa directo del kernel; **PKU/Memory Protection Keys** en usuario.
- Hardware: **SME/SEV/TDX** (memoria cifrada), **Intel CET** (flujo de control), **MTE** en ARM. Hipervisor: EPT, *VM introspection*.
- Migrar a **`mmap_prepare`** (el hook nuevo que aparece en `struct file_operations` de 6.19/7.2 `[H]`) cuando se estabilice, y añadir cuotas por UID.
- Persistir claves vía **kernel keyring**/TPM y re-sellar el respaldo.

## 6. Cumplimiento de la sección 4.1 del enunciado

| Requisito | Cumplido por |
|---|---|
| Código C modular y comentado, Linux 5.x/6.x | `secure_policy.h`, `secure_crypto.c`, `secure_audit.c`, `kmod_secure_mmap.c`; guardas `LINUX_VERSION_CODE`/`__has_include` (probado en 6.19 y 7.2) |
| Demostración de intercepción / permisos / cifrado | `tests/` + `evidencia/tests.log`, `matrix.log` |
| Makefile sin advertencias (*clean build*) | `-Wall -Wextra -Werror` en módulos y pruebas; `evidencia/compat.txt` = 0 warnings |
| Scripts de ataque (no autorizado, carrera, manipulación) | `test_unauthorized`, `test_fd_inherit`, `test_race_madvise`, `test_tamper`, `attack_matrix` |
| 4.2 Justificación kernel vs usuario · overhead · limitaciones | §3, §4, §5 |
