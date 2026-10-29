# Parte I — Análisis conceptual (30 %): 10 preguntas diagnósticas

> **Convenciones.** `[H]` = dato verificado contra los headers reales de Linux 6.19.10 / 7.2.13 (`kernel-devel`) usados en este proyecto.
> `[E]` = verificado empíricamente en la VM (ver [`evidencia/`](./evidencia/)). `[F]` = conocimiento del código fuente (`mm/*.c`, `arch/x86/mm/fault.c`) que **no** se puede comprobar solo con headers; confirmar en <https://elixir.bootlin.com> antes de citar un número de línea o commit.
> Esta versión **reemplaza y corrige** las respuestas de [`Parcial_CapaKernel_Solucion.md`](../Parcial_CapaKernel_Solucion.md); las correcciones están listadas al final (§ "Correcciones al borrador previo").

---

## 1. Mapeo virtual y Page Faults — secuencia exacta `mmap()` → primer fallo

**A. Alta de la VMA (no se crea ninguna PTE).**

1. `mmap()` de glibc → syscall `mmap` → `ksys_mmap_pgoff(addr, len, prot, flags, fd, off>>PAGE_SHIFT)` → `fget(fd)` → `vm_mmap_pgoff()`. `[F]`
2. `vm_mmap_pgoff()` llama primero a **`security_mmap_file(file, prot, flags)`** (el hook LSM `mmap_file`, `[H] lsm_hook_defs.h:199`). Es el punto donde actúan SELinux/AppArmor/BPF-LSM y donde engancha nuestro auditor kprobe (Paso 9). Corre **antes** de `do_mmap`, por eso se auditan incluso intentos que luego fallan con `EACCES` `[E]` (`kprobe.log`: aparece el intento `O_RDONLY+PROT_WRITE+MAP_SHARED`).
3. Toma `mmap_write_lock(mm)` y llama `do_mmap()` `[H]` (`mm.h:3680`): valida longitud/alineación/overflow, busca hueco (`get_unmapped_area`) y calcula `vm_flags` a partir de `prot`/`flags` (`calc_vm_prot_bits`, `calc_vm_flag_bits`) **más** `VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC`. Para `MAP_SHARED` comprueba `FMODE_WRITE` (si falta y se pidió `PROT_WRITE` → `EACCES`; si falta y no se pidió, **limpia `VM_MAYWRITE` y `VM_SHARED`**); para `MAP_PRIVATE` solo exige `FMODE_READ`. `[F]`
4. `mmap_region()` reserva un `struct vm_area_struct` (`vm_start`, `vm_end`, `vm_pgoff`, `vm_flags`, `vm_file`, `vm_ops`), invoca **`file->f_op->mmap(file, vma)`** (en nuestro módulo, `vault_mmap`: aquí se rechazan UID no autorizado, `PROT_EXEC`, `MAP_PRIVATE` y rangos inválidos), inserta la VMA en el **maple tree** `mm->mm_mt` `[H] mm_types.h:1092` y calcula `vm_page_prot` (`vma_set_page_prot` → `vma_wants_writenotify`: si el driver define `.page_mkwrite`, la PTE de un mapeo compartido escribible se instalará **de solo lectura** para poder interceptar la primera escritura). `[F]`
5. Retorna la dirección virtual. **No hay I/O ni PTEs** (salvo `MAP_POPULATE` o que el driver use `remap_pfn_range`, como el Paso 4). `[E]`: en la bóveda `minflt` por mapeo = 4 (uno por página tocada), en el Paso 4 = 0 (PTEs preinstaladas) — `bench_resumen.txt`.

**B. Primer acceso → Page Fault.**

6. La MMU consulta TLB (miss) y recorre `CR3 → PGD → P4D → PUD → PMD → PTE`. La PTE no está presente (bit P=0) → excepción **#PF (vector 14)**; la CPU apila el código de error (P, W/R, U/S, I/D, PK…) y deja la dirección en **`CR2`**.
7. `asm_exc_page_fault` → `exc_page_fault` → `do_user_addr_fault` (`arch/x86/mm/fault.c`) `[F]`. Intenta el camino rápido con el **bloqueo por VMA** (`lock_vma_under_rcu`, `FAULT_FLAG_VMA_LOCK` `[H] mm_types.h:1662`) y, si no, `mmap_read_lock` + `find_vma`. Verifica que el acceso sea compatible con `vm_flags` (`access_error`); si no, `SIGSEGV (SEGV_ACCERR)`.
8. `handle_mm_fault()` → `__handle_mm_fault()`: asigna niveles de tabla faltantes (`p4d/pud/pmd_alloc`) y llama `handle_pte_fault()`. PTE vacía → `do_pte_missing()` → `do_fault()`: sin `vm_ops->fault` ⇒ `SIGBUS`; lectura → `do_read_fault`; escritura privada → `do_cow_fault`; escritura compartida → `do_shared_fault`.
9. `__do_fault()` invoca **`vma->vm_ops->fault(vmf)`**: `filemap_fault` para archivos; **`vault_fault`** en nuestro módulo (descifra bajo demanda, verifica HMAC, `get_page`, `vmf->page`). `finish_fault()` instala la PTE bajo el *page-table lock*, añade el *rmap* y retorna.
10. La CPU **reejecuta la instrucción** que falló. Las siguientes lecturas/escrituras son accesos de hardware sin pasar por el kernel: `access_ns ≈ 0.5 ns` idéntico en el Paso 4 y en la bóveda `[E]`. Esta es la razón de que la defensa **no pueda vivir en `LD_PRELOAD`**: tras el paso 9 no existe ningún punto de intercepción en usuario.

> Evidencia de orden: `dmesg` de la bóveda muestra `mmap autorizado …` → (primer acceso) → `PRIMERA ESCRITURA pagina=1 …` (`tests.log`).

---

## 2. `MAP_SHARED` vs `MAP_PRIVATE` en `vm_area_struct`

La diferencia vive en `vma->vm_flags`: **`VM_MAYSHARE`** (el usuario pidió `MAP_SHARED`) y **`VM_SHARED`** (el mapeo es *efectivamente* compartido y escribible). `[H] mm.h:406` y `is_cow_mapping()` `[H] mm.h:1730`: `(flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE` ⇒ mapeo privado con permiso de escritura potencial ⇒ **COW**.

| | `MAP_SHARED` | `MAP_PRIVATE` |
|---|---|---|
| Páginas | Las del *page cache* del inodo (`address_space`) o, en un driver, las que devuelva `vm_ops->fault` | Se leen del page cache **solo lectura**; al escribir se copian a una página **anónima** del proceso (`do_cow_fault`) |
| Escrituras | Marcan el folio *dirty*; visibles al instante a **todos** los que mapean/leen el archivo; `writeback`/`msync` las persisten | Quedan en la copia privada; **nunca** llegan al archivo ni a otros procesos |
| `fork()` | Padre e hijo siguen compartiendo | Padre e hijo comparten COW (cada uno copia al escribir) |

**Sutileza verificada `[E]`.** Para un `MAP_SHARED` sobre un fd **sin** `FMODE_WRITE`, el core **limpia `VM_SHARED`** pero conserva `VM_MAYSHARE`. Por eso el plan original ("exigir `VM_SHARED`") era un error: la bóveda rechazaría mapeos de solo lectura legítimos. El mutante M8 (`VM_SHARED` en vez de `VM_MAYSHARE`) hace fallar 6 pruebas (`mutacion.txt`). La política correcta es `VM_MAYSHARE`.

**Implicaciones de seguridad.** *Shared*: un proceso con acceso al archivo observa en vivo (fuga) y altera (integridad) lo que otro escribe; la modificación **persiste**. *Private*: aísla escrituras pero rompe supuestos de inmutabilidad (Q8) y es el escenario de **Dirty COW** (Q3). Por ello la bóveda solo admite `MAP_SHARED`, con todo el control de acceso en `.mmap`, y deniega `MAP_PRIVATE` (`mmap_denied_private`, 2 intentos contados en `test_private_map`) `[E]`.

---

## 3. Copy-On-Write: ciclo de vida y escalada por banderas

**Ciclo (mapeo privado de archivo, escritura):**

1. Lectura inicial: la PTE apunta a la página del page cache, **sin `R/W`** aunque la VMA tenga `VM_WRITE` (así la primera escritura traza).
2. Escritura ⇒ #PF por protección (P=1, W=1). `handle_pte_fault` ve PTE presente sin escritura ⇒ `do_wp_page()`.
3. Si la página es **anónima y exclusiva** (`PageAnonExclusive` `[H] page-flags.h:1153`, mecanismo desde 5.19) se reutiliza: solo se enciende `R/W`+*dirty*. Si no, `wp_page_copy()`: nueva página, `copy_user_highpage`, PTE nueva `RW`, se baja la referencia de la original.
4. Si la página era del page cache de un archivo (`do_cow_fault`), se crea la copia anónima directamente.

**Banderas implicadas.** `VM_MAYWRITE` (puede llegar a escribirse vía `mprotect`), `VM_WRITE` (escritura actual), `VM_SHARED`/`VM_MAYSHARE`, y para el acceso del kernel `FOLL_WRITE|FOLL_FORCE` (permite que `ptrace`/`/proc/pid/mem` escriban incluso en mapeos sin `VM_WRITE` si hay `VM_MAYWRITE`).

**Dirty COW (CVE-2016-5195), mecánica.** `[F]` Un hilo escribe vía `/proc/self/mem` (`get_user_pages` con `FOLL_FORCE|FOLL_WRITE`) en un mapeo **privado de solo lectura** de un archivo; otro hilo ejecuta `madvise(MADV_DONTNEED)` en bucle. El GUP de la época: (a) no encuentra PTE escribible → provoca fallo COW y crea la copia privada; (b) para no exigir PTE escribible en un mapeo de solo lectura, **descartaba `FOLL_WRITE`** y reintentaba `follow_page`; (c) si `MADV_DONTNEED` destruía la copia entre (a) y (b), el reintento —ya sin `FOLL_WRITE`— devolvía la **página original del page cache**, y la escritura caía sobre ella ⇒ se modifica un archivo de solo lectura (`/etc/passwd`, binarios setuid) y se persiste por *writeback*. Corrección original: la bandera `FOLL_COW` (`can_follow_write_pte` exigía PTE *dirty* **y** `FOLL_COW`).

**Estado actual** `[H]`: en 6.19 **ya no existe `FOLL_COW`** (grep sobre `mm.h`/`mm_types.h` sin resultados) y el modelo se basa en `PageAnonExclusive` y en `FAULT_FLAG_UNSHARE` (`mm_types.h:1657`): el COW se *rompe* explícitamente y GUP exige una página exclusiva, de modo que la ventana ya no existe.

**Derivación a escalada/corrupción**: ocurre cuando una combinación `VM_MAYWRITE` + camino `FOLL_FORCE` permite que la escritura se resuelva sobre la página **compartida** en lugar de la copia privada. La bóveda elimina el vector de raíz: `MAP_PRIVATE` denegado, y en mapeos de solo lectura `VM_MAYWRITE` está limpio ⇒ `FOLL_FORCE` no puede forzar la escritura (`test_ro_write`: `pwrite(/proc/self/mem)` falla) `[E]`.

---

## 4. Intercepción: hook en la *System Call Table* vs LSM `file_mmap`

| | Hook de `sys_call_table` (LKM) | LSM `mmap_file` |
|---|---|---|
| Viabilidad en kernel moderno | **Muy baja** | **Alta** (diseñado para esto) |
| Símbolo | `sys_call_table` aparece declarado en `asm/syscall.h` `[H]` pero **no está exportado** a módulos: `modpost` falla con `"sys_call_table" undefined!` `[E]` | `security_mmap_file()` / hook `mmap_file` `[H]` |
| Búsqueda por nombre | `kallsyms_lookup_name` **no está exportada** (desde 5.7): `undefined!` `[E]` (evasión: un kprobe para obtener la dirección) | No hace falta |
| Escribir en la tabla | Tabla en `.rodata` protegida por `CONFIG_STRICT_KERNEL_RWX`; el truco de apagar `CR0.WP` **falla**: el kernel mantiene el bit *pinned* y avisa `CR0 WP bit went missing!?` `[E]` (`halluc.log`) | — |
| Cobertura | Parcial: `mmap`/`mmap2`/compat de 32 bits/x32, rutas internas (`io_uring`, `process_vm`…), envoltorios `__x64_sys_*` que reciben `pt_regs` | Total: todo `mmap` pasa por `vm_mmap_pgoff` → `security_mmap_file` |
| Contexto | Solo `pid`/args crudos | `struct file`, credenciales, etiquetas, y **puede vetar** |
| Estabilidad / SMP / CET | Carrera entre CPU, rompe *Lockdown*, CET/shadow stacks | Pila de LSM (`CONFIG_LSM`) |
| Limitación | — | **No es cargable como módulo**: se compila dentro del kernel o se usa **BPF-LSM** |

**Nota de nombres.** El enunciado habla de `file_mmap`; el hook actual se llama `mmap_file` `[H] lsm_hook_defs.h:199` (renombrado hace años). En esta distro `CONFIG_BPF_LSM=y` y `CONFIG_LSM="lockdown,yama,integrity,selinux,bpf,…"` `[H]`, de modo que **BPF-LSM es viable** como siguiente paso para *bloquear* globalmente (trabajo futuro). Mientras tanto, el proyecto usa la combinación práctica sin recompilar: **bóveda** (bloqueo en su recurso) + **kprobe sobre `security_mmap_file`** (observación global).

---

## 5. Cifrado transparente en memoria

**Qué hace el kernel real (fscrypt/eCryptfs/dm-crypt).** El disco guarda cifrado; el sistema de archivos **descifra al leer hacia el page cache** del archivo lógico (en fscrypt: `fscrypt_decrypt_pagecache_blocks` al completar la lectura), y `mmap()` mapea esas páginas ya en claro. Por tanto, **el page cache contiene texto plano** y el aislamiento *no* viene de un `address_space` por sesión: viene de (i) que sin la clave cargada el archivo **ni se abre** (`ENOKEY`), (ii) permisos POSIX/LSM sobre quién puede abrirlo, y (iii) la gestión de claves en el *keyring*. Con la clave presente, cualquier proceso con acceso POSIX ve el texto plano ya cacheado. `[F]`

**Qué implementa la bóveda (control 8).** Un diseño más estricto para su recurso: el respaldo en RAM es **solo texto cifrado** (AES-128-CTR; `test_crypto_rest` lo muestra: 32 B de aspecto aleatorio, sin la cadena `SECRETO`) `[E]`; cada `open()` recibe una **copia en claro privada** (`filp->private_data`) que se materializa en el `vm_ops->fault` y se pone a cero al cerrar (`memzero_explicit`). Un segundo proceso **no autorizado** no puede ni abrir (`EPERM`) ni mapear un fd heredado (`test_fd_inherit`) `[E]`.

**Complementos** (límites honestos): `VM_DONTDUMP` (el plano no va a *core dumps*), `mlock`/`memfd_secret` (sacar páginas del mapa directo), cifrado de memoria por hardware (SME/SEV/TDX) contra lectura física, cifrado del *swap*. La clave vive solo en el kernel (`get_random_bytes` al cargar) y no hay API para exportarla; un atacante con `root`/`/dev/mem`/`CAP_SYS_MODULE` sigue siendo un riesgo (ver limitaciones).

---

## 6. `msync` / `fsync` e integridad; evasión de filtros en `write()`

**Consistencia de páginas sucias.** En un mapeo compartido, la primera escritura de cada página pasa por `vm_ops->page_mkwrite` (el kernel instaló la PTE de solo lectura para poder interceptarla); el folio se marca *dirty* y la PTE gana `R/W` y el bit `D` (hardware). El *writeback* (`kworker` del `bdi`) persiste los folios sucios periódicamente; antes, `folio_mkclean`/`page_mkclean` recorre el *rmap*, **limpia `D` y vuelve a proteger la PTE**, de modo que la siguiente escritura vuelve a invocar `page_mkwrite`. `msync(MS_SYNC)` fuerza el volcado y espera (equivalente a `fsync` del rango), `MS_ASYNC` lo encola, `fsync(fd)` persiste datos+metadatos del archivo. `[F]`

**Evasión.** Con `mmap`, la escritura es una instrucción `MOV`: **no hay syscall `write`**, así que no se dispara `vfs_write`, ni los hooks LSM `file_permission` de escritura, ni el escaneo "al escribir" de un antivirus. Los puntos que sí observan son `page_mkwrite`, el *writeback* y `msync`/`fsync`.

**En el proyecto `[E]`.** `page_mkwrite` **sí se invoca** en este tipo de mapeo (`mkwrite` pasó de 0 a 1 en `test_authorized`; 353 llamadas en toda la batería). La bóveda lo usa para (a) auditar la primera escritura por página y (b) marcar la página como *potencialmente sucia*; el **commit** (re-cifrado + nuevo HMAC) ocurre al cerrar la VMA/fd, comparando el HMAC del texto plano con el guardado. *Limitación:* la integridad se verifica en el cierre, no en cada `store`.

> Detalle de contrato `[F]`: para páginas sin `address_space` (`folio->mapping == NULL`), `page_mkwrite` debe devolver la página bloqueada con **`VM_FAULT_LOCKED`**; nuestro módulo hace `folio_lock()` y lo devuelve (no probamos la variante sin `LOCKED`).

---

## 7. Control de accesos con eBPF / kprobes / fexit sin recompilar

- **Sondas.** `kprobe`/`kretprobe` sobre `security_mmap_file`, `vm_mmap_pgoff`, `handle_mm_fault`; o, mejor, **`fentry`/`fexit`** (trampolines BPF con tipos vía **BTF**; `CONFIG_DEBUG_INFO_BTF=y` `[H]`) y *tracepoints* estables (`syscalls:sys_enter_mmap`, `exceptions:page_fault_user`).
- **Datos.** Argumentos (`prot`, `flags`), `struct file` → ruta con `bpf_d_path`/`file_path`, `comm`/`pid`/`uid`; eventos a usuario con `BPF_MAP_TYPE_RINGBUF`; **CO-RE** para portabilidad entre versiones.
- **Patrones anómalos.** `W+X` simultáneo; `PROT_WRITE|MAP_SHARED` sobre rutas sensibles; `PROT_EXEC` sobre dispositivos; ráfagas de `mmap` por proceso; fallos de página inusuales.
- **Seguridad del propio mecanismo.** El **verificador** garantiza terminación y accesos acotados; el programa se compila JIT; no se recompila el kernel ni se carga un LKM arbitrario.
- **Límite.** Un kprobe/fexit **observa pero no veta**; para bloquear hace falta **BPF-LSM** (`SEC("lsm/mmap_file")`, `CONFIG_BPF_LSM=y`, y `bpf` en `lsm=` `[H]`) o un LSM compilado. Además el verificador y el *overhead* por evento limitan lo que se puede hacer en el *hot path*.

**Implementación `[E]` (Paso 9).** No hay `bpftrace`/`bpftool` en este entorno ni root, así que el auditor se implementó como **LKM con `register_kprobe(security_mmap_file)`** (mismo punto de enganche que un programa eBPF). Reglas `WX`, `WRSHARED`, `EXEC_DEV`; 32 `mmap` observados y 6 anomalías marcadas en `kprobe.log`, con `kprobe_nmissed=0`. *Ejemplo de one-liner equivalente (no ejecutado aquí):* `bpftrace -e 'kprobe:security_mmap_file { printf("%s pid=%d prot=%d\n", comm, pid, arg1); }'`.

---

## 8. `O_RDONLY` + `PROT_READ|PROT_WRITE` + `MAP_PRIVATE`: ¿posible?

**Sí.** `[E]` (`test_private_map`, parte "control", sobre un archivo de prueba propio): el `mmap` se concede, la escritura funciona **en la copia COW anónima**, y al releer el archivo su contenido sigue intacto.

**Por qué el kernel lo permite.** `do_mmap` solo exige `FMODE_READ` para `MAP_PRIVATE` (la escritura nunca se propaga al archivo), y activa `VM_MAYWRITE`. Para `MAP_SHARED` exigiría `FMODE_WRITE` (`EACCES`). `[F]`; el caso `MAP_SHARED` lo comprueba `test_ro_write` (`EACCES`) `[E]`.

**Riesgos.** (1) *Alteración temporal engañosa*: el proceso ve y usa datos modificados mientras `stat`/permisos/`O_RDONLY` sugieren "inmutable"; una validación basada en re-leer ese buffer queda envenenada. (2) *Fuga*: si esa región se comparte a otro componente (p. ej. vía `fork`, `SCM_RIGHTS` de un `memfd`, `process_vm_readv`) se exponen datos derivados. (3) *Superficie COW/Dirty COW* (Q3): el modelo de seguridad depende de que el COW realmente aísle. (4) Herramientas que juzgan la integridad solo por el modo de apertura. **Mitigación en la bóveda:** `MAP_PRIVATE` ⇒ `EACCES` siempre (`mmap_denied_private`).

---

## 9. Carreras `madvise(MADV_DONTNEED)` vs escrituras sobre páginas privadas

`MADV_DONTNEED` toma el `mmap_lock` en **lectura** (o el lock de VMA en kernels recientes) y *zapea* las PTE del rango bajo el **page-table lock (PTL)**; no cambia datos, solo hace que el siguiente acceso vuelva a fallar. La defensa moderna **no consiste en "un único lock"** (el borrador previo era impreciso), sino en:

1. **Revalidación bajo PTL.** Los manejadores de fallo guardan `vmf->orig_pte` y, antes de instalar o promover una PTE, comprueban `pte_same()` bajo el PTL; si la PTE cambió (p. ej. por un `DONTNEED` concurrente) **reintentan** el fallo en lugar de usar un estado obsoleto. `[F]`
2. **Ya no se "olvida" la intención de escritura.** El parche de 2016 (`FOLL_COW`) y, después, el rediseño con **`PageAnonExclusive`** (`[H]`) y `FAULT_FLAG_UNSHARE` (`[H]`) hacen que GUP **exija una página exclusiva escribible** antes de escribir; si el COW se perdió, vuelve a fallar con intención de escritura en vez de caer a la página del page cache.
3. **Refcount/pin.** GUP fija la página (`FOLL_PIN`) tras verificar la PTE, de modo que el `zap` posterior no puede cambiar *qué* página se está escribiendo.

> **Honestidad:** `test_race_madvise` **no** prueba el COW anónimo del kernel (que ya está parcheado) sino que el *mismo patrón de ataque* (hilo de escritura forzada vía `/proc/self/mem` + hilo `MADV_DONTNEED`) **no tiene efecto contra la bóveda**: 1.17 M intentos de escritura forzada, **0 éxitos**, contenido intacto y `VERIFY`=0 páginas corruptas `[E]`. Se debe a (i) no existir mapeo privado que descartar, (ii) `VM_MAYWRITE` limpio en el mapeo RO, (iii) datos propios del módulo que sobreviven al `zap`.

---

## 10. `struct page`, tablas multinivel y bits de la MMU

- **`struct page` / `struct folio`** (`[H] page-flags.h`): un descriptor por marco físico con `flags` (`PG_dirty`, `PG_locked`, `PG_reserved`, `PG_anon_exclusive`…), `_refcount` (lo que un `fault` incrementa con `get_page` para que el marco no se libere mientras una PTE lo use), `_mapcount`, `mapping`/`index`. Es la unidad de contabilidad: sin él el kernel no sabría quién usa cada marco, ni cuándo liberarlo. Nuestro `vault_fault` hace `get_page()` + `vmf->page`; `release` hace `memzero_explicit` + `put_page`.
- **Tablas PGD→P4D→PUD→PMD→PTE:** `CR3` apunta al PGD del proceso en ejecución ⇒ el mismo rango virtual de dos procesos traduce a marcos distintos salvo mapeo compartido explícito. Eso es el **aislamiento de direcciones**.
- **Bits de la PTE** (x86-64 `[H] pgtable_types.h`): **P** (bit 0, presente), **R/W** (bit 1), **U/S** (bit 2), **D** (bit 6, sucia), **NX** (bit 63).
  - **NX** impide ejecutar datos: sin `PROT_EXEC` la PTE lleva NX; es la base de **W^X**. La bóveda niega `PROT_EXEC` (`EACCES`) y limpia `VM_MAYEXEC`, por lo que ni `mprotect(PROT_EXEC)` posterior funciona `[E]`; en `/proc/self/smaps` la VMA no muestra `ex` ni `me` `[E]`.
  - **R/W** implementa COW y el *write-notify* (`page_mkwrite`).
  - **U/S** impide que Ring 3 direccione memoria del kernel; **SMEP** (el kernel no ejecuta páginas de usuario) y **SMAP** (no las accede salvo `copy_{from,to}_user`) cierran el camino inverso.
- **Del flag de VMA al bit de PTE:** `vm_get_page_prot(vm_flags)` traduce `VM_READ/WRITE/EXEC/SHARED` a `pgprot_t`; `mprotect` solo puede activar permisos para los que exista `VM_MAY*`. Por eso limpiar `VM_MAYEXEC` es una **prohibición permanente**, no solo inicial.
- **Resultado:** para convertir un `mmap` en ejecución de código inyectado el atacante tendría que alterar una PTE (NX), `vm_flags` (`VM_MAYEXEC`) o el control del kernel; los tres están fuera de su alcance salvo con otra vulnerabilidad.

---

## Correcciones al borrador previo (`Parcial_CapaKernel_Solucion.md`)

| # | Afirmación del borrador | Hallazgo | Evidencia |
|---|---|---|---|
| C1 | Q1: la VMA se enlaza en *red-black tree* `mm->mm_rb` y lista `mm->mmap` | Desde 6.1 se usa un **maple tree** (`mm->mm_mt`); en 6.19 no existen `mm_rb` ni `mm->mmap` | `[H] mm_types.h:1092` |
| C2 | Q4: presenta el apagado manual de `CR0.WP` (`write_cr0`) como la vía —insegura pero posible— para parchear la tabla | En kernels modernos **ni siquiera es posible**: el kernel *fija* (*pins*) `CR0.WP`, restaura el bit y emite `CR0 WP bit went missing!?` | `halluc.log` |
| C3 | Q4: hook llamado `file_mmap` | El hook actual es **`mmap_file`** (`security_mmap_file`) | `[H] lsm_hook_defs.h:199` |
| C4 | Q5: fscrypt usa "un `address_space` por sesión/clave" | No: el page cache contiene **texto plano**; el aislamiento es "sin clave no se abre" + permisos/LSM | `[F]` (confirmar en Bootlin `fs/crypto/`) |
| C5 | Q9: la mitigación es "revalidar bajo el mismo lock" | Es **revalidación `pte_same` bajo PTL + `PageAnonExclusive`/`UNSHARE`**; `madvise` solo toma `mmap_lock` en lectura | §9 |
| C6 | Q3: existe `FOLL_COW` como mecanismo vigente | `FOLL_COW` **ya no existe** en 6.19; lo sustituyen `PageAnonExclusive`/`FAULT_FLAG_UNSHARE` | `[H]` |
| C7 | Parte II del borrador: `kmap_atomic()` "ya no es válida (≥5.11)" | **Sigue compilando** en 6.19 y 7.2 (obsoleta, no eliminada); lo vigente es `kmap_local_page()` | `alucinaciones_compilacion.txt` |
| C8 | Parte III: promete `paso9_kprobe_auditor/kmod_auditor.c`, `run_benchmark_ext.sh`, script de carrera | Ahora existen y se ejecutan: `paso9_kprobe_auditor/`, `paso10_secure_mmap/bench/`, `tests/test_race_madvise.c`, `vm/` | `evidencia/` |
