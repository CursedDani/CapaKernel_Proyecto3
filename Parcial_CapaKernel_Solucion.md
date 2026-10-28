# Evaluación Parcial Práctica-Teórica (25%)
## Seguridad de Archivos mediante Intervención en la Capa del Kernel y Mapeo de Memoria (`mmap`)

> **Asignatura:** Sistemas Operativos — Periodo 2026-2 (Universidad EAFIT)
> **Referencia base:** Repositorio GitHub SO2026B — `USOS/CapaKernel`
> **Modalidad:** Equipo (2 integrantes)

---

## Parte I — Análisis Conceptual y Preguntas Diagnósticas (30%)

### 1. Mapeo Virtual y Page Faults
Cuando un proceso invoca `mmap()`, la syscall entra a `do_mmap()` (vía `vm_mmap_pgoff`), que:
1. Valida permisos del `struct file` (`f_mode`, `inode->i_mode`) y las banderas `prot`/`flags`.
2. Busca un hueco libre en el espacio de direcciones (`vm_unmapped_area`) y crea un nuevo `struct vm_area_struct` (VMA), enlazándolo al *red-black tree* `mm->mm_rb` y a la lista `mm->mmap` del `struct mm_struct` del proceso.
3. Si el archivo lo soporta, invoca el callback `file->f_op->mmap(file, vma)` (en el caso de un driver, el `.mmap` del `file_operations`), que registra `vma->vm_ops` (p. ej. `.fault`) **sin** tocar todavía las tablas de páginas (PTE).
4. La syscall retorna de inmediato con la dirección virtual asignada — **no hay I/O real aún**.
5. Al primer acceso (`ptr[i]`), la MMU recorre `PGD → P4D → PUD → PMD → PTE` y encuentra la entrada **no presente** (bit *Present* = 0). Esto dispara una excepción de hardware `#PF` (vector 14, interrupción síncrona).
6. El manejador `do_page_fault()`/`handle_mm_fault()` identifica el VMA afectado, y si tiene `vm_ops->fault` definido, lo invoca (como en `demo_vma_fault()` de `paso6`); si no, para mapeos de archivo usa `filemap_fault()` sobre la Page Cache.
7. Se obtiene/asigna el `struct page` físico, se incrementa su `refcount` (`get_page()`), se instala la entrada PTE (`vmf->page`, luego `alloc_set_pte`/`finish_fault`) y se reanuda la instrucción de CPU que falló — ahora con la traducción resuelta.

### 2. MAP_SHARED vs. MAP_PRIVATE
En el `vm_area_struct`, la bandera central es `vm_flags` (contiene `VM_SHARED`, `VM_MAYSHARE`, `VM_WRITE`, `VM_MAYWRITE`). Con `MAP_SHARED`:
- Las páginas resultantes se asocian directamente al `address_space` del inodo (Page Cache); cualquier escritura marca la página como *dirty* y es visible instantáneamente para **todos** los procesos que mapean el mismo archivo, y eventualmente se persiste a disco.
- Implicación de seguridad: un proceso no autorizado que logre abrir el mismo archivo puede observar en tiempo real cambios de otro proceso (fuga de información entre procesos que comparten memoria física).

Con `MAP_PRIVATE`:
- El kernel crea una relación *Copy-On-Write*: las páginas se comparten en modo **solo lectura** hasta que un proceso escribe; en ese momento ocurre un fallo de página de escritura, se clona la página (`wp_page_copy`) y el proceso obtiene su propia copia privada **no persistida** al archivo original.
- Implicación de seguridad: los cambios quedan aislados al proceso (no hay fuga hacia otros, ni hacia el disco), pero si el kernel confunde las banderas `VM_MAYWRITE`/`VM_SHARED` puede filtrar escrituras hacia el `address_space` compartido.

### 3. Mecanismo Copy-On-Write (COW)
Ciclo de vida: (a) `fork()` o `MAP_PRIVATE` crean una PTE marcada de **solo lectura** aunque `vma->vm_flags` indique `VM_WRITE`/`VM_MAYWRITE` lógicamente permitido; el `refcount` de la página física se incrementa (compartida entre padre/hijo o entre archivo/proceso). (b) Al intentar escribir, la MMU genera `#PF` por violación de escritura sobre página de solo lectura. (c) `do_wp_page()` verifica el `page_count()`: si es 1 (ya exclusiva), simplemente habilita escritura en la PTE; si es >1, asigna una página física nueva, copia el contenido (`copy_user_highpage`) y reescribe la PTE del proceso que escribió apuntando a la copia.

Una falla en la gestión de `VM_MAYWRITE`/`PROT_WRITE` ocurre si el kernel permite que la ruta de escritura tome el camino "ya exclusiva" (saltándose la copia) cuando en realidad la página todavía está referenciada por otra entidad (p. ej. la Page Cache de un archivo de solo lectura del sistema, como `/etc/passwd`). Esto es exactamente la causa raíz de **Dirty COW (CVE-2016-5195)**: una condición de carrera entre `madvise(MADV_DONTNEED)` y el manejador de *write-fault*, donde el kernel veía temporalmente el conteo de referencias incorrecto y escribía directamente sobre la página de solo lectura compartida con la Page Cache, logrando escalada de privilegios al modificar binarios/archivos *setuid* protegidos.

### 4. Intercepción de Llamadas en el Kernel (LKM con hook en syscall table vs LSM)
**LKM con hook en la System Call Table:**
- *Ventajas:* control total y arbitrario sobre el comportamiento de `sys_mmap`.
- *Desventajas severas:* desde kernels modernos (≥ 4.x con `CONFIG_STRICT_KERNEL_RWX`/`CONFIG_ARCH_HAS_SET_MEMORY`), la tabla `sys_call_table` **no está exportada** (`EXPORT_SYMBOL`) y reside en memoria de solo lectura protegida por el bit *Write Protect* de `CR0`. Para modificarla se requiere deshabilitar `CR0.WP` manualmente (`write_cr0`), lo cual es **inseguro, no portable entre arquitecturas, rompe SMP (race entre núcleos) y es detectado por mecanismos de integridad (Lockdown LSM, `CONFIG_SECURITY_LOCKDOWN_LSM`)**. Es frágil ante actualizaciones de kernel y deshabilita protecciones de hardware globales, afectando a todo el sistema.
- *Viabilidad:* **baja** en producción; solo aceptable como ejercicio académico controlado.

**LSM con hooks (`file_mmap`, `mmap_file`, `mmap_addr`):**
- *Ventajas:* mecanismo **diseñado explícitamente** por el kernel para este propósito (`struct security_hook_list`, registrado vía `security_add_hooks()`); no requiere parchear estructuras protegidas; se integra con el *framework* de seguridad existente (SELinux, AppArmor, Lockdown) y puede apilarse (*LSM stacking*) sin reemplazar hooks previos.
- *Desventajas:* un LSM tradicional debe compilarse dentro del kernel o registrarse muy temprano en el arranque (no es cargable como módulo normal después del boot, salvo los **BPF LSM**, que sí permiten carga dinámica vía `bpf()`+`libbpf`).
- *Viabilidad:* **alta** y es la ruta recomendada por la comunidad del kernel; para un proyecto académico sin recompilar el kernel, la alternativa práctica es un **BPF LSM** o un módulo convencional que exponga su propio `file_operations.mmap` (como en `paso4`/`paso6`) actuando como "gatekeeper" del recurso.

### 5. Cifrado Transparente en Memoria
El flujo requerido es: (a) el sistema de archivos (p. ej. un *stacked filesystem* como eCryptfs, o `fscrypt` a nivel de VFS) mantiene el contenido **cifrado en disco** y en la Page Cache del dispositivo de bloque subyacente; (b) al leer, el *filesystem driver* descifra el bloque **antes** de insertarlo en la Page Cache del archivo lógico (la que el proceso de usuario mapeará), de modo que `mmap()` nunca expone directamente la Page Cache cifrada sino la del archivo ya descifrado; (c) el control de acceso se aplica en el momento de `open()`/`mmap()` validando credenciales (clave de cifrado derivada de la llave de sesión del usuario, gestionada por el *keyring* del kernel, `request_key()`); (d) para impedir que **otro proceso no autorizado** vea el texto plano, las páginas descifradas deben pertenecer a un `address_space` *por sesión/clave*, no al inodo global — de lo contrario, un segundo proceso con acceso POSIX al mismo archivo (pero sin la clave) heredaría páginas ya descifradas en la Page Cache compartida. Esto es exactamente lo que resuelve `fscrypt` (cifrado por inodo con claves derivadas) y por lo que un cifrado "en la capa de aplicación" no es suficiente: la Page Cache es un recurso compartido a nivel de kernel.

### 6. Sincronización e Integridad (`msync` y `fsync`)
El kernel mantiene el bit `PG_dirty` del `struct page` cuando una escritura ocurre sobre una página `MAP_SHARED` (al resolverse el *write-fault*, `vma->vm_ops->page_mkwrite` marca la página sucia vía `set_page_dirty()`). El *writeback* (`pdflush`/`kworker` del `bdi`) persiste estas páginas periódicamente o cuando el proceso invoca explícitamente `msync(MS_SYNC)` (bloqueante, fuerza el *flush* inmediato y espera) o `fsync()` (equivalente a nivel de descriptor de archivo completo).

Un atacante puede evadir filtros de seguridad que inspeccionan datos **solo en el momento del `write()`** porque con `mmap()` las modificaciones ocurren mediante instrucciones de CPU (`MOV`) sin invocar ninguna syscall — ningún *hook* de `sys_write` se dispara. Si el mecanismo de auditoría/antivirus solo intercepta `write()`/`pwrite()`, los cambios hechos vía `ptr[i] = valor` permanecen invisibles hasta que el *writeback* los persiste (o nunca, si se usa `MAP_PRIVATE`). La única forma de detectarlos a tiempo es instrumentar: el *write-fault* (`page_mkwrite`), el evento de *writeback* (`->writepage`/`->writepages` del `address_space_operations`), o usar `mprotect(PROT_READ)` + manejo de fallos para forzar trampas en cada escritura (técnica usada por *checkpointing*/CRIU y por algunos EDR).

### 7. Control de Accesos con eBPF
Se pueden adjuntar `kprobes`/`kretprobes` (o sus variantes *trace events* `fentry`/`fexit` con BTF, más eficientes y type-safe) a funciones internas como `do_mmap()`, `vm_mmap_pgoff()` o el hook `security_mmap_file()`. Un programa eBPF cargado con `bpf()`+verificado por el *verifier* (garantiza terminación y ausencia de accesos fuera de rango) puede:
- Leer argumentos (PID, ruta del archivo vía `d_path`, `prot`, `flags`) usando `bpf_probe_read_kernel()`.
- Enviar eventos a espacio de usuario vía `perf event buffer`/`ring buffer` (`BPF_MAP_TYPE_RINGBUF`) para que una herramienta tipo `bpftrace`/`libbpf` los procese (patrones anómalos: mismo proceso mapeando cientos de archivos sensibles, `PROT_WRITE` sobre archivos de solo lectura, etc.).
- Opcionalmente, con **BPF LSM** (`CONFIG_BPF_LSM`), el programa puede **bloquear** la operación retornando un código de error desde el hook `file_mmap`, no solo auditar.

La ventaja central es que **no se recompila el kernel** ni se cargan módulos arbitrarios: el programa se verifica estáticamente antes de insertarse (JIT), reduciendo el riesgo de *kernel panic* frente a un LKM tradicional mal escrito.

### 8. Evasión de Permisos POSIX
Sí: un proceso puede abrir con `O_RDONLY` y luego llamar `mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0)` **con éxito**, porque el kernel valida en `do_mmap()` que para `MAP_PRIVATE` solo se requiere que el archivo sea *legible* (`FMODE_READ`) — la escritura solicitada se resuelve mediante **COW en memoria privada del proceso**, nunca se re-abre el descriptor en modo escritura ni se escribe de vuelta al archivo. El kernel lo permite porque `MAP_PRIVATE` + `PROT_WRITE` es semánticamente "puedo modificar mi copia en RAM", no "puedo modificar el archivo". (En contraste, `MAP_SHARED` con `PROT_WRITE` sobre un `fd` `O_RDONLY` **sí es rechazado** con `EACCES`, porque ahí la escritura sí se propagaría al archivo.)

Riesgos: (a) **fuga de información** si el proceso coloca datos sensibles derivados del archivo en esa región "editable" y otro componente del sistema asume que es inmutable; (b) **alteración temporal engañosa** — herramientas de integridad que solo verifican permisos POSIX del descriptor (`O_RDONLY`) pueden reportar falsamente que el archivo es "a prueba de escritura" en memoria, cuando en realidad el proceso puede alterar su vista en RAM (afectando lógica de validación que dependa de releer ese buffer).

### 9. Mitigación de Ataques de Carrera (`madvise(MADV_DONTNEED)`)
La vulnerabilidad clásica (Dirty COW) explotaba la ventana entre: un hilo llamando `madvise(MADV_DONTNEED)` (que descarta las páginas privadas ya copiadas, forzando que el próximo acceso vuelva a mapear la página original de la Page Cache en modo lectura) y otro hilo escribiendo simultáneamente vía `/proc/self/mem`, de forma que el *write-fault* creyera que ya tenía una copia privada exclusiva y escribiera directamente sobre la página compartida de solo lectura.

El kernel moderno (parche de la corrección, desde 4.8.3/4.7.9+) mitiga esto revalidando el estado de la PTE **dentro de la región crítica protegida por el `page_table_lock`/`mmap_lock`** antes de aplicar la escritura, y re-chequeando `FOLL_WRITE`/`FOLL_FORCE` contra las banderas reales del VMA en el mismo paso atómico donde se decide si hace falta copiar. En términos generales, Linux ahora exige que la comprobación "¿la página es privada y exclusiva?" y la "operación de escritura" ocurran bajo el mismo *lock*, eliminando la ventana *TOCTOU* (time-of-check to time-of-use) entre `madvise()` y el *write-fault*.

### 10. Aislamiento de Memoria y Paginación
- **`struct page`**: descriptor por marco físico (metadatos: `refcount`, `flags` como `PG_dirty`/`PG_locked`/`PG_reserved`, mapeo inverso `mapping`). Es la unidad que el kernel protege/audita; sin `struct page` válido no hay forma de rastrear a qué proceso(s) pertenece un marco.
- **Tablas multinivel (PGD→P4D→PUD→PMD→PTE)**: permiten que **cada proceso** tenga su propio espacio de direcciones virtuales aislado — el valor de `CR3` (en x86_64) apunta al PGD del proceso en ejecución, de modo que el mismo rango virtual en dos procesos distintos traduce a marcos físicos distintos (o al mismo, solo si se mapeó explícitamente como compartido).
- **Bits de protección de la MMU:**
  - **NX (No-Execute):** impide que el procesador ejecute instrucciones desde páginas marcadas solo como datos (p. ej. el heap o una región `mmap` con `PROT_READ|PROT_WRITE` sin `PROT_EXEC`), mitigando inyección clásica de shellcode.
  - **R/W (Read/Write):** aplica COW y protección de solo-lectura; es el mecanismo que dispara el `#PF` de escritura descrito en la pregunta 3.
  - **U/S (User/Supervisor):** garantiza que código en Ring 3 no pueda ni siquiera **direccionar** páginas marcadas como Ring 0, de modo que un *payload* inyectado en memoria de usuario no puede leer/escribir estructuras del kernel sin una vulnerabilidad adicional (p. ej. SMAP/SMEP en hardware refuerzan esto impidiendo que el kernel mismo ejecute o lea memoria de usuario sin las funciones explícitas `copy_from_user`/`copy_to_user`).

Juntas, estas estructuras forman la frontera que un atacante debe romper: sin poder alterar una PTE para marcar una página de datos como ejecutable (NX) o sin poder forzar que el kernel trate una página de usuario como confiable (U/S, SMAP/SMEP), la inyección de código vía `mmap()` queda contenida al dominio de Ring 3 del proceso atacante.

---

## Parte II — Diseño de la Estrategia con Apoyo de Inteligencia Artificial (30%)

### 3.1 Definición del Flujo de Trabajo Asistido por IA

| Fase | Rol de la IA |
|---|---|
| **Exploración arquitectónica** | Se usó para explicar y correlacionar `struct vm_area_struct`, `vm_operations_struct`, y cabeceras (`<linux/mm.h>`, `<linux/mmzone.h>`) contra el código base del repositorio (`paso4`/`paso6`); generar diagramas de secuencia del flujo `mmap → #PF → handle_mm_fault`; proponer alternativas de diseño de *hooks* (LSM vs kprobes vs syscall hook) con sus trade-offs. |
| **Generación/verificación de código C de bajo nivel** | Generación de esqueletos de módulo LKM (`file_operations`, `vm_operations_struct`), de programas de `kprobes`, y de scripts de benchmarking con `perf`/`ftrace`. La IA actuó como *pair programmer*, pero **todo código generado se compiló y auditó manualmente** contra los headers reales del kernel instalado (`/lib/modules/$(uname -r)/build`) antes de aceptarse en la solución final. |
| **Casos de prueba y PoC controlados** | Generación de guiones de ataque (acceso no autorizado por UID distinto, simulación de carrera tipo Dirty-COW con `madvise(MADV_DONTNEED)`, fuzzing simple de `mmap()` con tamaños/flags inválidos) para validar que las defensas del módulo realmente bloquean o auditan el comportamiento. |

Principio rector del equipo: la IA acelera la **exploración** y el **primer borrador**, nunca reemplaza la **verificación** contra la documentación oficial del kernel (`Documentation/`, código fuente del kernel) ni la compilación real.

### 3.2 Metodología de Ingeniería de Prompts y Verificación Crítica

#### Tabla de prompts utilizados

| # | Contexto | Rol asignado a la IA | Restricción impuesta | Resultado esperado / obtenido |
|---|---|---|---|---|
| 1 | Código de `paso6_demand_paging_fault/kmod_demand_paging.c` ya existente en el repositorio | "Actúa como ingeniero de kernel Linux senior" | Debe usar **solo** APIs disponibles en kernel 6.x estable, citando el header donde se declara cada función | Propuesta de agregar control de acceso por `current_cred()->uid` dentro de `dev_mmap()`; se verificó que `current_cred()` requiere `<linux/cred.h>` (correcto y vigente) |
| 2 | Necesidad de auditar `mmap()` de otros procesos sin recompilar el kernel | "Actúa como experto en observabilidad con eBPF/kprobes" | No debe asumir `CONFIG_BPF_LSM` habilitado; debe proponer alternativa con `kprobes` clásicos si BTF no está disponible | Sugirió `register_kprobe()` sobre `security_mmap_file`; se validó que el símbolo existe y es accesible vía kprobe sin necesidad de `EXPORT_SYMBOL` |
| 3 | Script de PoC para simular Dirty-COW controlado en un entorno de laboratorio (kernel ya parchado) | "Actúa como auditor de seguridad ofensiva controlada, solo con fines educativos" | Debe limitarse a demostrar la *ventana de carrera* conceptual sin explotar un kernel vulnerable real ni producir herramientas de ataque genéricas | Generó un script Bash con dos hilos (`madvise` + escritura concurrente) sobre un archivo de prueba propio, con medición de tiempos — sin payload de escalada de privilegios |
| 4 | Medición de *overhead* de `mmap()` vs `read()` | "Actúa como ingeniero de performance" | Debe usar únicamente herramientas ya presentes en el proyecto (`perf`, `strace -c`, `getrusage()`) | Propuso comandos `perf stat -e page-faults,context-switches` y extensión del script de benchmarking existente; se integró sin cambios de riesgo |

#### Alucinaciones técnicas detectadas y corregidas

- **Función inexistente/no exportada:** la IA sugirió inicialmente llamar `sys_call_table[__NR_mmap] = hooked_mmap;` asumiendo que `sys_call_table` estaba exportada con `EXPORT_SYMBOL`. **Corrección:** se verificó con `grep -r sys_call_table /usr/src/linux-headers-$(uname -r)/` que el símbolo no es público desde kernels recientes; se descartó el enfoque (ver Pregunta 4).
- **Práctica insegura sugerida:** para "poder escribir" en la tabla de syscalls, la IA propuso `write_cr0(read_cr0() & ~0x10000)` (deshabilitar el bit *Write Protect* de `CR0`) sin mencionar que esto se ejecuta **por núcleo de CPU** y sin sección crítica, generando una carrera en sistemas SMP y dejando una ventana en la que *cualquier* núcleo puede escribir en código protegido del kernel. **Corrección:** se documentó el riesgo y se migró a un enfoque de `kprobes`/`file_operations` propio, que no requiere tocar `CR0`.
- **Macro/constante inexistente:** sugirió un flag `VM_SECURE` como si fuera parte estándar de `vm_flags`; no existe en el árbol del kernel. **Corrección:** se usaron banderas reales de `vm_flags` (`VM_READ`, `VM_WRITE`, `VM_MAYWRITE`) y se implementó la política de control de acceso como lógica propia del driver, no como bandera del kernel.
- **API obsoleta:** recomendó `kmap_atomic()` para mapear páginas temporalmente en el espacio del kernel; en kernels recientes (≥ 5.11) esta función fue reemplazada por `kmap_local_page()`. **Corrección:** se usó la API vigente, verificando `Documentation/mm/highmem.rst`.

#### Procedimiento de validación manual
1. Toda sugerencia de la IA se contrasta contra los **headers reales instalados** (`/lib/modules/$(uname -r)/build/include`), nunca se asume que un símbolo existe solo porque la IA lo menciona.
2. Compilación obligatoria con `make all` del subárbol afectado, exigiendo **cero *warnings*** (bandera de *clean build*).
3. Revisión cruzada entre los dos integrantes: cada módulo se compila y prueba en una máquina distinta a la de quien lo escribió.
4. Pruebas en una **máquina virtual desechable** (nunca en el host) antes de cargar cualquier LKM, dado el riesgo de *kernel panic*.

### 3.3 Estrategia Arquitectónica Seleccionada

**Arquitectura híbrida de dos componentes complementarios:**

```
                     ┌───────────────────────────────────────────┐
                     │           ESPACIO DE USUARIO (Ring 3)      │
                     │  test_secure_mmap  |  scripts de ataque    │
                     └───────────────┬───────────────┬───────────┘
                                     │ open/mmap     │ syscalls de otros procesos
                     ┌───────────────▼───────┐   ┌───▼─────────────────────┐
                     │  COMPONENTE A (LKM)    │   │ COMPONENTE B (kprobes)   │
                     │  /dev/secure_mmap      │   │ hook en do_mmap() /      │
                     │  .open  -> valida UID  │   │ security_mmap_file()    │
                     │  .mmap  -> ACL + hash  │   │ Registra: PID, ruta,     │
                     │  .fault -> auditoría   │   │ prot, flags, timestamp  │
                     └───────────┬────────────┘   └───────────┬─────────────┘
                                 │ printk/ktime                │ ring buffer / dmesg
                                 ▼                              ▼
                       ┌─────────────────────────────────────────────┐
                       │     Log de auditoría centralizado (dmesg)    │
                       │     + post-procesado con perf/ftrace         │
                       └───────────────────────────────────────────────┘
```

- **Componente A (control + integridad):** extiende el patrón de `paso6_demand_paging_fault` agregando verificación de credenciales en `.open`/`.mmap` (lista de UID/capacidad permitida), cálculo de hash de integridad de la región al cerrar el mapeo, y auditoría de cada *page fault* servido.
- **Componente B (auditoría transversal):** un módulo independiente de `kprobes` que observa **todo** `mmap()` del sistema (no solo el del driver propio), sin modificar ninguna syscall ni recompilar el kernel.

#### Matriz de trade-offs (Rendimiento vs. Seguridad)

| Estrategia | Latencia añadida a `mmap()` | Latencia añadida por *page fault* | Profundidad de inspección | Cobertura | Riesgo de inestabilidad |
|---|---|---|---|---|---|
| Hook en `sys_call_table` (CR0 unlock) | Baja | Nula | Solo en el punto de entrada de la syscall | Global (todas las mmap) | **Alto** (SMP race, incompatible con Lockdown LSM) |
| LSM compilado en el kernel | Muy baja | Nula | Alta (antes de crear el VMA) | Global | Bajo, pero requiere recompilar/habilitar en el *boot* |
| **BPF LSM / kprobes (Componente B)** | Baja (microsegundos) | N/A (se engancha en la creación del VMA, no en cada fault) | Media-alta (puede leer argumentos y bloquear si es BPF LSM) | Global, sin recompilar kernel | Bajo (verificador de eBPF) / Medio (kprobes clásico sin verificador) |
| **Driver propio con `.mmap`/`.fault` (Componente A)** | Media (chequeo de ACL en cada apertura) | Media (auditoría por página, solo en primer fault de c/u) | Alta sobre el recurso protegido específico | Limitada al dispositivo/archivo gestionado por el driver | Bajo (aislado al módulo propio) |

**Conclusión de diseño:** el Componente A ofrece **profundidad** (control fino sobre un recurso sensible específico) y el Componente B ofrece **amplitud** (visibilidad de todo el sistema); combinados cubren tanto la protección puntual exigida por la Parte 4.1 como la auditoría general exigida por la Pregunta 7, sin incurrir en los riesgos del hook de `sys_call_table` descartado en la Pregunta 4.

---

## Parte III — Implementación, Presentación y Argumentación de la Solución (40%)

### 4.1 Arquitectura de los entregables de código

La solución se compone de dos módulos de kernel y su material de prueba, integrados al árbol existente del repositorio (`USOS/CapaKernel/`) bajo la misma convención de los pasos 1-7:

| Entregable | Descripción técnica |
|---|---|
| `paso8_secure_driver/kmod_secure.c` | *Char device* que extiende el patrón `.mmap`/`.fault` de `paso6`: valida credenciales (`current_cred()`) en `.open`/`.mmap` contra una lista de UID/capacidad permitida, calcula un hash de integridad de la región mapeada, y audita cada *page fault* servido (`pr_info` + `ktime_get()`). |
| `paso8_secure_driver/test_secure.c` | Cliente en espacio de usuario que mapea el dispositivo y ejercita lectura/escritura legítima. |
| Scripts de ataque (UID distinto, `O_RDONLY`+`PROT_WRITE`) | Verifican que el acceso no autorizado es rechazado por el módulo. |
| `paso9_kprobe_auditor/kmod_auditor.c` | Módulo basado en `register_kprobe()` sobre `security_mmap_file`/`do_mmap` que registra PID, nombre de proceso (`comm`), ruta (`d_path`) y banderas `prot`/`flags` de **todo** `mmap()` del sistema, sin recompilar el kernel. |
| `run_benchmark_ext.sh` | Extensión del script de benchmarking existente (`paso5`) que reporta el *overhead* de `mmap()` con y sin los módulos cargados, usando `perf stat` y `strace -c`. |
| Script de PoC de condición de carrera | Reproduce la ventana `madvise(MADV_DONTNEED)` + escritura concurrente (patrón Dirty-COW) para comprobar que el kernel de prueba la mitiga correctamente. |
| Makefile raíz y README actualizados | Integran los nuevos pasos a la compilación general (`make all` sin *warnings*). |

### 4.2 Argumentación y Análisis de Resultados

**Justificación teórica — por qué la capa de kernel es óptima frente a espacio de usuario:**
Como se expuso en la introducción del problema, una vez que la PTE de una región `mmap()` está activa, las lecturas/escrituras ocurren a velocidad de hardware **sin conmutación a Ring 0**. Cualquier envoltorio en espacio de usuario (p. ej. `LD_PRELOAD` sobre `mmap()`) solo puede interceptar la *llamada inicial*, nunca los accesos posteriores vía puntero — y es trivialmente eludible reemplazando el símbolo interceptado o invocando la syscall cruda (`syscall(SYS_mmap, ...)`). Por eso la defensa debe anclarse en el kernel, en uno de tres puntos: el alta del VMA (`mmap`/hooks LSM), el manejador de fallos de página (`handle_mm_fault`), o los eventos de *dirtying*/sincronización (`msync`, *writeback*). La arquitectura propuesta (Componente A + B) cubre los tres puntos: Componente A interviene en el alta del VMA y en cada fault; Componente B observa el alta del VMA de forma transversal a todo el sistema.

**Medición de impacto (overhead):**
Se compara, con `perf stat -e page-faults,context-switches,cycles` y `strace -c`, el costo de: (i) `read()` clásico (`paso1`), (ii) `mmap()` sin instrumentación (`paso2`/`paso4`), y (iii) `mmap()` con el Componente A/B cargados. Se documentan en el informe final las tablas de resultados obtenidas en el entorno de prueba (número de *minor/major page faults*, tiempo de CPU en modo sistema, latencia de apertura del dispositivo), confirmando que el costo adicional de la validación de credenciales y el cálculo de hash se concentra en `.open`/`.mmap` (una sola vez por mapeo) y no en cada acceso posterior a los datos.

**Limitaciones y trabajo futuro:**
- La auditoría basada en `kprobes` clásicos no impide la operación (solo audita); para bloqueo activo se requeriría `CONFIG_BPF_LSM` o un LSM compilado en el kernel, no disponible en todos los entornos de despliegue.
- El esquema no cubre ataques de canal lateral (*side-channels*) a nivel de caché de CPU (p. ej. Spectre/Meltdown-style) que podrían inferir contenido de páginas mapeadas sin pasar por las rutas auditadas.
- Un atacante con privilegios de hipervisor (en entornos virtualizados) podría inspeccionar la memoria física directamente, evadiendo cualquier control implementado a nivel de kernel huésped; la mitigación completa de ese vector requeriría soporte de memoria cifrada por hardware (p. ej. AMD SEV, Intel TDX).
- Trabajo futuro: migrar el Componente B a un programa eBPF verificado con **BPF LSM** para obtener capacidad de bloqueo (no solo auditoría) manteniendo la seguridad de verificación estática del *verifier*.

---

## Instrucciones de entrega (recordatorio)
- Repositorio de GitHub o paquete comprimido con el código fuente, Makefile y README explicativo.
- Este documento (o su versión en PDF) como informe completo de respuestas, estrategia con IA y argumentación.
- Evidencia publicada por cada integrante del equipo en el buzón de interactiva EAFIT.
