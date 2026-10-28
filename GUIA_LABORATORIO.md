# Guía de Laboratorio Práctico: Memoria Virtual, Capa Kernel y `mmap`

> **Asignatura:** Sistemas Operativos (DOCENCIA 2026-B)  
> **Tema:** Entrada/Salida, Paginación por Demanda y Mecanismos Zero-Copy en Linux

---

## 1. Objetivos del Laboratorio

1. Cuantificar el impacto del cambio de contexto (*Ring 3* a *Ring 0*) y la duplicación de memoria producida por `copy_to_user()`.
2. Comprender cómo la Unidad de Manejo de Memoria (**MMU**) de la CPU interactúa con el Kernel para resolver fallos de página (**Page Faults**).
3. Analizar la implementación en lenguaje C de controladores de dispositivo de caracteres (*char devices*) con soporte `read()`, `mmap()` con `remap_pfn_range()` y paginación por demanda con `vm_operations_struct->fault`.
4. Evaluar el rendimiento de sistemas de comunicación inter-procesos (**IPC**) con memoria compartida Zero-Copy frente a tuberías/sockets tradicionales.

---

## 2. Experimentos Prácticos

### Experimento 1: El Costo Oculto de `read()` vs `mmap()`

1. Ejecute la prueba de lectura clásica:
   ```bash
   make run-paso1
   ```
2. Ejecute la prueba de memoria mapeada:
   ```bash
   make run-paso2
   ```
3. Ejecute el comparador de llamadas al sistema con `strace`:
   ```bash
   make run-benchmark
   ```

**Preguntas de Análisis:**
- ¿Cuántas llamadas al sistema `sys_read` se ejecutaron en el Paso 1 frente al Paso 2?
- Al observar la salida de `strace -c`, ¿qué porcentaje del tiempo total se dedicó a atender la syscall `read` en el kernel?
- ¿Por qué el tiempo de CPU en modo sistema (`sys_cpu`) disminuye drásticamente con `mmap()`?

---

### Experimento 2: Inspección de Tablas de Páginas y PFN en Tiempo Real

1. Compile y ejecute la herramienta de inspección de la MMU:
   ```bash
   make run-inspector
   ```
2. Observe la salida de `/proc/self/pagemap` antes y después de acceder a la Página 2.

**Preguntas de Análisis:**
- ¿Por qué el bit "Presente en RAM" era `0` inmediatamente después de llamar a `mmap()`?
- ¿Qué componente de hardware interceptó el intento de acceso a `ptr[8192]` y qué excepción de CPU disparó?
- ¿En qué momento se asignó el Page Frame Number (PFN) físico?

---

### Experimento 3: Exploración en la Capa Kernel (Drivers y Zero-Copy)

> *Nota: Requiere permisos de administrador (`sudo`).*

1. Cargue los tres módulos del kernel:
   ```bash
   sudo ./scripts/load_modules.sh
   ```
2. Pruebe el driver clásico con `copy_to_user()`:
   ```bash
   ./paso3_driver_copy_user/test_copy_user
   ```
3. Pruebe el driver Zero-Copy con `remap_pfn_range()`:
   ```bash
   ./paso4_driver_mmap_kernel/test_mmap
   ```
4. Pruebe el driver con Paginación por Demanda real (`fault`):
   ```bash
   ./paso6_demand_paging_fault/test_demand_paging
   ```
5. Inspeccione los registros del kernel:
   ```bash
   sudo dmesg | tail -n 25
   ```
6. Descargue los módulos al finalizar:
   ```bash
   sudo ./scripts/unload_modules.sh
   ```

**Preguntas de Análisis:**
- En [`kmod_copy_user.c`](file:///home/edi/DOCENCIA2026/SO2026B/CapaKernel/paso3_driver_copy_user/kmod_copy_user.c), ¿por qué no es seguro que el kernel utilice `memcpy()` directamente sobre el puntero `buf` de espacio de usuario?
- En [`kmod_mmap.c`](file:///home/edi/DOCENCIA2026/SO2026B/CapaKernel/paso4_driver_mmap_kernel/kmod_mmap.c), ¿qué función cumple `remap_pfn_range()` y por qué se marcan las páginas con `SetPageReserved()`?
- En [`kmod_demand_paging.c`](file:///home/edi/DOCENCIA2026/SO2026B/CapaKernel/paso6_demand_paging_fault/kmod_demand_paging.c), ¿cuántas veces fue invocado el callback `demo_vma_fault()` en la prueba y por qué no se cargaron las páginas 1, 2, 3, 4, 6 y 7?

---

### Experimento 4: IPC de Ultra-Alto Rendimiento (Ring Buffer Zero-Copy)

1. Ejecute la prueba de comunicación entre dos procesos independientes:
   ```bash
   make run-ipc
   ```

**Preguntas de Análisis:**
- ¿Cuántos mensajes por segundo fueron transferidos entre el productor y el consumidor?
- ¿Por qué este modelo supera por órdenes de magnitud a las tuberías (`pipe`) y sockets Unix?
- ¿Cómo se garantiza la sincronización entre el productor y el consumidor sin recurrir a llamadas al sistema bloqueantes?

---

### Experimento 5: Seguridad en la Capa Kernel — Control de Acceso, Integridad y Auditoría (Parcial 25%)

> *Nota: Requiere permisos de administrador (`sudo`) para cargar el módulo.*

1. Compile y cargue el driver seguro:
   ```bash
   cd paso8_secure_driver
   make
   make load
   ```
2. Ejecute el cliente de prueba (demuestra control de acceso, escritura legítima, integridad y bloqueo de `PROT_EXEC`):
   ```bash
   make test
   ```
3. Ejecute la PoC de acceso no autorizado por UID distinto:
   ```bash
   ./attack_unauthorized_uid.sh
   ```
4. Inspeccione el registro de auditoría del kernel:
   ```bash
   sudo dmesg | tail -n 30
   ```
5. Descargue el módulo al finalizar:
   ```bash
   make unload
   ```

**Preguntas de Análisis:**
- En [`kmod_secure.c`](./paso8_secure_driver/kmod_secure.c), ¿por qué el control de acceso se valida tanto en `dev_open()` como en `dev_mmap()`, y no solo en uno de los dos puntos?
- ¿Por qué `dev_mmap()` rechaza explícitamente cualquier mapeo con la bandera `VM_EXEC`? Relacione su respuesta con los bits NX/U-S de la MMU (Pregunta 10 del parcial).
- ¿En qué momento exacto se recalcula el CRC32 de integridad, y por qué ese punto (`vm_ops->close`) es más confiable que verificar la integridad solo al momento de `open()`?
- Al ejecutar `attack_unauthorized_uid.sh`, ¿qué código de error (`errno`) recibe el proceso no autorizado y en qué línea del módulo se genera?
- ¿Por qué este mecanismo, implementado como *char device* en espacio de Kernel, no puede ser eludido por un `LD_PRELOAD` en espacio de usuario (ver Pregunta 4 del parcial)?
