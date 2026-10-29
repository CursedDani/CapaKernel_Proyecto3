/**
 * @file kmod_secure.c
 * @brief PASO 8 (Componente A del Parcial): Driver de Kernel con Control de Acceso,
 *        Verificacion de Integridad y Auditoria sobre regiones mmap().
 * @course Sistemas Operativos - DOCENCIA 2026-B
 *
 * ==============================================================================
 * OBJETIVO DE SEGURIDAD (Parcial 25% - Seguridad en Capa Kernel y mmap)
 * ==============================================================================
 *
 * Este modulo extiende el patron de paginacion por demanda de `paso6_demand_paging_fault`
 * (callback `vm_operations_struct->fault`) agregando tres mecanismos de defensa que,
 * segun el enunciado del parcial, SOLO pueden implementarse de forma confiable en la
 * capa de Kernel (Ring 0), pues una vez activa la PTE el acceso a `mmap()` ocurre a
 * velocidad de hardware sin pasar por ningun punto de intercepcion de espacio de usuario:
 *
 *   1. CONTROL DE ACCESO (UID / capability):
 *      - `dev_open()` solo permite abrir el dispositivo a un UID autorizado
 *        (parametro de modulo `allowed_uid`) o a un proceso con `CAP_SYS_ADMIN`.
 *      - `dev_mmap()` ademas rechaza cualquier mapeo con `PROT_EXEC` (VM_EXEC) para
 *        evitar que la region de datos se use como vector de inyeccion de codigo
 *        (ver Pregunta 10 del parcial: NX / bits de proteccion de la MMU).
 *
 *   2. INTEGRIDAD (hash CRC32):
 *      - Al inicializar el modulo se calcula un `baseline_crc` sobre el buffer fisico.
 *      - Cada vez que una region mapeada se desmapea (`vm_ops->close`), se recalcula
 *        el CRC32 (`crc32_le`, <linux/crc32.h>) y se audita si el contenido cambio.
 *      - El estado de integridad puede consultarse en caliente via `read()` sobre
 *        el propio dispositivo (no requiere herramientas externas).
 *
 *   3. AUDITORIA (Page Faults y accesos denegados):
 *      - Cada fallo de pagina atendido en `secure_vma_fault()` se registra con
 *        PID, nombre de proceso, UID y numero de pagina (equivalente a lo que
 *        haria un hook LSM/eBPF, pero implementado aqui como char device didactico).
 *      - Cada intento de apertura o mapeo no autorizado incrementa un contador y
 *        se registra con `pr_warn`/`pr_alert`.
 *
 * NOTA DE DISENO (ver Parte II.3.3 del informe): este componente ofrece PROFUNDIDAD
 * de inspeccion sobre un recurso especifico. La AMPLITUD (auditar mmap() de TODO el
 * sistema) se cubre con el Componente B (`paso9_kprobe_auditor`, basado en kprobes).
 */

#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/capability.h>
#include <linux/crc32.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>

#define DEVICE_NAME     "secure_mmap"
#define CLASS_NAME      "secure_mmap_class"

/* 4 paginas de 4 KB = 16 KB contiguas (ORDER = 2 -> 2^2 = 4 paginas) */
#define PAGE_ORDER      2
#define NUM_PAGES       (1 << PAGE_ORDER)
#define BUFFER_SIZE     (NUM_PAGES * PAGE_SIZE)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Equipo SO 2026-B - Parcial CapaKernel");
MODULE_DESCRIPTION("Driver didactico con control de acceso, integridad (CRC32) y auditoria de mmap()");
MODULE_VERSION("1.0");

/* ---- Parametro de modulo: control de acceso por UID ---- */
static int allowed_uid = 0; /* Por defecto, solo root (UID 0) */
module_param(allowed_uid, int, 0644);
MODULE_PARM_DESC(allowed_uid,
	"UID autorizado para abrir y escribir el dispositivo (por defecto 0 = root). "
	"Procesos con CAP_SYS_ADMIN siempre tienen acceso.");

static int major_number;
static struct class *secure_class;
static struct device *secure_device;
static struct cdev secure_cdev;

/* Buffer fisico protegido */
static struct page *kernel_pages;
static char *kernel_buffer;

/* Estado de integridad y auditoria, protegido por mutex */
static DEFINE_MUTEX(secure_lock);
static u32 baseline_crc;

static atomic_t active_mappings = ATOMIC_INIT(0);
static atomic_t fault_count     = ATOMIC_INIT(0);
static atomic_t denied_count    = ATOMIC_INIT(0);

/**
 * caller_is_authorized - Politica de control de acceso (UID o capability)
 */
static bool caller_is_authorized(void)
{
	kuid_t uid = current_uid();

	if (capable(CAP_SYS_ADMIN))
		return true;

	return uid_eq(uid, make_kuid(&init_user_ns, allowed_uid));
}

static int dev_open(struct inode *inodep, struct file *filep)
{
	if (!caller_is_authorized()) {
		atomic_inc(&denied_count);
		pr_warn("[kmod_secure] ACCESO DENEGADO: PID %d (%s) UID %d intento abrir /dev/%s (UID autorizado=%d)\n",
			current->pid, current->comm,
			from_kuid(&init_user_ns, current_uid()),
			DEVICE_NAME, allowed_uid);
		return -EACCES;
	}

	pr_info("[kmod_secure] Apertura autorizada: PID %d (%s) UID %d\n",
		current->pid, current->comm,
		from_kuid(&init_user_ns, current_uid()));
	return 0;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
	pr_info("[kmod_secure] Dispositivo cerrado por PID %d (%s)\n",
		current->pid, current->comm);
	return 0;
}

/**
 * dev_read - Interfaz de consulta en caliente del estado de integridad/auditoria.
 *            No requiere herramientas externas: basta con `cat /dev/secure_mmap`
 *            (si los permisos del nodo lo permiten) o un read() explicito.
 */
static ssize_t dev_read(struct file *filep, char __user *buf, size_t count, loff_t *ppos)
{
	char status[256];
	int len;
	u32 current_crc;

	if (*ppos > 0)
		return 0; /* una sola "lectura" por invocacion, estilo /proc */

	mutex_lock(&secure_lock);
	current_crc = crc32_le(0, kernel_buffer, BUFFER_SIZE);
	len = scnprintf(status, sizeof(status),
		"[kmod_secure] crc_baseline=0x%08x crc_actual=0x%08x estado=%s mmaps_activos=%d faults_auditados=%d accesos_denegados=%d allowed_uid=%d\n",
		baseline_crc, current_crc,
		(current_crc == baseline_crc) ? "SIN_CAMBIOS" : "MODIFICADO",
		atomic_read(&active_mappings),
		atomic_read(&fault_count),
		atomic_read(&denied_count),
		allowed_uid);
	mutex_unlock(&secure_lock);

	if (copy_to_user(buf, status, min_t(size_t, count, (size_t)len)))
		return -EFAULT;

	*ppos += len;
	return len;
}

/**
 * secure_vma_open - Invocado cuando se crea/duplica una VMA sobre nuestro buffer
 */
static void secure_vma_open(struct vm_area_struct *vma)
{
	atomic_inc(&active_mappings);
	pr_info("[kmod_secure] VMA abierta: PID %d (%s) rango [0x%lx-0x%lx]\n",
		current->pid, current->comm, vma->vm_start, vma->vm_end);
}

/**
 * secure_vma_close - Invocado al desmapear (munmap/exit). Punto de auditoria de
 *                     integridad: recalcula el CRC32 y reporta si el contenido
 *                     cambio respecto al valor base calculado en la inicializacion.
 */
static void secure_vma_close(struct vm_area_struct *vma)
{
	u32 current_crc;

	atomic_dec(&active_mappings);

	mutex_lock(&secure_lock);
	current_crc = crc32_le(0, kernel_buffer, BUFFER_SIZE);
	if (current_crc != baseline_crc) {
		pr_alert("[kmod_secure] AUDITORIA DE INTEGRIDAD: el buffer fue MODIFICADO por PID %d (%s). CRC previo=0x%08x, CRC actual=0x%08x\n",
			current->pid, current->comm, baseline_crc, current_crc);
	} else {
		pr_info("[kmod_secure] AUDITORIA DE INTEGRIDAD: sin cambios tras el cierre de VMA de PID %d (%s). CRC=0x%08x\n",
			current->pid, current->comm, current_crc);
	}
	mutex_unlock(&secure_lock);

	pr_info("[kmod_secure] VMA cerrada: PID %d (%s)\n", current->pid, current->comm);
}

/**
 * secure_vma_fault - Manejador de Page Fault (#PF) con auditoria por pagina.
 *                     Implementa paginacion por demanda real: ninguna pagina se
 *                     mapea hasta que la MMU genera el fallo correspondiente.
 */
static vm_fault_t secure_vma_fault(struct vm_fault *vmf)
{
	unsigned long offset = vmf->pgoff;
	struct page *page;

	atomic_inc(&fault_count);

	if (offset >= NUM_PAGES) {
		pr_warn("[kmod_secure] Page Fault fuera de rango: PID %d pagina #%lu (max %d) -> SIGBUS\n",
			current->pid, offset, NUM_PAGES - 1);
		return VM_FAULT_SIGBUS;
	}

	page = kernel_pages + offset;
	get_page(page);
	vmf->page = page;

	pr_info("[kmod_secure] PAGE FAULT auditado #%d: PID %d (%s) UID %d -> pagina #%lu direccion 0x%lx\n",
		atomic_read(&fault_count), current->pid, current->comm,
		from_kuid(&init_user_ns, current_uid()), offset, vmf->address);

	return 0;
}

static const struct vm_operations_struct secure_vm_ops = {
	.open  = secure_vma_open,
	.close = secure_vma_close,
	.fault = secure_vma_fault,
};

/**
 * dev_mmap - Callback invocado por sys_mmap(). Aplica las tres defensas:
 *            validacion de tamano, rechazo de PROT_EXEC y control de escritura
 *            compartida por UID/capability.
 */
static int dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;

	if (size > BUFFER_SIZE) {
		pr_err("[kmod_secure] mmap rechazado: PID %d solicito %lu bytes (maximo %lu)\n",
			current->pid, size, (unsigned long)BUFFER_SIZE);
		return -EINVAL;
	}

	/* Defensa 1: ninguna region de datos debe ser ejecutable (mitiga inyeccion de codigo) */
	if (vma->vm_flags & VM_EXEC) {
		atomic_inc(&denied_count);
		pr_alert("[kmod_secure] mmap BLOQUEADO: PID %d (%s) intento mapear PROT_EXEC sobre una region de datos (posible inyeccion de codigo)\n",
			current->pid, current->comm);
		return -EPERM;
	}

	/* Defensa 2: escritura compartida (persistente/visible a otros procesos) solo para UID autorizado */
	if ((vma->vm_flags & VM_WRITE) && (vma->vm_flags & VM_SHARED) &&
	    !caller_is_authorized()) {
		atomic_inc(&denied_count);
		pr_warn("[kmod_secure] mmap BLOQUEADO: PID %d (%s) UID %d intento MAP_SHARED+PROT_WRITE sin autorizacion\n",
			current->pid, current->comm,
			from_kuid(&init_user_ns, current_uid()));
		return -EACCES;
	}

	vma->vm_ops = &secure_vm_ops;
	vma->vm_private_data = NULL;

	pr_info("[kmod_secure] mmap autorizado: PID %d (%s) rango [0x%lx-0x%lx] tamano=%lu flags=0x%lx\n",
		current->pid, current->comm, vma->vm_start, vma->vm_end, size, vma->vm_flags);

	/* Notificar la apertura inicial de la VMA (equivalente a fork/mmap->open) */
	secure_vma_open(vma);

	return 0;
}

static const struct file_operations fops = {
	.owner   = THIS_MODULE,
	.open    = dev_open,
	.release = dev_release,
	.read    = dev_read,
	.mmap    = dev_mmap,
};

static int __init secure_init(void)
{
	dev_t dev_num;
	int ret, i;

	pr_info("[kmod_secure] Inicializando driver de seguridad (Componente A del parcial)...\n");

	kernel_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, PAGE_ORDER);
	if (!kernel_pages) {
		pr_err("[kmod_secure] Error al reservar paginas con alloc_pages\n");
		return -ENOMEM;
	}
	kernel_buffer = page_address(kernel_pages);

	for (i = 0; i < NUM_PAGES; i++)
		SetPageReserved(kernel_pages + i);

	for (i = 0; i < NUM_PAGES; i++) {
		snprintf(kernel_buffer + (i * PAGE_SIZE), PAGE_SIZE,
			"[PAGINA_SEGURA_%d]: contenido protegido por kmod_secure.\n"
			"Control de acceso UID=%d | Integridad CRC32 | Auditoria de Page Faults.\n",
			i, allowed_uid);
	}

	mutex_lock(&secure_lock);
	baseline_crc = crc32_le(0, kernel_buffer, BUFFER_SIZE);
	mutex_unlock(&secure_lock);
	pr_info("[kmod_secure] CRC32 base calculado: 0x%08x (buffer de %lu bytes)\n",
		baseline_crc, (unsigned long)BUFFER_SIZE);

	ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
	if (ret < 0)
		goto err_free_pages;
	major_number = MAJOR(dev_num);

	cdev_init(&secure_cdev, &fops);
	secure_cdev.owner = THIS_MODULE;
	ret = cdev_add(&secure_cdev, dev_num, 1);
	if (ret < 0)
		goto err_unregister;

	/* class_create(): 2 args hasta Linux 6.3, 1 arg desde 6.4 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	secure_class = class_create(CLASS_NAME);
#else
	secure_class = class_create(THIS_MODULE, CLASS_NAME);
#endif
	if (IS_ERR(secure_class)) {
		ret = PTR_ERR(secure_class);
		goto err_cdev_del;
	}

	secure_device = device_create(secure_class, NULL, dev_num, NULL, DEVICE_NAME);
	if (IS_ERR(secure_device)) {
		ret = PTR_ERR(secure_device);
		goto err_class_destroy;
	}

	pr_info("[kmod_secure] Dispositivo /dev/%s creado (major=%d). allowed_uid=%d\n",
		DEVICE_NAME, major_number, allowed_uid);
	return 0;

err_class_destroy:
	class_destroy(secure_class);
err_cdev_del:
	cdev_del(&secure_cdev);
err_unregister:
	unregister_chrdev_region(dev_num, 1);
err_free_pages:
	for (i = 0; i < NUM_PAGES; i++)
		ClearPageReserved(kernel_pages + i);
	__free_pages(kernel_pages, PAGE_ORDER);
	return ret;
}

static void __exit secure_exit(void)
{
	dev_t dev_num = MKDEV(major_number, 0);
	int i;

	device_destroy(secure_class, dev_num);
	class_destroy(secure_class);
	cdev_del(&secure_cdev);
	unregister_chrdev_region(dev_num, 1);

	for (i = 0; i < NUM_PAGES; i++)
		ClearPageReserved(kernel_pages + i);
	__free_pages(kernel_pages, PAGE_ORDER);

	pr_info("[kmod_secure] Modulo descargado. Mapeos activos al momento del cierre: %d, faults auditados: %d, accesos denegados: %d\n",
		atomic_read(&active_mappings), atomic_read(&fault_count), atomic_read(&denied_count));
}

module_init(secure_init);
module_exit(secure_exit);
