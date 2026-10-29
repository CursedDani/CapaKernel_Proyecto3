// SPDX-License-Identifier: GPL-2.0
/**
 * @file kmod_secure_mmap.c
 * @brief PASO 10 (Parcial 25%): "Boveda segura" /dev/secure_vault. Endurece el patron
 *        mmap + vm_operations_struct->fault de los Pasos 4/6/8 con controles que solo
 *        son confiables en Ring 0.
 *
 * ======================================================================================
 * POR QUE EN EL KERNEL (y no en LD_PRELOAD)
 * ======================================================================================
 * Una vez que la PTE esta instalada, ptr[i] se resuelve en hardware (MMU) sin pasar
 * por ninguna syscall: un wrapper de usuario solo ve el mmap() inicial y se evade con
 * syscall(SYS_mmap), binarios estaticos o ptrace. Los unicos puntos de control fiables
 * son (1) el alta de la VMA (f_op->mmap), (2) el page fault (vm_ops->fault) y
 * (3) la primera escritura (vm_ops->page_mkwrite). Este modulo actua en los tres.
 *
 * ======================================================================================
 * CONTROLES IMPLEMENTADOS (numeracion = Plan de Accion, seccion 3.1)
 * ======================================================================================
 *  1 Control de acceso : open() y mmap() exigen UID autorizado o CAP_SYS_ADMIN.
 *                        mmap() RE-VERIFICA porque un fd puede heredarse (fork) o
 *                        pasarse (SCM_RIGHTS) a un proceso sin autorizacion.
 *  2 W^X               : PROT_EXEC => -EACCES; se limpia VM_MAYEXEC (mprotect falla).
 *  3 Solo lectura real : fd sin FMODE_WRITE => se limpian VM_WRITE|VM_MAYWRITE.
 *  4 Solo MAP_SHARED   : MAP_PRIVATE => -EACCES (elimina el vector COW / Dirty COW).
 *                        OJO: se detecta con VM_MAYSHARE; el core limpia VM_SHARED en
 *                        mapeos compartidos de un fd de solo lectura.
 *  5 Limites estrictos : pgoff + tamano dentro de la boveda (corrige el Paso 4, que
 *                        ignora vm_pgoff y por tanto el offset que pide el usuario).
 *  6 Aislamiento       : VM_DONTCOPY | VM_DONTDUMP | VM_DONTEXPAND.
 *  7 Auditoria         : contadores atomicos + /proc/secure_vault/stats + dmesg.
 *  8 Cifrado en reposo : respaldo AES-128-CTR; cada open() recibe una copia EN CLARO
 *                        privada (filp->private_data), nunca el respaldo compartido.
 *  9 Integridad        : HMAC-SHA256 por pagina verificado en cada descifrado.
 * 10 Deteccion de      : page_mkwrite() cuenta la primera escritura por pagina.
 *    escrituras          (verificado empiricamente que se invoca; ver docs/).
 *
 * Contrato de bloqueo (orden estricto para evitar deadlock): session->lock -> vault_lock.
 */

#define pr_fmt(fmt) "secure_vault: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/uidgid.h>
#include <linux/gfp.h>

#include "secure_policy.h"
#include "secure_audit.h"
#include "secure_crypto.h"
#include "secure_vault_uapi.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Equipo SO 2026-B - Parcial CapaKernel");
MODULE_DESCRIPTION("Boveda mmap con control de acceso, W^X, cifrado AES-CTR e integridad HMAC-SHA256");
MODULE_VERSION("1.0");

/* 0444: tras cargar el modulo la politica NO se puede cambiar via /sys (hardening) */
static int allowed_uid;
module_param(allowed_uid, int, 0444);
MODULE_PARM_DESC(allowed_uid, "UID autorizado (por defecto 0). CAP_SYS_ADMIN siempre autorizado.");

static bool verbose;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Registrar cada page fault en dmesg (limitado en tasa)");

/* ------------------------------------------------------------------------- *
 * Estado global: respaldo cifrado
 * ------------------------------------------------------------------------- */
static DEFINE_MUTEX(vault_lock);

static struct {
	struct page *cipher[VAULT_NUM_PAGES];            /* texto CIFRADO en reposo */
	u64          gen[VAULT_NUM_PAGES];               /* generacion (parte del IV) */
	u8           mac[VAULT_NUM_PAGES][VAULT_MAC_LEN]; /* HMAC del texto plano */
} vault;

/* Sesion por open(): copia en claro PRIVADA a esta apertura */
struct vault_session {
	struct mutex lock;
	struct page *plain[VAULT_NUM_PAGES];
	bool         loaded[VAULT_NUM_PAGES];
	bool         writable;     /* el fd se abrio con FMODE_WRITE */
	/*
	 * Paginas que ALGUNA VEZ se escribieron en esta sesion (pegajoso, nunca se limpia).
	 * Es una PISTA para no recalcular HMAC en sesiones que solo leyeron; la decision
	 * final siempre la toma el HMAC. Es solida porque toda transicion de PTE solo-lectura
	 * a escritura en un mapeo MAP_SHARED con .page_mkwrite pasa por vault_page_mkwrite().
	 */
	unsigned long dirty_mask;
};

static dev_t vault_devt;
static struct cdev vault_cdev;
static struct class *vault_class;

/* ------------------------------------------------------------------------- *
 * Control 1: politica de identidad
 * ------------------------------------------------------------------------- */
static bool vault_caller_authorized(void)
{
	if (capable(CAP_SYS_ADMIN))
		return true;
	return uid_eq(current_euid(), make_kuid(&init_user_ns, allowed_uid));
}

/* ------------------------------------------------------------------------- *
 * Respaldo cifrado: descifrar + verificar integridad
 * ------------------------------------------------------------------------- */

/**
 * vault_decrypt_verify - descifra la pagina @idx hacia @dst y verifica su HMAC.
 * @dst: direccion (mapa directo) de una pagina completa
 * Return: 0 OK, -EBADMSG si el HMAC no verifica (manipulacion), <0 otro error.
 */
static int vault_decrypt_verify(unsigned int idx, void *dst)
{
	u8 mac[VAULT_MAC_LEN];
	int ret;

	mutex_lock(&vault_lock);
	ret = vault_crypt_page(dst, page_address(vault.cipher[idx]), idx, vault.gen[idx]);
	if (!ret)
		ret = vault_mac_page(dst, idx, mac);
	if (!ret && crypto_memneq(mac, vault.mac[idx], VAULT_MAC_LEN))
		ret = -EBADMSG;
	mutex_unlock(&vault_lock);

	if (ret == -EBADMSG) {
		vault_stat_inc(integrity_fail);
		pr_alert_ratelimited("ALERTA DE INTEGRIDAD: pagina %u del respaldo fue MANIPULADA (HMAC invalido) [" VAULT_CTX_FMT "]\n",
				     idx, VAULT_CTX_ARGS);
	} else if (!ret) {
		vault_stat_inc(decrypts);
	}
	return ret;
}

static int vault_load_page(struct vault_session *s, unsigned int idx)
{
	struct page *p = alloc_page(GFP_KERNEL | __GFP_ZERO);
	int ret;

	if (!p)
		return -ENOMEM;

	ret = vault_decrypt_verify(idx, page_address(p));
	if (ret) {
		memzero_explicit(page_address(p), PAGE_SIZE);
		__free_page(p);
		return ret;
	}
	s->plain[idx] = p;
	s->loaded[idx] = true;
	return 0;
}

/**
 * vault_commit_session - persiste en el respaldo las escrituras AUTORIZADAS.
 *
 * Para cada pagina cargada se recalcula el HMAC del texto plano; si difiere del
 * almacenado, hubo una escritura (solo posible con VM_WRITE, que unicamente tiene un
 * fd abierto con FMODE_WRITE por un UID autorizado). Se re-cifra con generacion+1 para
 * no reutilizar el keystream de CTR.
 */
static void vault_commit_session(struct vault_session *s)
{
	struct page *tmp;
	unsigned int i;
	u8 mac[VAULT_MAC_LEN];

	if (!s->writable || !READ_ONCE(s->dirty_mask))
		return;   /* nada que persistir: evita HMAC + alloc en cada munmap de solo-lectura */

	tmp = alloc_page(GFP_KERNEL);
	if (!tmp) {
		pr_err("sin memoria para persistir escrituras (se pierden)\n");
		return;
	}

	mutex_lock(&s->lock);
	mutex_lock(&vault_lock);
	for (i = 0; i < VAULT_NUM_PAGES; i++) {
		if (!s->loaded[i] || !test_bit(i, &s->dirty_mask))
			continue;
		if (vault_mac_page(page_address(s->plain[i]), i, mac))
			continue;
		if (!crypto_memneq(mac, vault.mac[i], VAULT_MAC_LEN))
			continue; /* sin cambios */

		if (vault_crypt_page(page_address(tmp), page_address(s->plain[i]),
				     i, vault.gen[i] + 1)) {
			pr_err("fallo al re-cifrar la pagina %u\n", i);
			continue;
		}
		memcpy(page_address(vault.cipher[i]), page_address(tmp), PAGE_SIZE);
		memcpy(vault.mac[i], mac, VAULT_MAC_LEN);
		vault.gen[i]++;
		vault_stat_inc(commits);
		pr_info_ratelimited("escritura AUTORIZADA persistida: pagina %u gen=%llu [" VAULT_CTX_FMT "]\n",
				    i, vault.gen[i], VAULT_CTX_ARGS);
	}
	mutex_unlock(&vault_lock);
	mutex_unlock(&s->lock);

	memzero_explicit(page_address(tmp), PAGE_SIZE);
	__free_page(tmp);
}

/* ------------------------------------------------------------------------- *
 * vm_operations_struct: auditoria por pagina y por escritura
 * ------------------------------------------------------------------------- */
static void vault_vma_open(struct vm_area_struct *vma)
{
	atomic_inc(&vault_stats.active_maps);
}

static void vault_vma_close(struct vm_area_struct *vma)
{
	struct vault_session *s = vma->vm_file->private_data;

	atomic_dec(&vault_stats.active_maps);
	vault_commit_session(s);
	pr_info_ratelimited("VMA cerrada [" VAULT_CTX_FMT "] rango [0x%lx-0x%lx]\n",
			    VAULT_CTX_ARGS, vma->vm_start, vma->vm_end);
}

static void vault_stat_max(atomic64_t *max, s64 val)
{
	s64 cur = atomic64_read(max);

	while (val > cur && !atomic64_try_cmpxchg(max, &cur, val))
		;
}

/**
 * vault_fault - Page Fault (#PF) sobre la VMA de la boveda.
 *
 * Aqui se descifra bajo demanda: ninguna pagina en claro existe hasta que un proceso
 * AUTORIZADO la toca. vmf->pgoff ya incluye vma->vm_pgoff (offset pedido en mmap).
 */
static vm_fault_t vault_fault(struct vm_fault *vmf)
{
	struct vault_session *s = vmf->vma->vm_file->private_data;
	pgoff_t idx = vmf->pgoff;
	bool write = vmf->flags & FAULT_FLAG_WRITE;
	u64 t0 = ktime_get_ns();
	vm_fault_t ret = 0;
	s64 dt;

	if (idx >= VAULT_NUM_PAGES) {
		vault_stat_inc(fault_oob);
		pr_warn_ratelimited("fault FUERA DE RANGO pagina=%lu -> SIGBUS [" VAULT_CTX_FMT "]\n",
				    idx, VAULT_CTX_ARGS);
		return VM_FAULT_SIGBUS;
	}

	mutex_lock(&s->lock);
	if (!s->loaded[idx]) {
		int err = vault_load_page(s, idx);

		if (err) {
			mutex_unlock(&s->lock);
			return err == -ENOMEM ? VM_FAULT_OOM : VM_FAULT_SIGBUS;
		}
	}
	get_page(s->plain[idx]);
	vmf->page = s->plain[idx];
	mutex_unlock(&s->lock);

	if (write)
		vault_stat_inc(fault_write);
	else
		vault_stat_inc(fault_read);
	if (verbose)
		pr_info_ratelimited("PAGE FAULT %s pagina=%lu addr=0x%lx [" VAULT_CTX_FMT "]\n",
				    write ? "ESCRITURA" : "LECTURA", idx, vmf->address,
				    VAULT_CTX_ARGS);

	dt = ktime_get_ns() - t0;
	vault_stat_add(fault_ns_total, dt);
	vault_stat_max(&vault_stats.fault_ns_max, dt);
	return ret;
}

/**
 * vault_page_mkwrite - primera escritura sobre una pagina (control 10).
 *
 * El core de mm solo lo invoca si la PTE se instalo de SOLO LECTURA en un mapeo
 * MAP_SHARED|PROT_WRITE que tiene este callback (vma_wants_writenotify()).
 * Como nuestra pagina no pertenece a un address_space (folio->mapping == NULL),
 * devolvemos la pagina bloqueada con VM_FAULT_LOCKED: asi do_page_mkwrite() no
 * intenta comprobar folio->mapping y reintentar el fault indefinidamente.
 */
static vm_fault_t vault_page_mkwrite(struct vm_fault *vmf)
{
	struct vault_session *s = vmf->vma->vm_file->private_data;

	if (vmf->pgoff < VAULT_NUM_PAGES)
		set_bit(vmf->pgoff, &s->dirty_mask);
	vault_stat_inc(mkwrite);
	pr_info_ratelimited("PRIMERA ESCRITURA pagina=%lu addr=0x%lx [" VAULT_CTX_FMT "]\n",
			    vmf->pgoff, vmf->address, VAULT_CTX_ARGS);
	folio_lock(page_folio(vmf->page));
	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct vault_vm_ops = {
	.open         = vault_vma_open,
	.close        = vault_vma_close,
	.fault        = vault_fault,
	.page_mkwrite = vault_page_mkwrite,
};

/* ------------------------------------------------------------------------- *
 * file_operations
 * ------------------------------------------------------------------------- */
static int vault_open(struct inode *inode, struct file *filp)
{
	struct vault_session *s;

	if (!vault_caller_authorized()) {
		vault_stat_inc(open_denied_uid);
		pr_warn_ratelimited("open DENEGADO (UID no autorizado; permitido=%d) [" VAULT_CTX_FMT "]\n",
				    allowed_uid, VAULT_CTX_ARGS);
		return -EPERM;
	}

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	mutex_init(&s->lock);
	s->writable = !!(filp->f_mode & FMODE_WRITE);
	filp->private_data = s;

	vault_stat_inc(open_ok);
	pr_info_ratelimited("open autorizado %s [" VAULT_CTX_FMT "]\n",
			    s->writable ? "RW" : "RO", VAULT_CTX_ARGS);
	return 0;
}

static int vault_release(struct inode *inode, struct file *filp)
{
	struct vault_session *s = filp->private_data;
	unsigned int i;

	vault_commit_session(s);
	for (i = 0; i < VAULT_NUM_PAGES; i++) {
		if (!s->plain[i])
			continue;
		/* No dejar texto plano en paginas que el allocator reutilizara */
		memzero_explicit(page_address(s->plain[i]), PAGE_SIZE);
		put_page(s->plain[i]);
	}
	kfree(s);
	return 0;
}

/**
 * vault_mmap - alta de la VMA: aqui se aplican los controles 1-6.
 * Se ejecuta con el mmap_lock en escritura (por eso vm_flags_set/clear es valido).
 */
static int vault_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct vault_session *s = filp->private_data;

	/* 1. Re-verificar identidad: el fd pudo heredarse/pasarse a otro UID */
	if (!vault_caller_authorized()) {
		vault_stat_inc(mmap_denied_uid);
		pr_warn_ratelimited("mmap DENEGADO (fd heredado por UID no autorizado) [" VAULT_CTX_FMT "]\n",
				    VAULT_CTX_ARGS);
		return -EPERM;
	}

	/* 2. W^X */
	if (vma->vm_flags & VM_EXEC) {
		vault_stat_inc(mmap_denied_exec);
		pr_alert_ratelimited("mmap DENEGADO: PROT_EXEC sobre la boveda (inyeccion de codigo?) [" VAULT_CTX_FMT "]\n",
				     VAULT_CTX_ARGS);
		return -EACCES;
	}

	/* 4. Solo MAP_SHARED (VM_MAYSHARE sobrevive aunque el core limpie VM_SHARED) */
	if (!(vma->vm_flags & VM_MAYSHARE)) {
		vault_stat_inc(mmap_denied_private);
		pr_warn_ratelimited("mmap DENEGADO: MAP_PRIVATE no permitido (vector COW) [" VAULT_CTX_FMT "]\n",
				    VAULT_CTX_ARGS);
		return -EACCES;
	}

	/* 5. Limites: offset y longitud dentro de la boveda (sin desbordar pgoff + paginas) */
	if (vma->vm_pgoff >= VAULT_NUM_PAGES ||
	    vma_pages(vma) > VAULT_NUM_PAGES - vma->vm_pgoff) {
		vault_stat_inc(mmap_denied_range);
		pr_warn_ratelimited("mmap DENEGADO: rango fuera de la boveda pgoff=%lu paginas=%lu [" VAULT_CTX_FMT "]\n",
				    vma->vm_pgoff, vma_pages(vma), VAULT_CTX_ARGS);
		return -EINVAL;
	}

	/* 3. Un fd de solo lectura jamas podra escribir, ni siquiera tras mprotect() */
	if (!s->writable)
		vault_vm_flags_clear(vma, VM_WRITE | VM_MAYWRITE);

	/* 2b/6. Aislamiento y W^X permanente */
	vault_vm_flags_clear(vma, VM_MAYEXEC);
	vault_vm_flags_set(vma, VAULT_ISOLATION_FLAGS);

	vma->vm_ops = &vault_vm_ops;

	/* El core NO invoca .open para el primer mapeo, solo para split/fork */
	atomic_inc(&vault_stats.active_maps);
	vault_stat_inc(mmap_ok);
	pr_info_ratelimited("mmap autorizado pgoff=%lu paginas=%lu %s [" VAULT_CTX_FMT "]\n",
			    vma->vm_pgoff, vma_pages(vma),
			    (vma->vm_flags & VM_WRITE) ? "RW" : "RO", VAULT_CTX_ARGS);
	return 0;
}

/* ------------------------------------------------------------------------- *
 * ioctl (solo para pruebas de laboratorio)
 * ------------------------------------------------------------------------- */
static long vault_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	unsigned int i;

	if (!vault_caller_authorized())
		return -EPERM;

	switch (cmd) {
	case SECURE_VAULT_IOC_TAMPER: {
		__u32 page;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&page, uarg, sizeof(page)))
			return -EFAULT;
		if (page >= VAULT_NUM_PAGES)
			return -EINVAL;
		mutex_lock(&vault_lock);
		*(u8 *)page_address(vault.cipher[page]) ^= 0x01;
		mutex_unlock(&vault_lock);
		pr_alert("TAMPER de laboratorio: 1 bit del cifrado de la pagina %u invertido [" VAULT_CTX_FMT "]\n",
			 page, VAULT_CTX_ARGS);
		return 0;
	}
	case SECURE_VAULT_IOC_VERIFY: {
		struct page *tmp = alloc_page(GFP_KERNEL);
		__u32 bad = 0;

		if (!tmp)
			return -ENOMEM;
		for (i = 0; i < VAULT_NUM_PAGES; i++)
			if (vault_decrypt_verify(i, page_address(tmp)))
				bad++;
		memzero_explicit(page_address(tmp), PAGE_SIZE);
		__free_page(tmp);
		return copy_to_user(uarg, &bad, sizeof(bad)) ? -EFAULT : 0;
	}
	case SECURE_VAULT_IOC_PEEK: {
		struct secure_vault_peek pk;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&pk, uarg, sizeof(pk)))
			return -EFAULT;
		if (pk.page >= VAULT_NUM_PAGES)
			return -EINVAL;
		mutex_lock(&vault_lock);
		memcpy(pk.data, page_address(vault.cipher[pk.page]), sizeof(pk.data));
		mutex_unlock(&vault_lock);
		return copy_to_user(uarg, &pk, sizeof(pk)) ? -EFAULT : 0;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations vault_fops = {
	.owner          = THIS_MODULE,
	.open           = vault_open,
	.release        = vault_release,
	.mmap           = vault_mmap,
	.unlocked_ioctl = vault_ioctl,
	.compat_ioctl   = vault_ioctl,
};

/* ------------------------------------------------------------------------- *
 * Carga / descarga
 * ------------------------------------------------------------------------- */
static void vault_free_backing(void)
{
	unsigned int i;

	for (i = 0; i < VAULT_NUM_PAGES; i++) {
		if (!vault.cipher[i])
			continue;
		memzero_explicit(page_address(vault.cipher[i]), PAGE_SIZE);
		__free_page(vault.cipher[i]);
		vault.cipher[i] = NULL;
	}
}

/* Siembra el contenido inicial: lo cifra y guarda el HMAC del texto plano */
static int vault_seed_backing(void)
{
	struct page *tmp = alloc_page(GFP_KERNEL);
	unsigned int i;
	int ret = 0;

	if (!tmp)
		return -ENOMEM;

	for (i = 0; i < VAULT_NUM_PAGES; i++) {
		vault.cipher[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!vault.cipher[i]) {
			ret = -ENOMEM;
			break;
		}
		memset(page_address(tmp), 0, PAGE_SIZE);
		snprintf(page_address(tmp), PAGE_SIZE,
			 "SECRETO-VAULT-PAGE-%u :: contenido confidencial; solo visible en claro para procesos autorizados.\n",
			 i);
		ret = vault_mac_page(page_address(tmp), i, vault.mac[i]);
		if (!ret)
			ret = vault_crypt_page(page_address(vault.cipher[i]),
					       page_address(tmp), i, 0);
		if (ret)
			break;
	}

	memzero_explicit(page_address(tmp), PAGE_SIZE);
	__free_page(tmp);
	if (ret)
		vault_free_backing();
	return ret;
}

static int __init secure_vault_init(void)
{
	struct device *dev;
	int ret;

	ret = vault_crypto_init();
	if (ret)
		return ret;

	ret = vault_seed_backing();
	if (ret)
		goto err_crypto;

	ret = vault_audit_init();
	if (ret)
		goto err_backing;

	ret = alloc_chrdev_region(&vault_devt, 0, 1, VAULT_DEVICE_NAME);
	if (ret)
		goto err_audit;

	cdev_init(&vault_cdev, &vault_fops);
	vault_cdev.owner = THIS_MODULE;
	ret = cdev_add(&vault_cdev, vault_devt, 1);
	if (ret)
		goto err_region;

	vault_class = vault_class_create(VAULT_CLASS_NAME);
	if (IS_ERR(vault_class)) {
		ret = PTR_ERR(vault_class);
		goto err_cdev;
	}

	dev = device_create(vault_class, NULL, vault_devt, NULL, VAULT_DEVICE_NAME);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto err_class;
	}

	pr_info("cargado: /dev/%s (major=%d) %lu paginas cifradas AES-128-CTR + HMAC-SHA256, allowed_uid=%d\n",
		VAULT_DEVICE_NAME, MAJOR(vault_devt), (unsigned long)VAULT_NUM_PAGES, allowed_uid);
	return 0;

err_class:
	class_destroy(vault_class);
err_cdev:
	cdev_del(&vault_cdev);
err_region:
	unregister_chrdev_region(vault_devt, 1);
err_audit:
	vault_audit_exit();
err_backing:
	vault_free_backing();
err_crypto:
	vault_crypto_exit();
	return ret;
}

static void __exit secure_vault_exit(void)
{
	device_destroy(vault_class, vault_devt);
	class_destroy(vault_class);
	cdev_del(&vault_cdev);
	unregister_chrdev_region(vault_devt, 1);
	vault_audit_exit();
	vault_free_backing();
	vault_crypto_exit();
	pr_info("descargado (mmaps activos=%d, fallos de integridad=%lld)\n",
		atomic_read(&vault_stats.active_maps),
		(long long)atomic64_read(&vault_stats.integrity_fail));
}

module_init(secure_vault_init);
module_exit(secure_vault_exit);
