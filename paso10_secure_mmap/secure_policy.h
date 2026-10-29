/* SPDX-License-Identifier: GPL-2.0 */
/**
 * @file secure_policy.h
 * @brief Politica de seguridad y constantes compartidas de la boveda segura
 *        (/dev/secure_vault). Paso 10 - Parcial 25% (Seguridad en Capa Kernel y mmap).
 *
 * Aqui vive TODO lo que es "politica" (que se permite y que no) y las
 * macros de compatibilidad entre versiones del kernel (5.x / 6.x / 7.x), para
 * que el resto del codigo lea como logica y no como #ifdefs.
 */
#ifndef SECURE_POLICY_H
#define SECURE_POLICY_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#define VAULT_DEVICE_NAME  "secure_vault"
#define VAULT_CLASS_NAME   "secure_vault_class"
#define VAULT_PROC_DIR     "secure_vault"

/* Cuatro paginas de respaldo. El tamano es un multiplo exacto de PAGE_SIZE. */
#define VAULT_NUM_PAGES    4
#define VAULT_SIZE         ((unsigned long)VAULT_NUM_PAGES * PAGE_SIZE)

#define VAULT_KEY_LEN      16   /* AES-128 */
#define VAULT_MAC_KEY_LEN  32   /* HMAC-SHA256 */
#define VAULT_MAC_LEN      32

/*
 * W^X: la boveda es datos, jamas codigo.
 *   - VM_EXEC    : si el usuario pidio PROT_EXEC se RECHAZA el mmap.
 *   - VM_MAYEXEC : el core de mm lo activa SIEMPRE (es "puede llegar a ser exec");
 *                  hay que LIMPIARLO para que un mprotect(PROT_EXEC) posterior falle.
 * Banderas que SIEMPRE se imponen (aislamiento):
 *   - VM_DONTCOPY   : el hijo de un fork() NO hereda el mapeo.
 *   - VM_DONTDUMP   : no aparece en core dumps (el texto plano no se filtra).
 *   - VM_DONTEXPAND : mremap() no puede crecer el mapeo mas alla de lo validado.
 */
#define VAULT_ISOLATION_FLAGS  (VM_DONTCOPY | VM_DONTDUMP | VM_DONTEXPAND)

/*
 * Algunas cabeceras cambiaron de ubicacion entre versiones del kernel
 * (<asm/unaligned.h> -> <linux/unaligned.h> en 6.12; crypto_memneq se movio a
 * <crypto/utils.h>). __has_include evita adivinar numeros de version.
 */
#if __has_include(<linux/unaligned.h>)
# include <linux/unaligned.h>
#else
# include <asm/unaligned.h>
#endif
#if __has_include(<crypto/utils.h>)
# include <crypto/utils.h>
#else
# include <crypto/algapi.h>
#endif

/* ------------------------------------------------------------------------- *
 * Compatibilidad entre versiones del kernel
 * ------------------------------------------------------------------------- */

/*
 * Desde Linux 6.3 vma->vm_flags es de solo lectura "de facto": hay que usar
 * vm_flags_set()/vm_flags_clear() (requieren el mmap_lock en escritura, que
 * el kernel ya sostiene dentro de f_op->mmap).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
# define vault_vm_flags_set(vma, f)    vm_flags_set((vma), (f))
# define vault_vm_flags_clear(vma, f)  vm_flags_clear((vma), (f))
#else
# define vault_vm_flags_set(vma, f)    ((vma)->vm_flags |= (f))
# define vault_vm_flags_clear(vma, f)  ((vma)->vm_flags &= ~(f))
#endif

/* class_create(): 2 argumentos (THIS_MODULE, name) hasta 6.3; 1 argumento desde 6.4 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
# define vault_class_create(name)  class_create(name)
#else
# define vault_class_create(name)  class_create(THIS_MODULE, name)
#endif

#endif /* SECURE_POLICY_H */
