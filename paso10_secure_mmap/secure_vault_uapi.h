/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/**
 * @file secure_vault_uapi.h
 * @brief Interfaz kernel<->usuario (ioctl) de /dev/secure_vault.
 *
 * Los ioctl existen SOLO para pruebas controladas en laboratorio / VM:
 *   - SECURE_VAULT_IOC_VERIFY  : verifica la integridad (HMAC) de todo el respaldo.
 *   - SECURE_VAULT_IOC_TAMPER  : (CAP_SYS_ADMIN) corrompe 1 byte del texto cifrado
 *                                para simular una manipulacion fisica/no autorizada.
 *   - SECURE_VAULT_IOC_PEEK    : (CAP_SYS_ADMIN) copia los primeros bytes del texto
 *                                CIFRADO en reposo, para demostrar que RAM no tiene
 *                                el texto plano.
 */
#ifndef SECURE_VAULT_UAPI_H
#define SECURE_VAULT_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define SECURE_VAULT_IOC_MAGIC 'V'
#define SECURE_VAULT_PEEK_LEN  32

struct secure_vault_peek {
	__u32 page;                       /* IN : indice de pagina */
	__u8  data[SECURE_VAULT_PEEK_LEN]; /* OUT: texto cifrado en reposo */
};

/* arg: __u32 (indice de pagina a corromper) */
#define SECURE_VAULT_IOC_TAMPER _IOW(SECURE_VAULT_IOC_MAGIC, 1, __u32)
/* arg: __u32 (OUT, numero de paginas cuyo HMAC NO verifica) */
#define SECURE_VAULT_IOC_VERIFY _IOR(SECURE_VAULT_IOC_MAGIC, 2, __u32)
/* arg: struct secure_vault_peek */
#define SECURE_VAULT_IOC_PEEK   _IOWR(SECURE_VAULT_IOC_MAGIC, 3, struct secure_vault_peek)

#endif /* SECURE_VAULT_UAPI_H */
