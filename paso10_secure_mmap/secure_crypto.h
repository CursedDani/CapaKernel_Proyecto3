/* SPDX-License-Identifier: GPL-2.0 */
/**
 * @file secure_crypto.h
 * @brief Envoltorio sobre la crypto API del kernel (cifrado en reposo + integridad).
 *
 *  - Confidencialidad: AES-128 en modo CTR ("ctr(aes)", skcipher).
 *      IV (16 B) = { page_idx:le32 | generation:le64 | contador de bloque:be32 }.
 *      La "generacion" sube en cada re-cifrado de la misma pagina, de modo que
 *      NUNCA se reutiliza el par (clave, IV) => no hay keystream reuse (two-time pad).
 *  - Integridad: HMAC-SHA256 ("hmac(sha256)", shash) sobre (page_idx || texto plano).
 *      CTR es maleable (voltear un bit del cifrado voltea el mismo bit del plano),
 *      por eso el cifrado SIN MAC no detecta manipulacion: el HMAC si.
 *
 * Las claves se generan con get_random_bytes() al cargar el modulo y jamas salen
 * del kernel (no hay ioctl para leerlas). Si se descarga el modulo, los datos
 * cifrados se pierden por diseno.
 */
#ifndef SECURE_CRYPTO_H
#define SECURE_CRYPTO_H

#include <linux/types.h>

int  vault_crypto_init(void);
void vault_crypto_exit(void);

/*
 * AES-CTR es simetrico: la misma operacion cifra y descifra.
 * @dst y @src son paginas completas (PAGE_SIZE) en el mapa directo del kernel.
 */
int vault_crypt_page(void *dst, const void *src, u32 page_idx, u64 generation);

/* HMAC-SHA256 de una pagina completa en claro. @out: VAULT_MAC_LEN bytes. */
int vault_mac_page(const void *plain, u32 page_idx, u8 *out);

#endif /* SECURE_CRYPTO_H */
