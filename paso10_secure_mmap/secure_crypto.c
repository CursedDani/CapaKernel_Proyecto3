// SPDX-License-Identifier: GPL-2.0
/**
 * @file secure_crypto.c
 * @brief Implementacion de cifrado AES-CTR y HMAC-SHA256 con la crypto API.
 *
 * Todas las funciones pueden dormir (GFP_KERNEL, CRYPTO_TFM_REQ_MAY_SLEEP): solo
 * se invocan desde contexto de proceso (fault handler, release, ioctl), nunca
 * desde contexto atomico.
 */
#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>

#include "secure_policy.h"
#include "secure_crypto.h"

static struct crypto_skcipher *vault_cipher;
static struct crypto_shash *vault_mac;

int vault_crypto_init(void)
{
	u8 key[VAULT_KEY_LEN];
	u8 mac_key[VAULT_MAC_KEY_LEN];
	int ret;

	vault_cipher = crypto_alloc_skcipher("ctr(aes)", 0, 0);
	if (IS_ERR(vault_cipher)) {
		ret = PTR_ERR(vault_cipher);
		pr_err("secure_vault: ctr(aes) no disponible (%d)\n", ret);
		vault_cipher = NULL;
		return ret;
	}

	vault_mac = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(vault_mac)) {
		ret = PTR_ERR(vault_mac);
		pr_err("secure_vault: hmac(sha256) no disponible (%d)\n", ret);
		vault_mac = NULL;
		goto err_cipher;
	}

	get_random_bytes(key, sizeof(key));
	get_random_bytes(mac_key, sizeof(mac_key));

	ret = crypto_skcipher_setkey(vault_cipher, key, sizeof(key));
	if (ret)
		goto err_mac;
	ret = crypto_shash_setkey(vault_mac, mac_key, sizeof(mac_key));
	if (ret)
		goto err_mac;

	/* No dejar las claves en la pila del kernel */
	memzero_explicit(key, sizeof(key));
	memzero_explicit(mac_key, sizeof(mac_key));
	return 0;

err_mac:
	crypto_free_shash(vault_mac);
	vault_mac = NULL;
err_cipher:
	crypto_free_skcipher(vault_cipher);
	vault_cipher = NULL;
	memzero_explicit(key, sizeof(key));
	memzero_explicit(mac_key, sizeof(mac_key));
	return ret;
}

void vault_crypto_exit(void)
{
	if (vault_mac)
		crypto_free_shash(vault_mac);
	if (vault_cipher)
		crypto_free_skcipher(vault_cipher);
	vault_mac = NULL;
	vault_cipher = NULL;
}

int vault_crypt_page(void *dst, const void *src, u32 page_idx, u64 generation)
{
	struct skcipher_request *req;
	struct scatterlist sg_src, sg_dst;
	DECLARE_CRYPTO_WAIT(wait);
	u8 iv[16] = { 0 };
	int ret;

	req = skcipher_request_alloc(vault_cipher, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	/* IV = page_idx (le32) | generation (le64) | contador de bloque (4 B a 0) */
	put_unaligned_le32(page_idx, iv);
	put_unaligned_le64(generation, iv + 4);

	sg_init_one(&sg_src, src, PAGE_SIZE);
	sg_init_one(&sg_dst, dst, PAGE_SIZE);

	skcipher_request_set_callback(req,
		CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg_src, &sg_dst, PAGE_SIZE, iv);

	ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);

	skcipher_request_free(req);
	memzero_explicit(iv, sizeof(iv));
	return ret;
}

int vault_mac_page(const void *plain, u32 page_idx, u8 *out)
{
	struct shash_desc *desc;
	__le32 idx = cpu_to_le32(page_idx);
	int ret;

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(vault_mac), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	desc->tfm = vault_mac;

	ret = crypto_shash_init(desc);
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)&idx, sizeof(idx));
	if (!ret)
		ret = crypto_shash_update(desc, plain, PAGE_SIZE);
	if (!ret)
		ret = crypto_shash_final(desc, out);

	kfree_sensitive(desc);
	return ret;
}
