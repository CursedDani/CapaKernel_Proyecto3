// SPDX-License-Identifier: GPL-2.0
/**
 * test_crypto_rest.c - Cifrado en reposo (control 8). Requiere CAP_SYS_ADMIN (ioctl PEEK).
 * Demuestra que el respaldo en RAM NO contiene el texto plano, pero un mapeo autorizado
 * lo ve descifrado.
 */
#include "test_common.h"

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long ps = page_size();
	struct secure_vault_peek pk = { .page = 0 };
	int fd = open(dev, O_RDONLY);
	char *p;
	unsigned int i, distinct = 0, seen[256] = { 0 };

	CHECK(fd >= 0, "root abre el dispositivo");
	if (fd < 0)
		return test_summary("test_crypto_rest");

	CHECK(ioctl(fd, SECURE_VAULT_IOC_PEEK, &pk) == 0, "ioctl PEEK (CAP_SYS_ADMIN) lee el cifrado en reposo");

	printf("cifrado en reposo (pagina 0, 32 B): ");
	for (i = 0; i < sizeof(pk.data); i++)
		printf("%02x", pk.data[i]);
	printf("\n");

	CHECK(memcmp(pk.data, "SECRETO-VAULT-PAGE-0", 20) != 0, "el respaldo en RAM NO empieza con el texto plano");
	CHECK(!memmem(pk.data, sizeof(pk.data), "SECRETO", 7), "la cadena 'SECRETO' NO aparece en el respaldo cifrado");

	for (i = 0; i < sizeof(pk.data); i++)
		if (!seen[pk.data[i]]++)
			distinct++;
	CHECK(distinct >= 16, "el cifrado parece aleatorio: %u valores de byte distintos de 32", distinct);

	p = vmap(fd, ps, PROT_READ, 0);
	CHECK(p != MAP_FAILED && !strncmp(p, "SECRETO-VAULT-PAGE-0", 20),
	      "un mapeo autorizado SI ve el texto plano (descifrado en el fault)");
	if (p != MAP_FAILED)
		munmap(p, ps);

	close(fd);
	return test_summary("test_crypto_rest");
}
