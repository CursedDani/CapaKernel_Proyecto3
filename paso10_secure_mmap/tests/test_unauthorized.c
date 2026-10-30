// SPDX-License-Identifier: GPL-2.0
/**
 * test_unauthorized.c - Debe ejecutarse como un UID NO autorizado (p. ej. nobody=65534).
 * El nodo /dev/secure_vault es 0666 a proposito: la defensa NO depende de permisos
 * de archivo sino de la politica del kernel.
 */
#include "test_common.h"

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long long d0 = stat_get("open_denied_uid");
	int fd;

	printf("uid efectivo = %d\n", (int)geteuid());
	CHECK(geteuid() != 0, "la prueba corre como usuario SIN privilegios");

	fd = open(dev, O_RDWR);
	CHECK(fd < 0 && errno == EPERM, "open(O_RDWR) por UID no autorizado -> EPERM (errno=%d)", errno);
	if (fd >= 0)
		close(fd);

	fd = open(dev, O_RDONLY);
	CHECK(fd < 0 && errno == EPERM, "open(O_RDONLY) por UID no autorizado -> EPERM (errno=%d)", errno);
	if (fd >= 0)
		close(fd);

	CHECK(stat_get("open_denied_uid") >= d0 + 2,
	      "auditoria: los 2 intentos denegados quedaron contados (%lld -> %lld)",
	      d0, stat_get("open_denied_uid"));
	return test_summary("test_unauthorized");
}
