// SPDX-License-Identifier: GPL-2.0
/**
 * test_tamper.c - Deteccion de manipulacion (control 9). Requiere CAP_SYS_ADMIN.
 * Simula que un atacante con acceso a la RAM invierte UN bit del cifrado de la pagina 2.
 * AES-CTR es maleable (el bit cambia identico en el texto plano) => solo el HMAC lo
 * detecta. Debe ejecutarse la ULTIMA: la manipulacion es persistente hasta descargar el modulo.
 */
#include "test_common.h"

/* El hijo abre y mapea por su cuenta (VM_DONTCOPY: no hereda el mapeo del padre) */
static void touch_page2(void *arg)
{
	int fd = open((const char *)arg, O_RDONLY);
	volatile char *p;
	volatile char c;

	if (fd < 0)
		_exit(90);
	p = vmap(fd, page_size(), PROT_READ, 2 * page_size());
	if (p == MAP_FAILED)
		_exit(91);
	c = p[0];
	(void)c;    /* el fault debe fallar con SIGBUS */
}

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long ps = page_size();
	long long if0 = stat_get("integrity_fail");
	int fd = open(dev, O_RDWR);
	__u32 bad = 99, page = 2;
	char *p;
	int rc;

	CHECK(fd >= 0, "root abre el dispositivo");
	if (fd < 0)
		return test_summary("test_tamper");

	CHECK(ioctl(fd, SECURE_VAULT_IOC_VERIFY, &bad) == 0 && bad == 0,
	      "antes del ataque: VERIFY reporta 0 paginas corruptas (bad=%u)", bad);

	CHECK(ioctl(fd, SECURE_VAULT_IOC_TAMPER, &page) == 0, "ataque: 1 bit del cifrado de la pagina 2 invertido");

	CHECK(ioctl(fd, SECURE_VAULT_IOC_VERIFY, &bad) == 0 && bad == 1,
	      "despues del ataque: VERIFY detecta exactamente 1 pagina corrupta (bad=%u)", bad);

	p = vmap(fd, VAULT_PAGES * ps, PROT_READ, 0);
	CHECK(p != MAP_FAILED, "mapeo de la boveda completa");
	if (p != MAP_FAILED) {
		CHECK(!strncmp(p + ps, "SECRETO-VAULT-PAGE-1", 20), "las paginas sanas siguen sirviendose (pagina 1)");

		rc = run_in_child(touch_page2, (void *)dev);
		CHECK(rc == -SIGBUS, "leer la pagina manipulada produce SIGBUS, NO datos corruptos (rc=%d)", rc);
		munmap(p, VAULT_PAGES * ps);
	}

	CHECK(stat_get("integrity_fail") >= if0 + 2,
	      "auditoria: fallos de integridad contados (%lld -> %lld)", if0, stat_get("integrity_fail"));
	close(fd);
	return test_summary("test_tamper");
}
