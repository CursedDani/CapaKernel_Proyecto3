// SPDX-License-Identifier: GPL-2.0
/**
 * test_fd_inherit.c - Segunda linea de defensa: un fd YA ABIERTO (por un autorizado)
 * cae en manos de un proceso sin autorizacion (fork + setuid, equivalente a SCM_RIGHTS).
 * open() ya no se vuelve a ejecutar, por eso .mmap y .ioctl re-verifican la identidad.
 * Debe ejecutarse como root (para poder abrir y luego degradar privilegios).
 */
#include "test_common.h"
#include <grp.h>

static int g_fd;

static void child_fn(void *arg)
{
	long ps = page_size();
	__u32 bad;
	void *p;

	(void)arg;
	if (setgroups(0, NULL) || setgid(65534) || setuid(65534))
		_exit(90);
	if (geteuid() != 65534)
		_exit(91);

	p = mmap(NULL, ps, PROT_READ, MAP_SHARED, g_fd, 0);
	if (p != MAP_FAILED)
		_exit(10);              /* ATAQUE EXITOSO: mapeo concedido */
	if (errno != EPERM)
		_exit(11);

	if (ioctl(g_fd, SECURE_VAULT_IOC_VERIFY, &bad) == 0)
		_exit(12);              /* ioctl concedido */
	if (errno != EPERM)
		_exit(13);
	_exit(0);
}

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long long d0 = stat_get("mmap_denied_uid");
	int rc;

	g_fd = open(dev, O_RDWR);
	CHECK(g_fd >= 0, "el proceso autorizado (root) abre el dispositivo");
	if (g_fd < 0)
		return test_summary("test_fd_inherit");

	rc = run_in_child(child_fn, NULL);
	CHECK(rc == 0, "hijo con fd heredado y UID 65534: mmap -> EPERM e ioctl -> EPERM (rc=%d)", rc);
	CHECK(stat_get("mmap_denied_uid") == d0 + 1,
	      "auditoria: mmap_denied_uid incremento en 1 (%lld -> %lld)", d0, stat_get("mmap_denied_uid"));

	close(g_fd);
	return test_summary("test_fd_inherit");
}
