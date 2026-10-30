// SPDX-License-Identifier: GPL-2.0
/**
 * test_prot_exec.c - W^X: la boveda nunca puede ser ejecutable (Pregunta 10: bit NX).
 */
#include "test_common.h"

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long ps = page_size();
	long long d0 = stat_get("mmap_denied_exec");
	int fd = open(dev, O_RDWR);
	void *p;

	CHECK(fd >= 0, "UID autorizado abre el dispositivo");
	if (fd < 0)
		return test_summary("test_prot_exec");

	p = mmap(NULL, ps, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
	CHECK(p == MAP_FAILED && errno == EACCES, "mmap(PROT_READ|PROT_EXEC) -> EACCES (errno=%d)", errno);

	p = mmap(NULL, ps, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
	CHECK(p == MAP_FAILED && errno == EACCES, "mmap(RWX) -> EACCES (errno=%d)", errno);

	/* Segundo intento del atacante: mapear legitimamente y luego mprotect(PROT_EXEC) */
	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(p != MAP_FAILED, "mmap(RW) legitimo");
	if (p != MAP_FAILED) {
		int r = mprotect(p, ps, PROT_READ | PROT_EXEC);

		CHECK(r == -1 && errno == EACCES,
		      "mprotect(PROT_EXEC) posterior -> EACCES (VM_MAYEXEC limpiado) (errno=%d)", errno);
		munmap(p, ps);
	}

	CHECK(stat_get("mmap_denied_exec") == d0 + 2,
	      "auditoria: 2 intentos PROT_EXEC contados (%lld -> %lld)", d0, stat_get("mmap_denied_exec"));
	close(fd);
	return test_summary("test_prot_exec");
}
