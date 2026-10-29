// SPDX-License-Identifier: GPL-2.0
/**
 * test_ro_write.c - Un fd de solo lectura no puede convertirse en escritura:
 *   - mmap(PROT_WRITE, MAP_SHARED) sobre O_RDONLY       -> EACCES (core de mm)
 *   - mprotect(PROT_WRITE) sobre un mapeo PROT_READ      -> EACCES (VM_MAYWRITE limpiado)
 *   - escritura "a la fuerza" via /proc/self/mem          -> falla (FOLL_FORCE respeta VM_MAYWRITE)
 * La tercera es la primitiva que usaba Dirty COW (FOLL_FORCE | FOLL_WRITE).
 */
#include "test_common.h"

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long ps = page_size();
	int fd = open(dev, O_RDONLY);
	char before[24], *p;
	int memfd;
	ssize_t n;

	CHECK(fd >= 0, "UID autorizado abre O_RDONLY");
	if (fd < 0)
		return test_summary("test_ro_write");

	p = vmap(fd, ps, PROT_READ | PROT_WRITE, 0);
	CHECK(p == MAP_FAILED && errno == EACCES, "O_RDONLY + MAP_SHARED + PROT_WRITE -> EACCES (errno=%d)", errno);

	p = vmap(fd, ps, PROT_READ, 0);
	CHECK(p != MAP_FAILED, "O_RDONLY + MAP_SHARED + PROT_READ permitido");
	if (p == MAP_FAILED)
		return test_summary("test_ro_write");

	CHECK(mprotect(p, ps, PROT_READ | PROT_WRITE) == -1 && errno == EACCES,
	      "mprotect(PROT_WRITE) posterior -> EACCES (VM_MAYWRITE limpiado) (errno=%d)", errno);

	memcpy(before, p, sizeof(before));
	memfd = open("/proc/self/mem", O_RDWR);
	if (memfd < 0) {
		printf("[SKIP] /proc/self/mem no disponible (errno=%d)\n", errno);
	} else {
		n = pwrite(memfd, "HACKED", 6, (off_t)(uintptr_t)p);
		CHECK(n < 6, "escritura forzada por /proc/self/mem (FOLL_FORCE) RECHAZADA (n=%zd errno=%d)", n, errno);
		close(memfd);
	}
	CHECK(!memcmp(before, p, sizeof(before)), "el contenido de la boveda quedo INTACTO");

	munmap(p, ps);
	close(fd);
	return test_summary("test_ro_write");
}
