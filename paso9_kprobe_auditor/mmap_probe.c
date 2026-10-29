// SPDX-License-Identifier: GPL-2.0
/**
 * mmap_probe.c - Genera mmaps "sospechosos" CONTROLADOS (solo sobre un archivo de
 * prueba propio) para demostrar que el auditor global los detecta.
 *
 *   uso: mmap_probe <archivo-de-prueba> [dispositivo]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void attempt(const char *what, void *p)
{
	if (p == MAP_FAILED)
		printf("  %-58s -> fallo (%s)\n", what, strerror(errno));
	else
		printf("  %-58s -> concedido\n", what);
}

int main(int argc, char **argv)
{
	const char *file = argc > 1 ? argv[1] : "/tmp/secret.txt";
	const char *dev = argc > 2 ? argv[2] : NULL;
	long ps = sysconf(_SC_PAGESIZE);
	void *p;
	int fd;

	fd = open(file, O_RDWR | O_CREAT, 0600);
	if (fd < 0 || ftruncate(fd, ps)) {
		perror("archivo de prueba");
		return 1;
	}
	close(fd);

	printf("mmap_probe pid=%d\n", getpid());

	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	attempt("anonimo RW (ruido normal tipo malloc)", p);

	fd = open(file, O_RDONLY);
	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	attempt("archivo sensible O_RDONLY + PROT_WRITE + MAP_SHARED", p);
	close(fd);

	fd = open(file, O_RDWR);
	p = mmap(NULL, ps, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
	attempt("archivo RWX MAP_PRIVATE (W^X violado)", p);
	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	attempt("archivo sensible RW MAP_SHARED (escritura legitima)", p);
	close(fd);

	if (dev) {
		fd = open(dev, O_RDWR);
		if (fd >= 0) {
			p = mmap(NULL, ps, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
			attempt("dispositivo con PROT_EXEC", p);
			close(fd);
		} else {
			printf("  open(%s) -> %s\n", dev, strerror(errno));
		}
	}
	return 0;
}
