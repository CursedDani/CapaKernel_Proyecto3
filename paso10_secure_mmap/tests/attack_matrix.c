// SPDX-License-Identifier: GPL-2.0
/**
 * attack_matrix.c - Matriz de ataques ANTES/DESPUES. Se ejecuta contra CUALQUIER
 * dispositivo mmap (p. ej. /dev/demo_mmap del Paso 4 y /dev/secure_vault del Paso 10)
 * y reporta, por ataque, si el kernel lo PERMITIO o lo BLOQUEO.
 *
 *   uso: attack_matrix <dispositivo>
 *
 * Salida parseable:   ATAQUE <id> | <descripcion> | PERMITIDO|BLOQUEADO(<errno>)
 * No requiere privilegios: son los intentos de un proceso comun y hostil.
 * Solo se ataca el dispositivo indicado (laboratorio/VM).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* @why: motivo del bloqueo (texto libre); si es NULL se usa strerror(err) */
static void report_why(const char *id, const char *desc, int allowed, int err, const char *why)
{
	if (allowed)
		printf("ATAQUE %s | %-62s | PERMITIDO\n", id, desc);
	else
		printf("ATAQUE %s | %-62s | BLOQUEADO(%s)\n", id, desc, why ? why : strerror(err));
	fflush(stdout);
}

static void report(const char *id, const char *desc, int allowed, int err)
{
	report_why(id, desc, allowed, err, NULL);
}

/* Proceso hijo: intenta leer la direccion heredada; devuelve 1 si pudo */
static int child_can_read(volatile char *addr)
{
	int st;
	pid_t pid = fork();

	if (pid == 0) {
		volatile char c = *addr;

		(void)c;
		_exit(0);
	}
	waitpid(pid, &st, 0);
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

int main(int argc, char **argv)
{
	const char *dev = argc > 1 ? argv[1] : "/dev/secure_vault";
	long ps = sysconf(_SC_PAGESIZE);
	char *p, *q;
	int fd, rfd;

	printf("# attack_matrix contra %s (uid=%d)\n", dev, (int)geteuid());

	/* A1: acceso por un UID cualquiera */
	fd = open(dev, O_RDWR);
	report("A1", "open(O_RDWR) por este UID (BLOQUEADO solo si NO esta autorizado)", fd >= 0, errno);
	if (fd < 0) {
		printf("# el kernel bloqueo en open(); los demas ataques requieren un fd => no ejecutables como este UID\n");
		return 0;
	}

	/* A2: PROT_EXEC sobre la region de datos */
	p = mmap(NULL, ps, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
	report("A2", "mmap(PROT_READ|PROT_EXEC): region de datos ejecutable", p != MAP_FAILED, errno);
	if (p != MAP_FAILED)
		munmap(p, ps);

	/* A3: mprotect(PROT_EXEC) tras un mapeo legitimo */
	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		report("A3", "mprotect(PROT_EXEC) tras mapear RW (mapeo RW no concedido)", 0, errno);
	} else {
		int r = mprotect(p, ps, PROT_READ | PROT_EXEC);

		report("A3", "mprotect(PROT_EXEC) tras mapear RW", r == 0, errno);
		munmap(p, ps);
	}

	/* A4: MAP_PRIVATE + PROT_WRITE (vector COW) */
	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	report("A4", "mmap(MAP_PRIVATE|PROT_WRITE): vector COW / Dirty COW", p != MAP_FAILED, errno);
	if (p != MAP_FAILED)
		munmap(p, ps);

	/* A5: el offset solicitado se ignora (ver si pgoff=1 devuelve otra pagina) */
	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	q = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ps);
	if (p == MAP_FAILED || q == MAP_FAILED) {
		report("A5", "offset de mmap respetado (pgoff=1 apunta a otra pagina)", 0, errno);
		printf("#   (mmap con offset rechazado o sin escritura: no se pudo evaluar aliasing)\n");
	} else {
		char saved = p[0];

		p[0] = (char)(saved ^ 0x5a);
		/* Si q[0] cambio, "offset 1 pagina" apunta a la MISMA pagina => offset ignorado */
		report_why("A5", "BUG pgoff: mmap(offset=1 pagina) es alias de la pagina 0",
			   q[0] == p[0], 0, "offset respetado: son paginas distintas");
		p[0] = saved;
	}
	if (p != MAP_FAILED)
		munmap(p, ps);
	if (q != MAP_FAILED)
		munmap(q, ps);

	/* A6: offset muy por encima del tamano del dispositivo (1 MiB): debe rechazarse */
	p = mmap(NULL, ps, PROT_READ, MAP_SHARED, fd, 1 << 20);
	report("A6", "mmap(offset=1 MiB) mas alla del final del dispositivo", p != MAP_FAILED, errno);
	if (p != MAP_FAILED)
		munmap(p, ps);

	/* A9: longitud mayor que cualquier buffer del dispositivo (1 MiB) */
	p = mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, fd, 0);
	report("A9", "mmap(longitud=1 MiB) mayor que el buffer del dispositivo", p != MAP_FAILED, errno);
	if (p != MAP_FAILED)
		munmap(p, 1 << 20);

	/* A7: fuga a procesos hijos por fork() */
	p = mmap(NULL, ps, PROT_READ, MAP_SHARED, fd, 0);
	if (p != MAP_FAILED) {
		(void)p[0];
		report_why("A7", "fork(): el hijo hereda y puede leer la region protegida",
			   child_can_read(p), 0, "el hijo recibe SIGSEGV (VM_DONTCOPY)");
		munmap(p, ps);
	}

	/* A8: escritura forzada FOLL_FORCE via /proc/self/mem sobre mapeo de solo lectura */
	rfd = open(dev, O_RDONLY);
	if (rfd >= 0) {
		p = mmap(NULL, ps, PROT_READ, MAP_SHARED, rfd, 0);
		if (p != MAP_FAILED) {
			int mem = open("/proc/self/mem", O_RDWR);
			char before = p[0];
			ssize_t n = mem >= 0 ? pwrite(mem, "Z", 1, (off_t)(unsigned long)p) : -1;

			report_why("A8", "escritura forzada (FOLL_FORCE) en mapeo de solo lectura",
				   n == 1 && p[0] == 'Z', 0, "pwrite(/proc/self/mem) falla");
			(void)before;
			if (mem >= 0)
				close(mem);
			munmap(p, ps);
		}
		close(rfd);
	}

	close(fd);
	return 0;
}
