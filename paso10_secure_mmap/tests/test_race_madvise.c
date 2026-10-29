// SPDX-License-Identifier: GPL-2.0
/**
 * test_race_madvise.c - Carrera estilo Dirty COW CONTRA NUESTRO PROPIO MODULO (lab/VM).
 *
 * Dirty COW (CVE-2016-5195): un hilo escribe a la fuerza (FOLL_FORCE via /proc/self/mem)
 * sobre un mapeo de solo lectura mientras otro hilo hace madvise(MADV_DONTNEED) para
 * descartar la copia COW privada y que la escritura caiga sobre la pagina compartida.
 *
 * Aqui el mismo patron NO tiene presa porque:
 *   (a) no existe mapeo privado (MAP_PRIVATE denegado) => no hay copia COW que descartar;
 *   (b) VM_MAYWRITE esta limpio en el mapeo RO => FOLL_FORCE no puede forzar la escritura;
 *   (c) MADV_DONTNEED sobre un mapeo compartido solo destruye PTEs; los datos viven en
 *       nuestras paginas y se vuelven a mapear en el siguiente fault.
 * Solo se ataca el dispositivo de prueba; no se toca ningun archivo del sistema.
 */
#include "test_common.h"
#include <pthread.h>

#define RACE_MS 1500

static char *g_ro;       /* mapeo de solo lectura (victima) */
static char *g_rw;       /* mapeo RW legitimo de la pagina 2 */
static long g_ps;
static volatile int g_stop;
static volatile long g_forced_ok;    /* escrituras forzadas que "funcionaron" (debe ser 0) */
static volatile long g_iters;
static char g_orig[32];

static void *th_force_write(void *a)
{
	int memfd = open("/proc/self/mem", O_RDWR);

	(void)a;
	while (!g_stop && memfd >= 0) {
		ssize_t n = pwrite(memfd, "HACKED", 6, (off_t)(uintptr_t)g_ro);

		if (n == 6)
			g_forced_ok++;
		g_iters++;
	}
	if (memfd >= 0)
		close(memfd);
	return NULL;
}

static void *th_madvise(void *a)
{
	(void)a;
	while (!g_stop) {
		madvise(g_ro, g_ps, MADV_DONTNEED);
		madvise(g_rw, g_ps, MADV_DONTNEED);
	}
	return NULL;
}

static void *th_reader(void *a)
{
	(void)a;
	while (!g_stop)
		if (memcmp(g_ro, g_orig, sizeof(g_orig)))
			g_forced_ok += 1000000; /* contenido alterado: fallo grave */
	return NULL;
}

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long long if0 = stat_get("integrity_fail");
	pthread_t t[3];
	char stamp[32];
	__u32 bad = 99;
	int rofd, rwfd;

	g_ps = page_size();
	rofd = open(dev, O_RDONLY);
	rwfd = open(dev, O_RDWR);
	CHECK(rofd >= 0 && rwfd >= 0, "abrir RO y RW (autorizado)");
	if (rofd < 0 || rwfd < 0)
		return test_summary("test_race_madvise");

	g_ro = vmap(rofd, g_ps, PROT_READ, 0);
	g_rw = vmap(rwfd, g_ps, PROT_READ | PROT_WRITE, 2 * g_ps);
	CHECK(g_ro != MAP_FAILED && g_rw != MAP_FAILED, "mapeos RO (pagina 0) y RW (pagina 2)");
	if (g_ro == MAP_FAILED || g_rw == MAP_FAILED)
		return test_summary("test_race_madvise");
	memcpy(g_orig, g_ro, sizeof(g_orig));

	pthread_create(&t[0], NULL, th_force_write, NULL);
	pthread_create(&t[1], NULL, th_madvise, NULL);
	pthread_create(&t[2], NULL, th_reader, NULL);

	/* Mientras tanto, el escritor legitimo sigue operando sobre su pagina */
	{
		struct timespec ts = { 0, 5 * 1000 * 1000 };
		int i;

		for (i = 0; i < RACE_MS / 5; i++) {
			snprintf(stamp, sizeof(stamp), "ITER-%d", i);
			strcpy(g_rw + 200, stamp);
			nanosleep(&ts, NULL);
		}
	}
	g_stop = 1;
	pthread_join(t[0], NULL);
	pthread_join(t[1], NULL);
	pthread_join(t[2], NULL);

	printf("intentos de escritura forzada: %ld\n", g_iters);
	CHECK(g_forced_ok == 0, "NINGUNA escritura forzada tuvo exito durante la carrera (exitos=%ld)", g_forced_ok);
	CHECK(!memcmp(g_ro, g_orig, sizeof(g_orig)), "la pagina victima conserva su contenido original");

	/* El escritor legitimo no pierde datos por los DONTNEED concurrentes */
	snprintf(stamp, sizeof(stamp), "FINAL-OK-%d", (int)getpid());
	strcpy(g_rw + 200, stamp);
	madvise(g_rw, g_ps, MADV_DONTNEED);
	CHECK(!strcmp(g_rw + 200, stamp), "el escritor legitimo conserva su dato tras madvise(DONTNEED)");

	munmap(g_ro, g_ps);
	munmap(g_rw, g_ps);
	CHECK(ioctl(rwfd, SECURE_VAULT_IOC_VERIFY, &bad) == 0 && bad == 0,
	      "VERIFY: 0 paginas con HMAC invalido tras la carrera (bad=%u)", bad);
	CHECK(stat_get("integrity_fail") == if0, "auditoria: sin nuevos fallos de integridad");

	close(rofd);
	close(rwfd);
	return test_summary("test_race_madvise");
}
