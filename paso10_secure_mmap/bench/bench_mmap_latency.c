// SPDX-License-Identifier: GPL-2.0
/**
 * bench_mmap_latency.c - Mide el OVERHEAD de la boveda frente a un driver mmap sin
 * proteccion (Paso 4: remap_pfn_range), con N corridas y media +- desviacion estandar.
 *
 *   uso: bench_mmap_latency <dispositivo> [iteraciones=2000] [corridas=30]
 *
 * Metricas (todas en ns salvo indicacion):
 *   mmap_ns     latencia de la syscall mmap() de 4 paginas (alta de la VMA)
 *   touch_ns    tiempo de tocar por primera vez las 4 paginas (page faults)
 *   fault_ns    touch_ns / 4  (costo por page fault)
 *   munmap_ns   latencia de munmap() (incluye vm_ops->close: HMAC + commit en la boveda)
 *   total_ns    mmap + touch + munmap  (costo completo de usar un mapeo nuevo)
 *   session_ns  open + mmap + touch + munmap + close con un fd NUEVO cada vez: aqui la
 *               boveda paga el descifrado + HMAC de cada pagina (sesion privada por open)
 *   access_ns  costo por acceso en regimen estacionario (PTE ya instalada): sin syscalls
 *   minflt      fallos menores de pagina por iteracion (getrusage)
 *
 * Salida: lineas "METRIC <nombre> mean=<..> sd=<..> min=<..> max=<..>" (parseables).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define NPAGES 4
#define ACCESS_LOOPS (1 << 22)

enum { M_MMAP, M_TOUCH, M_FAULT, M_MUNMAP, M_TOTAL, M_FULL, M_ACCESS, M_MINFLT, M_COUNT };
static const char *names[M_COUNT] = { "mmap_ns", "touch_ns", "fault_ns", "munmap_ns",
				      "total_ns", "session_ns", "access_ns", "minflt" };

static inline long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static long minflt(void)
{
	struct rusage ru;

	getrusage(RUSAGE_SELF, &ru);
	return ru.ru_minflt;
}

int main(int argc, char **argv)
{
	const char *dev = argc > 1 ? argv[1] : "/dev/secure_vault";
	int iters = argc > 2 ? atoi(argv[2]) : 2000;
	int runs = argc > 3 ? atoi(argv[3]) : 30;
	long ps = sysconf(_SC_PAGESIZE);
	size_t len = NPAGES * ps;
	double *samples[M_COUNT];
	int r, i, m, fd;

	for (m = 0; m < M_COUNT; m++)
		samples[m] = calloc(runs, sizeof(double));

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "no se pudo abrir %s: %s\n", dev, strerror(errno));
		return 1;
	}

	for (r = 0; r < runs; r++) {
		double s_mmap = 0, s_touch = 0, s_munmap = 0;
		long f0 = minflt();

		for (i = 0; i < iters; i++) {
			long long t0, t1, t2, t3;
			volatile char *p;
			int pg;

			t0 = now_ns();
			p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			t1 = now_ns();
			if (p == MAP_FAILED) {
				fprintf(stderr, "mmap fallo: %s\n", strerror(errno));
				return 1;
			}
			for (pg = 0; pg < NPAGES; pg++)
				(void)p[pg * ps];
			t2 = now_ns();
			munmap((void *)p, len);
			t3 = now_ns();

			s_mmap += t1 - t0;
			s_touch += t2 - t1;
			s_munmap += t3 - t2;
		}
		samples[M_MMAP][r] = s_mmap / iters;
		samples[M_TOUCH][r] = s_touch / iters;
		samples[M_FAULT][r] = s_touch / iters / NPAGES;
		samples[M_MUNMAP][r] = s_munmap / iters;
		samples[M_TOTAL][r] = (s_mmap + s_touch + s_munmap) / iters;
		samples[M_MINFLT][r] = (double)(minflt() - f0) / iters;

		/* Ciclo completo con un fd nuevo por iteracion (sesion nueva => descifra de cero) */
		{
			int n = iters / 4 > 0 ? iters / 4 : 1;
			long long t0 = now_ns();

			for (i = 0; i < n; i++) {
				int sfd = open(dev, O_RDWR);
				volatile char *p;
				int pg;

				if (sfd < 0)
					return 1;
				p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0);
				if (p == MAP_FAILED)
					return 1;
				for (pg = 0; pg < NPAGES; pg++)
					(void)p[pg * ps];
				munmap((void *)p, len);
				close(sfd);
			}
			samples[M_FULL][r] = (double)(now_ns() - t0) / n;
		}

		/* Regimen estacionario: PTE ya instaladas => acceso a velocidad de hardware */
		{
			volatile char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			long long t0, t1;
			unsigned long acc = 0;
			int k;

			for (k = 0; k < NPAGES; k++)
				acc += p[k * ps];
			t0 = now_ns();
			for (k = 0; k < ACCESS_LOOPS; k++)
				acc += p[(k * 64) & (len - 1)];
			t1 = now_ns();
			samples[M_ACCESS][r] = (double)(t1 - t0) / ACCESS_LOOPS + (acc == 1 ? 1e-12 : 0);
			munmap((void *)p, len);
		}
	}

	printf("# dispositivo=%s iteraciones=%d corridas=%d\n", dev, iters, runs);
	for (m = 0; m < M_COUNT; m++) {
		double sum = 0, sq = 0, mn = samples[m][0], mx = samples[m][0];

		for (r = 0; r < runs; r++) {
			sum += samples[m][r];
			if (samples[m][r] < mn)
				mn = samples[m][r];
			if (samples[m][r] > mx)
				mx = samples[m][r];
		}
		sum /= runs;
		for (r = 0; r < runs; r++)
			sq += (samples[m][r] - sum) * (samples[m][r] - sum);
		printf("METRIC %-10s mean=%.2f sd=%.2f min=%.2f max=%.2f\n",
		       names[m], sum, runs > 1 ? sqrt(sq / (runs - 1)) : 0.0, mn, mx);
	}
	close(fd);
	return 0;
}
