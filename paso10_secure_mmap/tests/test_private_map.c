// SPDX-License-Identifier: GPL-2.0
/**
 * test_private_map.c - MAP_PRIVATE y la Pregunta 8 (O_RDONLY + PROT_WRITE + MAP_PRIVATE).
 *
 * Parte A (experimento de control): en un archivo normal el kernel SI lo permite,
 *   porque la escritura va a una copia COW anonima y nunca toca el archivo.
 * Parte B: la boveda lo PROHIBE (elimina el vector COW / Dirty COW por completo).
 */
#include "test_common.h"

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long ps = page_size();
	long long d0 = stat_get("mmap_denied_private");
	char tmpl[] = "/tmp/vault_ctl_XXXXXX";
	char *p;
	int fd, tfd;

	/* ---- Parte A: archivo normal ---- */
	tfd = mkstemp(tmpl);
	if (tfd >= 0) {
		char buf[16] = "ORIGINAL";

		if (write(tfd, buf, sizeof(buf)) != (ssize_t)sizeof(buf))
			perror("write");
		close(tfd);
		tfd = open(tmpl, O_RDONLY);
		p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE, tfd, 0);
		CHECK(p != MAP_FAILED,
		      "[control] archivo normal O_RDONLY + PROT_WRITE + MAP_PRIVATE: el kernel lo PERMITE (Q8)");
		if (p != MAP_FAILED) {
			char chk[16] = { 0 };
			int rfd;

			memcpy(p, "MODIFICADO", 10);   /* COW: escribe en una copia anonima privada */
			rfd = open(tmpl, O_RDONLY);
			if (read(rfd, chk, sizeof(chk)) < 0)
				perror("read");
			close(rfd);
			CHECK(!strcmp(chk, "ORIGINAL"),
			      "[control] la escritura privada NO llega al archivo (COW), archivo intacto");
			munmap(p, ps);
		}
		close(tfd);
		unlink(tmpl);
	}

	/* ---- Parte B: la boveda ---- */
	fd = open(dev, O_RDONLY);
	CHECK(fd >= 0, "abrir la boveda O_RDONLY (autorizado)");
	if (fd >= 0) {
		p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		CHECK(p == MAP_FAILED && errno == EACCES,
		      "boveda: O_RDONLY + PROT_WRITE + MAP_PRIVATE -> EACCES (errno=%d)", errno);
		close(fd);
	}

	fd = open(dev, O_RDWR);
	if (fd >= 0) {
		p = mmap(NULL, ps, PROT_READ, MAP_PRIVATE, fd, 0);
		CHECK(p == MAP_FAILED && errno == EACCES,
		      "boveda: incluso MAP_PRIVATE de solo lectura -> EACCES (errno=%d)", errno);
		close(fd);
	}

	CHECK(stat_get("mmap_denied_private") == d0 + 2,
	      "auditoria: 2 intentos MAP_PRIVATE contados (%lld -> %lld)", d0, stat_get("mmap_denied_private"));
	return test_summary("test_private_map");
}
