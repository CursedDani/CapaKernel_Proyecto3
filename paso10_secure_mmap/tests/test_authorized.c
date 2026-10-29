// SPDX-License-Identifier: GPL-2.0
/**
 * test_authorized.c - CASO FELIZ: un UID autorizado usa la boveda legitimamente.
 *
 * Demuestra: descifrado transparente bajo demanda, respeto del offset (pgoff),
 * deteccion de la primera escritura (page_mkwrite empirico) y persistencia cifrada.
 */
#include "test_common.h"

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long ps = page_size();
	char marker[64];
	long long mk0, cm0, dc0, fr0, fw0;
	int fd;
	char *p;

	snprintf(marker, sizeof(marker), "ESCRITURA-AUTORIZADA-%d", (int)getpid());

	mk0 = stat_get("mkwrite"); cm0 = stat_get("commits");
	dc0 = stat_get("decrypts"); fr0 = stat_get("fault_read"); fw0 = stat_get("fault_write");

	fd = open(dev, O_RDWR);
	CHECK(fd >= 0, "UID autorizado puede abrir %s en RW (errno=%d)", dev, fd < 0 ? errno : 0);
	if (fd < 0)
		return test_summary("test_authorized");

	p = vmap(fd, VAULT_PAGES * ps, PROT_READ | PROT_WRITE, 0);
	CHECK(p != MAP_FAILED, "mmap(MAP_SHARED, PROT_READ|PROT_WRITE) de 4 paginas permitido");
	if (p == MAP_FAILED)
		return test_summary("test_authorized");

	/* Lectura: el fault descifra bajo demanda; el contenido debe ser el texto plano sembrado */
	CHECK(!strncmp(p, "SECRETO-VAULT-PAGE-0", 20), "lectura de pagina 0 = texto plano descifrado");
	CHECK(!strncmp(p + 3 * ps, "SECRETO-VAULT-PAGE-3", 20), "lectura de pagina 3 = texto plano descifrado");

	/* Escritura legitima (primero se lee, luego se escribe => PTE solo-lectura => page_mkwrite) */
	strcpy(p + ps + 100, marker);
	CHECK(!strcmp(p + ps + 100, marker), "escritura autorizada visible en el mapeo");

	CHECK(stat_get("fault_read") + stat_get("fault_write") >= fr0 + fw0 + 2,
	      "auditoria: los page faults quedaron contados");
	CHECK(stat_get("decrypts") >= dc0 + 2, "auditoria: se descifraron paginas bajo demanda");
	CHECK(stat_get("mkwrite") >= mk0 + 1,
	      "page_mkwrite SE INVOCA en este tipo de mapeo (mkwrite %lld -> %lld)",
	      mk0, stat_get("mkwrite"));

	munmap(p, VAULT_PAGES * ps);
	close(fd);

	CHECK(stat_get("commits") >= cm0 + 1, "la escritura autorizada se re-cifro y persistio (commits)");

	/* Persistencia: reabrir en SOLO LECTURA y leer el marcador descifrado */
	fd = open(dev, O_RDONLY);
	p = vmap(fd, ps, PROT_READ, ps); /* offset = pagina 1 */
	CHECK(p != MAP_FAILED, "reabrir O_RDONLY + mmap(PROT_READ) con offset de 1 pagina");
	if (p != MAP_FAILED) {
		CHECK(!strncmp(p, "SECRETO-VAULT-PAGE-1", 20),
		      "el offset del mmap se RESPETA (se obtuvo la pagina 1, no la 0)");
		CHECK(!strcmp(p + 100, marker), "el dato escrito persiste cifrado y se descifra al releer");
		munmap(p, ps);
	}
	close(fd);

	return test_summary("test_authorized");
}
