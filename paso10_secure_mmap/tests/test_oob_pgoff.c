// SPDX-License-Identifier: GPL-2.0
/**
 * test_oob_pgoff.c - Limites estrictos (control 5) + aislamiento (control 6).
 * Regresion del bug del Paso 4: valida el TAMANO pero ignora vm_pgoff.
 */
#include "test_common.h"

/* Devuelve 1 si la linea VmFlags del mapeo en @addr contiene el flag de 2 letras @flag */
static int vmflag_present(void *addr, const char *flag)
{
	char line[512];
	unsigned long lo, hi;
	int in_map = 0, found = 0;
	FILE *f = fopen("/proc/self/smaps", "r");

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && strchr(line, '-') && line[0] != 'V')
			in_map = ((unsigned long)addr >= lo && (unsigned long)addr < hi);
		else if (in_map && !strncmp(line, "VmFlags:", 8)) {
			char *tok = strtok(line + 8, " \n");

			while (tok) {
				if (!strcmp(tok, flag))
					found = 1;
				tok = strtok(NULL, " \n");
			}
			break;
		}
	}
	fclose(f);
	return found;
}

static void touch_child(void *arg)
{
	volatile char c = *(volatile char *)arg;

	(void)c;      /* si la VMA no se heredo => SIGSEGV */
}

int main(int argc, char **argv)
{
	const char *dev = dev_path(argc, argv);
	long ps = page_size();
	long long d0 = stat_get("mmap_denied_range");
	int fd = open(dev, O_RDWR);
	char *p;

	CHECK(fd >= 0, "UID autorizado abre el dispositivo");
	if (fd < 0)
		return test_summary("test_oob_pgoff");

	p = vmap(fd, (VAULT_PAGES + 1) * ps, PROT_READ, 0);
	CHECK(p == MAP_FAILED && errno == EINVAL, "5 paginas (> boveda) -> EINVAL (errno=%d)", errno);

	p = vmap(fd, VAULT_PAGES * ps, PROT_READ, ps);
	CHECK(p == MAP_FAILED && errno == EINVAL,
	      "REGRESION Paso 4: offset=1 pagina + longitud completa -> EINVAL (errno=%d)", errno);

	p = vmap(fd, ps, PROT_READ, VAULT_PAGES * ps);
	CHECK(p == MAP_FAILED && errno == EINVAL, "offset = fin exacto de la boveda -> EINVAL (errno=%d)", errno);

	p = vmap(fd, ps, PROT_READ, 1L << 40);
	CHECK(p == MAP_FAILED && (errno == EINVAL || errno == EOVERFLOW),
	      "offset gigante (2^40) -> rechazado (errno=%d)", errno);

	CHECK(stat_get("mmap_denied_range") >= d0 + 3,
	      "auditoria: rangos invalidos contados (%lld -> %lld)", d0, stat_get("mmap_denied_range"));

	/* Un offset valido SI funciona y apunta a la pagina correcta */
	p = vmap(fd, ps, PROT_READ | PROT_WRITE, 3 * ps);
	CHECK(p != MAP_FAILED && !strncmp(p, "SECRETO-VAULT-PAGE-3", 20),
	      "offset valido (pagina 3) entrega el contenido de la pagina 3");

	if (p != MAP_FAILED) {
		/* Aislamiento: flags de la VMA vistos en /proc/self/smaps */
		CHECK(vmflag_present(p, "dc") == 1, "VmFlags contiene 'dc' (VM_DONTCOPY)");
		CHECK(vmflag_present(p, "dd") == 1, "VmFlags contiene 'dd' (VM_DONTDUMP)");
		CHECK(vmflag_present(p, "de") == 1, "VmFlags contiene 'de' (VM_DONTEXPAND)");
		CHECK(vmflag_present(p, "ex") == 0, "VmFlags NO contiene 'ex' (no ejecutable)");
		CHECK(vmflag_present(p, "me") == 0, "VmFlags NO contiene 'me' (VM_MAYEXEC limpiado)");

		/* fork(): el hijo NO hereda el mapeo => SIGSEGV al tocarlo */
		int rc = run_in_child(touch_child, p);

		CHECK(rc == -SIGSEGV, "hijo tras fork() no hereda la boveda: SIGSEGV (rc=%d)", rc);

		/* mremap(): no se puede crecer el mapeo para leer mas alla de lo validado */
		void *q = mremap(p, ps, 2 * ps, MREMAP_MAYMOVE);

		CHECK(q == MAP_FAILED, "mremap() para crecer la VMA falla (VM_DONTEXPAND) (errno=%d)", errno);
		munmap(p, ps);
	}

	close(fd);
	return test_summary("test_oob_pgoff");
}
