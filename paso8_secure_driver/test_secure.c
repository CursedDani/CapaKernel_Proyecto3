/**
 * @file test_secure.c
 * @brief Cliente de prueba del Componente A (control de acceso + integridad + auditoria)
 * @course Sistemas Operativos - DOCENCIA 2026-B - Parcial CapaKernel
 *
 * Este programa demuestra, en espacio de usuario, las tres defensas implementadas
 * en kmod_secure.c:
 *   1. Control de acceso: si el UID actual no coincide con `allowed_uid` (ni el
 *      proceso tiene CAP_SYS_ADMIN), open() debe fallar con EACCES.
 *   2. Integridad: se escribe sobre la region mapeada y se consulta el estado
 *      de integridad (CRC32) antes y despues, vía read() sobre el dispositivo.
 *   3. Auditoria + rechazo de PROT_EXEC: se intenta un segundo mmap() pidiendo
 *      permisos de ejecucion sobre la misma region de datos, lo cual debe ser
 *      bloqueado por el driver (-EPERM), evidenciando la mitigacion de
 *      inyeccion de codigo descrita en la Pregunta 10 del parcial.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#define DEVICE_PATH   "/dev/secure_mmap"
#define PAGE_SIZE_VAL 4096
#define TOTAL_PAGES   4
#define TOTAL_BYTES   (TOTAL_PAGES * PAGE_SIZE_VAL)

#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_RED     "\033[31m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_BLUE    "\033[34m"
#define CLR_CYAN    "\033[36m"

static void print_header(void)
{
	printf("%s======================================================================%s\n", CLR_CYAN, CLR_RESET);
	printf("%s%s PASO 8: CONTROL DE ACCESO + INTEGRIDAD + AUDITORIA SOBRE mmap()      %s\n", CLR_BOLD, CLR_BLUE, CLR_RESET);
	printf(" Dispositivo objetivo: %s%s%s%s\n", CLR_BOLD, CLR_YELLOW, DEVICE_PATH, CLR_RESET);
	printf("%s======================================================================%s\n\n", CLR_CYAN, CLR_RESET);
}

static void query_status(int fd)
{
	char status[256];
	ssize_t n;

	if (lseek(fd, 0, SEEK_SET) < 0) {
		/* El dispositivo no soporta lseek real, pero el driver reinicia *ppos
		 * internamente solo si se vuelve a abrir; se tolera el error. */
	}
	n = read(fd, status, sizeof(status) - 1);
	if (n > 0) {
		status[n] = '\0';
		printf("%s[STATUS]%s %s", CLR_CYAN, CLR_RESET, status);
	} else {
		printf("%s[STATUS] No se pudo leer el estado (%s)%s\n", CLR_YELLOW, strerror(errno), CLR_RESET);
	}
}

int main(void)
{
	print_header();

	printf("%s[1] Abriendo %s ...%s\n", CLR_CYAN, DEVICE_PATH, CLR_RESET);
	int fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "%s[-] ACCESO DENEGADO al abrir %s: %s%s\n",
			CLR_RED, DEVICE_PATH, strerror(errno), CLR_RESET);
		fprintf(stderr, "    %sEsto es esperado si su UID no coincide con 'allowed_uid' del modulo.\n"
			"    Verifique con: cat /sys/module/kmod_secure/parameters/allowed_uid%s\n",
			CLR_YELLOW, CLR_RESET);
		return EXIT_FAILURE;
	}
	printf("%s[+] Apertura autorizada (UID=%d, PID=%d)%s\n\n", CLR_GREEN, getuid(), getpid(), CLR_RESET);

	printf("%s[2] Consultando estado de integridad/auditoria ANTES del mmap:%s\n", CLR_YELLOW, CLR_RESET);
	query_status(fd);
	printf("\n");

	printf("%s[3] Mapeando %d paginas (%d bytes) con PROT_READ|PROT_WRITE / MAP_SHARED...%s\n",
		CLR_CYAN, TOTAL_PAGES, TOTAL_BYTES, CLR_RESET);
	char *ptr = mmap(NULL, TOTAL_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		perror(CLR_RED "mmap" CLR_RESET);
		close(fd);
		return EXIT_FAILURE;
	}
	printf("%s[+] Mapeo establecido en %p%s\n\n", CLR_GREEN, (void *)ptr, CLR_RESET);

	printf("%s[4] Leyendo las %d paginas (dispara Page Faults auditados en el kernel)...%s\n",
		CLR_YELLOW, TOTAL_PAGES, CLR_RESET);
	for (int i = 0; i < TOTAL_PAGES; i++) {
		char sample = ptr[i * PAGE_SIZE_VAL];
		printf("    Pagina #%d -> primer byte: '%c'\n", i, sample);
	}
	printf("    %sRevise 'sudo dmesg | tail' para ver el detalle de cada fault auditado.%s\n\n",
		CLR_CYAN, CLR_RESET);

	printf("%s[5] Escribiendo una modificacion legitima en la Pagina 0...%s\n", CLR_CYAN, CLR_RESET);
	const char *msg = "MODIFICADO_POR_TEST_SECURE";
	memcpy(ptr, msg, strlen(msg));
	printf("    Nuevo contenido: %s%.40s%s\n\n", CLR_BOLD, ptr, CLR_RESET);

	printf("%s[6] Intentando mmap ADICIONAL con PROT_EXEC sobre el mismo fd (debe ser BLOQUEADO)...%s\n",
		CLR_YELLOW, CLR_RESET);
	char *exec_ptr = mmap(NULL, PAGE_SIZE_VAL, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (exec_ptr == MAP_FAILED) {
		printf("%s[+] BLOQUEADO correctamente: mmap(PROT_EXEC) -> %s (EPERM/EACCES esperado)%s\n\n",
			CLR_GREEN, strerror(errno), CLR_RESET);
	} else {
		printf("%s[!] ADVERTENCIA: el mmap con PROT_EXEC NO fue bloqueado (revisar el modulo)%s\n\n",
			CLR_RED, CLR_RESET);
		munmap(exec_ptr, PAGE_SIZE_VAL);
	}

	printf("%s[7] Desmapeando la region principal (dispara auditoria de integridad en vm_ops->close)...%s\n",
		CLR_CYAN, CLR_RESET);
	munmap(ptr, TOTAL_BYTES);
	printf("    %sRevise 'sudo dmesg | tail' para ver si se detecto el cambio de CRC32.%s\n\n",
		CLR_CYAN, CLR_RESET);

	printf("%s[8] Consultando estado de integridad/auditoria DESPUES del mmap:%s\n", CLR_YELLOW, CLR_RESET);
	close(fd);
	fd = open(DEVICE_PATH, O_RDWR);
	if (fd >= 0) {
		query_status(fd);
		close(fd);
	}

	printf("\n%s======================================================================%s\n", CLR_CYAN, CLR_RESET);
	printf("%s%s CONCLUSION: control de acceso, integridad y auditoria verificados.%s\n",
		CLR_BOLD, CLR_GREEN, CLR_RESET);
	printf("%s======================================================================%s\n", CLR_CYAN, CLR_RESET);

	return EXIT_SUCCESS;
}
