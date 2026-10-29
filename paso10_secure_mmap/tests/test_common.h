/* SPDX-License-Identifier: GPL-2.0 */
/**
 * @file test_common.h
 * @brief Utilidades comunes de las pruebas de ataque/defensa de /dev/secure_vault.
 *
 * Convencion de salida (la parsean run_tests.sh y el harness de la VM):
 *     [PASS] descripcion
 *     [FAIL] descripcion (detalle)
 * El proceso termina con exit(0) solo si TODAS las comprobaciones pasaron.
 */
#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../secure_vault_uapi.h"

#define VAULT_PAGES 4
#define DEFAULT_DEV "/dev/secure_vault"

static int g_fail;
static int g_pass;

#define CHECK(cond, ...) do {                                         \
	if (cond) { g_pass++; printf("[PASS] "); printf(__VA_ARGS__); printf("\n"); } \
	else      { g_fail++; printf("[FAIL] "); printf(__VA_ARGS__); printf("\n"); } \
	fflush(stdout);                                                   \
} while (0)

static inline const char *dev_path(int argc, char **argv)
{
	return argc > 1 ? argv[1] : DEFAULT_DEV;
}

static inline long page_size(void)
{
	return sysconf(_SC_PAGESIZE);
}

/* Lee un contador de /proc/secure_vault/stats; -1 si no existe */
static inline long long stat_get(const char *key)
{
	char line[128];
	size_t klen = strlen(key);
	long long val = -1;
	FILE *f = fopen("/proc/secure_vault/stats", "r");

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, key, klen) && line[klen] == '=') {
			val = atoll(line + klen + 1);
			break;
		}
	}
	fclose(f);
	return val;
}

/* mmap compartido sobre el dispositivo; devuelve MAP_FAILED y deja errno */
static inline void *vmap(int fd, size_t len, int prot, off_t off)
{
	return mmap(NULL, len, prot, MAP_SHARED, fd, off);
}

/*
 * Ejecuta fn() en un hijo y devuelve como termino:
 *   >=0 : exit status ; -SIGnnn : muerto por esa senal
 */
static inline int run_in_child(void (*fn)(void *), void *arg)
{
	int st;
	pid_t pid = fork();

	if (pid == 0) {
		fn(arg);
		_exit(0);
	}
	waitpid(pid, &st, 0);
	if (WIFSIGNALED(st))
		return -WTERMSIG(st);
	return WEXITSTATUS(st);
}

static inline int test_summary(const char *name)
{
	printf("== %s: %d PASS, %d FAIL ==\n", name, g_pass, g_fail);
	return g_fail ? 1 : 0;
}

#endif /* TEST_COMMON_H */
