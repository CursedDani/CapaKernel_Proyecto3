// SPDX-License-Identifier: GPL-2.0
/**
 * init.c - PID 1 minimo para la VM de pruebas (QEMU/KVM). Sin shell, sin busybox.
 *
 * Lee /plan.txt y ejecuta, linea a linea:
 *   echo <texto>                    imprime texto
 *   insmod <ruta.ko> [params...]    carga un modulo (finit_module)
 *   rmmod <nombre>                  descarga un modulo (delete_module)
 *   chmod <modo-octal> <ruta>       cambia permisos (p. ej. 666 /dev/secure_vault)
 *   run <uid> <gid> <prog> [args]   ejecuta un programa como ese UID/GID (alarm 120 s)
 *   cat <ruta>                      vuelca un archivo
 *   write <ruta> <texto...>         escribe texto (tracefs, sysfs, ...)
 *   mount <tipo> <destino>          monta un sistema de archivos (p. ej. tracefs /sys/kernel/tracing)
 *   dmesg [filtro]                  imprime el log del kernel (solo lineas que contengan filtro)
 *   sleep <segundos>
 * Al terminar apaga la maquina. Las lineas que empiezan con '#' se ignoran.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXARG 32

static void do_insmod(char **a, int n)
{
	char params[512] = "";
	int i, fd;

	for (i = 2; i < n; i++) {
		strncat(params, a[i], sizeof(params) - strlen(params) - 2);
		strncat(params, " ", sizeof(params) - strlen(params) - 1);
	}
	fd = open(a[1], O_RDONLY);
	if (fd < 0) {
		printf("[init] insmod: no se pudo abrir %s: %s\n", a[1], strerror(errno));
		return;
	}
	if (syscall(SYS_finit_module, fd, params, 0))
		printf("[init] insmod %s FALLO: %s\n", a[1], strerror(errno));
	else
		printf("[init] insmod %s OK (%s)\n", a[1], params);
	close(fd);
}

static void do_run(char **a, int n)
{
	int st;
	pid_t pid;

	if (n < 4)
		return;
	pid = fork();
	if (pid == 0) {
		uid_t uid = atoi(a[1]);
		gid_t gid = atoi(a[2]);

		alarm(120);
		if (uid != 0) {
			setgroups(0, NULL);
			if (setgid(gid) || setuid(uid)) {
				printf("[init] no se pudo cambiar a uid=%u\n", uid);
				_exit(127);
			}
		}
		a[n] = NULL;
		execv(a[3], &a[3]);
		printf("[init] execv %s fallo: %s\n", a[3], strerror(errno));
		_exit(127);
	}
	waitpid(pid, &st, 0);
	if (WIFSIGNALED(st))
		printf("[init] %s uid=%s -> MUERTO por senal %d\n", a[3], a[1], WTERMSIG(st));
	else
		printf("[init] %s uid=%s -> exit=%d\n", a[3], a[1], WEXITSTATUS(st));
	fflush(stdout);
}

static void do_cat(const char *path)
{
	char buf[4096];
	ssize_t r;
	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		printf("[init] cat %s: %s\n", path, strerror(errno));
		return;
	}
	while ((r = read(fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, r, stdout);
	close(fd);
}

static void do_dmesg(const char *filter)
{
	static char buf[1 << 20];
	int n = klogctl(3 /* SYSLOG_ACTION_READ_ALL */, buf, sizeof(buf) - 1);
	char *line, *save = NULL;

	if (n <= 0)
		return;
	buf[n] = 0;
	for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
		if (!filter || strstr(line, filter))
			printf("[dmesg] %s\n", line);
}

static void do_write(char **a, int n)
{
	char text[512] = "";
	int i, fd;

	for (i = 2; i < n; i++) {
		if (i > 2)
			strcat(text, " ");
		strncat(text, a[i], sizeof(text) - strlen(text) - 1);
	}
	fd = open(a[1], O_WRONLY | O_TRUNC);
	if (fd < 0 || write(fd, text, strlen(text)) < 0)
		printf("[init] write %s: %s\n", a[1], strerror(errno));
	if (fd >= 0)
		close(fd);
}

int main(void)
{
	char line[1024], *a[MAXARG + 1];
	FILE *plan;
	int n;

	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mount("tmpfs", "/tmp", "tmpfs", 0, NULL);
	setvbuf(stdout, NULL, _IOLBF, 0);

	plan = fopen("/plan.txt", "r");
	if (!plan) {
		printf("[init] no hay /plan.txt\n");
		goto out;
	}
	while (fgets(line, sizeof(line), plan)) {
		char *tok, *save = NULL;

		line[strcspn(line, "\n")] = 0;
		if (!line[0] || line[0] == '#')
			continue;
		n = 0;
		for (tok = strtok_r(line, " \t", &save); tok && n < MAXARG; tok = strtok_r(NULL, " \t", &save))
			a[n++] = tok;
		if (!n)
			continue;

		if (!strcmp(a[0], "echo")) {
			int i;

			for (i = 1; i < n; i++)
				printf("%s%s", a[i], i + 1 < n ? " " : "");
			printf("\n");
		} else if (!strcmp(a[0], "insmod") && n >= 2) {
			do_insmod(a, n);
		} else if (!strcmp(a[0], "rmmod") && n >= 2) {
			if (syscall(SYS_delete_module, a[1], O_NONBLOCK))
				printf("[init] rmmod %s FALLO: %s\n", a[1], strerror(errno));
			else
				printf("[init] rmmod %s OK\n", a[1]);
		} else if (!strcmp(a[0], "chmod") && n >= 3) {
			chmod(a[2], strtol(a[1], NULL, 8));
		} else if (!strcmp(a[0], "run")) {
			do_run(a, n);
		} else if (!strcmp(a[0], "cat") && n >= 2) {
			do_cat(a[1]);
		} else if (!strcmp(a[0], "write") && n >= 3) {
			do_write(a, n);
		} else if (!strcmp(a[0], "mount") && n >= 3) {
			if (mount(a[1], a[2], a[1], 0, NULL))
				printf("[init] mount %s: %s\n", a[1], strerror(errno));
		} else if (!strcmp(a[0], "dmesg")) {
			do_dmesg(n >= 2 ? a[1] : NULL);
		} else if (!strcmp(a[0], "sleep") && n >= 2) {
			sleep(atoi(a[1]));
		} else {
			printf("[init] comando desconocido: %s\n", a[0]);
		}
	}
	fclose(plan);
out:
	printf("[init] plan terminado, apagando\n");
	fflush(stdout);
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
