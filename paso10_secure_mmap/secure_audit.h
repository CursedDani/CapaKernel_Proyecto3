/* SPDX-License-Identifier: GPL-2.0 */
/**
 * @file secure_audit.h
 * @brief Contadores atomicos de auditoria + /proc/secure_vault/stats.
 *
 * Las lineas de dmesg son para el humano (y estan limitadas en tasa para que un
 * proceso hostil no pueda inundar el log); los CONTADORES son exactos y son la
 * fuente de verdad de las pruebas automaticas.
 */
#ifndef SECURE_AUDIT_H
#define SECURE_AUDIT_H

#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/printk.h>

struct vault_stats {
	/* Alta de VMA (.open del dispositivo y .mmap) */
	atomic64_t open_ok;
	atomic64_t open_denied_uid;
	atomic64_t mmap_ok;
	atomic64_t mmap_denied_uid;     /* fd heredado/pasado a un UID no autorizado */
	atomic64_t mmap_denied_exec;    /* PROT_EXEC (W^X) */
	atomic64_t mmap_denied_private; /* MAP_PRIVATE (vector COW / Dirty COW) */
	atomic64_t mmap_denied_range;   /* pgoff/tamano fuera de la boveda */
	/* Camino de Page Fault */
	atomic64_t fault_read;
	atomic64_t fault_write;
	atomic64_t fault_oob;           /* acceso fuera de rango -> SIGBUS */
	atomic64_t fault_ns_total;      /* tiempo acumulado dentro de vault_fault() */
	atomic64_t fault_ns_max;
	atomic64_t decrypts;
	/* Escrituras y persistencia */
	atomic64_t mkwrite;             /* primera escritura por pagina (page_mkwrite) */
	atomic64_t commits;             /* paginas re-cifradas tras escritura autorizada */
	/* Integridad */
	atomic64_t integrity_fail;      /* HMAC no verifica -> posible manipulacion */
	/* Mapeos vivos */
	atomic_t   active_maps;
};

extern struct vault_stats vault_stats;

/* Contexto del proceso para lineas de log: "pid=%d comm=%s uid=%u" */
#define VAULT_CTX_FMT   "pid=%d comm=%s uid=%u"
#define VAULT_CTX_ARGS  current->pid, current->comm, \
			from_kuid(&init_user_ns, current_euid())

#define vault_stat_inc(field)        atomic64_inc(&vault_stats.field)
#define vault_stat_add(field, n)     atomic64_add((n), &vault_stats.field)

int  vault_audit_init(void);
void vault_audit_exit(void);

#endif /* SECURE_AUDIT_H */
