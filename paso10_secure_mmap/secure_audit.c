// SPDX-License-Identifier: GPL-2.0
/**
 * @file secure_audit.c
 * @brief Implementacion de /proc/secure_vault/stats (seq_file, formato clave=valor
 *        facil de parsear desde bash/python para las pruebas y el benchmark).
 */
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>

#include "secure_policy.h"
#include "secure_audit.h"

struct vault_stats vault_stats;

static struct proc_dir_entry *vault_proc_dir;

#define STAT64(name) seq_printf(m, #name "=%lld\n", (long long)atomic64_read(&vault_stats.name))

static int vault_stats_show(struct seq_file *m, void *v)
{
	s64 faults = atomic64_read(&vault_stats.fault_read) +
		     atomic64_read(&vault_stats.fault_write);
	s64 total_ns = atomic64_read(&vault_stats.fault_ns_total);

	STAT64(open_ok);
	STAT64(open_denied_uid);
	STAT64(mmap_ok);
	STAT64(mmap_denied_uid);
	STAT64(mmap_denied_exec);
	STAT64(mmap_denied_private);
	STAT64(mmap_denied_range);
	STAT64(fault_read);
	STAT64(fault_write);
	STAT64(fault_oob);
	STAT64(fault_ns_total);
	STAT64(fault_ns_max);
	STAT64(decrypts);
	STAT64(mkwrite);
	STAT64(commits);
	STAT64(integrity_fail);
	seq_printf(m, "active_maps=%d\n", atomic_read(&vault_stats.active_maps));
	seq_printf(m, "fault_ns_avg=%lld\n", faults ? (long long)(total_ns / faults) : 0LL);
	return 0;
}

int vault_audit_init(void)
{
	vault_proc_dir = proc_mkdir(VAULT_PROC_DIR, NULL);
	if (!vault_proc_dir)
		return -ENOMEM;

	/* 0444: las estadisticas no son secretas; el contenido de la boveda si lo es */
	if (!proc_create_single("stats", 0444, vault_proc_dir, vault_stats_show)) {
		remove_proc_entry(VAULT_PROC_DIR, NULL);
		return -ENOMEM;
	}
	return 0;
}

void vault_audit_exit(void)
{
	remove_proc_entry("stats", vault_proc_dir);
	remove_proc_entry(VAULT_PROC_DIR, NULL);
}
