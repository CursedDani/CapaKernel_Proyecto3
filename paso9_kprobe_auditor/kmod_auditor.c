// SPDX-License-Identifier: GPL-2.0
/**
 * @file kmod_auditor.c
 * @brief PASO 9 (Parcial 25%, Componente B): auditor GLOBAL de mmap() con kprobes.
 *
 * Complementa a la boveda (Paso 10): la boveda da PROFUNDIDAD sobre un recurso; este
 * modulo da AMPLITUD, observando el mmap() de TODO el sistema sin recompilar el kernel
 * ni tocar la syscall table.
 *
 * Punto de enganche: security_mmap_file(file, prot, flags), la funcion que el core de
 * mm invoca en vm_mmap_pgoff() ANTES de do_mmap(). Es el mismo punto donde actuan los
 * LSM (hook file_mmap): por eso tambien se auditan los intentos que luego fallaran con
 * EACCES (p. ej. PROT_WRITE|MAP_SHARED sobre un fd de solo lectura).
 *
 * LIMITACION CONSCIENTE: un kprobe OBSERVA, no puede vetar la operacion (para bloquear
 * haria falta un LSM o BPF-LSM; ver docs). Se documenta como trabajo futuro.
 *
 * Reglas de anomalia (deteccion de patrones, Pregunta 7):
 *   WX        : PROT_WRITE|PROT_EXEC simultaneos (memoria inyectable Y ejecutable)
 *   WRSHARED  : PROT_WRITE + MAP_SHARED sobre un archivo bajo `watch_prefix`
 *   EXEC_DEV  : PROT_EXEC sobre un dispositivo (/dev/...)
 *
 * Contexto de ejecucion: el pre-handler corre con preemption deshabilitada => NO puede
 * dormir. Solo se usan spinlocks, d_path (RCU + seqlock, sin sleeps) y copias acotadas.
 */

#define pr_fmt(fmt) "mmap_auditor: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/string.h>
#include <linux/ptrace.h>
#include <linux/cred.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Equipo SO 2026-B - Parcial CapaKernel");
MODULE_DESCRIPTION("Auditor global de mmap() mediante kprobe sobre security_mmap_file");
MODULE_VERSION("1.0");

static char *watch_prefix = "/etc/";
module_param(watch_prefix, charp, 0444);
MODULE_PARM_DESC(watch_prefix, "Prefijo de ruta sensible; PROT_WRITE+MAP_SHARED sobre el se marca como anomalo");

static bool record_anon;
module_param(record_anon, bool, 0644);
MODULE_PARM_DESC(record_anon, "Guardar tambien mmaps anonimos (muy ruidoso); por defecto solo se cuentan");

#define RING_SIZE 128
#define PATH_MAX_REC 96

struct audit_event {
	u64  ts_ns;
	pid_t pid;
	uid_t uid;
	char comm[TASK_COMM_LEN];
	char path[PATH_MAX_REC];
	unsigned long prot;
	unsigned long flags;
	const char *rule;   /* NULL = normal */
};

static struct audit_event ring[RING_SIZE];
static unsigned int ring_head;       /* proxima posicion a escribir */
static unsigned long ring_total;     /* eventos guardados desde la carga */
static DEFINE_RAW_SPINLOCK(ring_lock);

static atomic64_t n_total = ATOMIC64_INIT(0);
static atomic64_t n_anon = ATOMIC64_INIT(0);
static atomic64_t n_file = ATOMIC64_INIT(0);
static atomic64_t n_write = ATOMIC64_INIT(0);
static atomic64_t n_exec = ATOMIC64_INIT(0);
static atomic64_t n_flagged = ATOMIC64_INIT(0);

static struct proc_dir_entry *proc_entry;

/*
 * Argumentos de la funcion enganchada segun la ABI. security_mmap_file(file, prot, flags)
 * llega en los 3 primeros registros de argumento.
 */
#if defined(CONFIG_X86_64)
# define ARG_FILE(r)  ((struct file *)(r)->di)
# define ARG_PROT(r)  ((unsigned long)(r)->si)
# define ARG_FLAGS(r) ((unsigned long)(r)->dx)
#elif defined(CONFIG_ARM64)
# define ARG_FILE(r)  ((struct file *)(r)->regs[0])
# define ARG_PROT(r)  ((unsigned long)(r)->regs[1])
# define ARG_FLAGS(r) ((unsigned long)(r)->regs[2])
#else
# error "kmod_auditor: arquitectura sin mapeo de argumentos implementado (x86_64/arm64)"
#endif

static const char *classify(unsigned long prot, unsigned long flags, const char *path)
{
	if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
		return "WX";
	if ((prot & PROT_WRITE) && (flags & MAP_SHARED) && watch_prefix && *watch_prefix &&
	    !strncmp(path, watch_prefix, strlen(watch_prefix)))
		return "WRSHARED";
	if ((prot & PROT_EXEC) && !strncmp(path, "/dev/", 5))
		return "EXEC_DEV";
	return NULL;
}

static int mmap_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = ARG_FILE(regs);
	unsigned long prot = ARG_PROT(regs);
	unsigned long flags = ARG_FLAGS(regs);
	struct audit_event ev = { 0 };
	char buf[PATH_MAX_REC];
	const char *path = "";
	unsigned long irq;

	atomic64_inc(&n_total);
	if (prot & PROT_WRITE)
		atomic64_inc(&n_write);
	if (prot & PROT_EXEC)
		atomic64_inc(&n_exec);

	if (!file) {
		atomic64_inc(&n_anon);
		if (!record_anon)
			return 0;
		path = "[anonimo]";
	} else {
		char *d;

		atomic64_inc(&n_file);
		d = file_path(file, buf, sizeof(buf));
		path = IS_ERR(d) ? "[ruta-larga]" : d;
	}

	ev.ts_ns = ktime_get_ns();
	ev.pid = current->tgid;
	ev.uid = from_kuid(&init_user_ns, current_euid());
	strscpy(ev.comm, current->comm, sizeof(ev.comm));
	strscpy(ev.path, path, sizeof(ev.path));
	ev.prot = prot;
	ev.flags = flags;
	ev.rule = classify(prot, flags, path);

	if (ev.rule) {
		atomic64_inc(&n_flagged);
		pr_warn_ratelimited("ANOMALIA %s: pid=%d comm=%s uid=%u prot=%c%c%c %s %s\n",
				    ev.rule, ev.pid, ev.comm, ev.uid,
				    (prot & PROT_READ) ? 'r' : '-', (prot & PROT_WRITE) ? 'w' : '-',
				    (prot & PROT_EXEC) ? 'x' : '-',
				    (flags & MAP_SHARED) ? "SHARED" : "PRIVATE", path);
	}

	raw_spin_lock_irqsave(&ring_lock, irq);
	ring[ring_head] = ev;
	ring_head = (ring_head + 1) % RING_SIZE;
	ring_total++;
	raw_spin_unlock_irqrestore(&ring_lock, irq);
	return 0;   /* 0 = continuar con la ejecucion normal (un kprobe no puede vetar) */
}

static struct kprobe mmap_kp = {
	.symbol_name = "security_mmap_file",
	.pre_handler = mmap_pre_handler,
};

static int audit_show(struct seq_file *m, void *v)
{
	unsigned long irq, total, i, n;
	unsigned int start;

	seq_printf(m, "total=%lld\nanonimos=%lld\narchivos=%lld\nprot_write=%lld\nprot_exec=%lld\nanomalos=%lld\n",
		   (long long)atomic64_read(&n_total), (long long)atomic64_read(&n_anon),
		   (long long)atomic64_read(&n_file), (long long)atomic64_read(&n_write),
		   (long long)atomic64_read(&n_exec), (long long)atomic64_read(&n_flagged));
	seq_printf(m, "kprobe_nmissed=%lu\n", mmap_kp.nmissed);

	raw_spin_lock_irqsave(&ring_lock, irq);
	total = ring_total;
	n = min_t(unsigned long, total, RING_SIZE);
	start = (ring_head + RING_SIZE - n) % RING_SIZE;
	/* Copia bajo el lock a una vista consistente: se imprime fuera de la region critica */
	raw_spin_unlock_irqrestore(&ring_lock, irq);

	/* Los eventos antiguos pueden sobrescribirse mientras se imprimen: es aceptable
	 * para una vista de diagnostico (cada entrada se copia completa al leerla). */
	for (i = 0; i < n; i++) {
		struct audit_event ev;
		unsigned int idx = (start + i) % RING_SIZE;

		raw_spin_lock_irqsave(&ring_lock, irq);
		ev = ring[idx];
		raw_spin_unlock_irqrestore(&ring_lock, irq);

		seq_printf(m, "EVT t=%llums pid=%d uid=%u comm=%s prot=%c%c%c flags=%s path=%s regla=%s\n",
			   (unsigned long long)(ev.ts_ns / 1000000), ev.pid, ev.uid, ev.comm,
			   (ev.prot & PROT_READ) ? 'r' : '-', (ev.prot & PROT_WRITE) ? 'w' : '-',
			   (ev.prot & PROT_EXEC) ? 'x' : '-',
			   (ev.flags & MAP_SHARED) ? "SHARED" : "PRIVATE", ev.path,
			   ev.rule ? ev.rule : "-");
	}
	return 0;
}

static int __init auditor_init(void)
{
	int ret;

	proc_entry = proc_create_single("mmap_audit", 0444, NULL, audit_show);
	if (!proc_entry)
		return -ENOMEM;

	ret = register_kprobe(&mmap_kp);
	if (ret < 0) {
		pr_err("register_kprobe(security_mmap_file) fallo: %d\n", ret);
		remove_proc_entry("mmap_audit", NULL);
		return ret;
	}
	pr_info("kprobe activo en %s (%pS); watch_prefix=%s; lectura en /proc/mmap_audit\n",
		mmap_kp.symbol_name, mmap_kp.addr, watch_prefix);
	return 0;
}

static void __exit auditor_exit(void)
{
	unregister_kprobe(&mmap_kp);
	remove_proc_entry("mmap_audit", NULL);
	pr_info("descargado: %lld mmaps observados, %lld anomalos, kprobe_nmissed=%lu\n",
		(long long)atomic64_read(&n_total), (long long)atomic64_read(&n_flagged),
		mmap_kp.nmissed);
}

module_init(auditor_init);
module_exit(auditor_exit);
