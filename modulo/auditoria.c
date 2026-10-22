// SPDX-License-Identifier: GPL-2.0
/*
 * auditoria.c
 *
 * Guarda los ultimos MAX_EVENTOS accesos a archivos protegidos en un
 * buffer circular y los muestra en /proc/mmap_guard.
 * Las denegaciones tambien se imprimen en dmesg.
 */

#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/mman.h>
#include <linux/timekeeping.h>
#include "mmap_guard.h"

struct evento {
	u64 tiempo_ns;            /* desde que arranco el sistema */
	pid_t pid;
	uid_t uid;
	char proceso[TASK_COMM_LEN];
	char archivo[LARGO_NOMBRE];
	enum tipo_evento tipo;
	unsigned long prot;
	bool compartido;
	bool denegado;
	const char *motivo;
};

struct contadores stats;

static struct evento eventos[MAX_EVENTOS];
static int siguiente;        /* posicion donde se escribe el proximo evento */
static int total_eventos;    /* cuantos se han guardado (max MAX_EVENTOS) */

/*
 * Spinlock y no mutex: los handlers de kprobes corren con la
 * apropiacion (preemption) desactivada, entonces no pueden dormir.
 */
static DEFINE_SPINLOCK(lock_eventos);

static struct proc_dir_entry *entrada_proc;

void auditoria_registrar(enum tipo_evento tipo, struct file *archivo,
			 unsigned long prot, bool compartido,
			 struct decision d)
{
	struct evento *e;
	unsigned long flags;

	spin_lock_irqsave(&lock_eventos, flags);

	e = &eventos[siguiente];
	e->tiempo_ns = ktime_get_ns();
	e->pid = current->pid;
	e->uid = from_kuid(&init_user_ns, current_uid());
	get_task_comm(e->proceso, current);
	/* %pD imprime el nombre del archivo a partir del struct file */
	snprintf(e->archivo, LARGO_NOMBRE, "%pD", archivo);
	e->tipo = tipo;
	e->prot = prot;
	e->compartido = compartido;
	e->denegado = d.denegar;
	e->motivo = d.motivo;   /* apunta a un texto constante, no hay que copiarlo */

	siguiente = (siguiente + 1) % MAX_EVENTOS;
	if (total_eventos < MAX_EVENTOS)
		total_eventos++;

	spin_unlock_irqrestore(&lock_eventos, flags);

	if (d.denegar)
		pr_warn_ratelimited("mmap_guard: DENEGADO %s pid=%d (%s) archivo=%pD motivo=%s\n",
				    tipo == EVENTO_MMAP ? "mmap" : "mprotect",
				    current->pid, current->comm, archivo, d.motivo);
}

/* Convierte PROT_* a un texto tipo "rw-" */
static void prot_a_texto(unsigned long prot, char *buf)
{
	buf[0] = (prot & PROT_READ) ? 'r' : '-';
	buf[1] = (prot & PROT_WRITE) ? 'w' : '-';
	buf[2] = (prot & PROT_EXEC) ? 'x' : '-';
	buf[3] = '\0';
}

/* Lo que se ve al hacer: cat /proc/mmap_guard */
static int mostrar_proc(struct seq_file *m, void *v)
{
	struct evento copia;
	unsigned long flags;
	char permisos[4];
	int i, inicio, n;

	seq_puts(m, "=== mmap_guard ===\n");
	seq_printf(m, "modo_estricto: %d  uid_autorizado: %d  contar_fallos: %d\n",
		   modo_estricto, uid_autorizado, contar_fallos);

	seq_puts(m, "\nArchivos protegidos:\n");
	for (i = 0; i < politica_num_archivos(); i++)
		seq_printf(m, "  %s\n", politica_ruta(i));

	seq_puts(m, "\nContadores:\n");
	seq_printf(m, "  mmap revisados:      %ld\n", atomic_long_read(&stats.mmap_revisados));
	seq_printf(m, "  mmap denegados:      %ld\n", atomic_long_read(&stats.mmap_denegados));
	seq_printf(m, "  mprotect revisados:  %ld\n", atomic_long_read(&stats.mprotect_revisados));
	seq_printf(m, "  mprotect denegados:  %ld\n", atomic_long_read(&stats.mprotect_denegados));
	seq_printf(m, "  page faults lectura: %ld\n", atomic_long_read(&stats.fallos_lectura));
	seq_printf(m, "  page faults escrit.: %ld\n", atomic_long_read(&stats.fallos_escritura));
	seq_printf(m, "  kprobes perdidos:    %d\n", kprobes_perdidos());

	seq_puts(m, "\nUltimos eventos (mas antiguo primero):\n");
	seq_puts(m, "  tiempo(s)      pid    uid  proceso          op        prot tipo   resultado  archivo / motivo\n");

	/* Se copia cada evento con el lock tomado y se imprime sin el lock */
	spin_lock_irqsave(&lock_eventos, flags);
	n = total_eventos;
	inicio = (siguiente - n + MAX_EVENTOS) % MAX_EVENTOS;
	spin_unlock_irqrestore(&lock_eventos, flags);

	for (i = 0; i < n; i++) {
		spin_lock_irqsave(&lock_eventos, flags);
		copia = eventos[(inicio + i) % MAX_EVENTOS];
		spin_unlock_irqrestore(&lock_eventos, flags);

		prot_a_texto(copia.prot, permisos);
		seq_printf(m, "  %5llu.%06llu  %-6d %-4u %-16s %-9s %s  %-6s %-9s  %s (%s)\n",
			   copia.tiempo_ns / 1000000000ULL,
			   (copia.tiempo_ns % 1000000000ULL) / 1000,
			   copia.pid, copia.uid, copia.proceso,
			   copia.tipo == EVENTO_MMAP ? "mmap" : "mprotect",
			   permisos,
			   copia.compartido ? "shared" : "priv",
			   copia.denegado ? "DENEGADO" : "ok",
			   copia.archivo, copia.motivo);
	}

	return 0;
}

static int abrir_proc(struct inode *inode, struct file *file)
{
	return single_open(file, mostrar_proc, NULL);
}

static const struct proc_ops ops_proc = {
	.proc_open    = abrir_proc,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

int auditoria_iniciar(void)
{
	/* 0444: cualquiera puede leer, nadie escribe */
	entrada_proc = proc_create("mmap_guard", 0444, NULL, &ops_proc);
	if (!entrada_proc)
		return -ENOMEM;
	return 0;
}

void auditoria_terminar(void)
{
	proc_remove(entrada_proc);
}
