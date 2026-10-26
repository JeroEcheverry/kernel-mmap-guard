/*
 * auditoria.c
 *
 * Guarda los ultimos MAX_EVENTOS accesos a archivos protegidos en un
 * buffer circular (cuando se llena, el nuevo evento pisa al mas viejo)
 * y los muestra en /proc/mmap_guard.
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
 * Spinlock y no mutex: el codigo de un kprobe no puede dormir, y un mutex
 * puede dormir mientras espera. El spinlock espera dando vueltas.
 */
static DEFINE_SPINLOCK(lock_eventos);

static struct proc_dir_entry *entrada_proc;

void auditoria_registrar(enum tipo_evento tipo, struct file *archivo,
			 unsigned long prot, bool compartido,
			 struct decision d)
{
	struct evento *e;
	unsigned long flags;

	/* irqsave: ademas del lock, apaga las interrupciones mientras lo tenemos */
	spin_lock_irqsave(&lock_eventos, flags);

	e = &eventos[siguiente];
	e->tiempo_ns = ktime_get_ns();
	e->pid = current->pid;   /* current = el proceso que hizo el mmap */
	e->uid = current_uid().val;   /* kuid_t guarda el numero en .val */
	get_task_comm(e->proceso, current);
	/* %pD imprime el nombre del archivo a partir del struct file */
	snprintf(e->archivo, LARGO_NOMBRE, "%pD", archivo);
	e->tipo = tipo;
	e->prot = prot;
	e->compartido = compartido;
	e->denegado = d.denegar;
	e->motivo = d.motivo;   /* es un texto fijo, basta guardar el puntero */

	siguiente = (siguiente + 1) % MAX_EVENTOS;   /* al llegar al final vuelve a 0 */
	if (total_eventos < MAX_EVENTOS)
		total_eventos++;

	spin_unlock_irqrestore(&lock_eventos, flags);

	/* ratelimited: si llegan muchos seguidos, no llena el dmesg */
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
	struct evento *e;
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

	seq_puts(m, "\nUltimos eventos (mas antiguo primero):\n");
	seq_puts(m, "  tiempo(s)      pid    uid  proceso          op        prot tipo   resultado  archivo / motivo\n");

	/* con el lock tomado para que nadie agregue eventos mientras leemos */
	spin_lock_irqsave(&lock_eventos, flags);
	n = total_eventos;
	/* el evento mas antiguo esta n posiciones antes de 'siguiente' */
	inicio = (siguiente - n + MAX_EVENTOS) % MAX_EVENTOS;

	for (i = 0; i < n; i++) {
		e = &eventos[(inicio + i) % MAX_EVENTOS];
		prot_a_texto(e->prot, permisos);
		seq_printf(m, "  %5llu.%06llu  %-6d %-4u %-16s %-9s %s  %-6s %-9s  %s (%s)\n",
			   e->tiempo_ns / 1000000000ULL,
			   (e->tiempo_ns % 1000000000ULL) / 1000,
			   e->pid, e->uid, e->proceso,
			   e->tipo == EVENTO_MMAP ? "mmap" : "mprotect",
			   permisos,
			   e->compartido ? "shared" : "priv",
			   e->denegado ? "DENEGADO" : "ok",
			   e->archivo, e->motivo);
	}
	spin_unlock_irqrestore(&lock_eventos, flags);

	return 0;
}

/*
 * Para crear un archivo en /proc se le dice al kernel que funciones llamar
 * al abrirlo y leerlo. seq_file es una ayuda del kernel: nosotros solo
 * escribimos el texto en mostrar_proc() y el kernel se encarga del resto.
 */
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
