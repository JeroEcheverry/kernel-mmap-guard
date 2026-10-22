// SPDX-License-Identifier: GPL-2.0
/*
 * main.c - mmap_guard
 *
 * Modulo de kernel que vigila los mmap() y mprotect() sobre una lista de
 * archivos protegidos. Usa kprobes, que permiten "engancharse" a una
 * funcion del kernel sin recompilarlo.
 *
 * Funciones interceptadas:
 *   - security_mmap_file()    : la llama el kernel en cada mmap() antes de
 *                               crear la VMA. Si devuelve error, el mmap falla.
 *   - security_file_mprotect(): la llama mprotect() antes de cambiar permisos.
 *   - handle_mm_fault()       : manejador de page faults (solo para contar).
 *
 * Para las dos primeras usamos kretprobe: en la entrada revisamos los
 * argumentos y, si hay que negar, en el retorno cambiamos el valor
 * devuelto por -EACCES. Asi el mmap()/mprotect() le falla al proceso.
 *
 * Uso:
 *   sudo insmod mmap_guard.ko archivos=/ruta/uno,/ruta/dos modo_estricto=1
 *   cat /proc/mmap_guard
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mman.h>
#include <linux/ptrace.h>
#include "mmap_guard.h"

MODULE_LICENSE("GPL");   /* necesario: register_kprobe es EXPORT_SYMBOL_GPL */
MODULE_AUTHOR("Equipo Sistemas Operativos EAFIT 2026-2");
MODULE_DESCRIPTION("Control de acceso y auditoria de mmap() sobre archivos protegidos");
MODULE_VERSION("1.0");

/* ---------- Parametros del modulo ---------- */

static char *archivos[MAX_ARCHIVOS];
static int num_archivos_param;
module_param_array(archivos, charp, &num_archivos_param, 0444);
MODULE_PARM_DESC(archivos, "Lista de rutas a proteger, separadas por coma");

int modo_estricto;
module_param(modo_estricto, int, 0644);   /* 0644: root lo puede cambiar en /sys */
MODULE_PARM_DESC(modo_estricto, "1 = tambien negar MAP_PRIVATE con PROT_WRITE");

int uid_autorizado = -1;
module_param(uid_autorizado, int, 0444);
MODULE_PARM_DESC(uid_autorizado, "UID que puede mapear con escritura (-1 = ninguno)");

int contar_fallos = 1;
module_param(contar_fallos, int, 0444);
MODULE_PARM_DESC(contar_fallos, "1 = contar page faults sobre archivos protegidos");

/* ---------- Hook 1: security_mmap_file ---------- */

/*
 * int security_mmap_file(struct file *file, unsigned long prot,
 *                        unsigned long flags);
 *
 * regs_get_kernel_argument(regs, n) devuelve el argumento n de la funcion
 * (en x86_64 son los registros rdi, rsi, rdx...).
 */
static int entrada_mmap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file *archivo = (struct file *)regs_get_kernel_argument(regs, 0);
	unsigned long prot = regs_get_kernel_argument(regs, 1);
	unsigned long flags = regs_get_kernel_argument(regs, 2);
	bool compartido = (flags & MAP_TYPE) != MAP_PRIVATE;
	struct decision d;

	if (!politica_archivo_protegido(archivo))
		return 1;   /* devolver 1 = no ejecutar el handler de retorno */

	atomic_long_inc(&stats.mmap_revisados);
	d = politica_revisar_mmap(archivo, prot, flags);
	auditoria_registrar(EVENTO_MMAP, archivo, prot, compartido, d);

	if (!d.denegar)
		return 1;

	atomic_long_inc(&stats.mmap_denegados);
	return 0;           /* 0 = si ejecutar retorno_negar() */
}

/*
 * Solo llega aqui cuando hay que negar. Si otro LSM (AppArmor, SELinux)
 * ya devolvio un error lo dejamos igual; si devolvio 0 lo cambiamos.
 */
static int retorno_negar(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (regs_return_value(regs) == 0)
		regs_set_return_value(regs, (unsigned long)-EACCES);
	return 0;
}

static struct kretprobe krp_mmap = {
	.kp.symbol_name = "security_mmap_file",
	.entry_handler  = entrada_mmap,
	.handler        = retorno_negar,
	.maxactive      = 64,   /* llamadas simultaneas que puede seguir */
};

/* ---------- Hook 2: security_file_mprotect ---------- */

/*
 * int security_file_mprotect(struct vm_area_struct *vma,
 *                            unsigned long reqprot, unsigned long prot);
 *
 * Sin este hook alguien podria hacer mmap(PROT_READ), que se permite, y
 * despues mprotect(PROT_READ | PROT_WRITE) para saltarse la regla.
 */
static int entrada_mprotect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 0);
	unsigned long reqprot = regs_get_kernel_argument(regs, 1);
	struct decision d;

	if (!politica_archivo_protegido(vma->vm_file))
		return 1;

	atomic_long_inc(&stats.mprotect_revisados);
	/* usamos reqprot (lo que pidio el usuario), no prot, que el kernel
	 * puede haber ajustado con READ_IMPLIES_EXEC */
	d = politica_revisar_mprotect(vma, reqprot);
	auditoria_registrar(EVENTO_MPROTECT, vma->vm_file, reqprot,
			    (vma->vm_flags & VM_SHARED) != 0, d);

	if (!d.denegar)
		return 1;

	atomic_long_inc(&stats.mprotect_denegados);
	return 0;
}

static struct kretprobe krp_mprotect = {
	.kp.symbol_name = "security_file_mprotect",
	.entry_handler  = entrada_mprotect,
	.handler        = retorno_negar,
	.maxactive      = 64,
};

/* ---------- Hook 3: handle_mm_fault (solo cuenta) ---------- */

/*
 * vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
 *                            unsigned int flags, struct pt_regs *regs);
 *
 * Se llama en TODOS los page faults del sistema, asi que aqui no se hace
 * nada pesado: solo comparar el inodo y sumar un contador.
 */
static int antes_fallo(struct kprobe *p, struct pt_regs *regs)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 0);
	unsigned int flags = regs_get_kernel_argument(regs, 2);

	if (vma && politica_archivo_protegido(vma->vm_file)) {
		if (flags & FAULT_FLAG_WRITE)
			atomic_long_inc(&stats.fallos_escritura);
		else
			atomic_long_inc(&stats.fallos_lectura);
	}
	return 0;
}

static struct kprobe kp_fallos = {
	.symbol_name = "handle_mm_fault",
	.pre_handler = antes_fallo,
};

static bool fallos_registrado;

int kprobes_perdidos(void)
{
	return krp_mmap.nmissed + krp_mprotect.nmissed;
}

/* ---------- Carga y descarga ---------- */

static int __init mmap_guard_init(void)
{
	int err;

	if (num_archivos_param == 0) {
		pr_err("mmap_guard: falta el parametro archivos=/ruta1,/ruta2\n");
		return -EINVAL;
	}

	if (politica_cargar(archivos, num_archivos_param) == 0) {
		pr_err("mmap_guard: ningun archivo valido para proteger\n");
		return -ENOENT;
	}

	err = auditoria_iniciar();
	if (err)
		return err;

	err = register_kretprobe(&krp_mmap);
	if (err) {
		pr_err("mmap_guard: fallo kretprobe security_mmap_file (%d)\n", err);
		goto error_proc;
	}

	err = register_kretprobe(&krp_mprotect);
	if (err) {
		pr_err("mmap_guard: fallo kretprobe security_file_mprotect (%d)\n", err);
		goto error_mmap;
	}

	if (contar_fallos) {
		err = register_kprobe(&kp_fallos);
		if (err)   /* no es grave, el modulo sigue sin contar fallos */
			pr_warn("mmap_guard: no se pudo engancharse a handle_mm_fault (%d)\n", err);
		else
			fallos_registrado = true;
	}

	pr_info("mmap_guard: cargado (modo_estricto=%d, uid_autorizado=%d)\n",
		modo_estricto, uid_autorizado);
	return 0;

error_mmap:
	unregister_kretprobe(&krp_mmap);
error_proc:
	auditoria_terminar();
	return err;
}

static void __exit mmap_guard_exit(void)
{
	/* Primero se quitan los hooks para que nadie use la auditoria */
	if (fallos_registrado)
		unregister_kprobe(&kp_fallos);
	unregister_kretprobe(&krp_mprotect);
	unregister_kretprobe(&krp_mmap);
	auditoria_terminar();

	pr_info("mmap_guard: descargado. mmap denegados=%ld mprotect denegados=%ld\n",
		atomic_long_read(&stats.mmap_denegados),
		atomic_long_read(&stats.mprotect_denegados));
}

module_init(mmap_guard_init);
module_exit(mmap_guard_exit);
