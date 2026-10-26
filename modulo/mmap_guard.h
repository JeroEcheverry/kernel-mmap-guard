/*
 * mmap_guard.h
 *
 * Declaraciones compartidas entre los archivos del modulo.
 *
 * El modulo esta dividido en 3 partes:
 *   - main.c      -> carga/descarga del modulo y registro de los kprobes
 *   - politica.c  -> lista de archivos protegidos y reglas (permitir/denegar)
 *   - auditoria.c -> registro de eventos y archivo /proc/mmap_guard
 */

#ifndef MMAP_GUARD_H
#define MMAP_GUARD_H

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/atomic.h>

#define MAX_ARCHIVOS     8    /* cuantos archivos se pueden proteger */
#define MAX_EVENTOS      64   /* tamano del buffer circular de auditoria */
#define LARGO_NOMBRE     64

/* Tipo de operacion que se audito */
enum tipo_evento {
	EVENTO_MMAP,
	EVENTO_MPROTECT,
};

/* Resultado de revisar una operacion contra la politica */
struct decision {
	bool denegar;
	const char *motivo;   /* texto corto para el log, ej: "escritura compartida" */
};

/* ---- politica.c ---- */
int politica_cargar(char *rutas[], int n);
bool politica_archivo_protegido(struct file *archivo);
/* La usan mmap y mprotect: prot = permisos pedidos, compartido = MAP_SHARED */
struct decision politica_revisar(unsigned long prot, bool compartido);
int politica_num_archivos(void);
const char *politica_ruta(int i);

/* Parametros del modulo (definidos en main.c) */
extern int modo_estricto;
extern int uid_autorizado;
extern int contar_fallos;

/* ---- auditoria.c ---- */

/* atomic_long_t: contador que varios CPUs pueden sumar a la vez sin lock */
struct contadores {
	atomic_long_t mmap_revisados;   /* mmap sobre archivos protegidos */
	atomic_long_t mmap_denegados;
	atomic_long_t mprotect_revisados;
	atomic_long_t mprotect_denegados;
	atomic_long_t fallos_lectura;   /* page faults de lectura en archivos protegidos */
	atomic_long_t fallos_escritura; /* page faults de escritura en archivos protegidos */
};

extern struct contadores stats;

void auditoria_registrar(enum tipo_evento tipo, struct file *archivo,
			 unsigned long prot, bool compartido,
			 struct decision d);
int auditoria_iniciar(void);
void auditoria_terminar(void);

#endif /* MMAP_GUARD_H */
