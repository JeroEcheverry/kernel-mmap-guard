// SPDX-License-Identifier: GPL-2.0
/*
 * politica.c
 *
 * Aqui se guarda la lista de archivos protegidos y se decide si una
 * operacion mmap()/mprotect() se permite o se niega.
 *
 * Los archivos se identifican por su inodo y no por el nombre. Asi un
 * enlace con otro nombre no sirve para saltarse la proteccion, porque
 * apunta al mismo inodo. Tambien se guarda el dispositivo (disco), porque
 * el numero de inodo solo es unico dentro de un mismo disco.
 */

#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/mman.h>
#include <linux/uidgid.h>
#include "mmap_guard.h"

struct archivo_protegido {
	dev_t dispositivo;
	unsigned long inodo;
	char ruta[LARGO_NOMBRE];
};

static struct archivo_protegido lista[MAX_ARCHIVOS];
static int num_archivos;

/*
 * Busca cada ruta en el sistema de archivos y guarda su inodo.
 * Se llama una sola vez al cargar el modulo.
 */
int politica_cargar(char *rutas[], int n)
{
	struct path p;
	struct inode *ino;
	int i, err;

	num_archivos = 0;
	for (i = 0; i < n && i < MAX_ARCHIVOS; i++) {
		/* kern_path busca la ruta (como hace open), siguiendo enlaces */
		err = kern_path(rutas[i], LOOKUP_FOLLOW, &p);
		if (err) {
			pr_warn("mmap_guard: no se encontro %s (error %d)\n",
				rutas[i], err);
			continue;
		}

		ino = d_inode(p.dentry);
		lista[num_archivos].dispositivo = ino->i_sb->s_dev;
		lista[num_archivos].inodo = ino->i_ino;
		strscpy(lista[num_archivos].ruta, rutas[i], LARGO_NOMBRE);
		pr_info("mmap_guard: protegiendo %s (inodo %lu)\n",
			rutas[i], ino->i_ino);
		num_archivos++;

		path_put(&p);   /* liberar lo que reservo kern_path */
	}

	return num_archivos;
}

int politica_num_archivos(void)
{
	return num_archivos;
}

const char *politica_ruta(int i)
{
	return lista[i].ruta;
}

/* Devuelve true si el archivo esta en la lista de protegidos */
bool politica_archivo_protegido(struct file *archivo)
{
	struct inode *ino;
	int i;

	if (!archivo)
		return false;   /* mmap sin archivo (memoria anonima) */

	ino = file_inode(archivo);
	for (i = 0; i < num_archivos; i++) {
		if (lista[i].inodo == ino->i_ino &&
		    lista[i].dispositivo == ino->i_sb->s_dev)
			return true;
	}
	return false;
}

/* El usuario autorizado puede hacer cualquier cosa (-1 = nadie) */
static bool es_usuario_autorizado(void)
{
	/* current_uid() devuelve un kuid_t: el numero del usuario esta en .val */
	uid_t uid = current_uid().val;

	return uid_autorizado >= 0 && uid == (uid_t)uid_autorizado;
}

/*
 * Reglas comunes para mmap y mprotect.
 *   1. Nunca se permite PROT_EXEC  -> evita ejecutar codigo inyectado.
 *   2. MAP_SHARED + PROT_WRITE     -> los cambios llegarian al disco, se niega.
 *   3. MAP_PRIVATE + PROT_WRITE    -> solo se niega en modo estricto. La copia
 *      es privada (COW) y no toca el disco, pero el proceso tendria en su
 *      memoria una version alterada del archivo.
 */
struct decision politica_revisar(unsigned long prot, bool compartido)
{
	struct decision d = { .denegar = false, .motivo = "permitido" };

	if (es_usuario_autorizado()) {
		d.motivo = "usuario autorizado";
		return d;
	}

	if (prot & PROT_EXEC) {
		d.denegar = true;
		d.motivo = "ejecucion no permitida";
	} else if (compartido && (prot & PROT_WRITE)) {
		d.denegar = true;
		d.motivo = "escritura compartida";
	} else if (!compartido && (prot & PROT_WRITE) && modo_estricto) {
		d.denegar = true;
		d.motivo = "escritura privada (modo estricto)";
	}

	return d;
}
