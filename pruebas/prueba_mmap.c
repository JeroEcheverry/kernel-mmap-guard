/*
 * prueba_mmap.c
 *
 * Programa de usuario que intenta distintos tipos de mmap() sobre un
 * archivo, para ver cuales deja pasar el modulo mmap_guard.
 *
 * Uso: ./prueba_mmap <archivo> <caso>
 *
 * Casos:
 *   lectura     -> O_RDONLY + PROT_READ + MAP_SHARED       (deberia funcionar)
 *   escritura   -> O_RDWR + PROT_READ|PROT_WRITE + MAP_SHARED (ataque: modificar el archivo)
 *   privada     -> O_RDONLY + PROT_READ|PROT_WRITE + MAP_PRIVATE (copia COW)
 *   ejecucion   -> O_RDONLY + PROT_READ|PROT_EXEC + MAP_PRIVATE  (ataque: ejecutar codigo)
 *   mprotect    -> mmap solo lectura y luego mprotect a escritura (ataque: saltarse el mmap)
 *
 * Codigo de salida: 0 = la operacion se permitio, 1 = se bloqueo, 2 = error de uso
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define PERMITIDO 0
#define BLOQUEADO 1

static int bloqueado(const char *que)
{
	printf("BLOQUEADO: %s fallo con errno=%d (%s)\n", que, errno, strerror(errno));
	return BLOQUEADO;
}

int main(int argc, char *argv[])
{
	const char *ruta, *caso;
	struct stat st;
	char *p;
	int fd;

	if (argc != 3) {
		fprintf(stderr, "uso: %s <archivo> <lectura|escritura|privada|ejecucion|mprotect>\n", argv[0]);
		return 2;
	}
	ruta = argv[1];
	caso = argv[2];

	/* Para escritura y mprotect se necesita abrir en O_RDWR */
	if (strcmp(caso, "escritura") == 0 || strcmp(caso, "mprotect") == 0)
		fd = open(ruta, O_RDWR);
	else
		fd = open(ruta, O_RDONLY);

	if (fd < 0) {
		perror("open");
		return 2;
	}
	fstat(fd, &st);

	if (strcmp(caso, "lectura") == 0) {
		p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (p == MAP_FAILED)
			return bloqueado("mmap(PROT_READ, MAP_SHARED)");
		/* leer el primer byte provoca el primer page fault */
		printf("PERMITIDO: primer byte = '%c'\n", p[0]);

	} else if (strcmp(caso, "escritura") == 0) {
		p = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (p == MAP_FAILED)
			return bloqueado("mmap(PROT_WRITE, MAP_SHARED)");
		memcpy(p, "HACKEADO", 8);
		msync(p, st.st_size, MS_SYNC);   /* forzar que llegue al disco */
		printf("PERMITIDO: se escribio 'HACKEADO' en el archivo\n");

	} else if (strcmp(caso, "privada") == 0) {
		p = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (p == MAP_FAILED)
			return bloqueado("mmap(PROT_WRITE, MAP_PRIVATE)");
		/* esta escritura va a una copia privada (COW), no al archivo */
		memcpy(p, "COPIA", 5);
		printf("PERMITIDO: se modifico la copia privada (el archivo no cambia)\n");

	} else if (strcmp(caso, "ejecucion") == 0) {
		p = mmap(NULL, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
		if (p == MAP_FAILED)
			return bloqueado("mmap(PROT_EXEC)");
		printf("PERMITIDO: el archivo quedo mapeado como ejecutable\n");

	} else if (strcmp(caso, "mprotect") == 0) {
		p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (p == MAP_FAILED)
			return bloqueado("mmap(PROT_READ) inicial");
		printf("  paso 1: mmap de solo lectura funciono\n");
		if (mprotect(p, st.st_size, PROT_READ | PROT_WRITE) != 0)
			return bloqueado("mprotect(PROT_WRITE)");
		memcpy(p, "HACKEADO", 8);
		msync(p, st.st_size, MS_SYNC);
		printf("PERMITIDO: mprotect dio escritura y se modifico el archivo\n");

	} else {
		fprintf(stderr, "caso desconocido: %s\n", caso);
		return 2;
	}

	munmap(p, st.st_size);
	close(fd);
	return PERMITIDO;
}
