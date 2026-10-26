/*
 * carrera.c
 *
 * Pruebas de condiciones de carrera (race conditions) sobre mmap().
 * Son pruebas benignas: NO intentan escribir en el archivo original ni
 * escalar privilegios. Solo sirven para comprobar que el modulo se
 * comporta bien cuando llegan muchas operaciones a la vez.
 *
 * Uso: ./carrera <archivo> <cow_privada|concurrente> [segundos]
 *
 * cow_privada:
 *   Un hilo escribe en un mapeo MAP_PRIVATE (las escrituras van a una
 *   copia COW, nunca al archivo) mientras otro hilo llama
 *   madvise(MADV_DONTNEED) sin parar (madvise bota la copia privada).
 *   Al final se verifica que el archivo en disco quedo intacto.
 *   OJO: esto NO reproduce Dirty COW (ese ataque escribia por
 *   /proc/self/mem); solo comprueba que la copia COW sigue aislada del
 *   archivo aunque haya concurrencia.
 *   Hay que correrla con modo_estricto=0, porque en modo estricto el
 *   modulo bloquea el mmap privado con escritura y la prueba no arranca.
 *
 * concurrente:
 *   Varios hilos intentan al mismo tiempo mmap(MAP_SHARED, PROT_WRITE)
 *   sobre el archivo protegido. Sirve para ver que el modulo no deja
 *   pasar ninguno aunque lleguen muchos a la vez.
 *
 * Codigo de salida: 0 = el archivo quedo intacto / ningun mmap paso, 1 = fallo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define NUM_HILOS 8

static const char *ruta;
static char *mapa;
static size_t tamano;
static volatile int seguir = 1;
static int exitos[NUM_HILOS];   /* cada hilo cuenta sus mmap que pasaron */

/* ---------- Prueba COW privada + madvise ---------- */

static void *hilo_madvise(void *arg)
{
	(void)arg;
	while (seguir)
		madvise(mapa, tamano, MADV_DONTNEED);
	return NULL;
}

static void *hilo_escribir_copia(void *arg)
{
	(void)arg;
	/* Escrituras normales al mapeo privado: el kernel hace una copia
	 * (COW) y escribe ahi, no en el archivo. Repetimos para chocar con
	 * el madvise del otro hilo. */
	while (seguir)
		memcpy(mapa, "COPIA_LOCAL", 11);
	return NULL;
}

static int prueba_cow(int segundos)
{
	pthread_t t1, t2;
	char original[64], ahora[64];
	ssize_t n;
	int fd;

	fd = open(ruta, O_RDONLY);
	if (fd < 0) { perror("open"); return 1; }

	/* guardamos el inicio del archivo para comparar al final */
	n = pread(fd, original, sizeof(original), 0);
	if (n < 0) { perror("pread"); close(fd); return 1; }

	mapa = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mapa == MAP_FAILED) {
		/* si el modulo bloquea el mmap privado+escritura, la prueba
		 * tambien se considera superada: nunca hubo escritura */
		printf("mmap privado bloqueado por el modulo (errno=%d)\n", errno);
		printf("  (para probar COW de verdad, correr con modo_estricto=0)\n");
		close(fd);
		return 0;
	}
	tamano = 4096;

	pthread_create(&t1, NULL, hilo_madvise, NULL);
	pthread_create(&t2, NULL, hilo_escribir_copia, NULL);
	sleep(segundos);
	seguir = 0;
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
	munmap(mapa, tamano);

	/* releer el archivo del disco y comparar */
	n = pread(fd, ahora, sizeof(ahora), 0);
	close(fd);
	if (n < 0) { perror("pread"); return 1; }

	if (memcmp(original, ahora, n) == 0) {
		printf("OK: el archivo quedo intacto (las escrituras fueron a la copia privada)\n");
		return 0;
	}
	printf("FALLO: el archivo original cambio (la copia COW no quedo aislada)\n");
	return 1;
}

/* ---------- Prueba de mmap concurrentes ---------- */

static void *hilo_mmap_escritura(void *arg)
{
	long id = (long)arg;
	int fd = open(ruta, O_RDWR);
	char *p;

	if (fd < 0)
		return NULL;
	p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p != MAP_FAILED) {
		exitos[id] = 1;   /* el modulo nos dejo pasar: eso seria malo */
		munmap(p, 4096);
	}
	close(fd);
	return NULL;
}

static int prueba_concurrente(void)
{
	pthread_t hilos[NUM_HILOS];
	int pasaron = 0;
	long i;

	for (i = 0; i < NUM_HILOS; i++)
		pthread_create(&hilos[i], NULL, hilo_mmap_escritura, (void *)i);
	for (i = 0; i < NUM_HILOS; i++)
		pthread_join(hilos[i], NULL);

	for (i = 0; i < NUM_HILOS; i++)
		pasaron += exitos[i];

	printf("mmap(MAP_SHARED, PROT_WRITE) que pasaron: %d de %d\n", pasaron, NUM_HILOS);
	if (pasaron == 0) {
		printf("OK: el modulo bloqueo todos los mmap de escritura concurrentes\n");
		return 0;
	}
	printf("FALLO: %d mmap de escritura se colaron\n", pasaron);
	return 1;
}

int main(int argc, char *argv[])
{
	int segundos = 3;

	if (argc < 3) {
		fprintf(stderr, "uso: %s <archivo> <cow_privada|concurrente> [segundos]\n", argv[0]);
		return 2;
	}
	ruta = argv[1];
	if (argc >= 4)
		segundos = atoi(argv[3]);

	if (strcmp(argv[2], "cow_privada") == 0)
		return prueba_cow(segundos);
	if (strcmp(argv[2], "concurrente") == 0)
		return prueba_concurrente();

	fprintf(stderr, "prueba desconocida: %s\n", argv[2]);
	return 2;
}
