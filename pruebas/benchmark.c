/*
 * benchmark.c
 *
 * Mide cuanto se demora el sistema en dos cosas, para comparar con y sin
 * el modulo cargado:
 *
 *   1. mmap() + munmap() de solo lectura sobre un archivo (repetido N veces).
 *      Asi se ve lo que agregan los kprobes de mmap.
 *   2. Page faults: mapear el archivo y tocar una pagina tras otra.
 *      Asi se ve lo que agrega el kprobe de handle_mm_fault.
 *
 * Uso: ./benchmark <archivo> <repeticiones>
 * Imprime tres lineas faciles de leer desde un script:
 *   mmap_ns  <nanosegundos promedio por mmap+munmap>
 *   fallo_ns <nanosegundos promedio por page fault>
 *   fallos   <cuantos page faults hubo en la prueba 2>
 *
 * Los page faults se cuentan con getrusage() (campo ru_minflt), igual que
 * en el paso 5 del repositorio del profesor. Se cuentan porque al tocar una
 * pagina el kernel a veces trae tambien las vecinas en el mismo fallo
 * ("fault-around"): no toda pagina tocada es un page fault.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>

/* tiempo actual en nanosegundos */
static long long ahora_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000000000LL + t.tv_nsec;
}

int main(int argc, char *argv[])
{
	long pagina = sysconf(_SC_PAGESIZE);
	long long inicio, total_ns = 0;
	long i, n, paginas, fallos;
	struct rusage antes, despues;
	volatile char leido;
	struct stat st;
	char *p;
	int fd;

	if (argc != 3) {
		fprintf(stderr, "uso: %s <archivo> <repeticiones>\n", argv[0]);
		return 2;
	}
	n = atol(argv[2]);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	fstat(fd, &st);
	paginas = st.st_size / pagina;
	if (paginas == 0 || n <= 0) {
		fprintf(stderr, "el archivo debe tener al menos una pagina y n > 0\n");
		return 2;
	}

	/* --- Prueba 1: mmap + munmap --- */
	inicio = ahora_ns();
	for (i = 0; i < n; i++) {
		p = mmap(NULL, pagina, PROT_READ, MAP_SHARED, fd, 0);
		if (p == MAP_FAILED) {
			perror("mmap");
			return 1;
		}
		munmap(p, pagina);
	}
	printf("mmap_ns %lld\n", (ahora_ns() - inicio) / n);

	/* --- Prueba 2: page faults --- */
	p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	getrusage(RUSAGE_SELF, &antes);
	for (i = 0; i < 5; i++) {   /* 5 rondas sobre todo el archivo */
		/* MADV_DONTNEED bota las paginas del proceso: el proximo
		 * acceso vuelve a causar un page fault */
		madvise(p, st.st_size, MADV_DONTNEED);

		inicio = ahora_ns();
		for (long j = 0; j < paginas; j++)
			leido = p[j * pagina];   /* tocar la pagina */
		total_ns += ahora_ns() - inicio;
	}
	getrusage(RUSAGE_SELF, &despues);
	(void)leido;

	/* ru_minflt = page faults "menores": la pagina ya estaba en RAM */
	fallos = despues.ru_minflt - antes.ru_minflt;
	if (fallos == 0)
		fallos = 1;   /* para no dividir por cero */
	printf("fallo_ns %lld\n", total_ns / fallos);
	printf("fallos %ld\n", fallos);

	munmap(p, st.st_size);
	close(fd);
	return 0;
}
