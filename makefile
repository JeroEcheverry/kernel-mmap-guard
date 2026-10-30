# Makefile principal del proyecto
#
#   make            -> compila el modulo y los programas de prueba
#   sudo make test  -> corre todas las pruebas (carga y descarga el modulo)
#   sudo make bench -> mide el overhead con y sin modulo
#   make clean      -> borra todo lo compilado
#
# Primero "make" como usuario normal (sin sudo) y despues las pruebas con
# sudo. Por eso test y bench no compilan: asi nada queda a nombre de root.

CC     := gcc
CFLAGS := -O2 -Wall -Wextra

PRUEBAS := pruebas/prueba_mmap pruebas/carrera pruebas/benchmark

all: modulo $(PRUEBAS)

modulo:
	$(MAKE) -C modulo

pruebas/prueba_mmap: pruebas/prueba_mmap.c
	$(CC) $(CFLAGS) -o $@ $<

pruebas/carrera: pruebas/carrera.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

pruebas/benchmark: pruebas/benchmark.c
	$(CC) $(CFLAGS) -o $@ $<

test:
	bash pruebas/correr_pruebas.sh

bench:
	bash pruebas/medir_overhead.sh

clean:
	$(MAKE) -C modulo clean
	rm -f $(PRUEBAS)

# "modulo" es el nombre de una carpeta: .PHONY le dice a make que igual
# lo trate como una orden y no como un archivo
.PHONY: all modulo test bench clean
