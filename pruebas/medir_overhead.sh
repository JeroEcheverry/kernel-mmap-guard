#!/bin/bash
#
# medir_overhead.sh
#
# Mide cuanto mas lento es mmap() y un page fault cuando el modulo esta
# cargado. Compara 3 situaciones:
#
#   A. sin modulo
#   B. con modulo, sobre un archivo que NO esta protegido
#   C. con modulo, sobre el archivo protegido
#
#   make
#   sudo make bench        (o: sudo ./pruebas/medir_overhead.sh)
#
# Los numeros cambian entre corridas (otros procesos, cache, etc.), por eso
# se repite cada medicion 3 veces. Lo importante es comparar A, B y C.

set -u

DIR_PRUEBAS="$(cd "$(dirname "$0")" && pwd)"
MODULO="$DIR_PRUEBAS/../modulo/mmap_guard.ko"
BENCH="$DIR_PRUEBAS/benchmark"
PROTEGIDO="/tmp/bench_protegido.bin"
NORMAL="/tmp/bench_normal.bin"
REPETICIONES=100000

if [ "$(id -u)" -ne 0 ]; then
	echo "Hay que correr este script con sudo."
	exit 1
fi
for f in "$MODULO" "$BENCH"; do
	if [ ! -f "$f" ]; then
		echo "No existe $f. Primero compilar con: make"
		exit 1
	fi
done

# si el script se corta a la mitad, igual se descarga el modulo
trap 'rmmod mmap_guard 2>/dev/null; rm -f "$PROTEGIDO" "$NORMAL"' EXIT

# dos archivos de 4 MB (1024 paginas) para que haya muchos page faults
dd if=/dev/zero of="$PROTEGIDO" bs=1M count=4 status=none
dd if=/dev/zero of="$NORMAL"    bs=1M count=4 status=none

# corre el benchmark 3 veces sobre un archivo
# $1 = titulo, $2 = archivo
medir() {
	echo
	echo "--- $1 ---"
	for i in 1 2 3; do
		echo "  corrida $i: $("$BENCH" "$2" $REPETICIONES | tr '\n' ' ')"
	done
}

rmmod mmap_guard 2>/dev/null
medir "A. sin modulo" "$PROTEGIDO"

insmod "$MODULO" archivos="$PROTEGIDO" || { echo "insmod fallo"; exit 1; }
medir "B. con modulo, archivo no protegido" "$NORMAL"
medir "C. con modulo, archivo protegido"    "$PROTEGIDO"

# strace -c cuenta las llamadas al sistema y su tiempo (como en el paso 5
# del repo del profesor). Se usan menos repeticiones porque strace es lento.
if command -v strace >/dev/null; then
	echo
	echo "--- strace -c (con modulo, archivo protegido) ---"
	strace -c -e trace=mmap,munmap "$BENCH" "$PROTEGIDO" 1000 >/dev/null
fi

echo
echo "--- contadores del modulo ---"
grep -A6 "Contadores" /proc/mmap_guard

rmmod mmap_guard

echo
echo "mmap_ns  = nanosegundos promedio de un mmap()+munmap()"
echo "fallo_ns = nanosegundos promedio de un page fault"
echo "fallos   = page faults que hubo (medido con getrusage)"
echo "Overhead = (C - A) / A. Copiar los numeros a docs/parte3_implementacion.md"
