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
#   sudo ./medir_overhead.sh
#
# Los numeros cambian entre corridas (otros procesos, cache, etc.), por eso
# se repite cada medicion 3 veces. Lo importante es comparar A, B y C.

set -u

DIR_PRUEBAS="$(cd "$(dirname "$0")" && pwd)"
DIR_MODULO="$DIR_PRUEBAS/../modulo"
MODULO="$DIR_MODULO/mmap_guard.ko"
PROTEGIDO="/tmp/bench_protegido.bin"
NORMAL="/tmp/bench_normal.bin"
REPETICIONES=100000

if [ "$(id -u)" -ne 0 ]; then
	echo "Hay que correr este script con sudo."
	exit 1
fi

make -C "$DIR_MODULO" >/dev/null || { echo "no compilo el modulo"; exit 1; }
gcc -O2 -Wall -o "$DIR_PRUEBAS/benchmark" "$DIR_PRUEBAS/benchmark.c" || exit 1

# dos archivos de 4 MB (1024 paginas) para que haya muchos page faults
dd if=/dev/zero of="$PROTEGIDO" bs=1M count=4 status=none
dd if=/dev/zero of="$NORMAL"    bs=1M count=4 status=none
chmod 644 "$PROTEGIDO" "$NORMAL"

# corre el benchmark 3 veces sobre un archivo
# $1 = titulo, $2 = archivo
medir() {
	echo
	echo "--- $1 ---"
	for i in 1 2 3; do
		echo "  corrida $i: $("$DIR_PRUEBAS/benchmark" "$2" $REPETICIONES | tr '\n' ' ')"
	done
}

rmmod mmap_guard 2>/dev/null
medir "A. sin modulo" "$PROTEGIDO"

insmod "$MODULO" archivos="$PROTEGIDO" || { echo "insmod fallo"; exit 1; }
medir "B. con modulo, archivo no protegido" "$NORMAL"
medir "C. con modulo, archivo protegido"    "$PROTEGIDO"

# perf cuenta los page faults del proceso (si esta instalado)
if command -v perf >/dev/null; then
	echo
	echo "--- perf stat (con modulo, archivo protegido) ---"
	perf stat -e page-faults,task-clock "$DIR_PRUEBAS/benchmark" "$PROTEGIDO" 1000
fi

echo
echo "--- contadores del modulo ---"
grep -A6 "Contadores" /proc/mmap_guard

rmmod mmap_guard
rm -f "$PROTEGIDO" "$NORMAL"

echo
echo "mmap_ns  = nanosegundos promedio de un mmap()+munmap()"
echo "fallo_ns = nanosegundos promedio por pagina tocada (incluye los page faults)"
echo "Overhead = (C - A) / A. Copiar los numeros a docs/parte3_implementacion.md"
