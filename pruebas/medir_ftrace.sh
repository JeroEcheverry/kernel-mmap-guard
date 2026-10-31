#!/bin/bash
#
# medir_ftrace.sh
#
# Mide con ftrace (el trazador que trae el kernel) cuanto tarda DENTRO del
# kernel cada llamada a dos funciones, con y sin el modulo:
#
#   vm_mmap_pgoff   -> atiende cada mmap(). Adentro llama a
#                      security_mmap_file(), donde esta nuestro kretprobe.
#   handle_mm_fault -> atiende cada page fault (ahi esta el kprobe que cuenta).
#
# Se usa el tracer "function_graph", que anota cuanto duro cada llamada.
# Con set_ftrace_filter, ftrace solo engancha esas dos funciones (si no,
# engancharia todas las del kernel y frenaria todo). Cada linea del trace
# lleva el nombre del proceso que la genero, y al final solo se cuentan
# las del benchmark.
#
# Se filtra por nombre y no por pid porque en WSL2 la distro corre en su
# propio "PID namespace": el pid que vemos desde la terminal no es el
# mismo que el kernel anota en el trace.
#
#   make
#   sudo make ftrace        (o: sudo ./pruebas/medir_ftrace.sh)
#
# Se reporta promedio y mediana. La mediana es mas confiable: si una
# interrupcion cae justo en una llamada, esa llamada sale muy lenta y
# sube el promedio, pero casi no mueve la mediana.

set -u

DIR_PRUEBAS="$(cd "$(dirname "$0")" && pwd)"
MODULO="$DIR_PRUEBAS/../modulo/mmap_guard.ko"
BENCH="$DIR_PRUEBAS/benchmark"
PROTEGIDO="/tmp/ftrace_protegido.bin"
NORMAL="/tmp/ftrace_normal.bin"
REPETICIONES=10000
T=/sys/kernel/tracing

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

# en algunos sistemas (como WSL) tracefs no viene montado
if [ ! -f "$T/current_tracer" ]; then
	mount -t tracefs nodev "$T" || { echo "No se pudo montar tracefs"; exit 1; }
fi

# dejar ftrace como estaba, descargar el modulo y borrar archivos
limpiar() {
	echo 0 > "$T/tracing_on"
	echo nop > "$T/current_tracer"
	echo > "$T/set_ftrace_filter"
	rmmod mmap_guard 2>/dev/null
	rm -f "$PROTEGIDO" "$NORMAL"
}
trap limpiar EXIT

dd if=/dev/zero of="$PROTEGIDO" bs=1M count=4 status=none
dd if=/dev/zero of="$NORMAL"    bs=1M count=4 status=none

# Configura ftrace para cronometrar solo las dos funciones
preparar() {
	echo 0 > "$T/tracing_on"
	echo nop > "$T/current_tracer"
	echo > "$T/trace"                       # borrar lo anterior
	echo 16384 > "$T/buffer_size_kb"        # espacio para todas las llamadas
	echo vm_mmap_pgoff > "$T/set_ftrace_filter"     # solo estas dos funciones
	echo handle_mm_fault >> "$T/set_ftrace_filter"
	echo function_graph > "$T/current_tracer"
	# estas opciones solo existen despues de elegir function_graph
	echo 1 > "$T/options/funcgraph-proc"    # anotar nombre-pid en cada linea
	echo 0 > "$T/options/funcgraph-irqs"    # no contar interrupciones
}

# Saca promedio y mediana (en ns) de las llamadas a una funcion, solo
# del proceso del benchmark. Con funcgraph-proc cada linea se ve asi
# (el kernel recorta el nombre a 7 letras):
#    4) benchma-31478  |   3.870 us    |  vm_mmap_pgoff();
# $1 = nombre de la funcion
resumir() {
	grep -E " benchm[a-z]*-[0-9]+ " "$T/trace" \
	| grep " $1();" \
	| awk '{ for (i = 1; i < NF; i++) if ($(i+1) == "us") { print $i * 1000; break } }' \
	| sort -n \
	| awk -v f="$1" '
		{ v[NR] = $1; suma += $1 }
		END {
			if (NR == 0) { printf "    %-16s sin datos\n", f; exit }
			printf "    %-16s llamadas=%-6d promedio=%6.0f ns  mediana=%6.0f ns\n",
			       f, NR, suma / NR, v[int((NR + 1) / 2)]
		}'
}

# $1 = titulo, $2 = archivo
medir() {
	echo
	echo "--- $1 ---"
	preparar
	echo 1 > "$T/tracing_on"
	"$BENCH" "$2" "$REPETICIONES" > /dev/null
	echo 0 > "$T/tracing_on"
	resumir vm_mmap_pgoff
	resumir handle_mm_fault
}

rmmod mmap_guard 2>/dev/null
medir "A. sin modulo" "$PROTEGIDO"

insmod "$MODULO" archivos="$PROTEGIDO" || { echo "insmod fallo"; exit 1; }
medir "B. con modulo, archivo no protegido" "$NORMAL"
medir "C. con modulo, archivo protegido"    "$PROTEGIDO"

echo
echo "vm_mmap_pgoff   = tiempo dentro del kernel de cada mmap()"
echo "handle_mm_fault = tiempo dentro del kernel de cada page fault"
echo "Overhead = (C - A) / A, usando la mediana"