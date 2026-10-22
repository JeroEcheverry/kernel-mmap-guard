#!/bin/bash
#
# correr_pruebas.sh
#
# Carga el modulo mmap_guard, corre todos los casos de prueba y al final
# descarga el modulo. Hay que correrlo con sudo porque insmod/rmmod
# necesitan permisos de root.
#
#   sudo ./correr_pruebas.sh
#
# Resultado esperado con el modulo cargado (modo_estricto=1):
#   - lectura    -> PERMITIDO
#   - escritura  -> BLOQUEADO
#   - privada    -> BLOQUEADO (por modo estricto)
#   - ejecucion  -> BLOQUEADO
#   - mprotect   -> BLOQUEADO
#   - carreras   -> archivo intacto / ningun mmap de escritura pasa

set -u

# --- rutas ---
DIR_PRUEBAS="$(cd "$(dirname "$0")" && pwd)"
DIR_MODULO="$DIR_PRUEBAS/../modulo"
MODULO="$DIR_MODULO/mmap_guard.ko"
ARCHIVO="/tmp/secreto.txt"

verde()  { echo -e "\033[32m$1\033[0m"; }
rojo()   { echo -e "\033[31m$1\033[0m"; }
titulo() { echo; echo "=== $1 ==="; }

if [ "$(id -u)" -ne 0 ]; then
	rojo "Hay que correr este script con sudo."
	exit 1
fi

# --- preparar ---
titulo "Compilando"
make -C "$DIR_MODULO" >/dev/null || { rojo "no compilo el modulo"; exit 1; }
gcc -O2 -Wall -o "$DIR_PRUEBAS/prueba_mmap" "$DIR_PRUEBAS/prueba_mmap.c"
gcc -O2 -Wall -pthread -o "$DIR_PRUEBAS/carrera" "$DIR_PRUEBAS/carrera.c"

echo "contenido original secreto, no tocar" > "$ARCHIVO"
chmod 666 "$ARCHIVO"

# --- cargar modulo ---
titulo "Cargando modulo"
rmmod mmap_guard 2>/dev/null
insmod "$MODULO" archivos="$ARCHIVO" modo_estricto=1 uid_autorizado=-1 \
	|| { rojo "insmod fallo"; exit 1; }
verde "modulo cargado"

# ejecuta un caso como un usuario normal (uid 1000) y revisa el resultado
# $1 = caso, $2 = esperado (PERMITIDO|BLOQUEADO)
probar() {
	local caso="$1" esperado="$2" salida rc
	salida=$(sudo -u "#1000" "$DIR_PRUEBAS/prueba_mmap" "$ARCHIVO" "$caso" 2>&1)
	rc=$?
	echo "  [$caso] $salida"
	if { [ "$esperado" = "PERMITIDO" ] && [ $rc -eq 0 ]; } || \
	   { [ "$esperado" = "BLOQUEADO" ] && [ $rc -eq 1 ]; }; then
		verde "  -> OK (se esperaba $esperado)"
	else
		rojo  "  -> MAL (se esperaba $esperado, rc=$rc)"
	fi
}

titulo "Casos de acceso"
probar lectura   PERMITIDO
probar escritura BLOQUEADO
probar privada   BLOQUEADO
probar ejecucion BLOQUEADO
probar mprotect  BLOQUEADO

titulo "Integridad del archivo"
if grep -q "contenido original" "$ARCHIVO"; then
	verde "  el archivo NO fue modificado por los intentos de escritura"
else
	rojo  "  el archivo fue modificado"
fi

titulo "Condiciones de carrera"
sudo -u "#1000" "$DIR_PRUEBAS/carrera" "$ARCHIVO" cow_privada 3
sudo -u "#1000" "$DIR_PRUEBAS/carrera" "$ARCHIVO" concurrente

titulo "Reporte de auditoria (/proc/mmap_guard)"
cat /proc/mmap_guard

# --- descargar ---
titulo "Descargando modulo"
rmmod mmap_guard && verde "modulo descargado"
echo "Revisa 'dmesg | tail -30' para ver los mensajes del kernel."
