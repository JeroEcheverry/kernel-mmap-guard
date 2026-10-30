#!/bin/bash
#
# correr_pruebas.sh
#
# Carga el modulo mmap_guard, corre todos los casos de prueba y al final
# descarga el modulo. Antes hay que compilar (como usuario normal):
#
#   make
#   sudo make test        (o: sudo ./pruebas/correr_pruebas.sh)
#
# Las pruebas se corren con el usuario que llamo a sudo (no como root),
# para simular un usuario normal intentando modificar el archivo.
#
# Resultado esperado con el modulo cargado (modo_estricto=1):
#   - lectura    -> PERMITIDO
#   - escritura  -> BLOQUEADO
#   - privada    -> BLOQUEADO (por modo estricto)
#   - ejecucion  -> BLOQUEADO
#   - mprotect   -> BLOQUEADO
#   - enlace     -> BLOQUEADO (otro nombre, mismo inodo)
#   - carreras   -> archivo intacto / ningun mmap de escritura pasa
#     (la prueba cow_privada se corre con modo_estricto=0 para que el
#      mmap privado se permita y de verdad se pruebe la copia COW)

set -u

# --- rutas ---
DIR_PRUEBAS="$(cd "$(dirname "$0")" && pwd)"
MODULO="$DIR_PRUEBAS/../modulo/mmap_guard.ko"
ARCHIVO="/tmp/secreto.txt"
ENLACE="/tmp/otro_nombre"
PARAM_ESTRICTO=/sys/module/mmap_guard/parameters/modo_estricto

# usuario que llamo a sudo (si no se uso sudo, el 1000)
USUARIO="${SUDO_UID:-1000}"

verde()  { echo -e "\033[32m$1\033[0m"; }
rojo()   { echo -e "\033[31m$1\033[0m"; }
titulo() { echo; echo "=== $1 ==="; }

BIEN=0
MAL=0

# corre un comando como el usuario normal
como_usuario() { sudo -u "#$USUARIO" "$@"; }

# revisa un resultado y lleva la cuenta
# $1 = descripcion, $2 = 0 si salio bien
anotar() {
	if [ "$2" -eq 0 ]; then
		verde "  -> OK: $1"
		BIEN=$((BIEN + 1))
	else
		rojo  "  -> MAL: $1"
		MAL=$((MAL + 1))
	fi
}

# prueba un caso de prueba_mmap
# $1 = archivo, $2 = caso, $3 = esperado (PERMITIDO|BLOQUEADO)
probar() {
	local salida rc esperado_rc
	salida=$(como_usuario "$DIR_PRUEBAS/prueba_mmap" "$1" "$2" 2>&1)
	rc=$?
	echo "  [$2] $salida"
	if [ "$3" = "PERMITIDO" ]; then esperado_rc=0; else esperado_rc=1; fi
	[ $rc -eq $esperado_rc ]
	anotar "$2 sobre $1 -> se esperaba $3" $?
}

# --- revisiones antes de empezar ---
if [ "$(id -u)" -ne 0 ]; then
	rojo "Hay que correr este script con sudo."
	exit 1
fi
for f in "$MODULO" "$DIR_PRUEBAS/prueba_mmap" "$DIR_PRUEBAS/carrera"; do
	if [ ! -f "$f" ]; then
		rojo "No existe $f. Primero compilar con: make"
		exit 1
	fi
done

# al terminar (bien o mal) se descarga el modulo y se borran los archivos
# de prueba, para que no queden en /tmp a nombre de root
trap 'rmmod mmap_guard 2>/dev/null; rm -f "$ARCHIVO" "$ENLACE"' EXIT

# --- preparar el archivo ---
# se borra antes de crearlo: si quedo de una prueba a mano a nombre de otro
# usuario, Linux no deja que root lo sobrescriba en /tmp (protected_regular)
rm -f "$ARCHIVO" "$ENLACE"
echo "contenido original secreto, no tocar" > "$ARCHIVO"
chmod 666 "$ARCHIVO"

# --- cargar modulo ---
titulo "Cargando modulo"
rmmod mmap_guard 2>/dev/null
if ! insmod "$MODULO" archivos="$ARCHIVO" modo_estricto=1 uid_autorizado=-1; then
	rojo "insmod fallo, revisar: sudo dmesg | tail"
	exit 1
fi
verde "modulo cargado (pruebas como uid $USUARIO)"

titulo "Casos de acceso"
probar "$ARCHIVO" lectura   PERMITIDO
probar "$ARCHIVO" escritura BLOQUEADO
probar "$ARCHIVO" privada   BLOQUEADO
probar "$ARCHIVO" ejecucion BLOQUEADO
probar "$ARCHIVO" mprotect  BLOQUEADO

titulo "Enlace duro (otro nombre, mismo inodo)"
ln "$ARCHIVO" "$ENLACE"
probar "$ENLACE" escritura BLOQUEADO
rm -f "$ENLACE"

if command -v python3 >/dev/null; then
	titulo "Pruebas con Python"
	como_usuario python3 "$DIR_PRUEBAS/prueba_python.py" "$ARCHIVO"
	anotar "pruebas en Python" $?
fi

titulo "Integridad del archivo"
grep -q "contenido original" "$ARCHIVO"
anotar "el archivo no fue modificado por los intentos de escritura" $?

titulo "Condiciones de carrera"
# modo_estricto se puede cambiar en caliente porque el parametro es 0644
echo 0 > "$PARAM_ESTRICTO"
echo "  (modo_estricto=0 para la prueba COW)"
como_usuario "$DIR_PRUEBAS/carrera" "$ARCHIVO" cow_privada 3
anotar "carrera cow_privada" $?
echo 1 > "$PARAM_ESTRICTO"
echo "  (modo_estricto=1 de nuevo)"
como_usuario "$DIR_PRUEBAS/carrera" "$ARCHIVO" concurrente
anotar "carrera concurrente" $?

titulo "Reporte de auditoria (/proc/mmap_guard)"
cat /proc/mmap_guard

# --- descargar ---
titulo "Descargando modulo"
rmmod mmap_guard && verde "modulo descargado"

titulo "Resumen"
echo "  pruebas OK: $BIEN   pruebas MAL: $MAL"
echo "  Revisa 'sudo dmesg | tail -30' para ver los mensajes del kernel."
[ $MAL -eq 0 ]
