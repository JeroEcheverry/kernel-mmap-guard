#!/usr/bin/env python3
"""
prueba_python.py

Los mismos ataques de prueba_mmap.c pero desde Python. Sirve para mostrar
que el bloqueo lo hace el kernel y no depende del lenguaje del programa:
el modulo mmap del interprete de Python termina llamando al mismo mmap().
"""

import ctypes
import mmap
import os
import sys

PERMITIDO = "PERMITIDO"
BLOQUEADO = "BLOQUEADO"
DIR_MODULO = "/sys/module/mmap_guard"

# libc para mprotect: el modulo mmap de Python no tiene mprotect
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
MAP_FAILED = ctypes.c_void_p(-1).value


def caso_lectura(ruta):
    with open(ruta, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
        m[0]          # primer acceso -> primer page fault
        m.close()


def caso_escritura(ruta):
    with open(ruta, "r+b") as f:
        m = mmap.mmap(f.fileno(), 0, flags=mmap.MAP_SHARED,
                      prot=mmap.PROT_READ | mmap.PROT_WRITE)
        m[0:8] = b"HACKEADO"
        m.flush()     # equivale a msync: manda el cambio al disco
        m.close()


def caso_privada(ruta):
    # O_RDONLY + escritura privada: el kernel lo permite porque es COW
    with open(ruta, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, flags=mmap.MAP_PRIVATE,
                      prot=mmap.PROT_READ | mmap.PROT_WRITE)
        m[0:5] = b"COPIA"   # va a la copia privada, no al archivo
        m.close()


def caso_ejecucion(ruta):
    with open(ruta, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, flags=mmap.MAP_PRIVATE,
                      prot=mmap.PROT_READ | mmap.PROT_EXEC)
        m.close()


def caso_mprotect(ruta):
    # mmap de solo lectura (se permite) y luego pedir escritura con mprotect
    tam = os.path.getsize(ruta)
    fd = os.open(ruta, os.O_RDWR)
    try:
        p = libc.mmap(None, tam, mmap.PROT_READ, mmap.MAP_SHARED, fd, 0)
        if p == MAP_FAILED:
            err = ctypes.get_errno()
            raise OSError(err, "mmap inicial: " + os.strerror(err))
        try:
            if libc.mprotect(p, tam, mmap.PROT_READ | mmap.PROT_WRITE) != 0:
                err = ctypes.get_errno()
                raise OSError(err, "mprotect: " + os.strerror(err))
            ctypes.memmove(p, b"HACKEADO", 8)
        finally:
            libc.munmap(p, tam)
    finally:
        os.close(fd)


def correr(funcion, ruta):
    """Corre un caso y devuelve PERMITIDO o BLOQUEADO."""
    try:
        funcion(ruta)
        return PERMITIDO, ""
    except OSError as e:
        return BLOQUEADO, f"errno={e.errno} ({e.strerror})"


def modo_estricto_actual():
    try:
        with open(DIR_MODULO + "/parameters/modo_estricto") as f:
            return f.read().strip() == "1"
    except OSError:
        return False


def main():
    if len(sys.argv) != 2:
        print(f"uso: {sys.argv[0]} <archivo>", file=sys.stderr)
        return 2
    ruta = sys.argv[1]
    if not os.path.isfile(ruta):
        print(f"no existe el archivo {ruta}", file=sys.stderr)
        return 2

    if os.path.isdir(DIR_MODULO):
        estricto = modo_estricto_actual()
        print(f"  modulo cargado (modo_estricto={int(estricto)})")
        esperado = {
            "lectura": PERMITIDO,
            "escritura": BLOQUEADO,
            "privada": BLOQUEADO if estricto else PERMITIDO,
            "ejecucion": BLOQUEADO,
            "mprotect": BLOQUEADO,
        }
    else:
        print("  modulo NO cargado: se espera que todo pase (PoC)")
        esperado = dict.fromkeys(
            ["lectura", "escritura", "privada", "ejecucion", "mprotect"], PERMITIDO)

    casos = [
        ("lectura", caso_lectura),
        ("escritura", caso_escritura),
        ("privada", caso_privada),
        ("ejecucion", caso_ejecucion),
        ("mprotect", caso_mprotect),
    ]

    fallos = 0
    for nombre, funcion in casos:
        resultado, detalle = correr(funcion, ruta)
        ok = resultado == esperado[nombre]
        if not ok:
            fallos += 1
        marca = "OK " if ok else "MAL"
        print(f"  [py:{nombre:9}] {resultado:9} {detalle}  -> {marca} "
              f"(se esperaba {esperado[nombre]})")

    return 0 if fallos == 0 else 1


if __name__ == "__main__":
    sys.exit(main())