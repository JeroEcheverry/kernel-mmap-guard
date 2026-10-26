# mmap_guard — Seguridad de archivos mapeados con mmap() en la capa del kernel

Proyecto para el parcial práctico-teórico de Sistemas Operativos (EAFIT, 2026-2).

**Idea en una frase:** un módulo de kernel que vigila los `mmap()` y `mprotect()`
sobre una lista de archivos sensibles, bloquea los accesos peligrosos
(escritura compartida, ejecución) y deja un registro de auditoría en
`/proc/mmap_guard`.

## ¿Por qué en el kernel y no en espacio de usuario?

Cuando un proceso mapea un archivo con `mmap()`, después lee y escribe en él
usando punteros normales, **sin volver a llamar al kernel**. Por eso una
defensa en espacio de usuario (por ejemplo una librería envuelta con
`LD_PRELOAD`) no sirve: el atacante simplemente no la usa. El único lugar
donde sí pasan todas las llamadas `mmap()` es dentro del kernel, y ahí es
donde ponemos el control.

## Estructura del proyecto

```
kernel-mmap-guard/
├── README.md              <- este archivo
├── modulo/                <- el modulo de kernel (lenguaje C)
│   ├── mmap_guard.h       <- declaraciones compartidas
│   ├── main.c             <- carga del modulo y registro de los kprobes
│   ├── politica.c         <- lista de archivos y reglas de permitir/denegar
│   ├── auditoria.c        <- registro de eventos y /proc/mmap_guard
│   └── Makefile
├── pruebas/               <- programas que simulan ataques
│   ├── prueba_mmap.c      <- distintos tipos de mmap (lectura, escritura, exec...)
│   ├── carrera.c          <- pruebas de condiciones de carrera
│   ├── correr_pruebas.sh  <- carga el modulo y corre todo
│   ├── benchmark.c        <- mide el tiempo de mmap y page faults
│   └── medir_overhead.sh  <- compara con y sin modulo
└── docs/                  <- las 3 partes del parcial
    ├── parte1_preguntas.md
    ├── parte2_ia.md
    ├── parte3_implementacion.md
    └── guia_pruebas_manual.md   <- como probar todo a mano
```

## Cómo se usa

> Necesita los headers del kernel: `sudo apt install linux-headers-$(uname -r)`

```bash
# 1. compilar el modulo
cd modulo
make

# 2. cargarlo protegiendo un archivo
sudo insmod mmap_guard.ko archivos=/tmp/secreto.txt modo_estricto=1

# 3. ver el reporte de auditoria
cat /proc/mmap_guard

# 4. descargarlo
sudo rmmod mmap_guard
```

O correr todo de una vez (compila, carga, prueba y descarga):

```bash
cd pruebas
sudo ./correr_pruebas.sh
```

## Parámetros del módulo

| Parámetro         | Por defecto | Qué hace                                              |
|-------------------|-------------|-------------------------------------------------------|
| `archivos`        | (ninguno)   | Lista de rutas a proteger, separadas por coma.        |
| `modo_estricto`   | `0`         | Si es `1`, también bloquea `MAP_PRIVATE + PROT_WRITE`.|
| `uid_autorizado`  | `-1`        | UID que puede mapear con escritura (`-1` = nadie).    |
| `contar_fallos`   | `1`         | Si es `1`, cuenta los page faults de los archivos.    |

## Qué bloquea y qué permite

| Operación sobre un archivo protegido        | Resultado          |
|---------------------------------------------|--------------------|
| `mmap` solo lectura (`PROT_READ`)           | Permitido          |
| `mmap` escritura compartida (`MAP_SHARED`)  | **Bloqueado**      |
| `mmap` ejecución (`PROT_EXEC`)              | **Bloqueado**      |
| `mmap` escritura privada (`MAP_PRIVATE`)    | Bloqueado solo en modo estricto |
| `mprotect` que agrega escritura o ejecución | **Bloqueado**      |

Todo (permitido o bloqueado) queda registrado en `/proc/mmap_guard`.
