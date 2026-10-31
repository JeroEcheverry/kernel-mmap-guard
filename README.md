# mmap_guard — Protección de archivos mapeados con mmap() desde el kernel

Parcial de Sistemas Operativos (EAFIT, 2026-2).

**En una frase:** un módulo de kernel que vigila los `mmap()` y `mprotect()`
sobre archivos protegidos, bloquea los accesos peligrosos (escribir el archivo
o ejecutarlo) y anota todo en `/proc/mmap_guard`.

## ¿Por qué en el kernel?

Después de un `mmap()`, el proceso lee y escribe el archivo con punteros, sin
volver a pedirle permiso al kernel. Una defensa en espacio de usuario se salta
fácil (basta con no usarla). Pero **todos** los `mmap()` pasan por el kernel,
así que ahí ponemos el control.

## Estructura

```
kernel-mmap-guard/
├── makefile               <- make, sudo make test, sudo make bench, sudo make ftrace
├── modulo/                <- el modulo de kernel (C)
│   ├── main.c             <- carga del modulo y kprobes
│   ├── politica.c         <- archivos protegidos y reglas
│   ├── auditoria.c        <- registro de eventos y /proc/mmap_guard
│   ├── mmap_guard.h
│   └── Makefile
├── pruebas/
│   ├── prueba_mmap.c      <- 5 ataques de prueba
│   ├── prueba_python.py   <- los mismos ataques en Python
│   ├── carrera.c          <- pruebas de concurrencia
│   ├── correr_pruebas.sh  <- corre todas las pruebas
│   ├── benchmark.c        <- mide mmap y page faults
│   ├── medir_overhead.sh  <- costo con y sin modulo (+ strace)
│   └── medir_ftrace.sh    <- costo dentro del kernel (ftrace)
└── docs/
    ├── parte1_preguntas.md
    ├── parte2_ia.md
    ├── parte3_implementacion.md
    └── guia_pruebas_manual.md
```

## Uso

```bash
make                # compilar (sin sudo)
sudo make test      # pruebas de seguridad
sudo make bench     # costo del modulo
sudo make ftrace    # costo medido con ftrace
```

A mano:

```bash
sudo insmod modulo/mmap_guard.ko archivos=/tmp/secreto.txt modo_estricto=1
cat /proc/mmap_guard
sudo rmmod mmap_guard
```

Paso a paso: `docs/guia_pruebas_manual.md`.

## Parámetros

| Parámetro | Por defecto | Qué hace |
|-----------|-------------|----------|
| `archivos` | (ninguno) | Rutas a proteger, separadas por coma |
| `modo_estricto` | `0` | `1` = también bloquea escritura privada |
| `uid_autorizado` | `-1` | Usuario que puede escribir (`-1` = nadie) |
| `contar_fallos` | `1` | Cuenta los page faults del archivo |

## Qué bloquea

| Operación sobre un archivo protegido | Resultado |
|--------------------------------------|-----------|
| `mmap` solo lectura | Permitido |
| `mmap` escritura compartida | **Bloqueado** |
| `mmap` ejecución | **Bloqueado** |
| `mmap` escritura privada | Bloqueado en modo estricto |
| `mprotect` para agregar escritura o ejecución | **Bloqueado** |

## Compilar en WSL2

Probado en `6.6.87.2-microsoft-standard-WSL2`. WSL2 no trae los headers de su
kernel, así que hay que armarlos una vez:

```bash
sudo apt install -y build-essential flex bison bc libelf-dev libssl-dev dwarves cpio

cd ~
git clone --depth 1 --branch linux-msft-wsl-6.6.87.2 \
    https://github.com/microsoft/WSL2-Linux-Kernel.git wsl-kernel
cd wsl-kernel
zcat /proc/config.gz > .config
make olddefconfig
make LOCALVERSION= kernelrelease     # debe ser igual a uname -r

# solo si tienes GCC 15 o mas nuevo
sed -i '/^REALMODE_CFLAGS += -fno-stack-protector/a REALMODE_CFLAGS += -std=gnu11' arch/x86/Makefile

make -j$(nproc) LOCALVERSION= vmlinux
cp vmlinux.symvers Module.symvers

sudo mkdir -p /lib/modules/$(uname -r)
sudo ln -sfn ~/wsl-kernel /lib/modules/$(uname -r)/build
```
