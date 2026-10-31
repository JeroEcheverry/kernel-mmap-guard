# Parte III — Implementación y resultados (40%)

## 4.1 Código

- **`modulo/`** — el módulo de kernel en C:
  - `main.c`: carga/descarga y registro de los kprobes.
  - `politica.c`: lista de archivos protegidos y reglas.
  - `auditoria.c`: registro de eventos y `/proc/mmap_guard`.
  - `mmap_guard.h`: declaraciones compartidas.
  - `Makefile`: compila con `-Wall -Werror` (sin warnings).
- **`pruebas/`** — ataques de prueba y mediciones:
  - `prueba_mmap.c` y `prueba_python.py`: los mismos 5 ataques en C y en Python.
  - `carrera.c`: pruebas de concurrencia.
  - `correr_pruebas.sh`: carga el módulo, corre todo y lo descarga.
  - `benchmark.c`, `medir_overhead.sh` y `medir_ftrace.sh`: miden el costo.
- **`makefile`** (raíz): `make`, `sudo make test`, `sudo make bench`,
  `sudo make ftrace`.

### Cómo funciona

El módulo pone un **kretprobe** sobre `security_mmap_file()`, una función que
el kernel llama en cada `mmap()` **antes** de crear el mapeo:

- **Al entrar**, miramos qué archivo es y qué permisos pide. Si es un archivo
  protegido, revisamos las reglas y lo anotamos en la auditoría.
- **Al salir**, si hay que negarlo, cambiamos lo que devuelve la función por
  `-EACCES` ("permiso denegado"). El kernel entonces no crea el mapeo.

Lo mismo hacemos con `mprotect` (`security_file_mprotect()`), para que nadie
pueda mapear en solo lectura y después pedir escritura.

### Reglas (`politica.c`)

1. Nunca se permite ejecución (`PROT_EXEC`).
2. Nunca se permite escritura compartida (`MAP_SHARED + PROT_WRITE`).
3. La escritura privada (`MAP_PRIVATE + PROT_WRITE`) solo se bloquea en modo
   estricto.
4. Un usuario autorizado (`uid_autorizado`) puede hacer todo.

## 4.2 Argumentación y resultados

### ¿Por qué en el kernel?

Después del `mmap()`, el proceso lee y escribe el archivo con punteros, sin
pasar por el kernel. Una defensa en espacio de usuario (por ejemplo una
librería con `LD_PRELOAD`) se salta fácil: basta con no usarla. En cambio,
**todos** los `mmap()` pasan por el kernel. Nuestras pruebas lo muestran: el
ataque falla igual desde C y desde Python.

### Resultados de las pruebas

`sudo make test` en el kernel 6.6.87.2 de WSL2, como usuario normal:

| Prueba | Esperado | Obtenido |
|--------|----------|----------|
| `mmap` lectura | PERMITIDO | PERMITIDO |
| `mmap` escritura compartida | BLOQUEADO | BLOQUEADO |
| `mmap` escritura privada (modo estricto) | BLOQUEADO | BLOQUEADO |
| `mmap` ejecución | BLOQUEADO | BLOQUEADO |
| truco `mprotect` | BLOQUEADO | BLOQUEADO |
| enlace duro (otro nombre) | BLOQUEADO | BLOQUEADO |
| mismos casos en Python | igual que en C | igual que en C |
| integridad del archivo | intacto | intacto |
| carrera COW | archivo intacto | archivo intacto |
| 8 mmap de escritura a la vez | 0 pasan | 0 pasan |

**Resultado: 10 pruebas OK, 0 MAL.** Sin el módulo, los mismos programas sí
modifican el archivo (queda `HACKEADO...`).

En la prueba de carrera hubo ~1.4 millones de page faults de escritura en 3
segundos: cada vez que `madvise` botaba la copia, la siguiente escritura
creaba una copia nueva. Aun así, el archivo quedó intacto.

### Costo del módulo (overhead)

Lo medimos en tres casos: **A** sin módulo, **B** con módulo sobre un archivo
no protegido, y **C** con módulo sobre el archivo protegido.

**1. Desde el programa** (`sudo make bench`, promedio de 3 corridas):

| Caso | `mmap`+`munmap` | page fault |
|------|-----------------|------------|
| A. sin módulo | 2152 ns | 2275 ns |
| B. no protegido | 2171 ns (+0.9%) | 2291 ns (+0.7%) |
| C. protegido | 2358 ns (+9.6%) | 2416 ns (+6.2%) |

**2. Dentro del kernel con ftrace** (`sudo make ftrace`, mediana):

| Función | A. sin módulo | B. no protegido | C. protegido |
|---------|---------------|-----------------|--------------|
| `vm_mmap_pgoff` (cada mmap) | 848 ns | 948 ns (+11.8%) | 964 ns (+13.7%) |
| `handle_mm_fault` (cada page fault) | 1243 ns | 1295 ns (+4.2%) | 1310 ns (+5.4%) |

**Qué significa:**

- El módulo agrega **unos 100–200 ns por `mmap()`**. Es poco.
- Casi todo ese costo es **entrar al kretprobe**, y lo pagan **todos** los
  `mmap()` del sistema, no solo los del archivo protegido (por eso B y C se
  parecen en ftrace). Revisar las reglas y auditar solo agrega ~16 ns.
- En el benchmark, B parecía casi gratis (+0.9%) porque una corrida lenta del
  caso A subió el promedio. Con la mediana da +5.3%, que coincide con ftrace.
- `strace -c` no sirve para medir el costo (el propio strace hace todo unas 7
  veces más lento), pero sí para contar las llamadas.

Notas: los tiempos son en WSL2, que es una máquina virtual. Hubo 320 page
faults y no 5120 porque el kernel trae 16 páginas vecinas en cada fallo
(*fault-around*).

### Limitaciones y trabajo futuro

1. **No cifra el contenido**: solo controla quién mapea el archivo.
2. **Usa el número de inodo**: si el archivo se borra y se crea otro, el nuevo
   podría quedar protegido (o el original desprotegido) hasta recargar el módulo.
3. **Root puede descargar el módulo** con `rmmod`. Un LSM compilado dentro del
   kernel no se puede quitar.
4. **No detiene Dirty COW**: ese ataque escribía por `/proc/self/mem`, que no
   pasa por `mmap()`. La defensa es tener el kernel actualizado.
5. **El kretprobe puede dejar pasar llamadas** si llegan demasiadas a la vez
   (tiene un número limitado de "turnos" simultáneos). En nuestras pruebas no
   pasó: el módulo contó todos los `mmap()`. Se podría subir ese límite
   (`maxactive`).
6. **Ataques de hardware** (DMA, canales laterales) pueden leer la memoria
   física sin pasar por las tablas de páginas. Se mitigan con IOMMU o memoria
   cifrada (AMD SEV, Intel TDX).

### Cómo reproducir

```bash
make               # compila (sin sudo)
sudo make test     # pruebas de seguridad
sudo make bench    # costo medido desde el programa
sudo make ftrace   # costo medido dentro del kernel
```

En WSL2 primero hay que preparar el kernel (ver `README.md`).