# Parte III — Implementación, resultados y argumentación (40%)

## 4.1 Entregables de código

Todo el código está en el repositorio:

- **`modulo/`** — el módulo de kernel en C, dividido en tres archivos para que
  cada uno tenga una sola responsabilidad:
  - `main.c`: carga/descarga del módulo y registro de los kprobes.
  - `politica.c`: la lista de archivos protegidos y las reglas de permitir/negar.
  - `auditoria.c`: el buffer de eventos y el archivo `/proc/mmap_guard`.
  - `mmap_guard.h`: declaraciones compartidas entre los tres.
  - `Makefile`: compila con `-Wall -Werror` (build limpio, sin warnings).
- **`pruebas/`** — programas que simulan los ataques:
  - `prueba_mmap.c`: prueba cada tipo de mapeo.
  - `carrera.c`: pruebas de condiciones de carrera (benignas).
  - `prueba_python.py`: los mismos casos en Python (el bloqueo no depende del programa).
  - `correr_pruebas.sh`: carga el módulo, corre todo y lo descarga.
- **`Makefile`** (raíz) — `make` compila todo, `sudo make test` corre las pruebas y `sudo make bench` mide el overhead.
  - `benchmark.c` y `medir_overhead.sh`: miden el costo extra del módulo.

### Cómo funciona la intercepción (resumen)

El módulo registra un **kretprobe** sobre `security_mmap_file()`. Un kretprobe
tiene dos manejadores:

- En la **entrada** leemos los argumentos (`struct file *`, `prot`, `flags`),
  revisamos si el archivo está protegido y si la operación rompe alguna regla, y
  anotamos el evento en la auditoría.
- En el **retorno**, si decidimos negar, cambiamos el valor devuelto por la
  función a `-EACCES`. Como `security_mmap_file()` es parte del camino del
  `mmap()`, ese error hace que el `mmap()` del proceso falle.

Lo mismo para `mprotect` con `security_file_mprotect()`, y un kprobe de solo
lectura sobre `handle_mm_fault()` para contar los page faults.

### Validación de permisos

Las reglas están en `politica_revisar()` en `politica.c`:

1. Nunca se permite `PROT_EXEC` (apoya el bit NX, evita ejecutar código inyectado).
2. Nunca se permite `MAP_SHARED + PROT_WRITE` (escritura persistente al disco).
3. `MAP_PRIVATE + PROT_WRITE` solo se niega en modo estricto.
4. El `uid_autorizado` (si se configura) se salta las reglas.

## 4.2 Argumentación y análisis de resultados

### ¿Por qué en el kernel y no en espacio de usuario?

Porque después del `mmap()`, el proceso lee y escribe en el archivo con punteros
normales, **sin volver a entrar al kernel** (esa es toda la gracia de `mmap()`:
evitar el costo de las syscalls). Una defensa en espacio de usuario
(como una librería envuelta con `LD_PRELOAD`) es trivial de evitar: el atacante
no la carga, o llama `mmap()` directo. El único punto por donde pasan **todos**
los `mmap()`, sin excepción, está dentro del kernel. Por eso el control tiene
que vivir ahí.

### Resultados de las pruebas

> Esta sección se llena corriendo `make` y luego `sudo make test`.
> A continuación la salida obtenida en nuestra máquina (kernel
> 6.6 WSL2 / Ubuntu). Los resultados confirman que:

Salida resumida de `sudo make test` (kernel 6.6.87.2-microsoft-standard-WSL2, modo_estricto=1, pruebas como usuario normal uid 1000):

```
[lectura]    PERMITIDO
[escritura]  BLOQUEADO  errno=13 (Permission denied)
[privada]    BLOQUEADO  errno=13 (Permission denied)
[ejecucion]  BLOQUEADO  errno=13 (Permission denied)
[mprotect]   mmap de solo lectura funciono -> mprotect(PROT_WRITE) BLOQUEADO errno=13
[enlace duro /tmp/otro_nombre] escritura BLOQUEADO
[python] mismos 5 casos -> mismo resultado
[integridad] el archivo no fue modificado
[carrera cow_privada] archivo intacto (~1.4 millones de page faults de escritura en 3 s)
[carrera concurrente] 0 de 8 mmap de escritura pasaron

pruebas OK: 10   pruebas MAL: 0
```

Sin el módulo, los mismos programas sí logran modificar el archivo
(queda `HACKEADO...`), lo que confirma que el bloqueo lo hace el módulo.


Tabla resumen de lo que esperábamos:

| Prueba                          | Esperado   |
|---------------------------------|------------|
| `mmap` lectura                  | PERMITIDO  |
| `mmap` escritura compartida     | BLOQUEADO  |
| `mmap` escritura privada        | BLOQUEADO (modo estricto) |
| `mmap` ejecución                | BLOQUEADO  |
| truco `mprotect`                | BLOQUEADO  |
| integridad del archivo          | intacto    |
| carrera COW privada             | archivo intacto |
| mmap concurrentes de escritura  | 0 pasan    |

### Medición de impacto (overhead)

Para medirlo usamos `pruebas/benchmark.c` y el script
`pruebas/medir_overhead.sh` (`sudo make bench`). El benchmark mide
el tiempo promedio de un `mmap()`+`munmap()` y de un page fault en tres casos:
sin módulo (A), con módulo sobre un archivo no protegido (B) y con módulo
sobre el archivo protegido (C). Los page faults se cuentan con `getrusage()`
(como en el paso 5 del repositorio del profesor) y, si `strace` está
instalado, el script también corre `strace -c`.

Promedio de 3 corridas (100.000 mmap por corrida; archivo de 4 MB):

| Caso | mmap+munmap (ns) | page fault (ns) | page faults contados |
|------|------------------|-----------------|----------------------|
| A. sin módulo | 2152 | 2275 | 320 |
| B. con módulo, archivo no protegido | 2171 (+0.9%) | 2291 (+0.7%) | 320 |
| C. con módulo, archivo protegido | 2358 (+9.6%) | 2416 (+6.2%) | 320 |

Overhead = (C − A) / A: **+9.6% en mmap()** (unos 200 ns) y **+6.2% en page faults**.
Para archivos no protegidos (B) el promedio da +0.9%, pero con la mediana de
las 3 corridas es +5.3% (~110 ns). La medición con ftrace (abajo) confirma que
ese costo existe: es el de entrar al kprobe, que se paga en todos los mmap().

Se midieron 320 page faults y no 5120 (1024 páginas × 5 rondas) porque el
kernel hace *fault-around*: en cada fallo trae 16 páginas vecinas.
Las mediciones se hicieron en WSL2, que es una máquina virtual, así que los
tiempos absolutos incluyen el costo de la virtualización; la comparación
A/B/C sigue siendo válida porque las tres corrieron en las mismas condiciones.

`strace -c` no sirve para medir el overhead, porque el propio strace frena
cada syscall (con strace cada `mmap()` tarda ~14 µs en vez de ~2 µs). Sí sirve
para contar las llamadas: 1009 `mmap` = 1000 del benchmark + 1 de la prueba
de page faults + 8 de la carga de la libc.

### Medición con ftrace (tiempo dentro del kernel)

Para aislar el costo del módulo se usó ftrace (`sudo make ftrace`, script
`pruebas/medir_ftrace.sh`) con el tracer `function_graph`, limitado con
`set_ftrace_filter` a las dos funciones donde actúa el módulo. Se reporta la
mediana porque es menos sensible a interrupciones:

| Función | A. sin módulo | B. no protegido | C. protegido |
|---|---|---|---|
| `vm_mmap_pgoff` (mmap) | 848 ns | 948 ns (+11.8%) | 964 ns (+13.7%) |
| `handle_mm_fault` (page fault) | 1243 ns | 1295 ns (+4.2%) | 1310 ns (+5.4%) |

B y C cuestan casi lo mismo: el costo principal (~100 ns por mmap) es el del
mecanismo de kprobe, que se paga en todos los `mmap()` del sistema. Revisar
las reglas y auditar (solo en C) agrega unos 16 ns. Un LSM compilado dentro
del kernel evitaría ese costo, porque sus hooks son llamadas directas.

Nota de WSL2: la distro corre en su propio PID namespace, así que los pid que
se ven desde la terminal no son los que anota el kernel en el trace. Por eso el
script filtra por nombre de proceso y no usa `set_ftrace_pid`.

### De dónde sale el costo

El trabajo extra por cada `mmap()` sobre un archivo protegido es:

- comparar el inodo contra la lista (unas pocas comparaciones enteras),
- revisar las banderas,
- escribir una entrada en el buffer de auditoría (bajo spinlock).

Para `mmap()` sobre archivos **no** protegidos, el módulo solo compara el inodo
y sale de inmediato (`return 1`). Pero como muestra ftrace, el solo hecho de
entrar al kretprobe ya cuesta unos 100 ns, y eso lo pagan todos los `mmap()`
del sistema. El kprobe sobre `handle_mm_fault` se dispara en cada page fault
del sistema; por eso ahí no hacemos nada más que comparar el inodo y sumar un
contador atómico (+50 a 70 ns según ftrace).

Para ver una sola llamada a mano también sirve `strace -T`, que muestra entre
`< >` cuánto tardó cada `mmap()`:

```bash
strace -T -e trace=mmap ./pruebas/prueba_mmap /tmp/secreto.txt lectura
```

### Limitaciones y trabajo futuro

Lo que esta solución **no** cubre todavía:

1. **No cifra el contenido.** Controla quién mapea el archivo, pero si el UID
   autorizado lee datos sensibles, quedan en claro en su memoria. Trabajo
   futuro: integrar con `fscrypt`.
2. **Identificación por inodo.** Si el archivo se borra y se vuelve a crear,
   cambia el inodo y hay que recargar el módulo. Una versión mejor volvería a
   buscar el inodo cuando el archivo cambie.
3. **Un atacante con root** puede descargar el módulo (`rmmod`). Una versión de
   producción iría compilada dentro del kernel como un LSM de verdad, que no se
   puede descargar.
4. **No detiene un ataque tipo Dirty COW.** Ese exploit mapeaba el archivo con
   solo `PROT_READ` (que nuestro módulo permite) y escribía por
   `/proc/self/mem`, un camino que no pasa por `mmap()` ni `mprotect()`. La
   defensa contra eso es tener el kernel actualizado; nuestro módulo protege
   contra el abuso "normal" de `mmap()`, no contra bugs del propio kernel.
5. **A nivel de hardware/hipervisor**, un ataque de canal lateral o DMA podría
   leer la memoria física saltándose las tablas de páginas. Eso se mitiga con
   tecnologías como IOMMU o memoria cifrada (AMD SEV / Intel TDX), fuera del
   alcance de este parcial.

### Cómo reproducir

```bash
make && sudo make test      # compila, carga, prueba y descarga
sudo dmesg | tail -30       # mensajes del kernel (incluye las denegaciones)
```
