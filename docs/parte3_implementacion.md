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
  - `correr_pruebas.sh`: compila, carga el módulo, corre todo y lo descarga.

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

Las reglas están en `politica.c::aplicar_reglas()`:

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

> Esta sección se llena corriendo `sudo ./pruebas/correr_pruebas.sh`.
> A continuación la salida obtenida en nuestra máquina (kernel
> 6.6 WSL2 / Ubuntu). Los resultados confirman que:

<!-- RESULTADOS -->

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

El sobrecosto que agrega el módulo se puede medir con `perf` o `strace -T`
comparando el tiempo de un `mmap()` con y sin el módulo cargado. El trabajo
extra por cada `mmap()` sobre un archivo protegido es:

- comparar el inodo contra la lista (unas pocas comparaciones enteras),
- revisar las banderas,
- escribir una entrada en el buffer de auditoría (bajo spinlock).

Para `mmap()` sobre archivos **no** protegidos, el módulo solo compara el inodo
y sale de inmediato (`return 1`), así que el impacto es mínimo. El kprobe sobre
`handle_mm_fault` es el más sensible porque se dispara en cada page fault del
sistema; por eso ahí no hacemos nada más que comparar el inodo y sumar un
contador atómico.

Comando sugerido para medir (incluido como referencia):

```bash
# sin modulo
strace -T -e trace=mmap ./pruebas/prueba_mmap /tmp/secreto.txt lectura
# con modulo cargado, repetir y comparar el tiempo entre < >
```

### Limitaciones y trabajo futuro

Lo que esta solución **no** cubre todavía:

1. **No cifra el contenido.** Controla quién mapea el archivo, pero si el UID
   autorizado lee datos sensibles, quedan en claro en su memoria. Trabajo
   futuro: integrar con `fscrypt`.
2. **Identificación por inodo.** Si el archivo se borra y se vuelve a crear,
   cambia el inodo y hay que recargar el módulo. Una versión mejor lo
   re-resolvería o usaría el path con `notifier` de cambios.
3. **Un atacante con root** puede descargar el módulo (`rmmod`). Mitigación a
   futuro: firmar el módulo y activar lockdown, o moverse a BPF-LSM que es más
   difícil de quitar.
4. **A nivel de hardware/hipervisor**, un ataque de canal lateral o DMA podría
   leer la memoria física saltándose las tablas de páginas. Eso se mitiga con
   tecnologías como IOMMU o memoria cifrada (AMD SEV / Intel TDX), fuera del
   alcance de este parcial.

### Cómo reproducir

```bash
cd pruebas
sudo ./correr_pruebas.sh      # compila, carga, prueba y descarga
dmesg | tail -30              # mensajes del kernel (incluye las denegaciones)
```
