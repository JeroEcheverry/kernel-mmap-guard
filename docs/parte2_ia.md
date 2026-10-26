# Parte II — Estrategia con apoyo de Inteligencia Artificial (30%)

## 3.1 Flujo de trabajo asistido por IA

Usamos un asistente de IA (modelo tipo LLM) como apoyo, pero **verificando todo
contra los headers reales del kernel** antes de confiar en el código. El rol de
la IA se dividió en tres fases:

**Exploración de la arquitectura.** Al principio no sabíamos bien dónde
engancharnos para ver todos los `mmap()`. Le pedimos a la IA que explicara la
diferencia entre modificar la tabla de syscalls, escribir un LSM y usar kprobes.
Eso nos ahorró tiempo de leer documentación dispersa. Igual confirmamos sus
afirmaciones leyendo `include/linux/security.h` y `include/linux/kprobes.h`.

**Generación y verificación de código C.** La IA nos dio el esqueleto de un
kretprobe y la forma de leer los argumentos con `regs_get_kernel_argument()`.
Pero el código que propuso tenía errores (ver tabla de alucinaciones abajo), así
que no lo pegamos tal cual: lo revisamos función por función y lo compilamos con
`-Wall -Werror` para que no pasara ningún warning.

**Casos de prueba.** La IA nos ayudó a listar qué ataques probar (escritura
compartida, ejecución, el truco de `mprotect`, una carrera inspirada en Dirty COW). A
partir de esa lista escribimos `prueba_mmap.c` y `carrera.c`. Importante: las
pruebas son **benignas**, no son exploits reales; solo verifican que la defensa
responde como esperamos.

## 3.2 Ingeniería de prompts y verificación crítica

### Tabla de prompts usados

| # | Contexto / Rol | Restricción | Resultado esperado |
|---|----------------|-------------|--------------------|
| 1 | "Eres experto en kernel Linux. Quiero interceptar todos los `mmap()` sobre un archivo." | Sin modificar la syscall table ni recompilar el kernel. Kernel 6.x. | Que recomiende el hook LSM `security_mmap_file` y/o kprobes, con la firma correcta. |
| 2 | "Dame un kretprobe sobre `security_mmap_file` que lea los 3 argumentos y pueda negar el mmap." | Código C que compile en kernel 6.6, usando la API oficial de kretprobe. | `entry_handler` que lee args + `handler` de retorno que pone `-EACCES`. |
| 3 | "¿Cómo identifico un archivo sin usar su nombre, para que no me engañen con enlaces?" | No usar strings de ruta en la comparación. | Que proponga comparar por `(i_sb->s_dev, i_ino)` del inodo. |
| 4 | "Escríbeme un programa de usuario que pruebe que el mmap de escritura compartida queda bloqueado." | Que no sea un exploit real, solo una prueba que reporte permitido/bloqueado. | `prueba_mmap.c` con casos separados y código de salida claro. |

### Alucinaciones técnicas detectadas

Estas son cosas que la IA sugirió y que al verificar resultaron mal. Las dejamos
documentadas porque la rúbrica lo pide y porque fue la parte donde más
aprendimos:

1. **Hook de syscall con CR0.** La primera respuesta propuso modificar
   `sys_call_table` desactivando el bit WP del registro CR0. Es justo la práctica
   insegura que menciona el enunciado: sin control de concurrencia puede dejar el
   kernel en estado inconsistente, y además `sys_call_table` ya no se exporta.
   La descartamos por los kprobes.

2. **Símbolo no exportado.** Sugirió llamar directamente a una función interna
   para resolver la ruta del archivo. Al compilar dio error de símbolo no
   definido porque no está marcada con `EXPORT_SYMBOL`. Lo resolvimos usando
   `%pD` en `printk`, que sí es la forma soportada de imprimir el nombre de un
   `struct file`.

3. **Firma vieja de `handle_mm_fault`.** Propuso una versión con dos argumentos.
   En el kernel 6.6 la firma real tiene cuatro:
   `handle_mm_fault(vma, address, flags, regs)`. Lo verificamos en
   `include/linux/mm.h` y corregimos la lectura de argumentos.

4. **`proc_create` con `file_operations`.** Sugirió registrar el archivo de
   `/proc` con `struct file_operations`. En kernels modernos los archivos de
   `/proc` usan `struct proc_ops`. El build nos avisó y lo cambiamos.

### Validación manual y compilación

Procedimiento que seguimos para cada cambio:

1. Leer la firma real de la función en los headers (`grep` en
   `/usr/src/linux-headers-*/include/`).
2. Compilar con `make` usando `ccflags-y := -Wall -Werror` (cualquier warning
   detiene el build).
3. Cargar el módulo con `insmod`, revisar `dmesg` por si hay quejas.
4. Correr las pruebas y comparar el resultado con lo esperado.
5. Descargar con `rmmod` y confirmar que no quedan fugas ni mensajes de error.

## 3.3 Arquitectura seleccionada

### Diagrama conceptual

```
   ESPACIO DE USUARIO                          ESPACIO DE KERNEL (Ring 0)
  ┌───────────────────┐                       ┌──────────────────────────────┐
  │  proceso           │   mmap()/mprotect()   │  security_mmap_file()         │
  │  (puede ser el     │ ────────────────────> │  security_file_mprotect()     │
  │   atacante)        │                       │         │                     │
  └───────────────────┘                       │         ▼                     │
                                               │   [ kretprobe: mmap_guard ]   │
                                               │     1. ¿archivo protegido?    │
                                               │        (compara inodo)        │
                                               │     2. revisa reglas          │
                                               │     3. audita el evento       │
                                               │     4. si es peligroso:       │
                                               │        retorno = -EACCES      │
                                               │         │                     │
                                               │         ▼                     │
                                               │   /proc/mmap_guard  (reporte) │
                                               └──────────────────────────────┘
```

Elegimos **un módulo de kernel en C con kretprobes sobre los hooks LSM**
(`security_mmap_file` y `security_file_mprotect`), más un kprobe de solo lectura
sobre `handle_mm_fault` para contar page faults. Es un punto medio entre
escribir un LSM completo (mucho trabajo, hay que recompilar) y modificar la
tabla de syscalls (inseguro y frágil).

### Matriz de compensaciones (trade-offs)

| Decisión | A favor (seguridad) | En contra (rendimiento / alcance) |
|----------|---------------------|-----------------------------------|
| Hook en `mmap`/`mprotect` y no en cada escritura | Imposible saltárselo: toda proyección pasa por ahí | No vemos las escrituras una por una (pero es que eso es imposible sin romper el rendimiento de mmap) |
| kprobe en `handle_mm_fault` | Da visibilidad de cuántos faults genera el archivo | Se ejecuta en TODOS los faults del sistema → por eso solo comparamos inodo y sumamos, nada pesado |
| Comparar por inodo, no por nombre | No se engaña con enlaces duros/simbólicos | Si el archivo se borra y se recrea, cambia el inodo (hay que recargar) |
| Bloquear devolviendo `-EACCES` | El `mmap` le falla limpio al proceso | Un programa que no revise el error de `mmap` podría comportarse raro |
