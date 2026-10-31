# Parte II — Estrategia con apoyo de IA (30%)

## 3.1 Cómo usamos la IA

Usamos un asistente de IA como apoyo, pero **verificando todo** contra el
código del kernel y probándolo en nuestra máquina.

- **Para entender la arquitectura:** le pedimos que nos explicara las opciones
  para vigilar `mmap()` (syscall table, LSM, kprobes). Después lo confirmamos
  en los headers del kernel.
- **Para el código en C:** nos dio el esqueleto del kretprobe. Tenía errores
  (ver alucinaciones), así que lo revisamos función por función y lo
  compilamos con `-Wall -Werror`.
- **Para las pruebas (PoC):** nos ayudó a listar qué ataques probar. Con eso
  hicimos `prueba_mmap.c`, `prueba_python.py` y `carrera.c`. **Sin el módulo**,
  un usuario normal logra modificar el archivo (queda `HACKEADO`); **con el
  módulo**, los mismos programas reciben "permiso denegado". Son pruebas
  controladas: solo atacan un archivo de prueba.
- **Para la revisión final:** le pedimos revisar todo contra la rúbrica.
  Encontró cosas que faltaban y nos ayudó a compilar y medir en WSL2. También
  se equivocó varias veces (ver abajo).

## 3.2 Prompts y verificación

### Prompts usados

| # | Contexto | Rol | Restricción | Resultado esperado |
|---|----------|-----|-------------|--------------------|
| 1 | Queremos vigilar todos los `mmap()` sobre un archivo. | Experto en kernel Linux. | Sin tocar la syscall table ni recompilar el kernel. | Que recomiende el hook `security_mmap_file` y kprobes. |
| 2 | Ya elegimos el hook `security_mmap_file`. | Programador de módulos en C. | Que compile en kernel 6.6 sin warnings. | Un kretprobe que lea los argumentos y devuelva `-EACCES`. |
| 3 | Alguien podría usar un enlace con otro nombre. | Experto en sistemas de archivos. | No comparar por nombre. | Comparar por inodo y dispositivo. |
| 4 | Hay que demostrar que la defensa funciona. | Ingeniero de pruebas. | Que no sea un exploit real. | Un programa que diga PERMITIDO o BLOQUEADO por caso. |
| 5 | Proyecto casi terminado + enunciado. | Revisor y evaluador. | Revisar punto por punto contra la rúbrica. | Lista de lo que falta o está mal. |
| 6 | `make` falla en WSL2 (no hay headers). | Experto en compilar el kernel. | Usar exactamente el kernel que está corriendo. | Pasos para poder compilar el módulo. |
| 7 | Hay que medir el overhead. | Experto en ftrace. | Medir solo nuestro benchmark y solo las funciones del módulo. | Un script que mida el tiempo dentro del kernel. |

### Alucinaciones detectadas

1. **Modificar la syscall table desactivando CR0.** Es una práctica insegura y
   la tabla ya no se exporta. Usamos kprobes.
2. **Usar una función no exportada** (sin `EXPORT_SYMBOL`) para sacar la ruta
   del archivo. No compiló. Usamos `%pD` en `printk`.
3. **Firma vieja de `handle_mm_fault`** con 2 argumentos. En el kernel 6.6
   tiene 4. Lo verificamos en `include/linux/mm.h`.
4. **`file_operations` para `/proc`.** En kernels nuevos se usa `proc_ops`.

### Errores de la IA que encontramos al probar

5. **Filtrar ftrace por pid.** No salían datos. Al revisar a mano vimos que el
   mismo proceso tenía un pid en la terminal (31123) y otro en el kernel
   (31478), porque WSL2 usa su propio "espacio de pids". Lo cambiamos a
   filtrar por nombre del proceso.
6. **ftrace mal configurado.** Enganchaba todas las funciones del kernel y hacía
   que todo fuera 4 veces más lento, dañando la medición. Lo limitamos a las 2
   funciones que nos interesan.
7. **Conclusión apresurada.** Dijo que en archivos no protegidos el costo era
   "menor al 1%". ftrace mostró que sí hay costo (~100 ns). Aprendimos a usar
   la mediana y a confirmar con dos herramientas.

### Validación y compilación

**Compilar en WSL2.** El kernel de WSL2 lo hace Microsoft, así que no existe
el paquete `linux-headers` y `make` fallaba. Lo resolvimos descargando el
código del kernel de **la misma versión** (6.6.87.2) con **la misma
configuración**, y compilándolo una vez para obtener `Module.symvers` (un
archivo con las "huellas" de las funciones del kernel que `insmod` revisa).

**Problema con GCC 15.** GCC 15 usa por defecto el estándar C23, donde `bool`
y `false` son palabras reservadas, y el kernel 6.6 las define él mismo. Una
parte del kernel no compilaba. Lo arreglamos agregando `-std=gnu11` en
`arch/x86/Makefile`.

**Para cada cambio del módulo:**

1. Revisar la firma real de la función en el código del kernel.
2. Compilar con `-Wall -Werror` (cualquier warning detiene todo).
3. Cargar con `insmod` y revisar `dmesg`.
4. Correr `sudo make test`.
5. Descargar con `rmmod`.


### Matriz de compensaciones

| Decisión | A favor (seguridad) | En contra (rendimiento) |
|----------|---------------------|-------------------------|
| Revisar en `mmap`/`mprotect`, no en cada escritura | Nadie se lo puede saltar | No vemos cada escritura (eso arruinaría la velocidad de mmap) |
| kretprobe en vez de LSM nativo | No hay que recompilar el kernel | ~100 ns extra en **todos** los `mmap()` del sistema; si el kprobe no alcanza a correr, deja pasar |
| Auditoría de cada evento | Queda registro de cada intento | Solo ~16 ns extra, y solo en archivos protegidos |
| Contar page faults | Vemos cuánto se usa el archivo | +4 a 5% en todos los page faults |
| Comparar por inodo | Un enlace con otro nombre no sirve para engañarlo | Si se borra y recrea el archivo, hay que recargar el módulo |