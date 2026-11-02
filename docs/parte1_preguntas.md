# Parte I — Preguntas diagnósticas (30%)

> Probado en el kernel 6.6.87.2-microsoft-standard-WSL2 (Ubuntu sobre WSL2).

---

## 1. Mapeo virtual y page faults

¿Qué pasa desde `mmap()` hasta el primer page fault?

1. El proceso llama `mmap()` y la CPU pasa de modo usuario a modo
   kernel.
2. El kernel primero llama al hook de seguridad `security_mmap_file()` (ahí se
   engancha nuestro módulo). Si lo permite, crea una `vm_area_struct` (VMA):
   una estructura que describe la región (dónde empieza, tamaño, permisos y
   qué archivo es).
3. `mmap()` devuelve una dirección.
4. Cuando el proceso lee o escribe ahí por primera vez, la MMU (el hardware que
   traduce direcciones) no encuentra la traducción y lanza un **page fault**.
5. El kernel atiende el fallo en `handle_mm_fault()`:
   - si fue **lectura**, trae la página del archivo (del Page Cache o del
     disco) y de paso mapea algunas páginas vecinas;
   - si fue **escritura en `MAP_PRIVATE`**, hace una copia privada (COW);
   - si fue **escritura en `MAP_SHARED`**, usa la página del archivo y la marca
     como modificada.
6. El kernel llena la PTE y la CPU repite la instrucción, que ahora sí funciona.

Después de eso, las lecturas y escrituras van directo por hardware, sin pasar
por el kernel. Por eso el control hay que ponerlo en el `mmap()`.

---

## 2. `MAP_SHARED` vs. `MAP_PRIVATE`

- **`MAP_SHARED`**: Este escribe directamente sobre las páginas del
  archivo. Los cambios **llegan al disco** y otros procesos los ven.
- **`MAP_PRIVATE`**: si el proceso escribe, el kernel le hace una **copia
  propia** de la página (Copy-On-Write). El archivo no cambia y nadie más ve
  esos cambios.

Para la seguridad, `MAP_SHARED` con escritura es el peligroso, porque modifica
el archivo de verdad. Por eso nuestro módulo siempre lo bloquea.

*** `SHARED toca el archivo real (peligroso) y PRIVATE trabaja sobre una copia (el archivo no cambia).`***

---

## 3. Copy-On-Write (COW)

1. Con `MAP_PRIVATE`, el proceso comparte la página original, pero marcada como
   solo lectura.
2. Cuando intenta escribir, salta un page fault.
3. El kernel copia la página, y el proceso escribe en su copia.

**Cómo se vuelve peligroso:** Si el kernel se confunde y escribe en la página
original en vez de la copia, se puede modificar un archivo protegido. Eso pasó
con **Dirty COW (CVE-2016-5195)**: con una carrera entre dos hilos (uno
escribiendo por `/proc/self/mem` y otro botando la copia con `madvise`), el
kernel terminaba escribiendo en el archivo original. Así un usuario normal
podía modificar archivos de root y volverse root. Se arregló en 2016
verificando que la página donde se va a escribir sea de verdad la copia.

---

## 4. Syscall table vs. LSM

La pregunta es en qué punto del camino de mmap() dentro del kernel ponemos el portero 
(nuestro módulo, que revisa cada mmap() que pide un programa). 
Opción A: en la syscall table (cambiar la tabla), que es inseguro y lo que hacen los rootkits. 
Opción B: en la ventanilla oficial de seguridad, security_mmap_file() (LSM), que es segura pero 
normalmente hay que compilarla dentro del kernel. Nosotros pusimos el portero en la ventanilla 
oficial (B), pero enganchado con un kretprobe desde un módulo, para no recompilar el kernel.

---

## 5. Cifrado transparente en memoria

Si el archivo está cifrado en disco, el kernel lo descifra **cuando lo trae a
memoria** (en el page fault), antes de dárselo al proceso. Así el proceso ve
el texto claro y en el disco sigue cifrado. Linux ya hace esto con `fscrypt`.

---

## 6. `msync` / `fsync` y páginas sucias

Cuando un proceso escribe en un mapeo `MAP_SHARED`, el cambio queda primero en
memoria y la página se marca como **sucia** (modificada). Para saberlo, el
kernel se entera de la **primera** escritura en cada página (por un page
fault), pero **no de las siguientes ni de qué se escribió**.

La página se guarda en disco más tarde: sola (hilos del kernel llamados
*writeback*) o cuando el proceso llama `msync()` o `fsync()`.

**El problema:** un filtro que revise solo en `write()` o `fsync()` no ve las
escrituras al mapeo, porque no pasan por `write()`. El dato llega al disco sin
que nadie lo revise. Por eso hay que decidir en el `mmap()` si se permite
escribir o no.

---

## 7. eBPF

eBPF permite cargar programas pequeños dentro del kernel sin recompilarlo. Un
verificador los revisa antes, así que no pueden tumbar el sistema. Para
`mmap()` se puede:

- poner un **kprobe** a la entrada de `security_mmap_file()` y registrar quién
  mapea qué archivo y con qué permisos;
- poner un **fexit** a la salida para ver si funcionó;
- con **BPF-LSM**, incluso negar la operación.

Nosotros usamos un módulo en C porque era más directo para aprender, pero la
misma idea se podría hacer con eBPF.

---

## 8. `O_RDONLY` + `MAP_PRIVATE` + `PROT_WRITE`

**Sí se puede.** Si abro un archivo en solo lectura, igual puedo mapearlo con
`MAP_PRIVATE` y permiso de escritura. El kernel lo permite porque lo que
escribo va a mi **copia privada** (COW), no al archivo.

El riesgo: mi proceso tiene en memoria una versión alterada del archivo, que
podría filtrarse o usarse para engañar a otro programa. Por eso nuestro
"modo estricto" también bloquea este caso.

---

## 9. Carreras entre `madvise(MADV_DONTNEED)` y escrituras

`madvise(MADV_DONTNEED)` bota las páginas de un mapeo. En un mapeo privado,
eso borra la copia COW. Ese era el truco de Dirty COW: botar la copia justo
cuando el kernel iba a escribir.

El kernel actual lo evita con **bloqueos (locks)** sobre la tabla de páginas, y
verificando que la página sea la copia antes de escribir. Si la copia
desapareció, hace una nueva.

Nuestra prueba `carrera.c` hace algo parecido pero inofensivo: un hilo escribe
en la copia privada y otro llama `madvise` sin parar. Al final, el archivo
quedó intacto.

---

## 10. Aislamiento de memoria

- **Tablas de páginas** (PGD → P4D → PUD → PMD → PTE): cada proceso tiene las
  suyas, así que la misma dirección en dos procesos apunta a memoria física
  distinta. Ese es el aislamiento básico.
- **`struct page`**: el kernel tiene una por cada página física para saber
  quién la usa y si está modificada.
- **Bits de protección de cada PTE**:
  - **R/W**: si se puede escribir o solo leer (COW se apoya en esto).
  - **U/S**: si el código de usuario puede tocarla o solo el kernel.
  - **NX**: si se puede ejecutar código desde ahí.

Nuestro módulo bloquea `PROT_EXEC` sobre los archivos protegidos para
apoyarse en el bit NX: así nadie puede usar ese archivo para ejecutar código.