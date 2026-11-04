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
El cuidado está en que solo el proceso autorizado tenga la página descifrada en 
su memoria, y que se borre al liberarla. Nuestro proyecto no cifra; solo controla 
quién mapea el archivo

---

## 6. `msync` / `fsync` y páginas sucias

Cuando un proceso escribe en un mapeo `MAP_SHARED`, el cambio queda primero en
memoria y la página se marca como sucia (modificada). Para saberlo, el
kernel se entera de la primera escritura en cada página (por un page
fault), pero **no de las siguientes ni de qué se escribió**.

La página se guarda en disco más tarde: sola (hilos del kernel llamados
*writeback*) o cuando el proceso llama `msync()` o `fsync()`.

---

## 7. eBPF

eBPF permite cargar programas pequeños dentro del kernel mientras está corriendo, 
sin recompilarlo. Se usa para observar lo que pasa en el sistema y para aplicar reglas 
de seguridad. Antes de cargarlo, un verificador revisa que el programa no pueda dañar 
el kernel, como ciclos infinitos ni accesos a memoria inválida.

Para vigilar mmap(), un programa eBPF puede poner un kprobe, una especie de espía, 
en security_mmap_file(), la función por donde pasan todos los mmap(). Así anota qué 
proceso mapea qué archivo y con qué permisos. Con un fexit (a la salida de la función)
 se ve si se permitió o no, y con BPF-LSM se podría incluso negar.

---

## 8. `O_RDONLY` + `MAP_PRIVATE` + `PROT_WRITE`

**Sí se puede.** Si abro un archivo en solo lectura, igual puedo mapearlo con
`MAP_PRIVATE` y permiso de escritura. El kernel lo permite porque lo que
escribo va a mi copia privada, no al archivo.

El riesgo es que si mi proceso tiene en memoria una versión alterada del archivo, que
podría filtrarse o usarse para engañar a otro programa. Por eso nuestro
"modo estricto" también bloquea este caso.

---

## 9. Carreras entre `madvise(MADV_DONTNEED)` y escrituras

Una condición de carrera es cuando dos cosas pasan al mismo tiempo y el resultado 
depende del orden. madvise(MADV_DONTNEED) bota la copia privada de COW; si eso se
cruza con una escritura, el kernel podría escribir en el original (Dirty COW). 
Hoy lo evita con dos cosas: candados sobre la tabla de páginas, las dos operaciones 
esperan su turno, y verificar que la página sea la copia antes de escribir; 
si la copia ya no existe, hace una nueva. Nuestra prueba carrera.c cruza millones 
de veces escrituras y madvise durante 3 segundos, y el archivo queda intacto.

---

## 10. Aislamiento de memoria

Cada proceso vive en su propia burbuja de memoria. Lo logran tres piezas:

Tabla de páginas, que es el mapa propio de cada proceso, que traduce sus direcciones 
a la RAM real. La misma dirección en dos procesos apunta a lugares distintos, así 
que uno no puede tocar la memoria de otro. Tiene niveles (PGD → P4D → PUD → PMD → PTE), 
como una dirección postal. La PTE dice dónde está cada página y con qué permisos.

struct page, quien es la libreta del kernel, con una hoja por cada página de la RAM. Anota 
quién la usa y si está sucia, para no darle a un proceso una página que ya es de otro.