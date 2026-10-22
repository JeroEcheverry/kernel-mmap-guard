# Parte I — Análisis conceptual (10 preguntas, 30%)

> Respuestas al nivel de un curso de Sistemas Operativos de pregrado.
> Las estructuras y funciones citadas se verificaron contra los headers del
> kernel Linux 6.6 / 7.0 que usamos en el proyecto.

---

## 1. Mapeo virtual y page faults

**¿Qué pasa desde `mmap()` hasta el primer page fault?**

1. El proceso llama a `mmap()`. Esto es una llamada al sistema, así que la CPU
   pasa de modo usuario (Ring 3) a modo kernel (Ring 0).
2. El kernel entra a `do_mmap()` / `mmap_region()`. Ahí **no se copia el
   archivo a memoria todavía**. Solo se crea una estructura `vm_area_struct`
   (VMA) que describe la región: dónde empieza, qué tamaño tiene, qué permisos
   (`vm_flags`) y qué archivo representa (`vm_file`).
3. La VMA se agrega al `mm_struct` del proceso (el descriptor de su espacio de
   memoria). `mmap()` devuelve la dirección virtual, pero las tablas de páginas
   todavía no tienen entradas para esa zona.
4. Cuando el proceso accede por primera vez a esa dirección, la MMU busca la
   traducción en la tabla de páginas y no la encuentra: eso dispara un **page
   fault** (una excepción del procesador).
5. El kernel atiende el fault en `handle_mm_fault()`. Busca la VMA que cubre
   esa dirección, pide la página al Page Cache (leyéndola del disco si hace
   falta, lo que se llama *demand paging* o paginación por demanda), y llena la
   entrada de la tabla de páginas (PTE) para que apunte a la página física.
6. La CPU reintenta el acceso y esta vez sí funciona.

La clave para el proyecto: **el único momento garantizado en que el kernel ve
el `mmap()` es el paso 2.** Después de eso, las lecturas y escrituras pasan por
hardware. Por eso el control hay que ponerlo en el momento del `mmap()`, no en
cada lectura.

---

## 2. `MAP_SHARED` vs. `MAP_PRIVATE`

La diferencia se guarda en `vma->vm_flags`:

- **`MAP_SHARED`** pone el bit `VM_SHARED`. La región apunta directo a las
  páginas del Page Cache del archivo. Si el proceso escribe, el cambio queda en
  esas páginas y **termina en el disco** (y lo ven todos los procesos que tengan
  el mismo archivo mapeado como compartido). Es memoria compartida de verdad.

- **`MAP_PRIVATE`** no pone `VM_SHARED`. Las lecturas salen del Page Cache,
  pero en cuanto el proceso escribe, el kernel hace **Copy-On-Write**: copia la
  página a una página privada del proceso y escribe ahí. El archivo en disco
  **no cambia** y los otros procesos no ven nada.

Implicación de seguridad: `MAP_SHARED` es el peligroso para la integridad del
archivo, porque las escrituras son persistentes y visibles entre procesos. Por
eso nuestro módulo bloquea siempre `MAP_SHARED + PROT_WRITE` sobre archivos
protegidos. `MAP_PRIVATE` es menos grave (los cambios se quedan en la copia),
pero aun así lo bloqueamos en "modo estricto" porque es la base de ataques tipo
Dirty COW.

---

## 3. Mecanismo Copy-On-Write (COW)

**Ciclo de vida de una página bajo COW:**

1. Al mapear con `MAP_PRIVATE`, las PTEs quedan marcadas como **solo lectura**,
   aunque la VMA tenga permiso de escritura (`VM_MAYWRITE`). La página física
   es la misma del Page Cache y se comparte.
2. El proceso lee sin problema.
3. El proceso **escribe** → como la PTE es solo lectura, salta un page fault de
   escritura.
4. El kernel ve que la VMA sí permitía escribir (`VM_WRITE`), entonces hace la
   copia: reserva una página nueva, copia el contenido, y cambia la PTE del
   proceso para que apunte a la copia, ahora con permiso de escritura.
5. De ahí en adelante el proceso escribe en su copia privada.

**¿Cómo se vuelve peligroso?** Si el kernel maneja mal las banderas de
protección, puede confundir "esta página ya es privada y escribible" con "esta
página es la original del archivo". Ese fue exactamente el bug de **Dirty COW
(CVE-2016-5195)**: una condición de carrera entre la escritura COW y
`madvise(MADV_DONTNEED)` lograba que la escritura cayera sobre la página
original del archivo en vez de sobre la copia. Como se podían mapear archivos
de solo lectura del sistema (por ejemplo binarios con setuid), un usuario normal
podía modificarlos y escalar privilegios. El arreglo del kernel fue separar
mejor el bit de "puede escribir" (`FOLL_WRITE`) del de "forzar la copia"
(`FOLL_FORCE`) y usar `pte_dirty()` para saber si la copia ya se hizo.

---

## 4. Intercepción: módulo con hook a la syscall table vs. LSM

**Opción A — módulo (LKM) que modifica la System Call Table:**
Se busca la tabla `sys_call_table`, se guarda el puntero original de `mmap` y se
reemplaza por uno propio.
- Ventaja: control total, se ve la llamada antes que nadie.
- Desventajas: hay que desactivar la protección de escritura del registro CR0
  para modificar la tabla (frágil y peligroso si hay concurrencia), la tabla ya
  no se exporta (`sys_call_table` no es un símbolo público), y rompe fácil entre
  versiones de kernel. Es la opción "clásica de rootkit" y se considera mala
  práctica hoy.

**Opción B — Linux Security Module (LSM) con hooks como `mmap_file`:**
El kernel ya tiene puntos de enganche oficiales para seguridad (los mismos que
usan SELinux y AppArmor). El hook `security_mmap_file()` se llama en cada
`mmap()`.
- Ventajas: es la interfaz **diseñada para esto**, es estable entre versiones,
  no toca la tabla de syscalls ni CR0, y puede negar la operación devolviendo
  un error.
- Desventaja: históricamente había que compilar el LSM dentro del kernel; desde
  hace poco se pueden apilar varios, pero cargar uno nuevo como módulo suelto
  sigue siendo limitado.

**Lo que hicimos nosotros (opción intermedia):** un módulo con **kretprobe** sobre
`security_mmap_file()`. Así aprovechamos el punto de enganche oficial del LSM
(estable y seguro) pero sin tener que escribir un LSM completo ni recompilar el
kernel. Los kprobes son la API oficial para engancharse a funciones del kernel.

---

## 5. Cifrado transparente en memoria

Si el archivo está cifrado en disco, el flujo correcto sería:

1. El proceso autorizado hace `mmap()`.
2. Al primer page fault, el driver del sistema de archivos lee el bloque
   cifrado del disco.
3. **Antes** de poner la página en el Page Cache de ese proceso, el kernel la
   descifra (esto es lo que hace `fscrypt`, el cifrado por archivo de ext4/f2fs).
4. El proceso ve el texto claro en su mapeo.

El punto delicado es que la página descifrada vive en memoria física. Para que
otros procesos no autorizados no la lean, el kernel tiene que asegurarse de que
esa página solo esté mapeada en el espacio del proceso autorizado y que al
liberarla se borre (no quede "basura" descifrada en memoria que otro proceso
reciba después). `fscrypt` maneja las llaves por sesión/usuario para esto.
Nuestro proyecto **no implementa cifrado** (lo dejamos como trabajo futuro),
pero sí controla *quién* puede mapear el archivo, que es el primer paso.

---

## 6. Sincronización e integridad (`msync` / `fsync`)

Cuando un proceso escribe en un mapeo `MAP_SHARED`, el cambio queda primero solo
en memoria: la página se marca como **sucia** (dirty, bit `PG_dirty`). El kernel
la escribe al disco más tarde, de dos maneras:
- automáticamente, cuando el hilo `pdflush`/`writeback` decide persistir las
  páginas sucias, o
- cuando el proceso llama `msync()` (para mapeos) o `fsync()` (para el archivo)
  para forzarlo.

**El hueco de seguridad:** si un filtro de seguridad solo inspecciona en el
momento de `write()`/`fsync()`, un atacante puede escribir directo en el mapeo
(que no pasa por `write()`) y el dato sucio queda en memoria sin ser
inspeccionado hasta que el writeback lo baje solo. Por eso, de nuevo, la defensa
tiene que estar en el `mmap()` (decidir si se permite el mapeo escribible)
y no confiar en inspeccionar la escritura, porque la escritura al mapeo nunca
pasa por el kernel.

---

## 7. Control de accesos con eBPF

eBPF permite cargar pequeños programas en el kernel, de forma segura (un
verificador los revisa antes), sin recompilarlo ni reiniciar. Para auditar
`mmap()` se puede:

- Poner un **kprobe/fentry** a la entrada de `security_mmap_file()` o
  `do_mmap()` y registrar quién llamó, sobre qué archivo y con qué permisos.
- Poner un **fexit** al retorno para ver si la operación tuvo éxito.
- Usar la familia de hooks **BPF-LSM** (`CONFIG_BPF_LSM`), que permite incluso
  **negar** la operación devolviendo un error desde eBPF.

Ventaja sobre un módulo: más seguro (si el programa eBPF tiene un bug, el
verificador lo rechaza y no hay kernel panic) y no hay que compilar contra los
headers. Desventaja: el lenguaje es más limitado y para patrones complejos
(estado entre llamadas) toca usar mapas BPF. En nuestro proyecto usamos kprobes
desde un módulo en C porque era más directo para aprender las estructuras del
kernel, pero el mismo diseño se podría hacer con eBPF.

---

## 8. Evasión de permisos POSIX

**Sí se puede.** Si abro un archivo con `O_RDONLY`, igual puedo hacer:

```c
mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
```

y el kernel lo **permite**. ¿Por qué? Porque con `MAP_PRIVATE` las escrituras
van a una copia COW, **no al archivo**. Como el archivo original nunca se
modifica, el kernel considera que no se viola el permiso de solo lectura: solo
hace falta `PROT_READ` sobre el descriptor para `MAP_PRIVATE`. (En cambio
`MAP_SHARED + PROT_WRITE` sí exige que el `fd` esté abierto en modo escritura,
y ahí el kernel sí lo rechaza con `EACCES`.)

El riesgo: el proceso puede tener en su memoria una versión modificada del
archivo confidencial (fuga/alteración temporal), aunque el disco no cambie. Si
ese contenido se filtra o se vuelca a otro lado, hay un problema. Por eso en
"modo estricto" nuestro módulo también bloquea `MAP_PRIVATE + PROT_WRITE`.

---

## 9. Mitigación de carreras (`madvise(MADV_DONTNEED)` vs. escritura)

`madvise(MADV_DONTNEED)` le dice al kernel "ya no necesito estas páginas,
bótalas". El problema de Dirty COW era una carrera: un hilo escribía (forzando
la copia COW) mientras otro botaba la página con `MADV_DONTNEED`, y en el
momento justo el kernel perdía el rastro de si la copia privada ya existía,
terminando por escribir sobre la página original del archivo.

El kernel actual lo previene de varias formas:
- La escritura COW y el `madvise` toman el lock de la tabla de páginas (PTL),
  así que no pueden pisarse en la zona crítica.
- Se cambió la lógica para que la decisión de escribir use `pte_dirty()` y la
  bandera `FOLL_FORCE` / `FAULT_FLAG_WRITE` de forma consistente, de modo que
  botar la página no haga que el kernel crea que puede escribir en la original.

Nuestro `pruebas/carrera.c` ejecuta esta misma combinación (escritura a un
mapeo privado + `madvise(MADV_DONTNEED)` en paralelo) de forma benigna y
verifica que el archivo en disco **no cambie**, confirmando que el kernel 6.6
ya está parchado.

---

## 10. Aislamiento de memoria y paginación

Las piezas que mantienen aislada la memoria:

- **`struct page`**: hay una por cada página física. El kernel la usa para saber
  quién la usa, si está sucia, su conteo de referencias, etc.
- **Tablas de páginas jerárquicas (PGD → P4D → PUD → PMD → PTE):** traducen una
  dirección virtual a una física en varios niveles. Cada proceso tiene su propia
  jerarquía, así que la dirección `0x400000` de un proceso **no es** la misma
  memoria física que la de otro: ese es el aislamiento base.
- **Bits de protección de la MMU en cada PTE:**
  - **R/W**: si la página es solo lectura o también escritura. COW lo usa para
    marcar páginas compartidas como solo lectura.
  - **U/S** (User/Supervisor): si la página la puede tocar código de usuario o
    solo el kernel. Evita que un proceso lea memoria del kernel.
  - **NX** (No-eXecute): si se puede ejecutar código desde esa página. Es lo que
    impide inyectar datos y saltar a ejecutarlos.

**Relación con el proyecto:** nuestro módulo bloquea `PROT_EXEC` sobre los
archivos protegidos justamente para apoyarse en el bit NX: si nunca dejamos que
la página del archivo sea ejecutable, un atacante no puede usar ese archivo para
colocar y ejecutar código. El aislamiento por tablas de páginas separadas es lo
que garantiza que la copia privada de un proceso (COW) no la vea otro.
