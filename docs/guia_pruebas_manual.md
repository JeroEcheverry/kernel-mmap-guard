# Guía para probar el módulo a mano

Esta guía hace lo mismo que `pruebas/correr_pruebas.sh`, pero paso a paso,
para ver con nuestros propios ojos qué pasa en cada caso. Conviene tener
**dos terminales** abiertas: una para los comandos y otra mirando los
mensajes del kernel.

---

## 0. Revisar el entorno

Para compilar un módulo se necesitan los *headers* del kernel que está
corriendo:

```bash
uname -r                            # version del kernel
ls /lib/modules/$(uname -r)/build   # si existe, se puede compilar
```

- **Ubuntu normal (VM o nativo):** si no existe la carpeta,
  `sudo apt install linux-headers-$(uname -r)`.
- **WSL2:** el kernel de WSL2 es de Microsoft y no hay paquete de headers.
  Hay dos opciones: compilar los headers desde el repositorio
  `microsoft/WSL2-Linux-Kernel` (con la misma versión que da `uname -r`), o
  usar una máquina virtual con Ubuntu. La VM es lo más sencillo.

Los kprobes tienen que estar activos en el kernel:

```bash
grep KPROBES /boot/config-$(uname -r)   # debe salir CONFIG_KPROBES=y
```

### Probar el entorno con el repositorio del profesor

Si los módulos del profesor cargan, el nuestro también va a cargar (usan el
mismo `KDIR`). Es una buena forma de descartar problemas del entorno:

```bash
cd ~/proyectos
git clone https://github.com/evalenciEAFIT/SO2026B.git
cd SO2026B/USOS/CapaKernel

make all                          # sin sudo: compila todo
make run-paso1                    # read(): 8192 syscalls
make run-paso2                    # mmap(): 0 syscalls de read
sudo ./scripts/load_modules.sh    # carga sus 3 modulos y crea /dev/demo_*
./paso3_driver_copy_user/test_copy_user
./paso4_driver_mmap_kernel/test_mmap
./paso6_demand_paging_fault/test_demand_paging
sudo dmesg | tail -25             # mensajes de sus modulos
sudo ./scripts/unload_modules.sh
```

Si `load_modules.sh` y las tres pruebas terminan sin error, el entorno está
listo. Si `make all` falla en los pasos 3, 4 o 6, faltan los headers.

---

## 1. Compilar

```bash
cd ~/proyectos/kernel-mmap-guard
make        # sin sudo: compila el modulo y los programas de prueba
```

Esto genera `modulo/mmap_guard.ko` y los programas `pruebas/prueba_mmap`,
`pruebas/carrera` y `pruebas/benchmark`. Compilar **sin sudo**: si se
compila como root, los archivos quedan a nombre de root y después
`make clean` falla.

Si `make` no muestra ningún warning, vamos bien (el Makefile usa `-Werror`,
así que cualquier warning detiene la compilación).

---

## 2. Crear el archivo a proteger

```bash
sudo rm -f /tmp/secreto.txt    # por si quedo uno de otra prueba
echo "contenido original secreto, no tocar" > /tmp/secreto.txt
chmod 666 /tmp/secreto.txt     # que cualquiera lo pueda abrir para escribir
```

Le damos permiso de escritura a todos a propósito: así se ve que lo que
bloquea es el módulo y no los permisos normales del archivo.

---

## 3. Cargar el módulo

En la **terminal 2**, dejar corriendo:

```bash
sudo dmesg -w      # muestra los mensajes del kernel en vivo
```

En la **terminal 1**:

```bash
sudo insmod modulo/mmap_guard.ko archivos=/tmp/secreto.txt modo_estricto=1
lsmod | grep mmap_guard        # debe aparecer
cat /proc/mmap_guard           # reporte inicial, contadores en 0
```

En `dmesg` deben salir las líneas `protegiendo /tmp/secreto.txt (inodo ...)`
y `cargado (modo_estricto=1, uid_autorizado=-1)`.

---

## 4. Probar cada caso

Correr como usuario normal (**sin** sudo). El programa termina con código
0 si se permitió y 1 si se bloqueó; `echo $?` lo muestra.

| Comando | Qué intenta | Esperado |
|---------|-------------|----------|
| `./pruebas/prueba_mmap /tmp/secreto.txt lectura` | `mmap(PROT_READ, MAP_SHARED)` | PERMITIDO |
| `./pruebas/prueba_mmap /tmp/secreto.txt escritura` | `mmap(PROT_WRITE, MAP_SHARED)` | BLOQUEADO |
| `./pruebas/prueba_mmap /tmp/secreto.txt privada` | `mmap(PROT_WRITE, MAP_PRIVATE)` | BLOQUEADO (modo estricto) |
| `./pruebas/prueba_mmap /tmp/secreto.txt ejecucion` | `mmap(PROT_EXEC)` | BLOQUEADO |
| `./pruebas/prueba_mmap /tmp/secreto.txt mprotect` | `mmap(PROT_READ)` y luego `mprotect(PROT_WRITE)` | paso 1 sí, paso 2 BLOQUEADO |

Después de cada caso bloqueado, en la terminal 2 debe aparecer una línea
`mmap_guard: DENEGADO ... motivo=...`. El error que ve el programa es
`errno=13 (Permission denied)`, que es el `-EACCES` que pone el módulo.

Revisar que el archivo no cambió:

```bash
cat /tmp/secreto.txt     # debe seguir diciendo "contenido original..."
```

---

## 5. Probar con otro programa (Python)

El bloqueo no depende de nuestro programa en C, funciona con cualquiera:

```bash
# mmap de lectura y escritura compartido -> debe dar PermissionError
python3 -c "import mmap; f=open('/tmp/secreto.txt','r+b'); mmap.mmap(f.fileno(), 0)"

# solo lectura -> debe funcionar e imprimir el contenido
python3 -c "import mmap; f=open('/tmp/secreto.txt','rb'); print(mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)[:])"
```

---

## 6. Intentar saltarse la protección con un enlace

```bash
ln /tmp/secreto.txt /tmp/otro_nombre        # enlace duro: otro nombre, mismo inodo
ls -i /tmp/secreto.txt /tmp/otro_nombre     # el numero de inodo es el mismo
./pruebas/prueba_mmap /tmp/otro_nombre escritura   # debe seguir BLOQUEADO
rm /tmp/otro_nombre
```

Esto funciona porque el módulo compara el **inodo**, no el nombre.

---

## 7. Cambiar el modo estricto sin recargar

El parámetro `modo_estricto` tiene permisos 0644, así que root lo puede
cambiar mientras el módulo está cargado:

```bash
echo 0 | sudo tee /sys/module/mmap_guard/parameters/modo_estricto
./pruebas/prueba_mmap /tmp/secreto.txt privada     # ahora PERMITIDO
cat /tmp/secreto.txt                                # el archivo NO cambio (copia COW)
echo 1 | sudo tee /sys/module/mmap_guard/parameters/modo_estricto
./pruebas/prueba_mmap /tmp/secreto.txt privada     # otra vez BLOQUEADO
```

Con `modo_estricto=0` se puede correr también la prueba de carrera de
copias privadas:

```bash
echo 0 | sudo tee /sys/module/mmap_guard/parameters/modo_estricto
./pruebas/carrera /tmp/secreto.txt cow_privada 3
echo 1 | sudo tee /sys/module/mmap_guard/parameters/modo_estricto
./pruebas/carrera /tmp/secreto.txt concurrente
```

---

## 8. Ver la auditoría

```bash
cat /proc/mmap_guard
```

Debe mostrar los contadores (revisados, denegados, page faults) y la tabla de
los últimos eventos con pid, uid, proceso, permisos pedidos y el motivo.
Comparar que el número de denegados coincide con los casos bloqueados que
corrimos.

---

## 9. (Opcional) Usuario autorizado

```bash
sudo rmmod mmap_guard
sudo insmod modulo/mmap_guard.ko archivos=/tmp/secreto.txt uid_autorizado=$(id -u)
./pruebas/prueba_mmap /tmp/secreto.txt escritura   # PERMITIDO para nuestro usuario
sudo ./pruebas/prueba_mmap /tmp/secreto.txt escritura   # root (uid 0) sigue BLOQUEADO
```

Ojo: el caso permitido **sí escribe** "HACKEADO" en el archivo. Volver a
crearlo como en el paso 2 antes de seguir probando. Como el archivo nuevo
tiene otro inodo, también hay que recargar el módulo.

---

## 10. Descargar

```bash
sudo rmmod mmap_guard
ls /proc/mmap_guard        # ya no existe
```

En `dmesg` sale `descargado. mmap denegados=N mprotect denegados=M`.

---

## Si algo sale mal

| Problema | Causa probable |
|----------|----------------|
| `make: *** /lib/modules/.../build: No such file` | faltan los headers (paso 0) |
| `insmod: ERROR: ... Invalid parameters` | falta el parámetro `archivos=` o la ruta no existe (`dmesg` dice cuál) |
| `bash: /tmp/secreto.txt: Permission denied` al crear el archivo | quedó uno de otro usuario en `/tmp`: borrarlo con `sudo rm /tmp/secreto.txt` |
| `insmod: ... Key was rejected by service` | Secure Boot activo: el kernel solo acepta módulos firmados. Desactivarlo en la VM |
| `fallo kretprobe security_mmap_file` en `dmesg` | el kernel no tiene kprobes o no deja engancharse a esa función |
| todo sale PERMITIDO | el módulo no está cargado o se corrió con `uid_autorizado` igual a nuestro uid |
