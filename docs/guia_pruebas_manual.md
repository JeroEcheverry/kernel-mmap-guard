# Guía para probar el módulo a mano

Hace lo mismo que `sudo make test`, pero paso a paso. Conviene tener **dos
terminales**: una para los comandos y otra mirando los mensajes del kernel.

## 0. Antes de empezar

```bash
uname -r                            # version del kernel
ls /lib/modules/$(uname -r)/build   # si existe, se puede compilar
```

Si no existe: en Ubuntu normal, `sudo apt install linux-headers-$(uname -r)`.
En WSL2, seguir la sección "Compilar en WSL2" del `README.md`.

## 1. Compilar (sin sudo)

```bash
cd ~/proyectos/kernel-mmap-guard
make
```

No debe salir ningún warning (el Makefile usa `-Werror`).

## 2. Crear el archivo a proteger

```bash
sudo rm -f /tmp/secreto.txt
echo "contenido original secreto, no tocar" > /tmp/secreto.txt
chmod 666 /tmp/secreto.txt
```

Le damos permiso de escritura a todos a propósito: así se ve que lo que
bloquea es el módulo y no los permisos del archivo.

## 3. PoC: el ataque sin el módulo

```bash
cp /tmp/secreto.txt /tmp/poc.txt
./pruebas/prueba_mmap /tmp/poc.txt escritura
cat /tmp/poc.txt          # dice HACKEADO...: el ataque funciona
```

## 4. Cargar el módulo

Terminal 2:

```bash
sudo dmesg -w
```

Terminal 1:

```bash
sudo insmod modulo/mmap_guard.ko archivos=/tmp/secreto.txt modo_estricto=1
cat /proc/mmap_guard
```

## 5. Probar cada caso (sin sudo)

| Comando | Esperado |
|---------|----------|
| `./pruebas/prueba_mmap /tmp/secreto.txt lectura` | PERMITIDO |
| `./pruebas/prueba_mmap /tmp/secreto.txt escritura` | BLOQUEADO |
| `./pruebas/prueba_mmap /tmp/secreto.txt privada` | BLOQUEADO |
| `./pruebas/prueba_mmap /tmp/secreto.txt ejecucion` | BLOQUEADO |
| `./pruebas/prueba_mmap /tmp/secreto.txt mprotect` | paso 1 sí, paso 2 BLOQUEADO |
| `python3 pruebas/prueba_python.py /tmp/secreto.txt` | los mismos resultados |

En cada bloqueo, la terminal 2 muestra `mmap_guard: DENEGADO ...` y el
programa recibe `errno=13 (Permission denied)`.

```bash
cat /tmp/secreto.txt     # sigue diciendo "contenido original..."
```

## 6. Intentar engañarlo con un enlace

```bash
ln /tmp/secreto.txt /tmp/otro_nombre
ls -i /tmp/secreto.txt /tmp/otro_nombre            # mismo inodo
./pruebas/prueba_mmap /tmp/otro_nombre escritura   # BLOQUEADO
rm /tmp/otro_nombre
```

## 7. Modo estricto y carreras

```bash
echo 0 | sudo tee /sys/module/mmap_guard/parameters/modo_estricto
./pruebas/prueba_mmap /tmp/secreto.txt privada     # ahora PERMITIDO (copia COW)
./pruebas/carrera /tmp/secreto.txt cow_privada 3   # archivo intacto
echo 1 | sudo tee /sys/module/mmap_guard/parameters/modo_estricto
./pruebas/carrera /tmp/secreto.txt concurrente     # 0 de 8 pasan
```

## 8. Ver la auditoría

```bash
cat /proc/mmap_guard
```

Muestra los contadores y los últimos eventos (pid, usuario, proceso,
permisos pedidos y motivo).

## 9. Descargar

```bash
sudo rmmod mmap_guard
```

## Si algo sale mal

| Problema | Causa probable |
|----------|----------------|
| `make: ... /lib/modules/.../build: No such file` | faltan los headers (paso 0) |
| `insmod: ... Invalid parameters` | falta `archivos=` o la ruta no existe |
| `insmod: ... Exec format error` | el módulo se compiló para otra versión del kernel (`modinfo -F vermagic` vs `uname -r`) |
| `Permission denied` al crear `/tmp/secreto.txt` | quedó uno de otro usuario: `sudo rm /tmp/secreto.txt` |
| todo sale PERMITIDO | el módulo no está cargado |