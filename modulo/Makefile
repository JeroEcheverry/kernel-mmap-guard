# Makefile del modulo mmap_guard
#
# El modulo se arma con 3 archivos .c (main, politica, auditoria).
# KDIR es la carpeta con los headers del kernel; por defecto usa la del
# kernel que esta corriendo. Se puede cambiar: make KDIR=/otra/ruta

obj-m := mmap_guard.o
mmap_guard-objs := main.o politica.o auditoria.o

# Mostrar todos los warnings y tratarlos como error (clean build)
ccflags-y := -Wall -Werror

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
