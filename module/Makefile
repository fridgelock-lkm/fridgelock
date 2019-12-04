obj-m += ramenc.o
ramenc-objs := src/ramenc.o src/userspace_device.o src/mm_crypt.o

EXTRA_CFLAGS=-I$(PWD)/include

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
