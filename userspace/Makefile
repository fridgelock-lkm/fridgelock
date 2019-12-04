.PHONY: clean install ramfs

all: fridgelock_stage2 ramfs

fridgelock_stage2: fridgelock_stage2.c
	gcc -o fridgelock_stage2 fridgelock_stage2.c -O2
	#gcc -o fridgelock main.c -lcryptsetup -Wl,-z,now -O2
	#gcc -o fridgelock main.c -I/root/cryptsetup/include/ -L/root/cryptsetup/lib/ -lcryptsetup -O2

ramfs: fridgelock_stage2
	rm -rf ramfs
	./build-ramfs.py
	cp fridgelock_stage2 ramfs/bin/; cd ramfs; tar --owner=root:0 -cJf ../ramfs.tar.xz *

clean:
	rm -f fridgelock_stage2 ramfs.tar.xz
	rm -rf ramfs

install:
	install fridgelock_stage1 /usr/local/bin/
	install ramfs.tar.xz /usr/local/lib/
