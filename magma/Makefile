version = 1.0

obj-m += magma.o

.PHONY: all modules clean install uninstall

all:
	@echo "To install, run \`sudo make install\`"

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

install:
	rm -rf /usr/src/kuznyechik-kernel-*
	mkdir /usr/src/kuznyechik-kernel-1.0
	cp -f *.c dkms.conf Makefile /usr/src/magma-kernel-1.0
	-dkms add -m magma-kernel -v $(version)
	dkms build -m magma-kernel -v $(version)
	dkms install -m magma-kernel -v $(version)

uninstall:
	modprobe -r magma
	dkms remove magma-kernel/$(version) --all
	rm -rf /usr/src/magma-kernel-$(version)
