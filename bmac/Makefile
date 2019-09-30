version = 1.0

obj-m += bmac.o

.PHONY: all modules clean install uninstall

all:
	@echo "To install, run \`sudo make install\`"

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

install:
	rm -rf /usr/src/bmac-kernel-*
	mkdir /usr/src/bmac-kernel-1.0
	cp -f *.c dkms.conf Makefile /usr/src/bmac-kernel-1.0
	-dkms add -m bmac-kernel -v $(version)
	dkms build -m bmac-kernel -v $(version)
	dkms install -m bmac-kernel -v $(version)

uninstall:
	modprobe -r bmac magma
	dkms remove bmac-kernel/$(version) --all
	rm -rf /usr/src/bmac-kernel-$(version)
