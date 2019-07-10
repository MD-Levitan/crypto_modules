version = 1.0

obj-m += belt.o
obj-m += cfb.o

.PHONY: all modules clean install uninstall

all:
	@echo "To install, run \`sudo make install\`"

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

install:
	rm -rf /usr/src/belt-kernel-*
	mkdir /usr/src/belt-kernel-1.0
	cp -f *.c dkms.conf Makefile /usr/src/belt-kernel-1.0
	-dkms add -m belt-kernel -v $(version)
	dkms build -m belt-kernel -v $(version)
	dkms install -m belt-kernel -v $(version)

uninstall:
	modprobe -r belt magma
	dkms remove belt-kernel/$(version) --all
	rm -rf /usr/src/belt-kernel-$(version)
