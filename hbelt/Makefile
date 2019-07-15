version = 1.0

obj-m += hbelt.o

.PHONY: all modules clean install uninstall

all:
	@echo "To install, run \`sudo make install\`"

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

install:
	rm -rf /usr/src/hbelt-kernel-*
	mkdir /usr/src/hbelt-kernel-1.0
	cp -f *.c dkms.conf Makefile /usr/src/hbelt-kernel-1.0
	-dkms add -m hbelt-kernel -v $(version)
	dkms build -m hbelt-kernel -v $(version)
	dkms install -m hbelt-kernel -v $(version)

uninstall:
	modprobe -r hbelt magma
	dkms remove hbelt-kernel/$(version) --all
	rm -rf /usr/src/hbelt-kernel-$(version)
