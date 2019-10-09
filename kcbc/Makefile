version = 1.0

obj-m += kcbc.o

.PHONY: all modules clean install uninstall

all:
	@echo "To install, run \`sudo make install\`"

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

install:
	rm -rf /usr/src/kcbc-kernel-*
	mkdir /usr/src/kcbc-kernel-1.0
	cp -f *.c dkms.conf Makefile /usr/src/kcbc-kernel-1.0
	-dkms add -m kcbc-kernel -v $(version)
	dkms build -m kcbc-kernel -v $(version)
	dkms install -m kcbc-kernel -v $(version)

uninstall:
	modprobe -r kcbc
	dkms remove kcbc-kernel/$(version) --all
	rm -rf /usr/src/kcbc-kernel-$(version)
