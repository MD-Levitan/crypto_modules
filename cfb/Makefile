version = 1.0

obj-m += cfb.o

.PHONY: all modules clean install uninstall

all:
	@echo "To install, run \`sudo make install\`"

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

install:
	rm -rf /usr/src/cfb-kernel-*
	mkdir /usr/src/cfb-kernel-1.0
	cp -f *.c dkms.conf Makefile /usr/src/cfb-kernel-1.0
	-dkms add -m cfb-kernel -v $(version)
	dkms build -m cfb-kernel -v $(version)
	dkms install -m cfb-kernel -v $(version)

uninstall:
	modprobe -r cfb 
	dkms remove cfbt-kernel/$(version) --all
	rm -rf /usr/src/cfb-kernel-$(version)
