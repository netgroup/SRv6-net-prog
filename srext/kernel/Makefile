

obj-m := srext.o
srext-m := sr_helper.o sr_hook.o sr_genl.o 

INCLUDES="-I $(PWD)/../include"
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD:= $(shell pwd)

.PHONY: default install clean deinstall

default:
	$(MAKE) -C $(KERNELDIR) EXTRA_CFLAGS=${INCLUDES} M=$(PWD) modules
	
install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c *.markers *.symvers *.order .*.o.d .tmp_versions
	
deinstall:
	sudo rm -rf /lib/modules/$(shell uname -r)/extra/srext*
	
