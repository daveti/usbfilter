# Makefile supports different kernel path
# Jul 1, 2014
# root@davejingtian.org
# http://davejingtian.org

ifneq ($(KERNELPATH),)
	KDIR	:= $(KERNELPATH)
else
	# Default kernel path
	KDIR	:= /lib/modules/$(shell uname -r)/build
endif

PWD	:= $(shell pwd)

obj-m += lum_block_scsi_write.o

all:
	make -C $(KDIR)  M=$(PWD) modules
clean:
	make -C $(KDIR)  M=$(PWD) clean

