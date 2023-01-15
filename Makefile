######## Documentation (1/2)

# Kernel build system requires makefiles that do not look like traditional ones.
# The said system hadles all this stuff. See for more:
# https://www.kernel.org/doc/Documentation/kbuild/
# (makefiles.txt and modules.txt should be the main ones)

# This line states that there is one module to be built from obj file <name>.o.
# The resulting module will be named <name>.ko after being built:
# obj-m := sbdd.o

# The command to build a module is the following:
# $ make -C <path_to_kernel_source_tree> M=`pwd` modules
# In the '<path_...>' it finds kernel's top-level makefile.
# 'M=...' option sets the path to module's files.
# 'modules' is the target of make. It refers to the list of modules found
# in the obj-m variable.


######## Documentation (2/2)

# There is an idiom on creating makefiles for kernel developers.
# If KERNELRELEASE is defined, we've been invoked from the kernel build system
# (we get here the 2nd time when 'modules' target is processed):
# ifneq ($(KERNELRELEASE),)
# 	# It is actually a Kbuild part of makefile (should be placed in different file)
# 	# and will only be processed by kbuild system, not make.
# 	obj-m := sbdd.o
# # Otherwise we were called directly from the command line and should invoke kbuild.
# else
# default:
# 	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
# endif


######## Makefile

TARG_BLK = /dev/disk/by-id/ata-QEMU_HARDDISK_QM00001
TARG_BLK2 = /dev/disk/by-id/ata-QEMU_HARDDISK_QM00003
DISK_LIST = "$(TARG_BLK),$(TARG_BLK2)"
SBDD_BLK = /dev/sbdd
DD_ARGS  = bs=512 count=1

default:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

load:
	dmesg -C
	insmod sbdd.ko disklist=$(DISK_LIST)
	dmesg

unload:
	dmesg -C
	rmmod sbdd.ko
	dmesg

test1:
	dd $(DD_ARGS) if=/dev/urandom of=$(SBDD_BLK)
	blockdev --flushbufs $(TARG_BLK)
	dd $(DD_ARGS) if=$(TARG_BLK) of=./drive.log
	dd $(DD_ARGS) if=$(SBDD_BLK) of=./sbdd.log
	diff ./sbdd.log ./drive.log

test2:
	dd $(DD_ARGS) if=/dev/urandom of=$(TARG_BLK)
	dd $(DD_ARGS) if=$(TARG_BLK) of=./drive.log
	dd $(DD_ARGS) if=$(SBDD_BLK) of=./sbdd.log
	diff ./sbdd.log ./drive.log

