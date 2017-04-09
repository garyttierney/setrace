ifeq (${KERNELRELEASE},)

KERNEL_SOURCE := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=$(PWD) clean

else

MODULE_NAME ?= setrace
EXTRA_CFLAGS := -I$(src)/include

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-y = src/setrace.o \
		   src/setrace_netlink.o \
		   src/setrace_sub.o

endif
