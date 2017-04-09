MODULE_NAME ?= setrace

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-y = src/setrace.o \
		   src/setrace_netlink.o \
		   src/setrace_sub.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
