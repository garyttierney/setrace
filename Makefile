.PHONY: all clean module userspace

all: module userspace
clean: module-clean userspace-clean

module:
	$(MAKE) -C module

module-clean:
	$(MAKE) -C module clean

userspace:
	$(MAKE) -C userspace

userspace-clean:
	$(MAKE) -C userspace clean
