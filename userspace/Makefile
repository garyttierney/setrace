CC ?= gcc
CFLAGS = -I../module/include -Wall \
	 $(shell pkg-config --libs --cflags libnl-genl-3.0 libnl-cli-3.0)

all: setrace
clean:
	rm -f ./setrace
	rm -f src/main.o

setrace: src/main.o
	$(CC) $(CFLAGS) -o setrace src/main.o
