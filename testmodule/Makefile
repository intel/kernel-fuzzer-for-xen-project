obj-m +=testmodule.o doublefetch.o

all:
	EXTRA_CFLAGS="-g -DDEBUG" make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
