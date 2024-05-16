obj-m += main.o
PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo $(PWD2)

clean:
	-mv compile_commands.json save
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	mv save compile_commands.json

reload:
	-rmmod $(PWD)/main.ko
	insmod $(PWD)/main.ko