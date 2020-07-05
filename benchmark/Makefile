
all : test
test: ../my_vm.h
	gcc test.c -L../ -lmy_vm -o test -lm -pthread

clean:
	rm -rf test
