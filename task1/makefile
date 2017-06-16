all: myELF

myELF: myELF.o
	gcc -g -m32 -Wall -o myELF myELF.o

myELF.o: myELF.c
	gcc -g -m32 -Wall -Iinclude -c -o myELF.o myELF.c
	
.PHONY: clean

clean:
	rm -f *.o myELF