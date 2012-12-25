all:
	make clean
	make sha256

sha256: sha256.c 
	gcc -c -O3 -march=i686 -funroll-loops -fforce-addr -minline-all-stringops sha256.c testes.c -Wall
	gcc -o sha256 sha256.o testes.o
clean: 
	rm -rf sha256 *~ *.o

