all: test

test: test.c csapp.c csapp.h
	gcc -o test test.c csapp.h csapp.c -lpthread -lssl -lcrypto
	
clean:
	rm -rf test