all: test

test: test.c csapp.c csapp.h
	gcc -o test test.c csapp.h csapp.c -lpthread -lssl -lcrypto

fork: forktest.c csapp.c csapp.h
	gcc -o fork forktest.c csapp.c csapp.h -lpthread
	
clean:
	rm -rf test *.out fork *.m4a *.mp3