all: test discord udprtp

test: test.c csapp.c csapp.h
	gcc -o test test.c csapp.h csapp.c -lpthread -lssl -lcrypto

fork: forktest.c csapp.c csapp.h
	gcc -o fork forktest.c csapp.c csapp.h -lpthread

discord: discord.c csapp.c csapp.h
	gcc -o discord discord.c csapp.c csapp.h -lpthread -lssl -lcrypto

udprtp: udprtp.c csapp.c csapp.h
	gcc -O2 -o udprtp udprtp.c csapp.c csapp.h -lpthread -lssl -lcrypto -lsodium -lopus -logg

discordrun : discord PHONY
	./discord

discordformat: discord.c
	clang-format-10 --style=llvm discord.c > discord.c.format && rm discord.c && cat discord.c.format > discord.c && rm discord.c.format

udprtpformat: discord.c
	clang-format-10 --style=llvm udprtp.c > udprtp.c.format && rm udprtp.c && cat udprtp.c.format > udprtp.c && rm udprtp.c.format
	
clean:
	rm -rf test *.out fork *.m4a *.mp3 discord *.opus udprt *.ogg

PHONY: