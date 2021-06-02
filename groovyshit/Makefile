all: test discord

test: test.c csapp.c csapp.h
	gcc -o test test.c csapp.h csapp.c -lpthread -lssl -lcrypto

fork: forktest.c csapp.c csapp.h
	gcc -o fork forktest.c csapp.c csapp.h -lpthread

discord: discord.c csapp.c csapp.h
	gcc -o discord discord.c csapp.c csapp.h -lpthread -lssl -lcrypto

discordformat: discord.c
	clang-format-10 --style=WebKit discord.c > discord.c.format && rm discord.c && cat discord.c.format > discord.c && rm discord.c.format
	
clean:
	rm -rf test *.out fork *.m4a *.mp3 discord