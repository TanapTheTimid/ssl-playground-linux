#include "csapp.h"

int main(int argc, char *argv[], char *envp[]){
    pid_t pid;

    if((pid =Fork()) == 0){
        int fd = Open("hi.out", O_RDWR | O_CREAT, 0644);
        Dup2(fd, STDOUT_FILENO);

        char *argv[4];
        argv[0] = "/usr/bin/python3";
        argv[1] = "pyscript.py";
        argv[2] = "j6WuUAuD8JU";
        argv[3] = 0;

        Execve(argv[0], argv, envp);
    }
    Waitpid(pid, NULL, 0);

    int fd = Open("hi.out", O_RDWR | O_CREAT, 0644);

    char str[20];

    int len = read(fd, str, 20);
    str[len] = 0;
    printf("%s\n", str);

    Close(fd);
}