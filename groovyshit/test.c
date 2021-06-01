#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "csapp.h"

SSL *ssl;
int sock;

/**
 * Initialise OpenSSL
 */
void init_openssl() {

    /* call the standard SSL init functions */
    SSL_load_error_strings();
    SSL_library_init();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /* seed the random number system - only really nessecary for systems without '/dev/random' */
    /* RAND_add(?,?,?); need to work out a cryptographically significant way of generating the seed */
}

void init_openssl_2(){
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
}

int RecvPacket()
{
    int len=100;
    char buf[1000000];
    do {
        len=SSL_read(ssl, buf, 100);
        buf[len]=0;
        printf("%s\n",buf);
//        fprintf(fp, "%s",buf);
    } while (len > 0);
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
    if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -1;
    }
}

int main(){
    int clientfd;
    struct addrinfo hints, *listp, *p;
    char buf[MAXLINE];

    char *hostname = "r5---sn-n3cgv5qc5oq-jwwe.googlevideo.com";
    char *request_line = "/videoplayback?expire=1622544840&ei=aL21YNaxAouilQSNjorgDg&ip=58.227.252.171&id=o-ANwxfvv9j-9rq4FB7yWaWgGKUb32y90q66XNenGv7_KD&itag=251&source=youtube&requiressl=yes&mh=ph&mm=31%2C29&mn=sn-n3cgv5qc5oq-jwwe%2Csn-n3cgv5qc5oq-bh2er&ms=au%2Crdu&mv=m&mvi=5&pl=25&initcwndbps=1417500&vprv=1&mime=audio%2Fwebm&ns=qtb1bk5WdOz87P4O4BC0CRgF&gir=yes&clen=3963609&dur=240.041&lmt=1497071637633052&mt=1622522926&fvip=5&keepalive=yes&fexp=24001373%2C24007246&c=WEB&n=0o7XMM8fs77iIF94&sparams=expire%2Cei%2Cip%2Cid%2Citag%2Csource%2Crequiressl%2Cvprv%2Cmime%2Cns%2Cgir%2Cclen%2Cdur%2Clmt&sig=AOq0QJ8wRQIhAMb2Yv0qTRlr5sVOKWs14Y6m1tuwtZO9FNa3tVVXlk5aAiB_5tZbHpC7pJvQUi1tiunP2kmIknWe-ln8b86EaWVs-Q%3D%3D&lsparams=mh%2Cmm%2Cmn%2Cms%2Cmv%2Cmvi%2Cpl%2Cinitcwndbps&lsig=AG3C_xAwRAIgSSZAj72PtBVoQA9_lC0pnOVPeg7Da79Dc-jZepeZsJwCIGT--StKd7CKhwNx262hOG6QPWRPt-OX6u3vadb0uGW8";
    char *required_header = "Host: r5---sn-n3cgv5qc5oq-jwwe.googlevideo.com";
    char *port = "443";

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;              //use ipv4
    hints.ai_flags = AI_NUMERICSERV;        //numeric port
    hints.ai_flags |= AI_ADDRCONFIG;        //use supported protocols
    Getaddrinfo(hostname, port, &hints, &listp);

    for (p = listp; p; p = p->ai_next) {
        Getnameinfo(listp->ai_addr, listp->ai_addrlen, buf, MAXLINE, NULL, 0, NI_NUMERICHOST);
        printf("%s:%d\n", buf, ((struct sockaddr_in*)(listp->ai_addr))->sin_port);
    }

    clientfd = socket(listp->ai_family, listp->ai_socktype, listp->ai_protocol);
    if(clientfd < 0){
        printf("ERROR: cannot create socket.\n");
        return -1;
    }

    if (connect(clientfd, listp->ai_addr, listp->ai_addrlen) < 0){
        printf("ERROR: cannot connect.\n");
        return -1;
    }

    init_openssl_2();

    const SSL_METHOD *meth = TLSv1_2_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);
    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("Error creating SSL.\n");
        return -1;
    }
    //sock = SSL_get_fd(ssl);
    SSL_set_fd(ssl, clientfd);
    int err = SSL_connect(ssl);
    if (err <= 0) {
        printf("Error creating SSL connection.  err=%x\n", err);
        return -1;
    }
    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

    //start transaction;;;;;;
    
    char request[10000];
    sprintf(request, "GET %s HTTP/1.1\n%s\r\n\r\n", request_line, required_header);
    printf("%s", request);

    SSL_write(ssl, request, strlen(request));
    RecvPacket();

    Close(clientfd);
}