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

    char *hostname = "r3---sn-n3cgv5qc5oq-jwwl.googlevideo.com";
    char *request_line = "/videoplayback?expire=1622500418&ei=4g-1YPC0Cqa0lQTniY2wDg&ip=58.227.252.171&id=o-AJp0HX5T5hybFisKy1F9DtObcD7OUumdWY1bkOkfPLrA&itag=140&source=youtube&requiressl=yes&mh=4R&mm=31%2C29&mn=sn-n3cgv5qc5oq-jwwl%2Csn-n3cgv5qc5oq-bh2sk&ms=au%2Crdu&mv=m&mvi=3&pcm2cms=yes&pl=25&initcwndbps=1121250&vprv=1&mime=audio%2Fmp4&ns=qs00s5tesXHPQ5zbKfROGukF&gir=yes&clen=72703826&dur=4492.317&lmt=1605913501856470&mt=1622478540&fvip=3&keepalive=yes&fexp=24001373%2C24007246&c=WEB&txp=5531432&n=C4nFhYGsCjp8UwXc&sparams=expire%2Cei%2Cip%2Cid%2Citag%2Csource%2Crequiressl%2Cvprv%2Cmime%2Cns%2Cgir%2Cclen%2Cdur%2Clmt&lsparams=mh%2Cmm%2Cmn%2Cms%2Cmv%2Cmvi%2Cpcm2cms%2Cpl%2Cinitcwndbps&lsig=AG3C_xAwRgIhAKuayQohTHrI6kMGbjJT1KAi_dAuFt6QAFtOZGiBnJLtAiEAvYNPlGUlJhbyb5QzvbqkvM0jPp05H6ofpNyUEJNAN7E%3D&sig=AOq0QJ8wRQIhAPb7q10X6wVpFiVE_GGP99wmRO-fXIB3eOfasjk99s2rAiB4JigJZEZ9TkB2OQE4N4nyMVdCNY7S5IRUHXlAySZKVg==";
    char *required_header = "Host: r3---sn-n3cgv5qc5oq-jwwl.googlevideo.com";
    char *port = "443";

    //hostname = "www.google.com";

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


    //char *request = "GET / HTTP/1.1\r\n\r\n";
    char request[10000];
    sprintf(request, "GET %s HTTP/1.1\n%s\r\n\r\n", request_line, required_header);
    printf("%s", request);

    SSL_write(ssl, request, strlen(request));
    RecvPacket();

    Close(clientfd);
}