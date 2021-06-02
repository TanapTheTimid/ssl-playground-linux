#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "csapp.h"

#define DISCORD_GATEWAY_VERSION 9
#define DISCORD_GATEWAY_ENCODING "json"

SSL* ssl;

void init_openssl_2()
{
    SSL_library_init();
    SSL_load_error_strings();
}

int simpleReceive(FILE *filep)
{
    int loopcnt = 0;

    int max_len = 1000;
    int len;
    int total_read_bytes = 0;
    char buf[100000];

    do {
        len = SSL_read(ssl, buf, max_len);
        total_read_bytes += len;

        buf[len]=0;
        printf("%s",buf);
    } while (len > 0);
}

int main()
{
    int clientfd, errval;
    struct addrinfo hints, *listp, *p;
    char buf[MAXLINE];

    init_openssl_2();
    const SSL_METHOD* meth = TLS_client_method();




    char* hostname = "stackoverflow.com";
    char* request_uri = "/";
    char* required_header = "Host: stackoverflow.com\nConnection: close";
    char* port = "443";




    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET; // use ipv4
    hints.ai_flags = AI_NUMERICSERV; // numeric port
    hints.ai_flags |= AI_ADDRCONFIG; // use supported protocols
    Getaddrinfo(hostname, port, &hints, &listp);

    for (p = listp; p; p = p->ai_next) {
        Getnameinfo(listp->ai_addr, listp->ai_addrlen, buf, MAXLINE, NULL, 0,
            NI_NUMERICHOST);
        printf("%s:%d\n", buf, ((struct sockaddr_in*)(listp->ai_addr))->sin_port);
    }

    clientfd = socket(listp->ai_family, listp->ai_socktype, listp->ai_protocol);
    if (clientfd < 0) {
        printf("ERROR: cannot create socket.\n");
        return -1;
    }

    if (connect(clientfd, listp->ai_addr, listp->ai_addrlen) < 0) {
        printf("ERROR: cannot connect.\n");
        return -1;
    }

    SSL_CTX* ctx = SSL_CTX_new(meth);
    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("Error creating SSL.\n");
        return -1;
    }
    // sock = SSL_get_fd(ssl);
    SSL_set_fd(ssl, clientfd);
    int err = SSL_connect(ssl);
    if (err <= 0) {
        printf("Error creating SSL connection.  err=%x\n", err);
        return -1;
    }
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    // start transaction;;;;;;



    char request[MAX_REQUEST_LINE];
    sprintf(request, "GET %s HTTP/1.1\n%s\r\n\r\n", request_uri, required_header);
    printf("%s", request);

    SSL_write(ssl, request, strlen(request));

    simpleReceive();

    SSL_shutdown(ssl);
    SSL_clear(ssl);
    Close(clientfd);
}