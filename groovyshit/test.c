#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "csapp.h"

#define MAX_REQUEST_LINE 10000

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

void getHeader(char *headerbuf){
    char *hbp = headerbuf;

    char four[4];
    four[0] = 0;
    four[1] = 0;
    four[2] = 0;
    four[3] = 0;

    char buf[10];
    int len;

    do{
        len = SSL_read(ssl, buf, 1);

        *hbp = buf[0];
        hbp++;

        four[0] = four[1];
        four[1] = four[2];
        four[2] = four[3];
        four[3] = buf[0];

    }while(len > 0 && !(four[0] == '\r' && four[1] == '\n' && four[2] == '\r' && four[3] == '\n'));

    *hbp = 0;
}

int getContentLength(char *header){
    char *p_start, *p_end;

    p_start = strstr(header, "Content-Length:");
    if(!p_start){
        return -1;
    }

    p_start += 16;

    p_end = strstr(p_start, "\r\n");
    *p_end = 0;

    return atoi(p_start);
}

int RecvPacket(FILE *filep)
{
    int max_len = 1000;
    int len;
    int total_read_bytes = 0;
    char buf[100000];

    char headerbuf[10000];
    getHeader(headerbuf);

    printf("-----RESPONSE-----\n%s\n\n", headerbuf);

    int content_length = getContentLength(headerbuf);

    if(content_length < 0){
        printf("ERROR: unexpected content type (no content length given)");
        return -1;
    }

    printf("Content___length: %d\n\n", content_length);

    do {
        len = SSL_read(ssl, buf, max_len);
        total_read_bytes += len;

        //buf[len]=0;
        //printf("%s\n",buf);
        //fprintf(filep, "%s", buf);

        fwrite(buf, sizeof(char), len, filep);
        fflush(filep);
    } while (len > 0 && total_read_bytes < content_length);


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

    char *hostname = "r2---sn-n3cgv5qc5oq-jwwl.googlevideo.com";
    char *request_uri = "/videoplayback?expire=1622559759&ei=r_e1YJm5FLKHlQTY9ZqIAQ&ip=58.227.252.171&id=o-ALtkrdKwzddysav0Rzfo-ESbKjAoCycWUAX1sUxdeIzL&itag=140&source=youtube&requiressl=yes&mh=uQ&mm=31%2C29&mn=sn-n3cgv5qc5oq-jwwl%2Csn-n3cgv5qc5oq-bh2sy&ms=au%2Crdu&mv=m&mvi=2&pcm2cms=yes&pl=25&initcwndbps=1727500&vprv=1&mime=audio%2Fmp4&ns=UdFPmkQzsnY6tH8m6p2OyvEF&gir=yes&clen=4294541&dur=270.349&lmt=1509193663599179&mt=1622537805&fvip=2&keepalive=yes&fexp=24001373%2C24007246&c=WEB&n=i05CE_oLz_-Qr2KB&sparams=expire%2Cei%2Cip%2Cid%2Citag%2Csource%2Crequiressl%2Cvprv%2Cmime%2Cns%2Cgir%2Cclen%2Cdur%2Clmt&lsparams=mh%2Cmm%2Cmn%2Cms%2Cmv%2Cmvi%2Cpcm2cms%2Cpl%2Cinitcwndbps&lsig=AG3C_xAwRAIgXNJDvYD1b9rwsonQ-2QrKiFEJdE1V9YrOUqfv9IzjKcCIHQqFlhmrbqdHDdjdR6xkqhwuBaLDk5g5A2iHrneAK9h&sig=AOq0QJ8wRQIhAJBGC5YOaKqTLyU_uJtQajfQ176l753g4TjN7dPdGsRtAiBfRPKNiLH3UPLNM3n7Q2JsTQh41sM_2sWD-iVHKS5DMg==";
    char *required_header = "Host: r2---sn-n3cgv5qc5oq-jwwl.googlevideo.com\nConnection: close";
    char *port = "443";

    //hostname = "stackoverflow.com";
    //request_uri = "/";
    //required_header = "Host: stackoverflow.com\nConnection: close";

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

    char request[MAX_REQUEST_LINE];
    sprintf(request, "GET %s HTTP/1.1\n%s\r\n\r\n", request_uri, required_header);
    printf("%s", request);

    SSL_write(ssl, request, strlen(request));

    FILE *filep = fopen("rec.out","w+");
    RecvPacket(filep);

    fclose(filep);
    Close(clientfd);
}