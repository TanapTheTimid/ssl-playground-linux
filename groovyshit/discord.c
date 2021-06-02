#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "csapp.h"

#define DISCORD_GATEWAY_VERSION 9
#define DISCORD_GATEWAY_ENCODING "json"

#define MAX_REQUEST_LINE 20000

SSL* ssl;

void init_openssl_2()
{
    SSL_library_init();
    SSL_load_error_strings();
}

void getHeader(char* headerbuf)
{
    char* hbp = headerbuf;

    char four[4];
    four[0] = 0;
    four[1] = 0;
    four[2] = 0;
    four[3] = 0;

    char buf[10];
    int len;

    do {
        len = SSL_read(ssl, buf, 1);

        *hbp = buf[0];
        hbp++;

        four[0] = four[1];
        four[1] = four[2];
        four[2] = four[3];
        four[3] = buf[0];

    } while (len > 0 && !(four[0] == '\r' && four[1] == '\n' && four[2] == '\r' && four[3] == '\n'));

    *hbp = 0;
}

int simpleReceive()
{
    int loopcnt = 0;

    int max_len = 1000;
    int len;
    int total_read_bytes = 0;
    char buf[100000];

    do {
        len = SSL_read(ssl, buf, max_len);
        total_read_bytes += len;

        buf[len] = 0;
        printf("%s", buf);
        fflush(stdout);
    } while (len > 0 && total_read_bytes < 120);
}

int experimentalHeartbeat()
{
    int mask = 0xE35E26AB;

    unsigned char ws_frame[1000];
    unsigned char* wsf_ptr = ws_frame;

    //flags and opcode
    ws_frame[0] = 0x81;

    //mask and payload
    ws_frame[1] = 37 + 128;

    //set the mask
    *((unsigned int*)(wsf_ptr + 2)) = mask;

    strcpy(wsf_ptr + 6, "{\"op\": 1,\"d\": {},\"s\": null,\"t\": null}");

    wsf_ptr[6 + 37] = 0;

    printf("\n\nBITMASKING FRAME\n");

    unsigned char* mask_bytes = (char*)&mask;

    for (int i = 0; i < 37; i++) {
        wsf_ptr[6 + i] = wsf_ptr[6 + i] ^ mask_bytes[i % 4];
    }

    for (int i = 0; i < 6 + 37; i++) {
        if (i % 4 == 0)
            printf("\n");
        printf(" %8x ", wsf_ptr[i]);
    }

    printf("\n\nREADY TO SEND\n");

    SSL_write(ssl, ws_frame, 6 + 37);
}

int main()
{
    int clientfd, errval;
    struct addrinfo hints, *listp, *p;
    char buf[MAXLINE];

    init_openssl_2();
    const SSL_METHOD* meth = TLS_client_method();

    char* hostname = "gateway.discord.gg";
    char* request_uri = "/?v=9&encoding=json";
    char* required_header = "Host: gateway.discord.gg:443\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                            "Sec-WebSocket-Version: 13";
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
    sprintf(request, "GET %s HTTP/1.1\r\n%s\r\n\r\n", request_uri, required_header);
    printf("\n%s\n", request);

    SSL_write(ssl, request, strlen(request));
    char header[100000];
    getHeader(header);
    simpleReceive();

    experimentalHeartbeat();

    simpleReceive();

    SSL_shutdown(ssl);
    SSL_clear(ssl);
    Close(clientfd);
}