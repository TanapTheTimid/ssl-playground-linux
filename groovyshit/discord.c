#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "csapp.h"

#define DISCORD_GATEWAY_VERSION 9
#define DISCORD_GATEWAY_ENCODING "json"

#define MAX_REQUEST_LINE 20000

SSL* ssl;

useconds_t heartbeat_interval_micros;
int heartbeating = 0;
pthread_t heartbeat_tid;

char *heartbeat_str_p;

char *heartbeat_opcode;

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

int readFrameHeader(){
    unsigned char frameHeader[16];
    unsigned int len;

    len = SSL_read(ssl, frameHeader, 2);

    printf("\nframe header 0: %x\n", frameHeader[0]);

    unsigned short plen_short = frameHeader[1] & 127;

    if(plen_short < 126) {
        return plen_short;
    }
    else if(plen_short == 126){
        SSL_read(ssl, frameHeader + 2, 2);
        ((unsigned char *)(&plen_short))[1] = frameHeader[2];
        ((unsigned char *)(&plen_short))[0] = frameHeader[3];

        printf("longer length = %d\n", plen_short);
        return plen_short;
    }
    else {
        return -1;
    }

}

int experimentalHeartbeat(char *msg, int verbose);

void *threaded_heartbeat(void *ptr){
    while(1){
        usleep(heartbeat_interval_micros);
        experimentalHeartbeat(heartbeat_str_p, 0);
        printf("\n------HEARTBEAT SENT------\n");
    }
}

int simpleReceive()
{
    int loopcnt = 0;
    int len;
    int total_read_bytes = 0;

    int content_len = readFrameHeader();
    int readlen = content_len;
    char buf[content_len];

    if(content_len < 0){
        printf("ERROR: not websocket...");
        return -1;
    }

    do {
        len = SSL_read(ssl, buf, readlen);
        total_read_bytes += len;
        readlen -= len;
    } while (len > 0 && total_read_bytes < content_len);

    if(len == 0){
        printf("connection closed!");
        return 0;
    }

    buf[total_read_bytes] = 0;
    printf("-------READ-------\n%s\n-------END READ-------\n\n", buf);

    if(strstr(buf, heartbeat_opcode) && !heartbeating){
        char *heartbeatp = strstr(buf, "\"heartbeat_interval");
        heartbeatp += 21;
        char *hbp_end = strchr(buf, ',');
        *hbp_end = 0;

        
        heartbeat_interval_micros = atoi(heartbeatp) * 1000;

        printf("heartbeat interval microseconds: %d\n", heartbeat_interval_micros);

        heartbeating = 1;
        pthread_create(&heartbeat_tid, NULL, threaded_heartbeat, NULL);
    }
    fflush(stdout);

    return 1;
}

int saylong(char *msg, short msglen, int verbose){
    unsigned int mask = 0xE35E26AB;

    getrandom(&mask, sizeof(int), 0);

    if(verbose) printf("\nMASK: %x\n", mask);

    unsigned char ws_frame[1000];
    unsigned char* wsf_ptr = ws_frame;

    //flags and opcode
    ws_frame[0] = 0x81;

    //mask and payload
    ws_frame[1] = 126 + 128;

    ws_frame[2] = ((char *)(&msglen))[1];
    ws_frame[3] = ((char *)(&msglen))[0];

    //set the mask
    *((unsigned int*)(wsf_ptr + 4)) = mask;

    strcpy(wsf_ptr + 8, msg);

    wsf_ptr[8 + msglen] = 0;

    if(verbose) printf("\nBitmasking frame...\n");

    unsigned char* mask_bytes = (char*)&mask;

    for (int i = 0; i < msglen; i++) {
        wsf_ptr[8 + i] = wsf_ptr[8 + i] ^ mask_bytes[i % 4];
    }

    if(verbose){
        for (int i = 0; i < 8 + msglen; i++) {
            if (i % 4 == 0)
                printf("\n");
            printf(" %8x ", wsf_ptr[i]);
        }
    }

    if(verbose) printf("\nSending data...\n");

    SSL_write(ssl, ws_frame, 8 + msglen);
}

int sayshort(char *msg, short msglen, int opcode, int verbose){
    unsigned int mask = 0xE35E26AB;

    getrandom(&mask, sizeof(int), 0);

    if(verbose) printf("\nMASK: %x\n", mask);

    unsigned char ws_frame[1000];
    unsigned char* wsf_ptr = ws_frame;

    //flags and opcode
    ws_frame[0] = 0x80 + opcode;

    //mask and payload
    ws_frame[1] = msglen + 128;

    //set the mask
    *((unsigned int*)(wsf_ptr + 2)) = mask;

    strcpy(wsf_ptr + 6, msg);

    wsf_ptr[6 + msglen] = 0;

    if(verbose) printf("\nBitmasking frame...\n");

    unsigned char* mask_bytes = (char*)&mask;

    for (int i = 0; i < msglen; i++) {
        wsf_ptr[6 + i] = wsf_ptr[6 + i] ^ mask_bytes[i % 4];
    }

    if(verbose){
        for (int i = 0; i < 6 + msglen; i++) {
            if (i % 4 == 0)
                printf("\n");
            printf(" %8x ", wsf_ptr[i]);
        }
    }

    if(verbose) printf("\nSending data...\n");

    SSL_write(ssl, ws_frame, 6 + msglen);
}

int experimentalHeartbeat(char *msg, int verbose)
{
    short msglen = strlen(msg);
    if(verbose) printf("msglen: %d", msglen);
    if(msglen <= 125){
        sayshort(msg, msglen, 0x1, verbose);
    }else{
        saylong(msg, msglen, verbose);
    }
}

int closeWebsocket(){
    sayshort("hi", 2, 0x8, 0);
}

void *threaded_receive_websock(void *ptr){
    pthread_detach(pthread_self());
    int run = 1;
    while(run)
        run = simpleReceive();
}

int main(int argc, char *argv[], char *envp[])
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

    heartbeat_str_p = "{\"op\": 1,\"d\": {},\"s\": null,\"t\": null}";
    heartbeat_opcode = "\"op\":10";

    if(argc == 5){
        printf("\ncustom host!!\n\n");
        hostname = argv[1];
        request_uri = argv[2];
        char required_header_tmp[1000];
        sprintf(required_header_tmp, "Host: %s:443\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                            "Sec-WebSocket-Version: 13", hostname);
        required_header = required_header_tmp;
        heartbeat_str_p = argv[3];
        heartbeat_opcode = argv[4];
    }

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

    heartbeating = 0;
    SSL_write(ssl, request, strlen(request));
    
    char header[100000];
    getHeader(header);
    //simpleReceive();

    pthread_t tid1;
    pthread_create(&tid1, NULL, threaded_receive_websock, NULL);

    //experimentalHeartbeat(heartbeat_str_p, 0);
    //simpleReceive();

    char inputbuf[100000];
    while(1){
        fgets(inputbuf, 100000, stdin);

        if(inputbuf[0] == '0') break;

        if(inputbuf[0] != '1') 
            experimentalHeartbeat(inputbuf, 0);
    }

    pthread_cancel(tid1);
    pthread_cancel(heartbeat_tid);

    closeWebsocket();

    printf("closing websocket!\n\n");

    SSL_shutdown(ssl);
    SSL_clear(ssl);
    Close(clientfd);

    exit(0);
}