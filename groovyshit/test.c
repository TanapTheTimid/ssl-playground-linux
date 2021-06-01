#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "csapp.h"

#define MAX_REQUEST_LINE 20000
#define MAX_HOSTNAME_LEN 100
#define MAX_URI_LEN 10000
#define MAX_HEADER_LEN 150
#define MAX_YOUTUBE_AUDIO_URL 10000
#define MAX_FILENAME_LEN 100

#define FILE_EXT ".m4a"

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
    int loopcnt = 0;

    int max_len = 1000;
    int len;
    int total_read_bytes = 0;
    char buf[100000];

    char headerbuf[10000];
    getHeader(headerbuf);

    printf("-----RESPONSE-----\n%s\n\n", headerbuf);

    int content_length = getContentLength(headerbuf);

    if(content_length < 0){
        printf("ERROR: unexpected content type (no content length given)\n");
        return -1;
    }else if(content_length == 0){
        printf("ERROR: unexpected redirect... retrying from start.\n");
        return -2;
    }

    printf("Content___length: %d\n\n", content_length);

    do {
        len = SSL_read(ssl, buf, max_len);
        total_read_bytes += len;

        //buf[len]=0;
        //printf("%s\n",buf);
        //fprintf(filep, "%s", buf);

        if(loopcnt % 128 == 0){
            printf("%d / %d\n", total_read_bytes, content_length);
        }
        loopcnt++;

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

void legalizeFilename(char *filename){
    char *p = strchr(filename, '/');
    while(p){
        *p = ' ';
        p = strchr(p, '/');
    }
}

void getRemoteInfoFromVideoId(char *video_id, char *hostname, char *request_uri, char *required_header, char *filename, char *envp[]){
    if(video_id == NULL){
        printf("Error: Please provide a video ID...\n");
        exit(-1);
    }

    pid_t pid;

    if((pid =Fork()) == 0){
        int fd = Open("audiostream.url.out", O_RDWR | O_CREAT | O_TRUNC, 0644);
        Dup2(fd, STDOUT_FILENO);

        char *argv[4];
        argv[0] = "/usr/bin/python3";
        argv[1] = "py_scripts/get_url_from_video_id.py";
        argv[2] = video_id;
        argv[3] = 0;

        Execve(argv[0], argv, envp);
    }
    Waitpid(pid, NULL, 0);

    int fd = Open("audiostream.url.out", O_RDWR | O_CREAT, 0644);

    char str[MAX_YOUTUBE_AUDIO_URL];

    int len = read(fd, str, MAX_YOUTUBE_AUDIO_URL);
    str[len] = 0;
    printf("%s\n", str);
    Close(fd);

    char *hostp = str + 8;
    char *hostp_end = strstr(hostp, ".com/") + 4;
    *hostp_end = 0;
    strcpy(hostname, hostp);

    *hostp_end = '/';
    char *urip_end = strstr(hostp_end, "\n");
    *urip_end = 0;
    strcpy(request_uri, hostp_end);

    char filename_no_ext[MAX_FILENAME_LEN - 10];
    char *namep_end = strstr(urip_end + 1, "\n");
    *namep_end = 0;
    strncpy(filename_no_ext, urip_end + 1, MAX_FILENAME_LEN - 10 - 1);
    filename_no_ext[MAX_FILENAME_LEN - 10 - 1] = 0;

    sprintf(filename, "%s"FILE_EXT, filename_no_ext);
    legalizeFilename(filename);

    sprintf(required_header, "Host: %s\nConnection: close", hostname);

    printf("%s\n\n%s\n\n%s\n\n%s\n", hostname, request_uri, required_header, filename);
    //exit(0);
}

#define HOSTNAME "r2---sn-n3cgv5qc5oq-jwwl.googlevideo.com"
#define REQUEST_URI "/videoplayback?expire=1622559759&ei=r_e1YJm5FLKHlQTY9ZqIAQ&ip=58.227.252.171&id=o-ALtkrdKwzddysav0Rzfo-ESbKjAoCycWUAX1sUxdeIzL&itag=140&source=youtube&requiressl=yes&mh=uQ&mm=31%2C29&mn=sn-n3cgv5qc5oq-jwwl%2Csn-n3cgv5qc5oq-bh2sy&ms=au%2Crdu&mv=m&mvi=2&pcm2cms=yes&pl=25&initcwndbps=1727500&vprv=1&mime=audio%2Fmp4&ns=UdFPmkQzsnY6tH8m6p2OyvEF&gir=yes&clen=4294541&dur=270.349&lmt=1509193663599179&mt=1622537805&fvip=2&keepalive=yes&fexp=24001373%2C24007246&c=WEB&n=i05CE_oLz_-Qr2KB&sparams=expire%2Cei%2Cip%2Cid%2Citag%2Csource%2Crequiressl%2Cvprv%2Cmime%2Cns%2Cgir%2Cclen%2Cdur%2Clmt&lsparams=mh%2Cmm%2Cmn%2Cms%2Cmv%2Cmvi%2Cpcm2cms%2Cpl%2Cinitcwndbps&lsig=AG3C_xAwRAIgXNJDvYD1b9rwsonQ-2QrKiFEJdE1V9YrOUqfv9IzjKcCIHQqFlhmrbqdHDdjdR6xkqhwuBaLDk5g5A2iHrneAK9h&sig=AOq0QJ8wRQIhAJBGC5YOaKqTLyU_uJtQajfQ176l753g4TjN7dPdGsRtAiBfRPKNiLH3UPLNM3n7Q2JsTQh41sM_2sWD-iVHKS5DMg=="

int main(int argc, char *argv[], char *envp[]){
    int clientfd, errval;
    struct addrinfo hints, *listp, *p;
    char buf[MAXLINE];

    init_openssl_2();
    const SSL_METHOD *meth = TLSv1_2_client_method();



    /*
    char *hostname = HOSTNAME;
    char *request_uri = REQUEST_URI;
    char *required_header = "Host: " HOSTNAME "\nConnection: close";
    char *port = "443";
    */

    /*
    hostname = "stackoverflow.com";
    request_uri = "/";
    required_header = "Host: stackoverflow.com\nConnection: close";
    */

    char hostname[MAX_HOSTNAME_LEN];
    char request_uri[MAX_URI_LEN];
    char required_header[MAX_HEADER_LEN];
    char filename[MAX_FILENAME_LEN];
    char *port = "443";



    do {

        getRemoteInfoFromVideoId(argv[1], hostname, request_uri, required_header, filename, envp);




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

        FILE *filep = fopen(filename,"w+");
        errval = RecvPacket(filep);

        fclose(filep);
        SSL_shutdown(ssl);
        SSL_clear(ssl);
        Close(clientfd);
    } while (errval == -2);
}