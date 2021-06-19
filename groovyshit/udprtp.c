/* Copyright 2012 Mozilla Foundation
   Copyright 2012 Xiph.Org Foundation
   Copyright 2012 Gregory Maxwell

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

   - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "csapp.h"
#include <sodium.h>
#include <sys/random.h>
#include <opus/opus.h>
#include <ogg/ogg.h>



#define SAMPLING_RATE 48000


#define ETH_HEADER_LEN 14
typedef struct {
  unsigned char src[6], dst[6]; /* ethernet MACs */
  int type;
} eth_header;

#define LOOP_HEADER_LEN 4
typedef struct {
  int family;
} loop_header;

#define IP_HEADER_MIN 20
#define IP6_HEADER_MIN 40
typedef struct {
  int version;
  int header_size;
  int protocol;
  char src[46];
  char dst[46];
} ip_header;

#define UDP_HEADER_LEN 8
typedef struct {
  int src, dst; /* ports */
  int size, checksum;
} udp_header;

#define RTP_HEADER_MIN 12
typedef struct {
  int version;
  int type;
  int pad, ext, cc, mark;
  int seq, time;
  int ssrc;
  int *csrc;
  int header_size;
  int payload_size;
} rtp_header;


/* helper, write a little-endian 32 bit int to memory */
void le32(unsigned char *p, int v)
{
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
  p[2] = (v >> 16) & 0xff;
  p[3] = (v >> 24) & 0xff;
}

/* helper, write a little-endian 16 bit int to memory */
void le16(unsigned char *p, int v)
{
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
}

/* helper, write a big-endian 32 bit int to memory */
void be32(unsigned char *p, int v)
{
  p[0] = (v >> 24) & 0xff;
  p[1] = (v >> 16) & 0xff;
  p[2] = (v >> 8) & 0xff;
  p[3] = v & 0xff;
}

/* helper, write a big-endian 16 bit int to memory */
void be16(unsigned char *p, int v)
{
  p[0] = (v >> 8) & 0xff;
  p[1] = v & 0xff;
}

/* check if an ogg page begins an opus stream */
int is_opus(ogg_page *og)
{
  ogg_stream_state os;
  ogg_packet op;

  ogg_stream_init(&os, ogg_page_serialno(og));
  ogg_stream_pagein(&os, og);
  if (ogg_stream_packetout(&os, &op) == 1) {
    if (op.bytes >= 19 && !memcmp(op.packet, "OpusHead", 8)) {
      ogg_stream_clear(&os);
      return 1;
    }
  }
  ogg_stream_clear(&os);
  return 0;
}

int serialize_rtp_header(unsigned char *packet, int size, rtp_header *rtp)
{
  int i;

  if (!packet || !rtp) {
    return -2;
  }
  if (size < RTP_HEADER_MIN) {
    fprintf(stderr, "Packet buffer too short for RTP\n");
    return -1;
  }
  if (size < rtp->header_size) {
    fprintf(stderr, "Packet buffer too short for declared RTP header size\n");
    return -3;
  }
  packet[0] = ((rtp->version & 3) << 6) |
              ((rtp->pad & 1) << 5) |
              ((rtp->ext & 1) << 4) |
              ((rtp->cc & 7));
  packet[1] = ((rtp->mark & 1) << 7) |
              ((rtp->type & 127));
  be16(packet+2, rtp->seq);
  be32(packet+4, rtp->time);
  be32(packet+8, rtp->ssrc);
  if (rtp->cc && rtp->csrc) {
    for (i = 0; i < rtp->cc; i++) {
      be32(packet + 12 + i*4, rtp->csrc[i]);
    }
  }

  return 0;
}

int update_rtp_header(rtp_header *rtp)
{
  rtp->header_size = 12 + 4 * rtp->cc;
  return 0;
}


void wait_for_time_slot(long delta)
{
  /* try to use POSIX monotonic clock */
  static int initialized = 0;
  static clockid_t clock_id;
  static struct timespec target;

  if (!initialized) {
#  if defined CLOCK_MONOTONIC && \
      defined _POSIX_MONOTONIC_CLOCK && _POSIX_MONOTONIC_CLOCK >= 0
    if (
#   if _POSIX_MONOTONIC_CLOCK == 0
        sysconf(_SC_MONOTONIC_CLOCK) > 0 &&
#   endif
        clock_gettime(CLOCK_MONOTONIC, &target) == 0) {
      clock_id = CLOCK_MONOTONIC;
      initialized = 1;
    } else
#  endif
    if (clock_gettime(CLOCK_REALTIME, &target) == 0) {
      clock_id = CLOCK_REALTIME;
      initialized = 1;
    }
  } else {
    target.tv_nsec += delta;
    if (target.tv_nsec >= 1000000000) {
      ++target.tv_sec;
      target.tv_nsec -= 1000000000;
    }
    clock_nanosleep(clock_id, TIMER_ABSTIME, &target, NULL);
  }
}


char *key;
char packet[65535];

int send_rtp_packet(int fd, struct sockaddr *addr, socklen_t addrlen,
    rtp_header *rtp, const unsigned char *opus_packet)
{
  //unsigned char *packet, *opus_encrypted_pack; //DANGEROUS
  int ret;

  update_rtp_header(rtp);
  //packet = malloc(rtp->header_size + rtp->payload_size + crypto_secretbox_MACBYTES); //DANGEROUS
  if (!packet) {
    fprintf(stderr, "Couldn't allocate packet buffer\n");
    return -1;
  }
  serialize_rtp_header(packet, rtp->header_size, rtp);


  //ENCRYPT HERE ___ENCRYPT OPUS PACKET___opus_packet
  char nonce[24];
  memcpy(nonce, packet, 12);
  memset(nonce + 12, 0, 12);

  //opus_encrypted_pack = malloc(rtp->payload_size + crypto_secretbox_MACBYTES); //DANGEROUS
  crypto_secretbox_easy(packet + rtp->header_size, opus_packet, rtp->payload_size, nonce, key);


  ret = sendto(fd, packet, 
      rtp->header_size + rtp->payload_size + crypto_secretbox_MACBYTES, 
      0,addr, addrlen);

  if (ret < 0) {
    fprintf(stderr, "error sending: %s\n", strerror(errno));
  }
  //free(packet);  //DANGEROUS
  //free(opus_encrypted_pack);   //DANGEROUS

  return ret;
}


int dis_ssrc;

int delay_count = 0;


int rtp_send_file_to_addr(const char *filename, struct sockaddr *addr,
    socklen_t addrlen, int payload_type)
{
  rtp_header rtp;
  int fd;
  int optval = 0;
  int ret;
  FILE *in;
  ogg_sync_state oy;
  ogg_stream_state os;
  ogg_page og;
  ogg_packet op;
  int headers = 0;
  char *in_data;
  const long in_size = 8192;
  size_t in_read;

  fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
  //check for fd < 0 Couldn't create socket
  ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
  //check ret < 0 Couldn't set socket options

  rtp.version = 2;
  rtp.type = payload_type;
  rtp.pad = 0;
  rtp.ext = 0;
  rtp.cc = 0;
  rtp.mark = 0;
  rtp.seq = rand();
  rtp.time = rand();
  rtp.ssrc = dis_ssrc; //= rand();  ////MODIFIED FROM ORIGINAL !!!!DANGEROUS
  rtp.csrc = NULL;
  rtp.header_size = 0;
  rtp.payload_size = 0;

  fprintf(stderr, "Sending %s...\n", filename);
  in = fopen(filename, "rb");
  //check !in Couldn't open input file
  
  ret = ogg_sync_init(&oy);
  //check ret < 0 Couldn't initialize Ogg sync state

  while (!feof(in)) {
    in_data = ogg_sync_buffer(&oy, in_size);
    //check !in_data ogg_sync_buffer failed

    in_read = fread(in_data, 1, in_size, in);
    ret = ogg_sync_wrote(&oy, in_read);
    //check ret < 0 ogg_sync_wrote failed

    while (ogg_sync_pageout(&oy, &og) == 1) {
      if (headers == 0) {
        if (is_opus(&og)) {
          /* this is the start of an Opus stream */
          ret = ogg_stream_init(&os, ogg_page_serialno(&og));
          //check ret < 0 ogg_stream_init failed
          headers++;
        } else if (!ogg_page_bos(&og)) {
          /* We're past the header and haven't found an Opus stream.
           * Time to give up. */
          fclose(in);
          return 1;
        } else {
          /* try again */
          continue;
        }
      }
      /* submit the page for packetization */
      ret = ogg_stream_pagein(&os, &og);
      //check ret < 0 ogg_stream_pagein failed
      
      /* read and process available packets */
      while (ogg_stream_packetout(&os,&op) == 1) {
        int samples;
        /* skip header packets */
        if (headers == 1 && op.bytes >= 19 && !memcmp(op.packet, "OpusHead", 8)) {
          headers++;
          continue;
        }
        if (headers == 2 && op.bytes >= 16 && !memcmp(op.packet, "OpusTags", 8)) {
          headers++;
          continue;
        }
        /* get packet duration */
        samples = opus_packet_get_nb_samples(op.packet, op.bytes, SAMPLING_RATE);
        if (samples <= 0) {
          fprintf(stderr, "skipping invalid packet\n");
          continue;
        }

        /* update the rtp header and send */
        rtp.seq++;
        rtp.time += samples;
        rtp.payload_size = op.bytes;
        fprintf(stderr, "rtp %d %d %d %3d ms %5d bytes\n",
            rtp.type, rtp.seq, rtp.time, samples/48, rtp.payload_size);
        send_rtp_packet(fd, addr, addrlen, &rtp, op.packet);
        

        //self modified DANGEROUS
        /* convert number of 48 kHz samples to nanoseconds without overflow */
        if(delay_count > -1){
          wait_for_time_slot(20000000); ///wait_for_time_slot(samples*62500/3);
        }else{
          delay_count++;
        }

      }
    }
  }

  if (headers > 0)
    ogg_stream_clear(&os);
  ogg_sync_clear(&oy);
  fclose(in);
  return 0;
}


int rtp_send_file(const char *filename, const char *dest, const char *port,
        int payload_type)
{
  int ret;
  struct addrinfo *addrs;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = IPPROTO_UDP;
  ret = getaddrinfo(dest, port, &hints, &addrs);
  if (ret != 0 || !addrs) {
    fprintf(stderr, "Cannot resolve host %s port %s: %s\n",
      dest, port, gai_strerror(ret));
    return -1;
  }
  ret = rtp_send_file_to_addr(filename, addrs->ai_addr, addrs->ai_addrlen,
    payload_type);
  freeaddrinfo(addrs);
  return ret;
}














int encryption(){
  if (sodium_init() == -1)
    return -1;

  //rtp_send_file(argv[1], argv[2], argv[3], 0x78);

  unsigned char msg[30];
  unsigned char out[crypto_secretbox_MACBYTES + 30] = {0};
  unsigned char out2[30] = {0};
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char key[crypto_secretbox_KEYBYTES];

  getrandom(nonce, crypto_secretbox_NONCEBYTES, 0);
  getrandom(key, crypto_secretbox_KEYBYTES, 0);
  strcpy(msg, "Hello Hello Hello Hello Hello");

  for(int x = 0; x < 30; x++){
    printf("%.2x ", msg[x]);
  }
  printf("\n");

  crypto_secretbox_easy(out, msg, 30, nonce, key);

  for(int x = 0; x < 30; x++){
    printf("%.2x ", out[x]);
  }
  printf("\n");

  int ret = crypto_secretbox_open_easy(out2, out, crypto_secretbox_MACBYTES + 30, nonce, key);

  printf("%d\n", ret);

  for(int x = 0; x < 30; x++){
    printf("%.2x ", out2[x]);
  }
  printf("\n");

  printf("%d %d\n", crypto_secretbox_NONCEBYTES, crypto_secretbox_KEYBYTES);
}

int dummy(){
  wait_for_time_slot(9999999);
  wait_for_time_slot(999999999);

  if (sodium_init() == -1)
    return -1;

  int fd = open("output.opus", O_RDONLY);

  unsigned char x[10000];

  read(fd, x, 10000);

  for (int i = 0; i < 1000; i++) {
    for (int j = 0; j < 8; j++) {
      printf("%.2x ", x[8 * i + j]);
    }
    printf("\n");
  }
}



int lol() {
  delay_count = 0;
  char diskey[32] = {97,237,125,242,73,232,161,10,30,215,179,93,65,128,97,234,18,153,139,186,120,155,231,51,85,99,17,254,94,174,86,113};
  key = diskey;
  dis_ssrc = 372972;
  rtp_send_file("testingfile.ogg", "213.179.201.59", "50001", 120);
}












#define MAX_URL_LEN 20000
#define MAX_FN_LEN 100
#define FILE_EXT ".ogg"

void legalizeFilename(char *filename){
    char *p = strchr(filename, '/');
    while(p){
        *p = ' ';
        p = strchr(p, '/');
    }
}

void getUrlFromVidId(char *video_id, char *url, char *filename, char *envp[]){
    int pipeids[2];
    
    if(video_id == NULL){
        printf("Error: Please provide a video ID...\n");
        exit(-1);
    }

    pipe(pipeids);

    pid_t pid;
    if((pid = Fork()) == 0){
        Close(pipeids[0]);
        Dup2(pipeids[1], STDOUT_FILENO);

        char *argv[4];
        argv[0] = "/usr/bin/python3";
        argv[1] = "py_scripts/get_url_from_video_id.py";
        argv[2] = video_id;
        argv[3] = 0;

        Execve(argv[0], argv, envp);
    }
    Close(pipeids[1]);
    char str[MAX_URL_LEN];
    int len = read(pipeids[0], str, MAX_URL_LEN);
    str[len] = 0;
    printf("%s\n", str);
    Close(pipeids[0]);
    Waitpid(pid, NULL, 0);

    char *urlendp = strstr(str, "\n");
    *urlendp = 0;
    strcpy(url, str);

    char filename_no_ext[MAX_FN_LEN - 10];
    char *namep_end = strstr(urlendp + 1, "\n");
    *namep_end = 0;
    strncpy(filename_no_ext, urlendp + 1, MAX_FN_LEN - 10 - 1);
    filename_no_ext[MAX_FN_LEN - 10 - 1] = 0;

    sprintf(filename, "%s"FILE_EXT, filename_no_ext);
    legalizeFilename(filename);

    printf("%s\n\n%s\n\n", url, filename);
    fflush(stdout);
}

int main(int argc, char *argv[], char *envp[]){
    char url[MAX_URL_LEN], filename[MAX_FN_LEN];
    int pid;

    if (access("audiostream.pipe.out", F_OK) != 0){
        mkfifo("audiostream.pipe.out", 0644);
    }

    for(int i = 1; i < argc; i++){

        getUrlFromVidId(argv[i], url, filename, envp);

        if((pid = Fork()) == 0){
            char *new_argv[30] = {
                  "ffmpeg"
                , "-ss"
                , "00:00:00.00"
                , "-i"
                , "..url.."
                , "-c:a"
                , "libopus"
                , "-b:a"
                , "64k"
                , "-vbr"
                , "off"
                , "-compression_level"
                , "4"
                , "-frame_duration"
                , "20"
                , "-application"
                , "audio"
                , "-f"
                , "ogg"
                , "-y"
                , "audiostream.pipe.out"
                , 0};

            printf("TEST: %s\n", url);
            fflush(stdout);
            new_argv[4] = url;
            //new_argv[19] = pipewritearg;

            if(execvp(new_argv[0], new_argv) < 0){
                printf("UNIX EXECVE ERROR\n");
                exit(1);
            }
        }
        
        delay_count = 0;
        char diskey[32] = {176,37,62,12,141,167,133,60,1,70,137,64,5,0,239,175,128,95,53,254,232,21,39,224,25,196,153,154,117,65,148,108};
        key = diskey;
        dis_ssrc = 66945;
        rtp_send_file("audiostream.pipe.out", "213.179.202.39", "50007", 120);

        Waitpid(pid, NULL, 0);
    }
}