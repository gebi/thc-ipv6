#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <pcap.h>
#include "thc-ipv6.h"

extern int debug;

void help(char *prg) {
  printf("%s %s (c) 2010 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface src6 dst6 srcmac dstmac data\n\n", prg);
  printf("Craft your special icmpv6 echo request packet.\n");
  printf("With the exception of dst6 you can put an \"x\" to put the correct values in.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[24];
  unsigned char *src6 = NULL, *dst6 = NULL, smac[6] = "", dmac[6] = "", *srcmac = smac, *dstmac = dmac;
  int pkt1_len = 0, flags = 0, dlen = 0;
  char *interface;
  int rawmode = 0;

  if (argc != 7 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  interface = argv[1];
  if (strcmp(argv[2], "x") != 0)
    src6 = thc_resolve6(argv[2]);
  dst6 = thc_resolve6(argv[3]);
  if (strcmp(argv[4], "x") != 0)
    sscanf(argv[4], "%x:%x:%x:%x:%x:%x", (unsigned int*)&smac[0], (unsigned int*)&smac[1], (unsigned int*)&smac[2], (unsigned int*)&smac[3], (unsigned int*)&smac[4], (unsigned int*)&smac[5]);
  else
    srcmac = NULL;
  if (strcmp(argv[5], "x") != 0)
    sscanf(argv[5], "%x:%x:%x:%x:%x:%x", (unsigned int*)&dmac[0], (unsigned int*)&dmac[1], (unsigned int*)&dmac[2], (unsigned int*)&dmac[3], (unsigned int*)&dmac[4], (unsigned int*)&dmac[5]);
  else
    dstmac = NULL;
  dlen = strlen(argv[6]);
  if (dlen > sizeof(buf))
    dlen = sizeof(buf);
  memcpy(buf, argv[6], dlen);

  if ((pkt1 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt1_len, src6, dst6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_ECHOREQUEST, 0, flags, (unsigned char *) &buf, dlen, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, srcmac, dstmac, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  printf("Sending packet - look in tcpdump what is happening\n");
  thc_send_pkt(interface, pkt1, &pkt1_len);
  
  return 0;
}
