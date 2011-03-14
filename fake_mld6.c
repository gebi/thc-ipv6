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
  printf("Syntax: %s [-r] interface multicast-address [[target-address] [[ttl] [[own-ip] [own-mac-address]]]]\n", prg);
  printf("Advertise yourself in a multicast group of your choice\n");
  printf("Use -r to use raw mode.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[24];
  unsigned char *multicast6, *dst6 = NULL, *src6 = NULL, srcmac[6] = "", *mac = srcmac;
  int pkt1_len = 0;
  char *interface;
  int ttl = 1;
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
  multicast6 = thc_resolve6(argv[2]);
  if (argv[3] != NULL && argc > 3) 
    dst6 = thc_resolve6(argv[3]);
  else
    dst6 = thc_resolve6("ff02::2");
  if (argv[4] != NULL && argc > 4)
    ttl = atoi(argv[4]);
  if (argv[5] != NULL && argc > 5)
    src6 = thc_resolve6(argv[5]);
  else
    src6 = thc_get_own_ipv6(interface, dst6, PREFER_LINK);
  if (rawmode == 0) {
    if (argv[6] != NULL && argc > 6)
      sscanf(argv[6], "%x:%x:%x:%x:%x:%x", (unsigned int*)&srcmac[0], (unsigned int*)&srcmac[1], (unsigned int*)&srcmac[2], (unsigned int*)&srcmac[3], (unsigned int*)&srcmac[4], (unsigned int*)&srcmac[5]);
    else
      mac = thc_get_own_mac(interface);
  }

  memset(buf, 0, sizeof(buf));
  memcpy(buf, multicast6, 16);

  if ((pkt1 = thc_create_ipv6(interface, PREFER_LINK, &pkt1_len, src6, dst6, ttl, 0, 0, 0, 0)) == NULL)
    return -1;
  memset(buf, 0, sizeof(buf));
  buf[0] = 5;
  buf[1] = 2;
  if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf, 6) < 0)
    return -1;
  memset(buf, 0, sizeof(buf));
  memcpy(buf, multicast6, 16);
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_MLD_REPORT, 0, 0, (unsigned char *) &buf, 16, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac, NULL, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  printf("Starting advertisement of %s (Press Control-C to end)\n", argv[2]);
  while (1) {
    thc_send_pkt(interface, pkt1, &pkt1_len);
    sleep(5);
  }
  
  return 0;
}
