
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
  printf("%s %s (c) 2011 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-DHF] interface ip-address-advertised [target-address [mac-address-advertised [source-ip-address]]]\n\n", prg);
  printf("Advertise ipv6 address on the network (with own mac if not defined)\n");
  printf("sending it to the all-nodes multicast address if no target specified.\n");
  printf("Option -H adds a hop-by-hop header, -F a one shot fragment header,\n");
  printf("-D adds a large destination header which fragments the packet.\n");
//  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, *pkt2 = NULL, buf[24], buf2[6], buf3[1500];
  unsigned char *unicast6, *src6 = NULL, *dst6 = NULL, srcmac[6] = "", *mac = srcmac;
  int pkt1_len = 0, pkt2_len = 0, flags, prefer = PREFER_GLOBAL, i, do_hop = 0, do_dst = 0, do_frag = 0, cnt, type = NXT_ICMP6;
  char *interface;
  int rawmode = 0;
  thc_ipv6_hdr *hdr;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  while ((i = getopt(argc, argv, "DFHr")) >= 0) {
    switch (i) {
    case 'r':
      thc_ipv6_rawmode(1);
      rawmode = 1;
      break;
    case 'F':
      do_frag++;
      break;
    case 'H':
      do_hop = 1;
      break;
    case 'D':
      do_dst = 1;
      break;
    default:
      fprintf(stderr, "Error: invalid option %c\n", i);
      exit(-1);
    }
  }

  if (argc - optind < 2)
    help(argv[0]);

  interface = argv[optind];
  unicast6 = thc_resolve6(argv[optind + 1]);
  if (argc - optind >= 3 && argv[optind + 2] != NULL)
    dst6 = thc_resolve6(argv[optind + 2]);
  else
    dst6 = thc_resolve6("ff02::1");
  if (dst6 == NULL) {
    fprintf(stderr, "Error: could not resolve destination of advertise: %s\n", argv[optind + 2]);
    exit(-1);
  }
  if (rawmode == 0) {
    if (argc - optind >= 4 && argv[optind + 3] != NULL)
      sscanf(argv[optind + 3], "%x:%x:%x:%x:%x:%x", (unsigned int *) &srcmac[0], (unsigned int *) &srcmac[1], (unsigned int *) &srcmac[2], (unsigned int *) &srcmac[3],
             (unsigned int *) &srcmac[4], (unsigned int *) &srcmac[5]);
    else
      mac = thc_get_own_mac(interface);
  }
  if (argc - optind >= 5 && argv[optind + 4] != NULL)
    src6 = thc_resolve6(argv[optind + 4]);
  else
    src6 = unicast6;

  memset(buf, 0, sizeof(buf));
  memcpy(buf, unicast6, 16);
  buf[16] = 2;
  buf[17] = 1;
  memcpy(&buf[18], mac, 6);
  flags = ICMP6_NEIGHBORADV_OVERRIDE;
  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));

  if ((pkt1 = thc_create_ipv6(interface, prefer, &pkt1_len, src6, dst6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (do_hop) {
    type = NXT_HBH;
    if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf2, sizeof(buf2)) < 0)
      return -1;
  }
  if (do_frag) {
    if (type == NXT_ICMP6)
      type = NXT_FRAG;
    for (i = 0; i <= do_frag; i++)
      if (thc_add_hdr_oneshotfragment(pkt1, &pkt1_len, cnt++) < 0)
        return -1;
  }
  if (do_dst) {
    if (type == NXT_ICMP6)
      type = NXT_DST;
    if (thc_add_hdr_dst(pkt1, &pkt1_len, buf3, sizeof(buf3)) < 0)
      return -1;
  }
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_NEIGHBORADV, 0, flags, (unsigned char *) &buf, 24, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac, NULL, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }
  if ((pkt2 = thc_create_ipv6(interface, prefer, &pkt2_len, src6, dst6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (do_hop)
    if (thc_add_hdr_hopbyhop(pkt2, &pkt2_len, buf2, sizeof(buf2)) < 0)
      return -1;
  if (do_frag)
    for (i = 0; i <= do_frag; i++)
      if (thc_add_hdr_oneshotfragment(pkt2, &pkt2_len, cnt++) < 0)
        return -1;
  if (do_dst)
    if (thc_add_hdr_hopbyhop(pkt2, &pkt2_len, buf3, sizeof(buf3)) < 0)
      return -1;
  if (thc_add_icmp6(pkt2, &pkt2_len, ICMP6_NEIGHBORADV, 0, 0, (unsigned char *) &buf, 24, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac, NULL, pkt2, &pkt2_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  printf("Starting advertisement of %s (Press Control-C to end)\n", argv[optind + 1]);
  while (1) {
    if (do_dst) {
      hdr = (thc_ipv6_hdr *) pkt1;
      thc_send_as_fragment6(interface, src6, dst6, type, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, 1240);
      hdr = (thc_ipv6_hdr *) pkt2;
      thc_send_as_fragment6(interface, src6, dst6, type, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, 1240);
    } else {
      thc_send_pkt(interface, pkt1, &pkt1_len);
      thc_send_pkt(interface, pkt2, &pkt2_len);
    }
    sleep(5);
  }

  return 0;
}
