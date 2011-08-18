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
char *frbuf, *frbuf2, *frint, buf3[1504];
int frbuflen, frbuf2len, do_hop = 0, do_frag = 0, do_dst = 0, type = NXT_ICMP6, seen = 0;
unsigned char *frip6, *frmac, *frdst;
thc_ipv6_hdr *frhdr = NULL;

void help(char *prg) {
  printf("%s %s (c) 2011 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-r] interface target\n\n", prg);
  printf("Sends an ICMPv6 node query request to the target and dumps the replies.\n\n");
//  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void dump_node_reply(u_char * foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  unsigned char *pkt = NULL, *ipv6hdr = (unsigned char *) (data + 14), *ptr;
  int pkt_len = 0, cnt, i, *j, k;

  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_INFOREPLY || header->caplen < 14 + 40 + 16)
    return;

  printf("Reply from %s:\n", thc_ipv62notation(ipv6hdr + 8));
  switch (ipv6hdr[45]) {
  case 2:
    printf("  DNS result: ");
    if (header->caplen <= 74) {
      printf("empty\n");
    } else {
      printf("%s\n", ipv6hdr + 60);
    }
    seen++;
    break;
  case 3:
    printf("  IPv6 result: ");
    if (header->caplen <= 90) {
      printf("empty\n");
    } else {
      printf("\n");
      i = 74;
      while (i + 16 <= header->caplen) {
        printf("    %s\n", thc_ipv62notation((char *) (data + i)));
        i += 20;
      }
    }
    seen++;
    break;
  case 4:
    printf("  IPv4 result: ");
    if (header->caplen == 70) {
      printf("empty\n");
    } else {
      printf("\n");
      i = 74;
      while (i + 4 <= header->caplen) {
        printf("    %d.%d.%d.%d\n", data[i], data[i + 1], data[i + 2], data[i + 3]);
        i += 8;
      }
    }
    seen++;
    break;
  default:
    printf("  Unknown type (%d) we did not send!\n", ipv6hdr[45]);
  }

  printf("\n");
}

void clean_exit(int sig) {
  exit(0);
}

int main(int argc, char *argv[]) {
  char *routerip, *interface, mac[6] = "", dmac[6] = "", string[] = "ip6 and icmp6";
  unsigned char *routerip6, *route6, *mac6 = mac, *ip6;
  unsigned char buf[512], *ptr;
  unsigned char *dst;
  int i, j, k, cnt;
  unsigned char *pkt = NULL;
  int pkt_len = 0;
  int rawmode = 0;
  pcap_t *p;

  if (argc != 3 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  while ((i = getopt(argc, argv, "r")) >= 0) {
    switch (i) {
    case 'r':
      thc_ipv6_rawmode(1);
      rawmode = 1;
      break;
    default:
      fprintf(stderr, "Error: invalid option %c\n", i);
      exit(-1);
    }
  }

  interface = argv[optind];
  mac6 = thc_get_own_mac(interface);
  dst = thc_resolve6(argv[2]);

  memset(buf, 0, sizeof(buf));
  memcpy(buf + 8, dst, 16);
  i = 24;
  cnt += getpid();
  memcpy(buf + 4, (char *) &cnt, 4);
  cnt++;

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n", interface, string);
    exit(-1);
  }

  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, NULL, dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_INFOREQUEST, 0, 0x00020000, buf, i, 0) < 0)
    return -1;
  if (thc_generate_and_send_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0)
    return -1;
  usleep(1000);
  memcpy(buf + 4, (char *) &cnt, 4);
  cnt++;
  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, NULL, dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_INFOREQUEST, 0, 0x0003003e, buf, i, 0) < 0)
    return -1;
  if (thc_generate_and_send_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0)
    return -1;
  usleep(1000);
  memcpy(buf + 4, (char *) &cnt, 4);
  cnt++;
  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, NULL, dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_INFOREQUEST, 0, 0x00040002, buf, i, 0) < 0)
    return -1;
  if (thc_generate_and_send_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0)
    return -1;

  signal(SIGALRM, clean_exit);
  alarm(5);
  while (seen != 3) {
    while (thc_pcap_check(p, (char *) dump_node_reply, NULL) > 0);
    usleep(100);
  }
  return 0;
}
