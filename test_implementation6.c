/*
 * Test:
 *       1. next header = hopbyhop, but no header
 *       2. next header = hopbyhop, but invalid length in hopbyhop header
 *       3. next header = hophyhop + no_next, but ip6 length longer than claimed
 *       4. next header = hophyhop + no_next, but ip6 length shorter than claimed
 *       5. 90 extension ignored headers
 *       6. 65535 byte packet (fragmented) with 3850 extension ignored headers
 *       7. jumbo packet (fragmented) with 7700 extension ignored headers
 *       8-10: same as 5-9 but final length larger than real packet
 *       11. 180 hop-by-bop headers
 *       12. forwarding header with 255 segements lefts (but only 1 defined)
 *
 *
 *       misc:
 *         - toobig6 with mtu = 600 on target
 *         - alive6 with target ff02::1 and router = target
 *         - alive6 with target = target and router = target (1shot frag + forward)
 *         - rsmurf on target
 */

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

unsigned char *pkt = NULL;
int pkt_len = 0;
thc_ipv6_hdr *ipv6;
char *interface;
int rawmode = 0;

void help(char *prg) {
  printf("%s %s (c) 2006 by %s %s\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-r] interface destination [test-case-number]\n", prg);
  printf("Performs some ipv6 implementation checks\n");
  printf("Use -r to use raw mode.\n");
  exit(-1);
}

void intercept(u_char *foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *)(data + 14);

// not used yet
  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data((unsigned char *)data, header->caplen, "Received Packet");
  }
  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_NEIGHBORSOL || header->caplen < 78)
    return;
  if (*(data+22) + *(data+23) + *(data+24) + *(data+25) + *(data+34) + *(data+35) + *(data+36) + *(data+37) != 0)
    return;
  if (debug)
    printf("DEBUG: packet is a valid duplicate ip6 check via icmp6 neighbor solitication\n");

  return;
}

int main(int argc, char *argv[]) {
  int test = 0, count = 1;
  unsigned char buf[1500], bla[1500];
  unsigned char *dst;
  thc_ipv6_hdr *hdr;
  int i;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);
    
  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  interface = argv[1];
  dst = thc_resolve6(argv[2]);
  if (argc >= 4)
    test = atoi(argv[3]);
  memset(buf, 0, sizeof(buf));

  if (test == 0 || test == count) {
    printf("Test %d: 180 hop2hop headers\n", count);
    if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, NULL, dst, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    memset(bla, test%256, sizeof(bla));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    for (i = 0; i < 182; i++)
      if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *) &buf, 0) < 0)
        return -1;
     thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0x34567890, (unsigned char *) &bla, 8, 0);
    if (thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    count++;
  }

  if (test == 0 || test == count) {
    printf("Test %d: 180 ignore headers\n", count);
    if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, NULL, dst, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    memset(bla, test%256, sizeof(bla));
    for (i = 0; i < 182; i++)
      if (thc_add_hdr_misc(pkt, &pkt_len, NXT_IGNORE, -1, (unsigned char *) &bla, 8) < 0)
        return -1;
     thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0x34567890, (unsigned char *) &bla, 8, 0);
    if (thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    count++;
  }

  if (test == 0 || test == count) {
    printf("Test %d: jumbo packet option\n", count);
    if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, NULL, dst, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    memset(bla, test%256, sizeof(bla));
    buf[0] = 194;
    buf[1] = 0;
    buf[2] = buf[3] = buf[4] = buf[5] = 255;
    buf[6] = buf[7] = 0;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *) &buf, 0) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0x34567890, (unsigned char *) &bla, sizeof(bla), 0);
    hdr = (thc_ipv6_hdr*) pkt;
    hdr->length = 0;
    if (thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    count++;
  }

  if (test == 0 || test == count) {
    printf("Test %d: size announced too small\n", count);
    if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, NULL, dst, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    memset(bla, test%256, sizeof(bla));
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0x34567890, (unsigned char *) &bla, 1300, 0);
    hdr = (thc_ipv6_hdr*) pkt;
    hdr->length = 1;
    if (thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    count++;
  }

  if (test == 0 || test == count) {
    printf("Test %d: size announced too big\n", count);
    if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, NULL, dst, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    memset(bla, test%256, sizeof(bla));
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0x34567890, (unsigned char *) &bla, 1000, 0);
    hdr = (thc_ipv6_hdr*) pkt;
    hdr->length = 1400;
    if (thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    count++;
  }

  return 0;
}
