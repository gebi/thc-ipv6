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
unsigned char buf[16];
unsigned char *alive[65536];
int alive_no = 0;

void help(char *prg) {
  printf("%s %s (c) 2006 by %s %s\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-r] interface [unicast-or-multicast-address [remote-router]]\n", prg);
  printf("Shows alive addresses in the segment. If you specify a remote router, the\n");
  printf("packets are sent with a routing header prefixed by fragmentation\n");
  printf("Use -r to use raw mode.\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  int i, ok = 0;
  unsigned char *ptr = (unsigned char *)data + 14;
  if (debug)
    thc_dump_data(ptr, header->caplen - 14, "Received Packet");
  for (i = 0; i < header->caplen - 14; i++)
    if (memcmp(&buf[2], ptr + i, 14) == 0) {
      ok = 1;
      i = header->caplen;
    }
  i = 0;
  while (ok && i < alive_no) {
    if (memcmp(alive[i], ptr + 8, 16) == 0)
      ok = 0;
    i++;
  }
  if (ok) {
    printf("Alive: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
      *(ptr+8),*(ptr+9),*(ptr+10),*(ptr+11),*(ptr+12),*(ptr+13),*(ptr+14),*(ptr+15),
      *(ptr+16),*(ptr+17),*(ptr+18),*(ptr+19),*(ptr+20),*(ptr+21),*(ptr+22),*(ptr+23));
    if ((alive[alive_no] = malloc(16)) != NULL) {
      memcpy(alive[alive_no], ptr + 8, 16);
      alive_no++;
    }
  }
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, *pkt2 = NULL, *pkt3 = NULL, *router6 = NULL;
  unsigned char *multicast6, *src6 = NULL, *mac = NULL, *routers[2], string[64] = "ip6 and dst ";
  int pkt1_len = 0, pkt2_len = 0, pkt3_len = 0, rawmode = 0;
  char *interface;
  thc_ipv6_hdr *hdr;
  time_t passed;
  pcap_t *p;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  interface = argv[1];
  if (argv[2] != NULL && argc > 2)
    multicast6 = thc_resolve6(argv[2]);
  else
    multicast6 = thc_resolve6("ff02::1");
  src6 = thc_get_own_ipv6(interface, multicast6, PREFER_GLOBAL);
  if (argv[3] != NULL && argc > 3) {
    router6 = thc_resolve6(argv[3]);
    routers[0] = multicast6;
    routers[1] = NULL;
    multicast6 = router6; // switch destination and router
  }
  if (rawmode == 0 && (mac = thc_get_mac(interface, src6, multicast6)) == NULL) {
    fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", argv[2]);
    exit(-1);
  }
  strcat(string, thc_string2notation(thc_ipv62string(src6)));
  
  // make the sending buffer unique
  memset(buf, 'A', sizeof(buf));
  time((time_t*)&buf[2]);
  buf[10] = getpid() % 256;
  buf[11] = getpid() / 256;
  memcpy(&buf[12], multicast6, 5);

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n", interface, string);
    exit(-1);
  }
  
  if ((pkt1 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt1_len, src6, multicast6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (router6 != NULL)
    if (thc_add_hdr_route(pkt1, &pkt1_len, routers, 1) < 0)
      return -1;
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, 16, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, NULL, mac, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not send packet, exiting ...\n");
    exit(-1);
  }
  if (router6 != NULL) {
    hdr = (thc_ipv6_hdr *) pkt1;
    thc_send_as_fragment6(interface, src6, multicast6, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
  } else
    thc_send_pkt(interface, pkt1, &pkt1_len);
  if ((pkt2 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt2_len, src6, multicast6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (router6 != NULL)
    if (thc_add_hdr_route(pkt2, &pkt2_len, routers, 1) < 0)
      return -1;
  if (thc_add_hdr_misc(pkt2, &pkt2_len, NXT_INVALID, -1, (unsigned char *) &buf, 16) < 0)
    return -1;
  if (thc_add_icmp6(pkt2, &pkt2_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, 16, 0) < 0)
    return -1;
  thc_generate_pkt(interface, NULL, mac, pkt2, &pkt2_len);
  if (router6 != NULL) {
    hdr = (thc_ipv6_hdr *) pkt2;
    thc_send_as_fragment6(interface, src6, multicast6, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
  } else
    thc_send_pkt(interface, pkt2, &pkt2_len);
  
  buf[0] = NXT_INVALID;
  buf[1] = 1;
  if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt3_len, src6, multicast6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (router6 != NULL)
    if (thc_add_hdr_route(pkt3, &pkt3_len, routers, 1) < 0)
      return -1;
  if (thc_add_hdr_hopbyhop(pkt3, &pkt3_len, (unsigned char *) &buf, 16) < 0)
    return -1;
  if (thc_add_icmp6(pkt3, &pkt3_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, 16, 0) < 0)
    return -1;
  thc_generate_pkt(interface, NULL, mac, pkt3, &pkt3_len);
  if (router6 != NULL) {
    hdr = (thc_ipv6_hdr *) pkt3;
    thc_send_as_fragment6(interface, src6, multicast6, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
  } else
    thc_send_pkt(interface, pkt3, &pkt3_len);

  while (thc_pcap_check(p, (char*)check_packets) > 0 && (alive_no == 0 || *multicast6 == 0xff));
  passed = time(NULL);
  while (passed + 5 >= time(NULL) && (alive_no == 0 || *multicast6 == 0xff))
    thc_pcap_check(p, (char*)check_packets);
  thc_pcap_close(p);
  printf("Found %d systems alive\n", alive_no);

  return 0;
}
