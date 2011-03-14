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
  printf("Syntax: %s interface ip-address [target-address [own-mac-address]]\n\n", prg);
  printf("Advertise ipv6 address on the network (with own mac if not defined)\n");
  printf("sending it to the all-nodes multicast address if no target specified.\n");
  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, *pkt2 = NULL, buf[24];
  unsigned char *unicast6, *dst6 = NULL, srcmac[6] = "", *mac = srcmac;
  int pkt1_len = 0, pkt2_len = 0, flags, prefer = PREFER_GLOBAL;
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
  unicast6 = thc_resolve6(argv[2]);
  if (argv[3] != NULL && argc > 3) 
    dst6 = thc_resolve6(argv[3]);
  else
    dst6 = thc_resolve6("ff02::1");
  if (rawmode == 0) {
    if (argv[4] != NULL && argc > 4)
      sscanf(argv[4], "%x:%x:%x:%x:%x:%x", (unsigned int*)&srcmac[0], (unsigned int*)&srcmac[1], (unsigned int*)&srcmac[2], (unsigned int*)&srcmac[3], (unsigned int*)&srcmac[4], (unsigned int*)&srcmac[5]);
    else
      mac = thc_get_own_mac(interface);
  }

  memset(buf, 0, sizeof(buf));
  memcpy(buf, unicast6, 16);
  buf[16] = 2;
  buf[17] = 1;
  memcpy(&buf[18], mac, 6);
  flags = ICMP6_NEIGHBORADV_OVERRIDE;

  if ((pkt1 = thc_create_ipv6(interface, prefer, &pkt1_len, unicast6, dst6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_NEIGHBORADV, 0, flags, (unsigned char *) &buf, 24, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac, NULL, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }
  if ((pkt2 = thc_create_ipv6(interface, prefer, &pkt2_len, unicast6, dst6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt2, &pkt2_len, ICMP6_NEIGHBORADV, 0, 0, (unsigned char *) &buf, 24, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac, NULL, pkt2, &pkt2_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  printf("Starting advertisement of %s (Press Control-C to end)\n", argv[2]);
  while (1) {
    thc_send_pkt(interface, pkt1, &pkt1_len);
    thc_send_pkt(interface, pkt2, &pkt2_len);
    sleep(5);
  }
  
  return 0;
}
