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
int mychecksum;
char *interface, *es, *script = NULL;
char *ptr3, *ptr4;
int i;

void help(char *prg) {
  printf("%s %s (c) 2010 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface [script]\n\n", prg);
  printf("This tools detects new ipv6 addresses joining the local network.\n");
  printf("If script is supplied, it is executed with the detected IPv6 address as option\n\n");
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
  if (*(data+22) + *(data+23) + *(data+24) + *(data+25) + *(data+34) + *(data+35) + *(data+36) + *(data+37) != 0)
    return;
  if (debug)
    printf("DEBUG: packet is a valid duplicate ip6 check via icmp6 neighbor solitication\n");

  ptr3 = thc_ipv62string((char*)(data + 62));
  ptr4 = thc_string2notation(ptr3);
  printf("Detected new ip6 address: %s\n", ptr4);

  if (script != NULL && fork() == 0) {
    sprintf(es, "%s %s", script, ptr4);
    if (system(es) < 0)
      fprintf(stderr, "Error: Executing failed - %s\n", es);
    exit(0);
  }
  
  free(ptr3); free(ptr4);
  (void) wait3(NULL, WNOHANG, NULL);
  return;
}

int main(int argc, char *argv[]) {
  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  interface = argv[1];
  if (argc > 2) {
    script = argv[2];
    if ((es = malloc(20 + strlen(script))) == NULL) {
      fprintf(stderr, "Error: malloc\n");
      exit(-1);
    }
  }

  printf("Started ICMP6 DAD detection (Press Control-C to end) ...\n");
  return thc_pcap_function(interface, "ip6", (char *) intercept, NULL);
}
