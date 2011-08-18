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
#include <sys/timeb.h>
#include "thc-ipv6.h"

extern int debug;
struct timespec ts, ts2;
int dlen = 8;

void help(char *prg) {
  printf("%s %s (c) 2011 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-af] [-H o:s:v] [-D o:s:v] [-F dst] [-t ttl] [-c class] [-l label] [-d size] interface src6 dst6 [srcmac [dstmac [data]]]\n\n", prg);
  printf("Craft your special icmpv6 echo request packet.\n");
  printf("You can put an \"x\" into src6, srcmac and dstmac for an automatic value.\n");
  printf("Options:\n");
  printf("  -a              add a hop-by-hop header with router alert option.\n");
  printf("  -H o:s:v        add a hop-by-hop header with special content\n");
  printf("  -D o:s:v        add a destination header with special content\n");
  printf("  -f              add a one-shot fragementation header\n");
  printf("  -F ipv6address  use source routing to this final destination\n");
  printf("  -t ttl          specify TTL (default: 64)\n");
  printf("  -c class        specify a class (0-4095)\n");
  printf("  -l label        specify a label (0-1048575)\n");
  printf("  -d data size    define the size of the ping data buffer\n");
  printf("o:s:v syntax: option-no:size:value, value is in hex, e.g. 1:2:feab\n");
  exit(-1);
}

void alarming() {
  printf("No packet received, terminating.\n");
  exit(-1);
}

void check_packets(u_char * pingdata, const struct pcap_pkthdr *header, const unsigned char *data) {
  int len = header->caplen, min = 0, usec, ok = 0;
  unsigned int mtu = 0;
  unsigned char *ptr = (unsigned char *) data;

  clock_gettime(CLOCK_REALTIME, &ts2);
  if (len < 58 || ((len + 58) < dlen && dlen < 1000) || (len < 1000 && dlen > 900)) {
    printf("ignoring too short packet\n");
    return;
  }
  if (dlen < 1000) {
    if (memcmp(pingdata, data + len - dlen, dlen) == 0)
      ok = 1;
  } else {
    if (memcmp(pingdata, data + 270, 100) == 0 || memcmp(pingdata, data + 274, 100) == 0 || memcmp(pingdata, data + 256, 100) == 0 || memcmp(pingdata, data + 260, 100) == 0)
      ok = 1;
  }
  if (ok) {
    if (ts2.tv_nsec < ts.tv_nsec) {
      min = 1;
      usec = (int) (100000 + ((ts2.tv_nsec - ts.tv_nsec) / 100000));
    } else
      usec = (int) ((ts2.tv_nsec - ts.tv_nsec) / 100000);
    printf("%04u.%04u \t", (int) (ts2.tv_sec - ts.tv_sec - min), usec);
    switch (ptr[54]) {
    case ICMP6_PINGREPLY:
      printf("pong");
      break;
    case ICMP6_PARAMPROB:
      printf("parameter problem %d", ptr[55]);
      break;
    case ICMP6_REDIR:
      printf("redirect");
      break;
    case ICMP6_UNREACH:
      printf("unreachable %d", ptr[55]);
      break;
    case ICMP6_TOOBIG:
      mtu = (ptr[58] << 24) + (ptr[59] << 16) + (ptr[60] << 8) + ptr[61];
      printf("too big (max mtu: %d)", mtu);
      break;
    case ICMP6_TTLEXEED:
      printf("ttl exceeded");
      break;
    default:
      printf("icmp6 %d:%d", ptr[54], ptr[55]);
    }
    printf(" packet received from %s\n", thc_ipv62notation(ptr + 22));
    exit(0);
  } else
    printf("(ignoring icmp6 packet with different contents)\n");
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[2096] = "thcping6", *routers[2], buf2[64];
  unsigned char *src6 = NULL, *dst6 = NULL, smac[6] = "", dmac[6] = "", *srcmac = smac, *dstmac = dmac;
  char string[255] = "icmp6 and dst ", *interface, *d_opt = NULL, *h_opt = NULL, *oo, *ol, *ov;
  int pkt1_len = 0, flags = 0, frag = 0, alert = 0, route = 0, ttl = 64, label = 0, class = 0, i, j;
  pcap_t *p;

  if (argc < 4)
    help(argv[0]);

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  memset(buf, 0, sizeof(buf));
  while ((i = getopt(argc, argv, "afd:D:H:F:t:c:l:")) >= 0) {
    switch (i) {
    case 'a':
      alert = 1;
      break;
    case 'f':
      frag = 1;
      break;
    case 'F':
      route = 1;
      routers[0] = thc_resolve6(optarg);
      routers[1] = NULL;
      break;
    case 'D':
      d_opt = optarg;
      break;
    case 'H':
      h_opt = optarg;
      break;
    case 't':
      ttl = atoi(optarg);
      break;
    case 'c':
      class = atoi(optarg);
      break;
    case 'l':
      label = atoi(optarg);
      break;
    case 'd':
      dlen = atoi(optarg);
      if (dlen > 2096)
        dlen = 2096;
      for (j = 0; j < (dlen / 8); j++)
        memcpy(buf + j * 8, "thcping6", 8);
      break;
    default:
      fprintf(stderr, "Error: invalid option %c\n", i);
      exit(-1);
    }
  }

  if (argc - optind < 3)
    help(argv[0]);

  interface = argv[optind];
  dst6 = thc_resolve6(argv[optind + 2]);
  if (strcmp(argv[optind + 1], "x") != 0)
    src6 = thc_resolve6(argv[optind + 1]);
  else if ((src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL)) == NULL) {
    fprintf(stderr, "Error: no ipv6 address found for interface %s!\n", interface);
    exit(-1);
  }
  if (argc - optind >= 4) {
    if (strcmp(argv[optind + 3], "x") != 0)
      sscanf(argv[optind + 3], "%x:%x:%x:%x:%x:%x", (unsigned int *) &smac[0], (unsigned int *) &smac[1], (unsigned int *) &smac[2], (unsigned int *) &smac[3],
             (unsigned int *) &smac[4], (unsigned int *) &smac[5]);
    else
      srcmac = NULL;
  } else
    srcmac = NULL;
  if (argc - optind >= 5) {
    if (strcmp(argv[optind + 4], "x") != 0)
      sscanf(argv[optind + 4], "%x:%x:%x:%x:%x:%x", (unsigned int *) &dmac[0], (unsigned int *) &dmac[1], (unsigned int *) &dmac[2], (unsigned int *) &dmac[3],
             (unsigned int *) &dmac[4], (unsigned int *) &dmac[5]);
    else
      dstmac = NULL;
  } else
    dstmac = NULL;

  if ((pkt1 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt1_len, src6, dst6, ttl, 0, label, class, 0)) == NULL)
    return -1;
  if (alert) {
    memset(buf2, 0, sizeof(buf2));
    buf2[0] = 5;
    buf2[1] = 2;
    if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf2, 6) < 0)
      return -1;
  }
  if (h_opt != NULL) {
    memset(buf2, 0, sizeof(buf2));
    oo = h_opt;
    if ((ol = index(oo, ':')) == NULL) {
      fprintf(stderr, "Error: option value must be optionnumber:length:value, e.g. 1:2:feab: %s\n", h_opt);
      exit(-1);
    }
    *ol++ = 0;
    if ((ov = index(ol, ':')) == NULL) {
      fprintf(stderr, "Error: option value must be optionnumber:length:value, e.g. 1:2:feab: %s\n", h_opt);
      exit(-1);
    }
    *ov++ = 0;
    buf2[0] = (atoi(oo)) % 256;
    buf2[1] = (atoi(ol)) % 256;
    if (*ov != 0)
      for (i = 0; i < strlen(ov) / 2; i++) {
        if (tolower(ov[i * 2]) >= 'a' && tolower(ov[i * 2]) <= 'f')
          j = (ov[i * 2] - 'a' + 10) * 16;
        else if (ov[i * 2] >= '0' && ov[i * 2] <= '9')
          j = (ov[i * 2] - '0') * 16;
        else {
          fprintf(stderr, "Error: only hexadecimal characters are allowed in value: %s\n", ov);
          exit(-1);
        }
        if (tolower(ov[i * 2 + 1]) >= 'a' && tolower(ov[i * 2 + 1]) <= 'f')
          j += (ov[i * 2 + 1] - 'a' + 10);
        else if (ov[i * 2 + 1] >= '0' && ov[i * 2 + 1] <= '9')
          j += (ov[i * 2 + 1] - '0');
        else {
          fprintf(stderr, "Error: only hexadecimal characters are allowed in value: %s\n", ov);
          exit(-1);
        }
        buf2[2 + i] = j % 256;
      }
    if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf2, 2 + (atoi(ol) % 256)) < 0)
      return -1;
  }
  if (frag) {
    if (thc_add_hdr_oneshotfragment(pkt1, &pkt1_len, getpid()) < 0)
      return -1;
  }
  if (route) {
    if (thc_add_hdr_route(pkt1, &pkt1_len, routers, 1) < 0)
      return -1;
  }
  if (d_opt != NULL) {
    memset(buf2, 0, sizeof(buf2));
    oo = d_opt;
    if ((ol = index(oo, ':')) == NULL) {
      fprintf(stderr, "Error: option value must be optionnumber:length:value, e.g. 1:2:feab: %s\n", h_opt);
      exit(-1);
    }
    *ol++ = 0;
    if ((ov = index(ol, ':')) == NULL) {
      fprintf(stderr, "Error: option value must be optionnumber:length:value, e.g. 1:2:feab: %s\n", h_opt);
      exit(-1);
    }
    *ov++ = 0;
    buf2[0] = (atoi(oo)) % 256;
    buf2[1] = (atoi(ol)) % 256;
    if (*ov != 0)
      for (i = 0; i < strlen(ov) / 2; i++) {
        if (tolower(ov[i * 2]) >= 'a' && tolower(ov[i * 2]) <= 'f')
          j = (ov[i * 2] - 'a' + 10) * 16;
        else if (ov[i * 2] >= '0' && ov[i * 2] <= '9')
          j = (ov[i * 2] - '0') * 16;
        else {
          fprintf(stderr, "Error: only hexadecimal characters are allowed in value: %s\n", ov);
          exit(-1);
        }
        if (tolower(ov[i * 2 + 1]) >= 'a' && tolower(ov[i * 2 + 1]) <= 'f')
          j += (ov[i * 2 + 1] - 'a' + 10);
        else if (ov[i * 2 + 1] >= '0' && ov[i * 2 + 1] <= '9')
          j += (ov[i * 2 + 1] - '0');
        else {
          fprintf(stderr, "Error: only hexadecimal characters are allowed in value: %s\n", ov);
          exit(-1);
        }
        buf2[2 + i] = j % 256;
      }
    if (thc_add_hdr_dst(pkt1, &pkt1_len, buf2, 2 + (atoi(ol) % 256)) < 0)
      return -1;
  }
  if (argc - optind >= 6) {
    if (dlen != 8) {
      fprintf(stderr, "Warning: the data option is ignored if the -d option is supplied\n");
    } else {
      dlen = strlen(argv[optind + 5]);
      if (dlen > sizeof(buf))
        dlen = sizeof(buf) - 1;
      memcpy(buf, argv[optind + 5], dlen);
      buf[dlen] = 0;
    }
  }
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_ECHOREQUEST, 0, flags, (unsigned char *) &buf, dlen, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, srcmac, dstmac, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  strcat(string, thc_ipv62notation(src6));
  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n", interface, string);
    exit(-1);
  }
  signal(SIGALRM, alarming);
  alarm(6);
  printf("0000.0000 \tping packet sent to %s\n", thc_ipv62notation(dst6));
  thc_send_pkt(interface, pkt1, &pkt1_len);
  clock_gettime(CLOCK_REALTIME, &ts);
  while (1) {
    thc_pcap_check(p, (char *) check_packets, buf);
  }

  return 0;                     // not reached
}
