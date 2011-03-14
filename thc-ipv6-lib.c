/*
 * (c) 2010 by van Hauser / THC <vh@thc.org>
 *
 * THC IPv6 Attack Library
 *
 * Functions: see README
 *
 * The GPLv3 applies to this code, see the LICENSE file
 *
 */


#include <byteswap.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
/* network */
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
//#include <linux/if.h>
#include <net/if.h>
/* files */
#include <fcntl.h>
#include <sys/ioctl.h>
/* misc */
#include <time.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
/* libpcap */
#include <pcap.h>
#include "thc-ipv6.h"
/* libssl */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

int debug = 0;

char default_interface[16] = "eth0";
int _thc_ipv6_showerrors = SHOW_LIBRARY_ERRORS;
int thc_socket = -1;
int _thc_ipv6_rawmode = 0;

void thc_ipv6_rawmode(int mode) {
  _thc_ipv6_rawmode = mode;
  fprintf(stderr, "Error: raw mode is not working at the moment, sorry!\n");
  exit(-1);
}

void thc_ipv6_show_errors(int mode) {
  _thc_ipv6_showerrors = mode;
}

unsigned char *thc_ipv6_dummymac() {
  char *ptr = malloc(7);
  if (ptr == NULL)
    return NULL;
  memset(ptr, 0xff, 6);
  ptr[6] = 0;
  return ptr;
}

int thc_pcap_function(char *interface, unsigned char *capture, char *function, char *opt) {
  pcap_t *pcap_link = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;
  if (interface == NULL)
    interface = default_interface;
  if ((pcap_link = pcap_open_live(interface, 65535, 0, -1, errbuf)) == NULL)
    return -1;
  if (pcap_compile(pcap_link, &fcode, capture, 1, 0) < 0)
    return -2;
  pcap_setfilter(pcap_link, &fcode);
  if (pcap_loop(pcap_link, -1, (pcap_handler) function, opt) < 0)
    return -3;
  return -4; // never reached
}

pcap_t *thc_pcap_init(char *interface, unsigned char *capture) {
  pcap_t *pcap_link = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;
  if (interface == NULL)
    interface = default_interface;
  if ((pcap_link = pcap_open_live(interface, 65535, 0, -1, errbuf)) == NULL)
    return NULL;
  if (pcap_compile(pcap_link, &fcode, capture, 1, 0) < 0)
    return NULL;
  pcap_setfilter(pcap_link, &fcode);
  pcap_setnonblock(pcap_link, 1, errbuf);
  return pcap_link;
}

pcap_t *thc_pcap_init_promisc(char *interface, unsigned char *capture) {
  pcap_t *pcap_link = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;
  if (interface == NULL)
    interface = default_interface;
  if ((pcap_link = pcap_open_live(interface, 65535, 1, -1, errbuf)) == NULL)
    return NULL;
  if (pcap_compile(pcap_link, &fcode, capture, 1, 0) < 0)
    return NULL;
  pcap_setfilter(pcap_link, &fcode);
  pcap_setnonblock(pcap_link, 1, errbuf);
  return pcap_link;
}

int thc_pcap_check(pcap_t *pcap_link, char *function, char *opt) {
  if (pcap_link == NULL)
    return -1;
  return pcap_dispatch(pcap_link, 1, (pcap_handler) function, opt);
}

char *thc_pcap_close(pcap_t *pcap_link) {
  if (pcap_link != NULL)
    pcap_close(pcap_link);
  return NULL;
}

/* wow, ugly, complicated work for something a standard linux library could do as well :-) */
void thc_notation2beauty(unsigned char *ipv6) {
  char buf[40], buf2[40] = ":0:0:", *ptr, *ptr2 = NULL;
  int i, j, k = 0, l = 0;

  if (ipv6[39] != 0 || strlen(ipv6) != 39)
    return;
  
  memset(buf, 0, sizeof(buf));
  // remove leading zeros from ipv6-input to buf, :0023: = :23:, :0000: = :0:
  for (i = 0; i < 8; i++) {
    ptr = ipv6 + i * 4 + i;
    j = 0;
    while (*ptr == '0' && j < 3) {
      ptr++;
      j++;
    }
    memcpy(&buf[k], ptr, 4 - j);
    k += 4 - j;
    buf[k++] = ':';
  }
  buf[k-1] = 0;
  // find the longest :0: chain
  while ((ptr=strstr(buf, buf2)) != NULL) {
   ptr2 = ptr;
   strcat(buf2, "0:");
  }
  // if at least :0:0: is found, on the longest replace with ::, ptr2 shows where
  if (ptr2 != NULL) {
    buf2[strlen(buf2) - 2] = 0;
    memset(ipv6, 0, 40);
    // special case:  0000::....
    if (buf + 1 == ptr2 && buf[0] == '0') { 
      ipv6[0] = ':';
      l = -1;
    } else
      memcpy(ipv6, buf, ptr2 - buf + 1);
    memcpy(ipv6 + (ptr2 - buf + 1 + l), ptr2 + strlen(buf2) - 1, strlen(buf) - (ptr2 - buf) - strlen(buf2) + 1);
    // special case ....::0000
    if (ipv6[strlen(ipv6)-1] == '0' && ipv6[strlen(ipv6)-2] == ':' && ptr2 - buf + 1 + strlen(buf2) == strlen(buf))
      ipv6[strlen(ipv6)-1] = 0;
  } else
    strcpy(ipv6, buf);
}

unsigned char *thc_ipv62string(unsigned char *ipv6) {
  char *string = malloc(33);
  int a;

  if (ipv6 != NULL && string != NULL) {
    for (a=0; a < 16; a++) {
      if (ipv6[a] / 16 >= 10)
        string[a*2] = 'a' + ipv6[a] / 16 - 10;
      else
        string[a*2] = '0' + ipv6[a] / 16;
      if (ipv6[a] % 16 >= 10)
        string[a*2 + 1] = 'a' + ipv6[a] % 16 - 10;
      else
        string[a*2 + 1] = '0' + ipv6[a] % 16;
    }
    string[32] = 0;
  } else 
    return NULL;

  return string;
}

unsigned char *thc_string2ipv6(unsigned char *string) {
  unsigned char *ipv6 = malloc(16);
  int a;
  
  if (string != NULL && ipv6 != NULL) {
    for (a = 0; a < 16; a++) {
      ipv6[a] = (string[2*a] >= 'a' ? 10 + string[2*a] - 'a' : string[2*a] - '0') * 16;
      ipv6[a] += string[2*a + 1] >= 'a' ? 10 + string[2*a + 1] - 'a' : string[2*a + 1] - '0';
    }
  } else
    return NULL;
  
  return ipv6;
}

unsigned char *thc_string2notation(unsigned char *string) {
  unsigned char *notation = malloc(40);
  int a;

  if (notation != NULL && string != NULL) {
    for (a=0; a < 8; a++) {
      memcpy(notation + a*5, string + a*4, 4);
      notation[4 + a*5] = ':';
    }
    notation[39] = 0;
  } else
    return NULL;
  
  thc_notation2beauty(notation);
  return notation;
}

int calculate_checksum(unsigned char *data, int data_len) {
  int i=0, checksum=0;

  if (debug)
    thc_dump_data(data, data_len, "Checksum Packet Data");

  while (i < data_len) {
    if (i++ % 2 == 0)
      checksum += *data++;
    else
      checksum += *data++ << 8;
  }

  checksum = (checksum & 0xffff) + (checksum >> 16);
  checksum = htons(~checksum);
  
  return checksum;
}

int checksum_pseudo_header(unsigned char *src, unsigned char *dst, unsigned char type, unsigned char *data, int length) {
  unsigned char ptr[40 + length + 48];
  int checksum;

  if (length + 40 > 65535)
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: checksums for packets > 65535 are unreliable due implementation differences on target platforms\n");
  
  if (ptr == NULL)
    return -1;

  memset(&ptr, 0, 40 + length);
  memcpy(&ptr[0], src, 16);
  memcpy(&ptr[16], dst, 16);
  ptr[34] = length / 256;
  ptr[35] = length % 256;
  ptr[39] = type;
  if (data != NULL && length > 0)
    memcpy(&ptr[40], data, length);

  checksum = calculate_checksum(ptr, 40 + length);

/*if (length > 65495) {
printf("DEBUG length: %d, high: %d, low: %d, sum: %x\n", length, ptr[34], ptr[35], checksum);
printf("65535: %x\n", calculate_checksum(ptr, 65535));
printf("65536: %x\n", calculate_checksum(ptr, 65536));
printf("65535+40: %x\n", calculate_checksum(ptr, 65535 + 40));
printf("65535+40: %x\n", calculate_checksum(ptr, 65536 + 40));
}*/

  if (type == NXT_UDP && checksum == 0)
    checksum=65535;
  
  if (debug)
    printf("Checksum: %d = %p, %p, %d, %p, %d\n", checksum, src, dst, type, data, length);
  
  return checksum;
}

char *thc_resolve6(unsigned char *target) {
  char *ret_addr;
  struct in6_addr glob_in6;
  char *glob_addr = (char *) &glob_in6;
  struct addrinfo glob_hints, *glob_result;
  unsigned char out[64];
  
  if (target == NULL)
    return NULL;

  memset(&glob_hints, 0, sizeof(glob_hints));
  glob_hints.ai_family = AF_INET6;

  if (getaddrinfo(target, NULL, &glob_hints, &glob_result) != 0)
    return NULL;
  if (getnameinfo(glob_result->ai_addr, glob_result->ai_addrlen,
       out, sizeof(out), NULL, 0, NI_NUMERICHOST) != 0)
    return NULL;
  if (inet_pton(AF_INET6, out, glob_addr) < 0)
    return NULL;
  
  if ((ret_addr = malloc(16)) == NULL)
    return NULL;
  memcpy(ret_addr, glob_in6.s6_addr, 16);
  
  if (debug)
    thc_dump_data(ret_addr, 16, "Target Resolve IPv6");
  return ret_addr;
}

int thc_get_mtu(char *interface) {
  int s;
  struct ifreq ifr;

  if (interface == NULL)
    interface = default_interface;
    
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    return -1;
  memset(&ifr, 0, sizeof (ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
  if (ioctl(s, SIOCGIFMTU, (int8_t *)&ifr) < 0)
    return -1;
  
  close(s);
  if (debug)
    printf("DEBUG: MTU %d\n", ifr.ifr_mtu);

  return ifr.ifr_mtu;
}

unsigned char *thc_get_own_mac(char *interface) {
  int s;
  struct ifreq ifr;
  char *mac;
  
  if (interface == NULL)
    interface = default_interface;
    
  if (_thc_ipv6_rawmode)
    return thc_ipv6_dummymac();

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    return NULL;
  memset(&ifr, 0, sizeof (ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
  if (ioctl(s, SIOCGIFHWADDR, (int8_t *)&ifr) < 0)
    return NULL;
  
  mac = malloc(6);
  memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6);
  close(s);
  if (debug)
    thc_dump_data(mac, 6, "Own MAC address");
  return mac;
}

unsigned char *thc_get_own_ipv6(char *interface, unsigned char *dst, int prefer) {
  char *myipv6;
  FILE *f;
  unsigned char ipv6[34] = "", tmpbuf[34], buf[1024], *tmpdst = NULL;
  int a, b, c, done = 0, picky = 0, orig_prefer = prefer;
  unsigned char tmpd, tmpb;
  char bla[16];  
  
  if (interface == NULL)
    interface = default_interface;

  if (dst != NULL && dst[0] >= 0xf0)
    dst = NULL;
    
  if (dst != NULL)
    tmpdst = thc_ipv62string(dst);

  while (done < 2 && picky < 2) {
    if ((f = fopen("/proc/net/if_inet6", "r")) == NULL) {
      fprintf(stderr, "Error: /proc/net/if_inet6 does not exist, no IPv6 support on your Linux box!\n");
      exit(-1);
    }

    if (picky == 1) {
      if (prefer == PREFER_GLOBAL)
        prefer = PREFER_LINK;
      else
        prefer = PREFER_GLOBAL;
    }

    while (done < 2 && fgets(buf, sizeof(buf), f) != NULL) {
      if (strncmp(interface, &buf[strlen(buf)-strlen(interface)-1], strlen(interface)) == 0) {
        sscanf(buf, "%s %x %x %x %s", tmpbuf, &a, &b, &c, bla);
        if (c == prefer && done == 0) {
          ipv6[0] = c; // scope type
          ipv6[1] = b; // netmask
          memcpy(&ipv6[2], tmpbuf, 32);
          ipv6[34] = 0;
          if (dst == NULL)
            done = 2;
          else
            done = 1;
        }
      // if a destination was given, we always prefer the local ip which is in the same subnet of the target
        if (dst != NULL) {
          if (strncmp(tmpbuf, tmpdst, b / 4) == 0 || dst[0] == 0xff) {
          if (b % 4 > 0) {
            tmpb = tmpbuf[b / 4 + 1] >> (b % 4);
            tmpd = tmpdst[b / 4 + 1] >> (b % 4);
            if (tmpb == tmpd) {
              done = 2;
            }
          } else 
              done = 2;

            if (done == 2) {
              if (debug)
                printf("DEBUG: Found local ipv6 address to destination\n");
              ipv6[0] = c; // scope type
              ipv6[1] = b; // netmask
              memcpy(&ipv6[2], tmpbuf, 32);
              ipv6[34] = 0;
            }
          }
        }
      }
    }
    fclose(f);
    picky++;
  }

  if (strlen(&ipv6[2]) == 0) {
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: no IPv6 address on interface defined\n");
    return NULL;
  }

  if (picky == 2 && orig_prefer != ipv6[0])
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: unprefered IPv6 address had to be selected\n");

  if (tmpdst != NULL)
    free(tmpdst);
  tmpdst = thc_string2notation(&ipv6[2]);
  myipv6 = thc_resolve6(tmpdst);
  free(tmpdst);
  
  if (debug)
    thc_dump_data(myipv6, 16, "Own IPv6 address");
  return myipv6;
}

unsigned char *thc_get_multicast_mac(unsigned char *dst) {
  unsigned char *mac;
  
  if (_thc_ipv6_rawmode)
    return thc_ipv6_dummymac();

  if (dst == NULL || (mac = malloc(6)) == NULL)
    return NULL;
    
  mac[0] = 0x33;
  mac[1] = 0x33;
  memcpy(&mac[2], dst + 12, 4);

  return mac;
}

void thc_get_mac_from_sniff(u_char *foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  if (data[0x36] != ICMP6_NEIGHBORADV)
    return;
  if (header->len < 78)
    return;    
  if (memcmp(data + 0x3e, foo + 7, 16) != 0)
    return;
  foo[0] = 32;
  if (header->len >= 86 && data[0x4e] == 2 && data[0x4f] == 1)
    memcpy(foo + 1, data + 0x50, 6);
  else 
    memcpy(foo + 1, data + 6, 6);
}

unsigned char *thc_lookup_ipv6_mac(char *interface, unsigned char *dst) {
  unsigned char *mac = NULL;
  time_t curr;
  int count = 0, found = 0;
  char string[64] = "icmp6 and dst ", resolved_mac[23] = "", *p1, *p2;
  pcap_t *p;

  if (_thc_ipv6_rawmode)
    return thc_ipv6_dummymac();
  if (dst == NULL)
    return NULL;
  if (interface == NULL)
    interface = default_interface;
  if ((p1 = thc_get_own_ipv6(interface, dst, PREFER_LINK)) == NULL)
    return NULL;
  if ((p2 = thc_ipv62string(p1)) == NULL) {
    free(p1);
    return NULL;
  }
  free(p1);
  p1 = thc_string2notation(p2);
  
  strcat(string, p1);
  free(p1); free(p2);
  if ((p1 = thc_string2ipv6(dst)) == NULL)
    return NULL;
  memcpy(resolved_mac + 7, p1, 16);
  free(p1);
  if ((p = thc_pcap_init(interface, string)) == NULL)
    return NULL;
  while (found == 0 && count < 3) {
    p1 = thc_string2ipv6(dst);
    thc_neighborsol6(interface, NULL, NULL, p1, NULL, NULL);
    free(p1);
    curr = time(NULL);
    while (found == 0 && time(NULL) < curr + 2) {
      thc_pcap_check(p, (char*)thc_get_mac_from_sniff, resolved_mac);
      if (resolved_mac[0] != 0) {
        found = 1;
        if ((mac = malloc(6)) == NULL)
          return NULL;
        memcpy(mac, resolved_mac + 1, 6);
      }
    }
    count++;
  }
  thc_pcap_close(p);

  if (debug)
    thc_dump_data(mac, 6, "MAC address for packet target");
  return mac;
}

/* If the following looks like shit to you:
   This is code submitted by Dan Kaminksy with whom I bet that he is not
   able to code a 1 page function which extracts the mac address from the
   neighbor cache on linux - which is such a complex and horrible
   implementation. Well you get what you ask for - a function which will
   break once the interface even slightly changes ... but its 1 page.
 */
unsigned char *thc_look_neighborcache(unsigned char *dst) {
  int fd, fromlen, gotsize, rcvbuf = 65535;
  struct sockaddr_nl nladdr;
  unsigned char buf[32768], *ptr, *found;
//  char magic[] = { 0x80, 0x00, 0x00, 0x01, 0x14, 0x00, 0x01, 0x00 };
  char blob[] = { 0x14, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x01, 0x03, 0xda,
    0x0f, 0xb8, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  memset(&nladdr, 0, sizeof(struct sockaddr_nl));
  nladdr.nl_family=AF_NETLINK;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  bind(fd, (struct sockaddr*)&nladdr, sizeof(nladdr));
  sendto(fd, blob, sizeof(blob), 0, (struct sockaddr*)&nladdr, sizeof(nladdr));
  fromlen = sizeof(nladdr);
  gotsize = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&nladdr, &fromlen);
  shutdown(fd, SHUT_RDWR);
  close(fd);
  if (debug)
    thc_dump_data(buf, gotsize, "Neighbor cache lookup result");
//  if ((ptr = thc_memstr(buf, magic, gotsize, sizeof(magic))) == NULL)
//    return NULL;
  if ((ptr = thc_memstr(buf, dst, gotsize/* - (ptr - buf)*/, 16)) == NULL)
    return NULL;
  if ((found = malloc(7)) == NULL)
    return NULL;
  memcpy(found, ptr + 16 + 4, 6);
  found[6] = 0;
  return found;
}

int thc_is_dst_local(char *interface, unsigned char *dst) {
  int local = 0;
  FILE *f;
  unsigned char tmpbuf[34], buf[1024], *tmpdst = NULL;
  int a, b, c /*, found = 0, fd = -1 */;
  unsigned char tmpd, tmpb;
  char bla[16];  

  if (_thc_ipv6_rawmode || dst == NULL)
    return 0;
  if (interface == NULL)
    interface = default_interface;
  if (dst[0] == 0xff) // multicast address ?
    return 1;
  if (dst[0] == 0xfe && dst[1] == 0x80) // link local
    return 1;
  tmpdst = thc_ipv62string(dst);

  if ((f = fopen("/proc/net/if_inet6", "r")) == NULL) {
    fprintf(stderr, "Error: /proc/net/if_inet6 does not exist, no IPv6 support on your Linux box!\n");
    exit(-1);
  }
  while (local == 0 && fgets(buf, sizeof(buf), f) != NULL) {
    if (strncmp(interface, &buf[strlen(buf)-strlen(interface)-1], strlen(interface)) == 0) {
      sscanf(buf, "%s %x %x %x %s", tmpbuf, &a, &b, &c, bla);
      if (strncmp(tmpbuf, tmpdst, b / 4) == 0) {
        if (b % 4 > 0) {
          tmpb = tmpbuf[b / 4 + 1] >> (b % 4);
          tmpd = tmpdst[b / 4 + 1] >> (b % 4);
          if (tmpb == tmpd) {
            local =1;
          }
        } else 
          local = 1;
      }
    }
  }
  fclose(f);
  if (debug)
    printf("DEBUG: is dst local: %d\n", local);
  free(tmpdst);
  return local;
}

unsigned char *thc_get_mac(char *interface, unsigned char *src, unsigned char *dst) {
  int local = 0;
  FILE *f;
  unsigned char tmpbuf[34], router1[34], router2[34], defaultgw[34] = "", buf[1024], *tmpdst = NULL;
  int a, b, c /*, found = 0, fd = -1 */;
  unsigned char tmpd, tmpb;
  char bla[16], *ret, *p1;

  if (_thc_ipv6_rawmode)
    return thc_ipv6_dummymac();
  if (dst == NULL)
    return NULL;
  if (interface == NULL)
    interface = default_interface;
  if (dst[0] == 0xff) // then its a multicast target
    return thc_get_multicast_mac(dst);
  tmpdst = thc_ipv62string(dst);

  if ((f = fopen("/proc/net/if_inet6", "r")) == NULL) {
    fprintf(stderr, "Error: /proc/net/if_inet6 does not exist, no IPv6 support on your Linux box!\n");
    exit(-1);
  }
  while (local == 0 && fgets(buf, sizeof(buf), f) != NULL) {
    if (strncmp(interface, &buf[strlen(buf)-strlen(interface)-1], strlen(interface)) == 0) {
      sscanf(buf, "%s %x %x %x %s", tmpbuf, &a, &b, &c, bla);
      if (strncmp(tmpbuf, tmpdst, b / 4) == 0) {
        if (b % 4 > 0) {
          tmpb = tmpbuf[b / 4 + 1] >> (b % 4);
          tmpd = tmpdst[b / 4 + 1] >> (b % 4);
          if (tmpb == tmpd) {
            local = 1;
          }
        } else 
          local = 1;
      }
    }
  }
  fclose(f);
  if (debug)
    printf("DEBUG: is mac local: %d\n", local);

  if (! local) {
    if ((f = fopen("/proc/net/ipv6_route", "r")) == NULL) {
      fprintf(stderr, "Error: /proc/net/ipv6_route does not exist, no IPv6 support on your Linux box!\n");
      exit(-1);
    }
    while (local == 0 && fgets(buf, sizeof(buf), f) != NULL) {
      if (strncmp(interface, &buf[strlen(buf)-strlen(interface)-1], strlen(interface)) == 0) {
        sscanf(buf, "%s %x %s %x %s %s", tmpbuf, &b, router1, &a, router2, bla);
        if (b > 0) {
          if (strncmp(tmpbuf, tmpdst, b / 4) == 0) {
            if (b % 4 > 0) {
              tmpb = tmpbuf[b / 4 + 1] >> (b % 4);
              tmpd = tmpdst[b / 4 + 1] >> (b % 4);
              if (tmpb == tmpd)
                local = 1;
            } else 
              local = 1;
          }
        } else
          strcpy(defaultgw, router2);
        if (local == 1) {
          if (debug)
            printf("DEBUG: router found for %s: %s\n", tmpdst, router2);
          strcpy(tmpdst, router2);
        }
      }
    }
    if (local == 0 && strlen(defaultgw) > 0) {
      if (debug)
        printf("DEBUG: using default router for %s: %s\n", tmpdst, defaultgw);
      strcpy(tmpdst, defaultgw);
      local = 1;
    }
    if (local == 0) {
      if (_thc_ipv6_showerrors)
        fprintf(stderr, "Error: No idea where to route the packet to %s!\n", tmpdst);
      free(tmpdst);
      return NULL;
    }
  }

  p1 = thc_string2ipv6(tmpdst);
  if ((ret = thc_look_neighborcache(p1)) != NULL) {
    free(p1); free(tmpdst);
    return ret;
  }
  free(p1);
  p1 = thc_lookup_ipv6_mac(interface, tmpdst);
  free(tmpdst);
  return p1;
}

unsigned char *thc_inverse_packet(unsigned char *pkt, int pkt_len) {
  unsigned char tmp[16];
  int type = -1, iptr = 0, checksum;
  char *src = &pkt[8], *dst = &pkt[24];
  
  if (pkt == NULL)
    return NULL;

  pkt[7] = 255; // ttl
    
  memcpy(tmp, pkt + 8, 16);	// reverse IP6 src and dst
  memcpy(pkt + 8, pkt + 24, 16);
  memcpy(pkt + 24, tmp, 16);

  if (pkt_len > 44) {
    type = pkt[6];
    iptr = 40;
  }
  
  while (type == NXT_HDR || type == NXT_ROUTE || type == NXT_FRAG ||
         type == NXT_OPTS || type == NXT_ICMP6 || type == NXT_TCP ||
         type == NXT_UDP) {
    switch(type) {
      case NXT_ICMP6:
        if (pkt[iptr] == ICMP6_PINGREQUEST || pkt[iptr] == ICMP6_PINGREPLY)
          pkt[iptr] = (pkt[iptr] == ICMP6_PINGREQUEST ? ICMP6_PINGREPLY : ICMP6_PINGREQUEST);
        else
          if (pkt[iptr] ==  ICMP6_NEIGHBORSOL || pkt[iptr] == ICMP6_NEIGHBORADV)
            pkt[iptr] = (pkt[iptr] == ICMP6_NEIGHBORSOL ? ICMP6_NEIGHBORADV : ICMP6_NEIGHBORSOL);
          else
            if (pkt[iptr] ==  ICMP6_ROUTERSOL || pkt[iptr] == ICMP6_ROUTERADV)
              pkt[iptr] = (pkt[iptr] == ICMP6_ROUTERSOL ? ICMP6_ROUTERADV : ICMP6_ROUTERSOL);
            else
              if (_thc_ipv6_showerrors)
                fprintf(stderr, "Warning: ICMP6 type %d can not be inversed\n", type);
        pkt[iptr + 2] = 0;
        pkt[iptr + 3] = 0;
        checksum = checksum_pseudo_header(src, dst, NXT_ICMP6, &pkt[iptr], pkt_len - iptr);
        pkt[iptr + 2] = checksum / 256;
        pkt[iptr + 3] = checksum % 256;
        type = -1;
        break;
      case NXT_MIPV6:
      case NXT_UDP:
      case NXT_TCP:
        if (_thc_ipv6_showerrors)
          fprintf(stderr, "Warning: inverse_packet has not implement type %d yet!\n", type);
        // fall through
      case NXT_NONXT:
      case NXT_DATA:
      case NXT_AH:
      case NXT_ESP:
        type = -1;  // no processing of other headers
        break;
      case NXT_ROUTE:
      case NXT_FRAG:
      case NXT_HDR:
        if (_thc_ipv6_showerrors)
          fprintf(stderr, "Warning: inverse_packet has not implement type %d yet!\n", type);
        type = pkt[iptr];
        iptr += (pkt[iptr+1] + 1) * 8;
        if (iptr + 4 > pkt_len) {
          if (_thc_ipv6_showerrors)
            fprintf(stderr, "Warning: packet to inverse is shorter than header tells me\n");
          type = -1;
        }
        break;
      default:
        if (_thc_ipv6_showerrors)
          fprintf(stderr, "Warning: Unsupported header type %d!\n", type);
        // XXX TODO FIXME : other packet types
    }
  }
  if (type != -1)
      if (_thc_ipv6_showerrors)
        fprintf(stderr, "Warning: Unsupported header type %d!\n", type);

  if (debug)
    thc_dump_data(pkt, pkt_len, "Inversed Packet");
  return pkt;
}

int thc_send_as_fragment6(char *interface, unsigned char *src, unsigned char *dst, unsigned char type, unsigned char *data, int data_len, int frag_len) {
  unsigned char *pkt = NULL, *srcmac, *dstmac;
  int pkt_len;
  unsigned char buf[frag_len];
  int count, id = time(NULL) % 2000000000, dptr = 0, last_size, run = 0;

  if (frag_len % 8 > 0) {
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Error: frag_len for thc_send_as_fragment6 must be a multiple of 8, not sending!\n");
    return -1;
  }

  if ((srcmac = thc_get_own_mac(interface)) == NULL)
    return -1;
  if ((dstmac = thc_get_mac(interface, src, dst)) == NULL) {
    free(srcmac);
    return -1;
  }
  
  count = data_len / frag_len;
  if (data_len % frag_len > 0) {
    count++;
    last_size = data_len % frag_len;
  } else
    last_size = frag_len;

  if (debug)
    printf("DEBUG: data to fragment has size of %d bytes, sending %d packets, last packet has %d bytes\n", 
     data_len, count, last_size);

  while (count) {
    if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src, dst, 0, 0, 0, 0, 0)) == NULL) {
      free(srcmac); free(dstmac);
      return -1;
    }
    if (thc_add_hdr_fragment(pkt, &pkt_len, dptr / 8, count == 1 ? 0 : 1, id)) {
      free(srcmac); free(dstmac);
      return -1;
    }
    if (count > 1)
      memcpy(buf, data + run * frag_len, frag_len);
    else
      memcpy(buf, data + run * frag_len, last_size);
    dptr += frag_len;
    run++;
    if (thc_add_data6(pkt, &pkt_len, type, buf, count == 1 ? last_size : frag_len)) {
      free(srcmac); free(dstmac);
      return -1;
    }
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);  
    pkt = thc_destroy_packet(pkt);
    count--;
  }
  free(srcmac); free(dstmac);
  return 0;
}

int thc_ping6(char *interface, unsigned char *src, unsigned char *dst, int size, int count) { //, char **packet, int *packet_len) {
  unsigned char *pkt = NULL;
  int pkt_len;
  unsigned char buf[size];
  int ret, counter = count;

  memset(buf, 'A', size);

  if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src, dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0x34567890, (unsigned char *) &buf, size, 0) < 0)
    return -1;

  if (count < 0)
    counter = 1;
  else
    counter = count;
  while (counter > 0) {
    ret += thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len);
    counter--;
  }

  pkt = thc_destroy_packet(pkt);

  return ret;
}

int thc_neighboradv6(char *interface, unsigned char *src, unsigned char *dst, unsigned char *srcmac, unsigned char *dstmac, unsigned int flags, unsigned char *target) {
  unsigned char *pkt = NULL, *mysrc, *mydst, *mysrcmac;
  int pkt_len;
  unsigned char buf[24];
  int ret;

  if (src == NULL)
    mysrc = thc_get_own_ipv6(interface, dst, PREFER_LINK);
  else
    mysrc = src;
  if (target == NULL)
    target = mysrc;
  if (dst == NULL)
    mydst = thc_resolve6("FF02:0:0:0:0:0:0:1");
  else
    mydst = dst;
  if (srcmac == NULL)
    mysrcmac = thc_get_own_mac(interface);
  else
    mysrcmac = srcmac;

  memcpy(buf, target, 16);
  buf[16] = 2;
  buf[17] = 1;
  memcpy(&buf[18], mysrcmac, 6);

  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, mysrc, mydst, 0, 0, 0, 0, 0)) == NULL) {
    if (dst == NULL)
      free(mydst);
    if (src == NULL)
      free(mysrc);
    if (srcmac == NULL)
      free(mysrcmac);
    return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORADV, 0, flags, (unsigned char *) &buf, sizeof(buf), 0) < 0) {
    if (dst == NULL)
      free(mydst);
    if (src == NULL)
      free(mysrc);
    if (srcmac == NULL)
      free(mysrcmac);
    return -1;
  }

  ret = thc_generate_and_send_pkt(interface, mysrcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  if (dst == NULL)
    free(mydst);
  if (src == NULL)
    free(mysrc);
  if (srcmac == NULL)
    free(mysrcmac);

  return ret;
}

int thc_routersol6(char *interface, unsigned char *src, unsigned char *dst, unsigned char *srcmac, unsigned char *dstmac) {
  unsigned char *pkt = NULL, *mydst;
  int pkt_len;
  int ret;
//  unsigned char buf[8];

  if (dst == NULL)
    mydst = thc_resolve6("FF02:0:0:0:0:0:0:2");
  else
    mydst = dst;

//  memset(buf, 0, sizeof(buf));
  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, src, mydst, 0, 0, 0, 0, 0)) == NULL) {
    if (dst == NULL)
      free(mydst);
    return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERSOL, 0, 0, NULL, 0 /*(unsigned char*)&buf, sizeof(buf)*/, 0) < 0) {
    if (dst == NULL)
      free(mydst);
    return -1;
  }

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  if (dst == NULL)
    free(mydst);

  return ret;
}

int thc_neighborsol6(char *interface, unsigned char *src, unsigned char *dst, unsigned char *target, unsigned char *srcmac, unsigned char *dstmac) {
  unsigned char *pkt = NULL, *mysrc, *mymac, *mydst;
  int pkt_len;
  unsigned char buf[24];
  int ret;

  if (target == NULL && dst == NULL)
    return -1;

  if (src == NULL)
    mysrc = thc_get_own_ipv6(interface, dst, PREFER_LINK);
  else
    mysrc = src;
  if (srcmac == NULL)
    mymac = thc_get_own_mac(interface);
  else
    mymac = srcmac;
  if (target == NULL)
    target = dst;
  if (dst == NULL)
    mydst = thc_resolve6("FF02:0:0:0:0:0:0:1");
  else
    mydst = dst;

  memcpy(buf, target, 16);
  buf[16] = 1;
  buf[17] = 1;
  memcpy(&buf[18], mymac, 6);

  // XXX TODO FIXME: check if dst ip6 in ip6 header is target ip or multicast
  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, mysrc, mydst, 0, 0, 0, 0, 0)) == NULL) {
    if (dst == NULL)
      free(mydst);
    if (src == NULL)
      free(mysrc);
    if (srcmac == NULL)
      free(mymac);
    return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORSOL, 0, 0, (unsigned char *) &buf, 24, 0) < 0) {
    if (dst == NULL)
      free(mydst);
    if (src == NULL)
      free(mysrc);
    if (srcmac == NULL)
      free(mymac);
    return -1;
  }

  ret = thc_generate_and_send_pkt(interface, mymac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  if (dst == NULL)
    free(mydst);
  if (src == NULL)
    free(mysrc);
  if (srcmac == NULL)
    free(mymac);

  return ret;
}

int thc_routeradv6(char *interface, unsigned char *src, unsigned char *dst, unsigned char *srcmac, unsigned char default_ttl, int managed,  unsigned char *prefix, int prefixlen, int mtu, unsigned int lifetime) {
  unsigned char *pkt = NULL, *mysrc, *mydst, *mymac;
  int pkt_len;
  unsigned char buf[56];
  unsigned int flags;
  int ret;

  if (prefix == NULL)
    return -1;

  if (src == NULL)
    mysrc = thc_get_own_ipv6(interface, NULL, PREFER_LINK);
  else
    mysrc = src;
  if (srcmac == NULL)
    mymac = thc_get_own_mac(interface);
  else 
    mymac = srcmac;
  if (dst == NULL)
    mydst = thc_resolve6("FF02:0:0:0:0:0:0:1");
  else
    mydst = dst;

  flags = default_ttl << 24;
  if (managed)
    flags += (128 + 64 + 32 + 8) << 16;
  flags += (lifetime > 65535 ? 65535 : lifetime);

  memset(buf, 0, sizeof(buf));
  buf[1] = 250; // this defaults reachability checks to approx 1 minute
  buf[5] = 30;  // this defaults neighbor solitication messages to aprox 15 seconds
  // options start at byte 12
  // mtu
  buf[8] = 5;
  buf[9] = 1;
  if (mtu) {
    buf[12] = mtu / 16777216;
    buf[13] = (mtu % 16777216) / 65536;
    buf[14] = (mtu % 65536) / 256;
    buf[15] = mtu % 256;
  }
  // prefix info
  buf[16] = 3;
  buf[17] = 4;
  buf[18] = prefixlen;
  if (managed)
    buf[19] = 128 + 64 + 32 + 16;
  if (lifetime) {
    buf[20] = lifetime / 16777216;
    buf[21] = (lifetime % 16777216) / 65536;
    buf[22] = (lifetime % 65536) / 256;
    buf[23] = lifetime % 256;
    memcpy(&buf[24], &buf[20], 4);
  }
  // 4 bytes reserved
  memcpy(&buf[32], prefix, 16);
  // source link
  buf[48] = 1;
  buf[49] = 1;
  memcpy(&buf[50], mymac, 6);

  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, mysrc, mydst, 0, 0, 0, 0, 0)) == NULL) {
    if (dst == NULL)
      free(mydst);
    if (src == NULL)
      free(mysrc);
    if (srcmac == NULL)
      free(mymac);
    return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, flags, (unsigned char *) &buf, sizeof(buf), 0) < 0) {
    if (dst == NULL)
      free(mydst);
    if (src == NULL)
      free(mysrc);
    if (srcmac == NULL)
      free(mymac);
    return -1;
  }

  ret = thc_generate_and_send_pkt(interface, mymac, NULL, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  if (dst == NULL)
    free(mydst);
  if (src == NULL)
    free(mysrc);
  if (srcmac == NULL)
    free(mymac);
  
  return 0;
}

int thc_toobig6(char *interface, unsigned char *src, unsigned char *srcmac, unsigned char *dstmac, unsigned int mtu, unsigned char *orig_pkt, int orig_pkt_len) {
  unsigned char *pkt = NULL, *dst;
  int pkt_len;
  unsigned char buf[mtu];
  int ret, buflen;

  if (orig_pkt_len > 0)
    buflen = orig_pkt_len > mtu - 48 ? mtu - 48 : orig_pkt_len;
  if (buflen < 1)
    return -1;
  memcpy(buf, orig_pkt, buflen);
  dst = orig_pkt + 8;
  
  if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src, dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_TOOBIG, 0, mtu, (unsigned char *) &buf, buflen, 0) < 0)
    return -1;

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  
  return 0;
}

int thc_paramprob6(char *interface, unsigned char *src, unsigned char *srcmac, unsigned char *dstmac, unsigned char code, unsigned int pointer, unsigned char *orig_pkt, int orig_pkt_len) {
  unsigned char *pkt = NULL, *dst;
  int pkt_len;
  unsigned char buf[1022];
  int ret;

  if (orig_pkt_len > 0)
    memcpy(buf, orig_pkt, orig_pkt_len > 1022 ? 1022 : orig_pkt_len);
  dst = orig_pkt + 8;
  
  if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src, dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PARAMPROB, code, pointer, (unsigned char *) &buf, orig_pkt_len > 1022 ? 1022 : orig_pkt_len, 0) < 0)
    return -1;

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  
  return 0;
}

int thc_unreach6(char *interface, unsigned char *src, unsigned char *srcmac, unsigned char *dstmac, unsigned char code, unsigned char *orig_pkt, int orig_pkt_len) {
  unsigned char *pkt = NULL, *dst;
  int pkt_len;
  unsigned char buf[1022];
  int ret;

  if (orig_pkt_len > 0)
    memcpy(buf, orig_pkt, orig_pkt_len > 1022 ? 1022 : orig_pkt_len);
  dst = orig_pkt + 8;
  
  if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src, dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_UNREACH, code, 0, (unsigned char *) &buf, orig_pkt_len > 1022 ? 1022 : orig_pkt_len, 0) < 0)
    return -1;

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  
  return 0;
}

int thc_redir6(char *interface, unsigned char *src, unsigned char *srcmac, unsigned char *dstmac, unsigned char *newrouter, unsigned char *newroutermac, unsigned char *orig_pkt, int orig_pkt_len) {
  unsigned char *pkt = NULL, dst[16], osrc[16];
  int pkt_len;
  unsigned char buf[1070];
  int ret;

  memset(buf, 0, 1070);
  memcpy(dst, orig_pkt + 8, 16);
  memcpy(osrc, orig_pkt + 24, 16);
  memcpy(buf, newrouter, 16);
  memcpy(&buf[16], osrc, 16);
  buf[32] = 2;
  buf[33] = 1;
  memcpy(&buf[34], newroutermac, 6);
  buf[40] = 4;
  buf[41] = orig_pkt_len > 1022 ? 128 : (orig_pkt_len + 8) / 8;
  if ((orig_pkt_len + 8) % 8 > 0)
    buf[41] += 1;

  if (orig_pkt_len > 0)
    memcpy(buf + 48, orig_pkt, orig_pkt_len > 1022 ? 1022 : orig_pkt_len);
  
  if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, src, dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_REDIR, 0, 0, (unsigned char *) &buf, orig_pkt_len > 1022 ? 1042 : orig_pkt_len + 48, 0) < 0)
    return -1;

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  
  return 0;
}

char *thc_create_ipv6(char *interface, int prefer, int *pkt_len, unsigned char *src, unsigned char *dst, int ttl, int length, int label, int class, int version) {
  thc_ipv6_hdr *hdr;
  unsigned char *my_src;
  char *pkt = NULL;
  
  *pkt_len = 40;
  pkt = malloc(sizeof(thc_ipv6_hdr));
  hdr = (thc_ipv6_hdr *) pkt;
  if (pkt == NULL)
    return NULL;

  hdr->pkt = NULL;
  hdr->pkt_len = 0;

  if (src == NULL)
    my_src = thc_get_own_ipv6(interface, dst, prefer);
  else
    my_src = src;
    
  if (dst == NULL || my_src == NULL) {
    if (src == NULL)
      free(my_src);
    return NULL;
  }
  
  memcpy(hdr->src, my_src, 16);
  memcpy(hdr->dst, dst, 16);
  hdr->final_dst = hdr->dst;
  hdr->original_src = hdr->src;
  if (version == 0)
    hdr->version = 6;
  else
    hdr->version = version;
  if (length == 0)
    hdr->length = 0;
  else
    hdr->length = length;
  if (class == 0)
    hdr->class = 0;
  else
    hdr->class = class;
  if (label == 0)
    hdr->label = 0;
  else
    hdr->label = label;
  if (ttl == 0)
    hdr->ttl = 255;
  else
    hdr->ttl = ttl;

  hdr->next_segment = NULL;
  hdr->final = NULL;
  hdr->next = NXT_NONXT;
  hdr->final_type = NXT_NONXT;

  if (src == NULL)
    free(my_src);
  return pkt;
}

int thc_add_hdr_misc(unsigned char *pkt, int *pkt_len, unsigned char type, int len, unsigned char *buf, int buflen) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *) hdr->final, *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf2 = malloc((buflen % 8 == 6 ? buflen : (((buflen + 1) / 8) * 8) + 6));

  if (nehdr == NULL || hdr == NULL || buf == NULL || buf2 == NULL) {
    if (buf2 != NULL)
      free(buf2);
    if (nehdr != NULL)
      free(nehdr);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = type;
    hdr->next_segment = (char *) nehdr;
  } else {
    ehdr->next = type;
    ehdr->next_segment = (char *) nehdr;
  }
  hdr->final = (char *) nehdr;
  hdr->final_type = type;

  memset(buf2, 0, (buflen % 8 == 6 ? buflen : (((buflen + 1) / 8) * 8) + 6));
  memcpy(buf2, buf, buflen);

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf2;
  nehdr->data_len = (buflen % 8 == 6 ? buflen : (((buflen + 1) / 8) * 8) + 6);
  if (len == -1)
    nehdr->length = (nehdr->data_len + 1) / 8;
  else
    nehdr->length = len % 256;
  hdr->length += (buflen % 8 == 6 ? buflen + 2 : (((buflen + 1) / 8) * 8) + 6 + 2);
  *pkt_len += (buflen % 8 == 6 ? buflen + 2: (((buflen + 1) / 8) * 8) + 6 + 2);

  return 0;
}

int thc_add_hdr_route(unsigned char *pkt, int *pkt_len, unsigned char **routers, unsigned char routerptr) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *) hdr->final, *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  int i = 0, j;
  unsigned char *buf;

  if (nehdr == NULL || hdr == NULL) {
    free(nehdr);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_ROUTE;
    hdr->next_segment = (char *) nehdr;
  } else {
    ehdr->next = NXT_ROUTE;
    ehdr->next_segment = (char *) nehdr;
  }
  hdr->final = (char *) nehdr;
  hdr->final_type = NXT_ROUTE;

  while (routers[i] != NULL)
    i++;
  if (i > 23)
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: IPv6 Routing Header is adding more than 23 targets, packet might be dropped by destination\n");
  if (i == 0)
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: IPv6 Routing Header added without routing targets\n");
  if ((buf = malloc(i*16 + 2 + 4)) == NULL) {
    free(nehdr);
    return -1;
  }

  memset(buf, 0, i*16 + 2 + 4);
  buf[1] = routerptr;
  // byte 0 = type; byte 2 reserved; bytes 3-5: loose source routing
  for (j = 0; j < i; j++)
    memcpy(buf + 6 + j*16, routers[j], 16);

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf;
  nehdr->data_len = i*16 + 2 + 4;
  nehdr->length = i * 2;
  hdr->length += nehdr->data_len + 2;
  *pkt_len += nehdr->data_len + 2;

  if (i > 0 && routerptr > 0)
    hdr->final_dst = nehdr->data + 6 + (i - 1)*16;

  return 0;
}

int thc_add_hdr_mobileroute(unsigned char *pkt, int *pkt_len, unsigned char *dst) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *) hdr->final, *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf;

  if (nehdr == NULL || hdr == NULL) {
    free(nehdr);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_ROUTE;
    hdr->next_segment = (char *) nehdr;
  } else {
    ehdr->next = NXT_ROUTE;
    ehdr->next_segment = (char *) nehdr;
  }
  hdr->final = (char *) nehdr;
  hdr->final_type = NXT_ROUTE;

  if ((buf = malloc(16 + 2 + 4)) == NULL) {
    free(nehdr);
    return -1;
  }
  memset(buf, 0, 16 + 2 + 4);
  // byte 0 = type; 1 = routers to do; byte 2 reserved; bytes 3-5: loose source routing
  buf[0] = 2;
  buf[1] = 1;
  memcpy(buf+6, dst, 16);

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf;
  nehdr->data_len = 16 + 2 + 4;
  nehdr->length = 2;
  hdr->length += nehdr->data_len + 2;
  *pkt_len += nehdr->data_len + 2;

  hdr->final_dst = nehdr->data + 6;

  return 0;
}

int thc_add_hdr_fragment(unsigned char *pkt, int *pkt_len, int offset, char more_frags, unsigned int id) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *) hdr->final, *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf = malloc(6);
  int coffset = (offset > 8191 ? 8191 : offset) << 3;

  if (offset > 8191) {
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Error: fragment offset can not be larger than 8191 (2^13 - 1)\n");
    free(nehdr);
    free(buf);
    return -1;
  }

  if (nehdr == NULL || hdr == NULL || buf == NULL) {
    free(nehdr);
    free(buf);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_FRAG;
    hdr->next_segment = (char *) nehdr;
  } else {
    ehdr->next = NXT_FRAG;
    ehdr->next_segment = (char *) nehdr;
  }
  hdr->final = (char *) nehdr;
  hdr->final_type = NXT_FRAG;

  if (more_frags)
    coffset++;
  memset(buf, 0, 6);
  buf[0] = coffset / 256;
  buf[1] = coffset % 256;
  buf[2] = id / 16777216;
  buf[3] = (id % 16777216) / 65536;
  buf[4] = (id % 65536) / 256;
  buf[5] = id % 256;

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf;
  nehdr->data_len = 6;
  nehdr->length = (nehdr->data_len + 1) / 8;
  hdr->length += nehdr->data_len + 2;
  *pkt_len += nehdr->data_len + 2;

  return 0;
}

int thc_add_hdr_dst(unsigned char *pkt, int *pkt_len, unsigned char *buf, int buflen) {
  return thc_add_hdr_misc(pkt, pkt_len, NXT_OPTS, -1, buf, buflen);
}

int thc_add_hdr_hopbyhop(unsigned char *pkt, int *pkt_len, unsigned char *buf, int buflen) {
  return thc_add_hdr_misc(pkt, pkt_len, NXT_HDR, -1, buf, buflen);
}

int thc_add_hdr_nonxt(unsigned char *pkt, int *pkt_len, int hdropt) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  
  if (hdr->final_type == NXT_NONXT) {
    // nothing to be done, its the default
  } else {
    switch(hdr->final_type) {
      case NXT_IP6:
      case NXT_HDR:
      case NXT_ROUTE:
      case NXT_FRAG:
      case NXT_OPTS:
      case NXT_ESP:
      case NXT_AH:
        // nothing to be done as its the default
        break;
      default:
        if (_thc_ipv6_showerrors)
          fprintf(stderr, "Warning: Not possible to attach a no-next-header attribute if the last header is a icmp/tcp/udp/data segment\n");
    }
  }
  
  return 0;
}

int thc_add_icmp6(unsigned char *pkt, int *pkt_len, int type, int code, unsigned int flags, unsigned char *data, int data_len, int checksum) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_icmp6_hdr *ihdr = malloc(sizeof(thc_icmp6_hdr));
  thc_ipv6_ext_hdr *ehdr;

  if (ihdr == NULL)
    return -1;
  memset(ihdr, 0, sizeof(thc_icmp6_hdr));

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *) hdr->final;
    ehdr->next_segment = (char *) ihdr;
    ehdr->next=NXT_ICMP6;
  } else {
    hdr->next_segment = (char *) ihdr;
    hdr->next=NXT_ICMP6;
  }
  hdr->final = (char *) ihdr;
  hdr->final_type=NXT_ICMP6;
  
  ihdr->type = type;
  ihdr->code = code;
  ihdr->flags = flags;

  if (checksum == 0) {
    ihdr->checksum = DO_CHECKSUM;
  } else
    ihdr->checksum = checksum;

  if (data_len > 0 && data != NULL) {
    ihdr->data = malloc(data_len);
    ihdr->data_len = data_len;
    memcpy(ihdr->data, data, data_len);
  } else {
    ihdr->data = NULL;
    ihdr->data_len = 0;
  }
  
  hdr->length += data_len + 8;
  *pkt_len += data_len + 8;

  return 0;
}

int thc_add_tcp(unsigned char *pkt, int *pkt_len, unsigned short int sport, unsigned short int dport, unsigned int sequence, unsigned int ack, unsigned char flags, unsigned short int window, unsigned short int urgent, char *option, int option_len, char *data, int data_len) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_tcp_hdr *ihdr = malloc(sizeof(thc_tcp_hdr));
  thc_ipv6_ext_hdr *ehdr;
  int i = option_len;

  if (ihdr == NULL)
    return -1;
  memset(ihdr, 0, sizeof(thc_tcp_hdr));

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *) hdr->final;
    ehdr->next_segment = (char *) ihdr;
    ehdr->next=NXT_TCP;
  } else {
    hdr->next_segment = (char *) ihdr;
    hdr->next=NXT_TCP;
  }
  hdr->final = (char *) ihdr;
  hdr->final_type=NXT_TCP;
  
  ihdr->sport = sport;
  ihdr->dport = dport;
  ihdr->sequence = sequence;
  ihdr->ack = ack;
  ihdr->flags = flags;
  ihdr->window = window;
  ihdr->urgent = urgent;

//  if (checksum == 0) {
    ihdr->checksum = DO_CHECKSUM;
//  } else
//    ihdr->checksum = checksum;

  if (data_len > 0 && data != NULL) {
    ihdr->data = malloc(data_len);
    ihdr->data_len = data_len;
    memcpy(ihdr->data, data, data_len);
  } else {
    ihdr->data = NULL;
    ihdr->data_len = 0;
  }

  if (option_len > 0 && option != NULL) {
    if ((i = option_len) % 4 > 0)
      option_len = (((option_len / 4) + 1) * 4);
    ihdr->option = malloc(option_len);
    ihdr->option_len = option_len;
    memcpy(ihdr->option, option, i);
  } else {
    ihdr->option = NULL;
    ihdr->option_len = 0;
  }

  i = (20 + option_len) / 4;
  ihdr->length = ((i % 16) * 16) + (i / 16);

  hdr->length += data_len + 20 + option_len;
  *pkt_len += data_len + 20 + option_len;

  return 0;
}

int thc_add_udp(unsigned char *pkt, int *pkt_len, unsigned short int sport, unsigned short int dport, unsigned int checksum, char *data, int data_len) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_udp_hdr *ihdr = malloc(sizeof(thc_udp_hdr));
  thc_ipv6_ext_hdr *ehdr;

  if (ihdr == NULL)
    return -1;
  memset(ihdr, 0, sizeof(thc_udp_hdr));

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *) hdr->final;
    ehdr->next_segment = (char *) ihdr;
    ehdr->next=NXT_UDP;
  } else {
    hdr->next_segment = (char *) ihdr;
    hdr->next=NXT_UDP;
  }
  hdr->final = (char *) ihdr;
  hdr->final_type=NXT_UDP;
  
  ihdr->sport = sport;
  ihdr->dport = dport;

  if (checksum == 0) {
    ihdr->checksum = DO_CHECKSUM;
  } else
    ihdr->checksum = checksum;

  if (data_len > 0 && data != NULL) {
    ihdr->data = malloc(data_len);
    ihdr->data_len = data_len;
    memcpy(ihdr->data, data, data_len);
  } else {
    ihdr->data = NULL;
    ihdr->data_len = 0;
  }

  ihdr->length = data_len + 8;
  hdr->length += data_len + 8;
  *pkt_len += data_len + 8;

  return 0;
}

int thc_add_data6(unsigned char *pkt, int *pkt_len, unsigned char type, unsigned char *data, int data_len) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *) hdr->final, *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf = malloc(data_len);

  if (nehdr == NULL || hdr == NULL || buf == NULL) {
    free(nehdr);
    free(buf);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_DATA;
    hdr->next_segment = (char *) nehdr;
  } else {
    ehdr->next = NXT_DATA;
    ehdr->next_segment = (char *) nehdr;
  }
  hdr->final = (char *) nehdr;
  hdr->final_type = NXT_DATA;

  memset(buf, 0, sizeof(buf));
  memcpy(buf, data, data_len);

  nehdr->next_segment = NULL;
  nehdr->next = type;
  nehdr->data = buf;
  nehdr->data_len = data_len;
  hdr->length += data_len;
  *pkt_len += data_len;

  return 0;
}

int thc_open_ipv6() {
  if (_thc_ipv6_rawmode)
    return socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)); // XXX BUG TODO FIXME : no this is not working.
  else
    return socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
}

int thc_generate_pkt(char *interface, unsigned char *srcmac, unsigned char *dstmac, unsigned char *pkt, int *pkt_len) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr*) pkt;
  thc_ipv6_ext_hdr *ehdr;
  thc_icmp6_hdr *ihdr;
  thc_tcp_hdr *thdr;
  thc_udp_hdr *uhdr;
  char *next, *mysrcmac, *mydstmac, *last_type, *checksum_src;
  int type, bufptr, do_checksum = 0, offset = 0;

  if (pkt == NULL || hdr->pkt != NULL || (hdr->pkt = malloc(*pkt_len + 14)) == NULL)
    return -1;

  hdr->pkt_len = *pkt_len;

  if (interface == NULL)
    interface = default_interface;
  
  if (_thc_ipv6_rawmode == 0) {
    offset += 14;
    hdr->pkt_len += offset;
    *pkt_len += offset;
    if (srcmac == NULL)
      mysrcmac = thc_get_own_mac(interface);
    else
      mysrcmac = srcmac;
  
    if (dstmac == NULL)
      mydstmac = thc_get_mac(interface, hdr->src, hdr->dst);
    else
      mydstmac = dstmac;

    if (mysrcmac == NULL || mydstmac == NULL) {
      if (_thc_ipv6_showerrors)
        fprintf(stderr, "Error: could not get target MAC address\n");
      if (mysrcmac != NULL && srcmac == NULL)
        free(mysrcmac);
      if (mydstmac != NULL && dstmac == NULL)
        free(mydstmac);
      return -1;
    }
  
    memset(hdr->pkt, 0, *pkt_len);
    memcpy(&hdr->pkt[0], mydstmac, 6);
    memcpy(&hdr->pkt[6], mysrcmac, 6);
    hdr->pkt[12] = IPV6_FRAME_TYPE / 256;
    hdr->pkt[13] = IPV6_FRAME_TYPE % 256;
  }
  
  hdr->pkt[0+offset] = ((hdr->version % 16) <<4) | (hdr->class / 16);
  hdr->pkt[1+offset] = (hdr->class % 16) | ((hdr->label % 1048576) / 65536);
  hdr->pkt[2+offset] = (hdr->label % 65536) / 256;
  hdr->pkt[3+offset] = hdr->label % 256;
  hdr->pkt[4+offset] = hdr->length / 256;
  hdr->pkt[5+offset] = hdr->length % 256;
  hdr->pkt[6+offset] = hdr->next;
  last_type = &hdr->pkt[7+offset];
  hdr->pkt[7+offset] = hdr->ttl;
  memcpy(&hdr->pkt[8+offset], hdr->src, 16);
  memcpy(&hdr->pkt[24+offset], hdr->dst, 16);
  
  next = hdr->next_segment;
  type = hdr->next;
  bufptr = 40+offset;
  checksum_src = hdr->original_src;

  while (type == NXT_HDR || type == NXT_ROUTE || type == NXT_FRAG
         || type == NXT_OPTS || type == NXT_INVALID || type == NXT_IGNORE) {
    ehdr = (thc_ipv6_ext_hdr *) next;
    hdr->pkt[bufptr] = ehdr->next;
    hdr->pkt[bufptr+1] = ehdr->length;
    last_type = &hdr->pkt[bufptr];
    if (ehdr->data != NULL && ehdr->data_len > 0) {
      memcpy(&hdr->pkt[bufptr+2], ehdr->data, ehdr->data_len);
      if (type == NXT_OPTS && hdr->pkt[bufptr+2] == 0xc9) { // mobile home address option
        checksum_src = &hdr->pkt[bufptr+4];
      }
    }
    bufptr += 2 + ehdr->data_len;
    next = ehdr->next_segment;
    type = ehdr->next;
  }
  
  switch(type) {
    case NXT_NONXT:
      break;
    case NXT_ICMP6:
        ihdr = (thc_icmp6_hdr *) next;
        if (ihdr->checksum == DO_CHECKSUM) {
          ihdr->checksum = 0;
          do_checksum = 1;
        }
        hdr->pkt[bufptr] = ihdr->type;
        hdr->pkt[bufptr+1] = ihdr->code;
        hdr->pkt[bufptr+2] = ihdr->checksum / 256;
        hdr->pkt[bufptr+3] = ihdr->checksum % 256;
        hdr->pkt[bufptr+4] = ihdr->flags / 16777216;
        hdr->pkt[bufptr+5] = (ihdr->flags % 16777216) / 65536;
        hdr->pkt[bufptr+6] = (ihdr->flags % 65536) / 256;
        hdr->pkt[bufptr+7] = ihdr->flags % 256;
        if (ihdr->data != NULL && ihdr->data_len > 0)
          memcpy(&hdr->pkt[bufptr+8], ihdr->data, ihdr->data_len);
        if (do_checksum) {
//memcpy( hdr->final_dst, hdr->pkt + 38, 16);
          ihdr->checksum = checksum_pseudo_header(checksum_src, hdr->final_dst, NXT_ICMP6, &hdr->pkt[bufptr], 8 + ihdr->data_len);
/*
printf("\n");
thc_dump_data((unsigned char *)hdr->pkt + 22, 16,"packet     source");
thc_dump_data((unsigned char *)checksum_src, 16, "original   source");
thc_dump_data((unsigned char *)hdr->final_dst, 16,    "final destination");
thc_dump_data((unsigned char *)hdr->pkt + 38, 16,    "pkt   destination");
printf("\n");
*/
          hdr->pkt[bufptr+2] = ihdr->checksum / 256;
          hdr->pkt[bufptr+3] = ihdr->checksum % 256;
          do_checksum = 0;
        }
        bufptr += 8 + ihdr->data_len;
      break;
    case NXT_TCP:
        thdr = (thc_tcp_hdr *) next;
        if (thdr->checksum == DO_CHECKSUM) {
          thdr->checksum = 0;
          do_checksum = 1;
        }
        hdr->pkt[bufptr] = thdr->sport / 256;
        hdr->pkt[bufptr + 1] = thdr->sport % 256;
        hdr->pkt[bufptr + 2] = thdr->dport / 256;
        hdr->pkt[bufptr + 3] = thdr->dport % 256;
        hdr->pkt[bufptr + 4] = thdr->sequence / 16777216;
        hdr->pkt[bufptr + 5] = (thdr->sequence % 16777216) / 65536;
        hdr->pkt[bufptr + 6] = (thdr->sequence % 65536) / 256;
        hdr->pkt[bufptr + 7] = thdr->sequence % 256;
        hdr->pkt[bufptr + 8] = thdr->ack / 16777216;
        hdr->pkt[bufptr + 9] = (thdr->ack % 16777216) / 65536;
        hdr->pkt[bufptr + 10] = (thdr->ack % 65536) / 256;
        hdr->pkt[bufptr + 11] = thdr->ack % 256;
        hdr->pkt[bufptr + 12] = thdr->length;
        hdr->pkt[bufptr + 13] = thdr->flags;
        hdr->pkt[bufptr + 14] = thdr->window % 256;
        hdr->pkt[bufptr + 15] = thdr->window / 256;
        hdr->pkt[bufptr + 18] = thdr->urgent % 256;
        hdr->pkt[bufptr + 19] = thdr->urgent / 256;
        
        if (thdr->option != NULL && thdr->option_len > 0)
          memcpy(&hdr->pkt[bufptr+20], thdr->option, thdr->option_len);
        if (thdr->data != NULL && thdr->data_len > 0)
          memcpy(&hdr->pkt[bufptr+20+thdr->option_len], thdr->data, thdr->data_len);
        if (do_checksum) {
//memcpy( hdr->final_dst, hdr->pkt + 38, 16);
          thdr->checksum = checksum_pseudo_header(checksum_src, hdr->final_dst, NXT_TCP, &hdr->pkt[bufptr], 20 + thdr->option_len + thdr->data_len);
/*
printf("\n");
thc_dump_data((unsigned char *)hdr->pkt + 22, 16,"packet     source");
thc_dump_data((unsigned char *)checksum_src, 16, "original   source");
thc_dump_data((unsigned char *)hdr->final_dst, 16,    "final destination");
thc_dump_data((unsigned char *)hdr->pkt + 38, 16,    "pkt   destination");
printf("\n");
*/
          hdr->pkt[bufptr+16] = thdr->checksum / 256;
          hdr->pkt[bufptr+17] = thdr->checksum % 256;
          do_checksum = 0;
        }
        bufptr += 20 + thdr->option_len + thdr->data_len;
      
      break;
   case NXT_UDP:
        uhdr = (thc_udp_hdr *) next;
        if (uhdr->checksum == DO_CHECKSUM) {
          uhdr->checksum = 0;
          do_checksum = 1;
        }
        hdr->pkt[bufptr] = uhdr->sport / 256;
        hdr->pkt[bufptr + 1] = uhdr->sport % 256;
        hdr->pkt[bufptr + 2] = uhdr->dport / 256;
        hdr->pkt[bufptr + 3] = uhdr->dport % 256;
        hdr->pkt[bufptr + 4] = uhdr->length / 256;
        hdr->pkt[bufptr + 5] = uhdr->length % 256;
        
        if (uhdr->data != NULL && uhdr->data_len > 0)
          memcpy(&hdr->pkt[bufptr+8], uhdr->data, uhdr->data_len);
        if (do_checksum) {
//memcpy( hdr->final_dst, hdr->pkt + 38, 16);
          uhdr->checksum = checksum_pseudo_header(checksum_src, hdr->final_dst, NXT_UDP, &hdr->pkt[bufptr], 8 + uhdr->data_len);
/*
printf("\n");
thc_dump_data((unsigned char *)hdr->pkt + 22, 16,"packet     source");
thc_dump_data((unsigned char *)checksum_src, 16, "original   source");
thc_dump_data((unsigned char *)hdr->final_dst, 16,    "final destination");
thc_dump_data((unsigned char *)hdr->pkt + 38, 16,    "pkt   destination");
printf("\n");
*/
          hdr->pkt[bufptr+6] = uhdr->checksum / 256;
          hdr->pkt[bufptr+7] = uhdr->checksum % 256;
          do_checksum = 0;
        }
        bufptr += 8 + uhdr->data_len;
      
      break;
    case NXT_DATA:
        ehdr = (thc_ipv6_ext_hdr *) next;
        memcpy(&hdr->pkt[bufptr], ehdr->data, ehdr->data_len);
        if (ehdr->next == NXT_MIPV6) {
          do_checksum = checksum_pseudo_header(checksum_src, hdr->final_dst, NXT_MIPV6, &hdr->pkt[bufptr], ehdr->data_len);
          hdr->pkt[bufptr+4] = do_checksum / 256;
          hdr->pkt[bufptr+5] = do_checksum % 256;
        }
        bufptr += ehdr->data_len;
        *last_type = ehdr->next;
      break;

    // XXX TODO FIXME: other protocols
      
    default:
      if (_thc_ipv6_showerrors)
        fprintf(stderr, "Error: Data packet type %d not implemented!\n", type);
      if (srcmac == NULL)
        free(mysrcmac);
      if (dstmac == NULL)
        free(mydstmac);
      return -1;
  }

  if (bufptr != *pkt_len)
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: packet size mismatch (%d != %d)!\n", *pkt_len, bufptr);
  
  if (debug)
    thc_dump_data(hdr->pkt, *pkt_len, "Generated Packet");
  if (srcmac == NULL)
    free(mysrcmac);
  if (dstmac == NULL)
    free(mydstmac);

  return 0;
}

int thc_send_pkt(char *interface, unsigned char *pkt, int *pkt_len) {
  struct sockaddr sa;
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr*) pkt;
  
  if (pkt == NULL || hdr->pkt == NULL || hdr->pkt_len < 1 || hdr->pkt_len > 65535)
    return -1;

  if (interface == NULL)
    interface = default_interface;
  strcpy(sa.sa_data, interface);
  if (thc_socket < 0)
    thc_socket = thc_open_ipv6();

  if (debug)
    thc_dump_data(hdr->pkt, hdr->pkt_len, "Sent Packet");

  if (hdr->pkt_len > thc_get_mtu(interface))
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: packet size is larger than MTU of interface (%d > %d)!\n", hdr->pkt_len, thc_get_mtu(interface));
  
  return sendto(thc_socket, hdr->pkt, hdr->pkt_len, 0, &sa, sizeof(sa));
}

int thc_generate_and_send_pkt(char *interface, unsigned char *srcmac, unsigned char *dstmac, unsigned char *pkt, int *pkt_len) {
  if (thc_generate_pkt(interface, srcmac, dstmac, pkt, pkt_len))
    return -1;
  return thc_send_pkt(interface, pkt, pkt_len);
}

unsigned char *thc_destroy_packet(unsigned char *pkt) {
  char *ptrs[16375];
  int iptr=0;
  char *next;
  int type;
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr*) pkt;
  thc_ipv6_ext_hdr *ehdr;
  thc_icmp6_hdr *ihdr;
  thc_tcp_hdr *thdr;
  thc_udp_hdr *uhdr;
  
  ptrs[iptr] = pkt;
  iptr++;
  next = hdr->next_segment;
  type = hdr->next;
  
  if (hdr->pkt != NULL)
    free(hdr->pkt);

  while (type == NXT_HDR || type == NXT_ROUTE || type == NXT_FRAG
         || type == NXT_OPTS || type == NXT_INVALID || type == NXT_IGNORE) {
    ehdr = (thc_ipv6_ext_hdr *) next;
    ptrs[iptr] = ehdr->data;
    iptr++;
    ptrs[iptr] = (char*) ehdr;
    iptr++;
    next = ehdr->next_segment;
    type = ehdr->next;
  }

  switch(type) {
    case NXT_NONXT:
      break;
    case NXT_ICMP6:
        ihdr = (thc_icmp6_hdr *) next;
        ptrs[iptr] = ihdr->data;
        iptr++;
        ptrs[iptr] = (char*) ihdr;
        iptr++;
      break;
    case NXT_TCP:
        thdr = (thc_tcp_hdr *) next;
        ptrs[iptr] = thdr->option;
        iptr++;
        ptrs[iptr] = thdr->data;
        iptr++;
        ptrs[iptr] = (char*) thdr;
        iptr++;
      break;
    case NXT_UDP:
        uhdr = (thc_udp_hdr *) next;
        ptrs[iptr] = uhdr->data;
        iptr++;
        ptrs[iptr] = (char*) uhdr;
        iptr++;
      break;
    case NXT_DATA:
        ehdr = (thc_ipv6_ext_hdr *) next;
        ptrs[iptr] = ehdr->data;
        iptr++;
        ptrs[iptr] = (char*) ehdr;
        iptr++;
      break;
      
    // XXX TODO: other protocols
      
    default:
      if (_thc_ipv6_showerrors)
        fprintf(stderr, "Error: Data packet type %d not implemented - some data not free'ed!\n", type);
  }
  ptrs[iptr] = NULL;
  
  while (iptr >= 0) {
    if (debug)
      printf("free ptrs[%d]=%p\n", iptr, ptrs[iptr]);
    if (ptrs[iptr] != NULL)
      free(ptrs[iptr]);
    iptr--;
  }

  return NULL;
}

void thc_dump_data(unsigned char *buf, int len, char *text) {
  unsigned char *p = (unsigned char *) buf;
  unsigned char lastrow_data[16];
  int rows = len / 16;
  int lastrow = len % 16;
  int i, j;
  
  if (buf == NULL || len == 0)
    return;

  if (text != NULL && text[0] != 0)
    printf("%s (%d bytes):\n", text, len);
  for (i = 0; i < rows; i++) {
    printf("%04hx:  ", i * 16);
    for (j = 0; j < 16; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1)
         printf(" ");
    }
    printf("   [ ");
    for (j = 0; j < 16; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    printf(" ]\n");
  }
  if (lastrow > 0) {
    memset(lastrow_data, 0, sizeof(lastrow_data));
    memcpy(lastrow_data, p + len - lastrow, lastrow);
    printf("%04hx:  ", i * 16);
    for (j = 0; j < lastrow; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1)
        printf(" ");
    }
    while(j < 16) {
      printf("  ");
      if (j % 2 == 1)
        printf(" ");
      j++;
    }
    printf("   [ ");
    for (j = 0; j < lastrow; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    while(j < 16) {
      printf(" ");
      j++;
    }
    printf(" ]\n");
  }
}

unsigned char *thc_memstr(char *haystack, char *needle, int haystack_length, int needle_length) {
  register int i;
  if (needle_length > haystack_length)
    return NULL;
  for (i = 0; i <= haystack_length - needle_length; i++)
    if (memcmp(haystack + i, needle, needle_length) == 0)
      return (haystack + i);
  return NULL;
}

/* Added by willdamn <willdamn@gmail.com> 2006/07 */
thc_key_t *thc_generate_key(int key_len) {
  thc_key_t *key;
  if ((key = (thc_key_t *)malloc(sizeof(thc_key_t))) == NULL)
    return NULL;
  if ((key->rsa = RSA_generate_key(key_len, 65535, NULL, NULL)) == NULL)
       return NULL;
  key->len = key_len;
  return key;
}

thc_cga_hdr *thc_generate_cga(unsigned char *prefix, thc_key_t *key, unsigned char **cga) {
  thc_cga_hdr *cga_hdr;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned char *p, *tmp;
  int klen, rand_fd, cgasize, ignore;

  if ((cga_hdr = (thc_cga_hdr *)malloc(sizeof(thc_cga_hdr))) == NULL)
    return NULL;
    
  cga_hdr->type = 11;
    
  /* prepare CGA paramater */
  /* CGA header & mod_value, prefix, collision_count from CGA parameter*/
  cgasize = 29;
    
  if ((rand_fd = open("/dev/urandom", O_RDONLY)) < 0) {
    if (_thc_ipv6_showerrors)
      printf("Cannot open source of randomness!\n");
    free(cga_hdr);
    return NULL;
  }
  ignore = read(rand_fd, cga_hdr->modifier, 16);
  close(rand_fd);

  /* DER-encode public key */
  klen = i2d_RSA_PUBKEY(key->rsa, NULL);
  if ((cga_hdr->pub_key = (unsigned char *)malloc(klen)) == NULL) {
    return NULL;
    free(cga_hdr);
  }
  p = cga_hdr->pub_key;
  klen = i2d_RSA_PUBKEY(key->rsa, &p); 

  key->len = klen;
  cgasize += klen;
  cga_hdr->collision_cnt = 0;    
  memcpy(cga_hdr->prefix, prefix, 8); 
    
  if ((tmp = malloc(cgasize - 4)) == NULL) {
    if (_thc_ipv6_showerrors)
      perror("tmp malloc "); 
    free(cga_hdr);
    return NULL;
  }
    
  memcpy(tmp, cga_hdr->modifier, 25);
  memcpy(tmp+25, cga_hdr->pub_key, klen);
    
  /* compute hash1 */
  SHA1(tmp, cgasize - 4, md_value);
  free(tmp);
    
  if (cgasize % 8 == 0) {
    cga_hdr->len = cgasize / 8;
    cga_hdr->pad_len = 0;
  } else {
    cga_hdr->len = cgasize / 8 + 1;
    cga_hdr->pad_len = cga_hdr->len * 8 - cgasize; 
    cga_hdr->pad = (char *)malloc(cga_hdr->pad_len);
  }

    /* Prepare CGA */
  if ((*cga = (char *)malloc(16)) == NULL)  {
    free(cga_hdr);
    return NULL;
  }

  memcpy(*cga, prefix, 8);
  /* add address identifier to cga */
  memcpy(*cga+8, md_value, 8);
  /* set "U" & "G" bits ; currently sec equals 0*/
  *(*cga+8) &= 0x1c;
  // XXX BUG TODO FIXME:
  // here must be something missing in will's code.
  // cga is not pointed to by cga_hdr when we return
                                       
  return cga_hdr;                                    
}

thc_timestamp_hdr *generate_timestamp(void) {
  thc_timestamp_hdr *timestamp;
  struct timeval time;

  if ((timestamp = (thc_timestamp_hdr *)calloc(1, sizeof(thc_timestamp_hdr))) == NULL)
    return NULL;
  timestamp->type = 13;
  timestamp->len = 2;
  gettimeofday(&time, NULL);
  timestamp->timeval = bswap_64(time.tv_sec << 16);
  return timestamp;
}

thc_nonce_hdr *generate_nonce(void) {
  thc_nonce_hdr *nonce;
    
  if ((nonce = (thc_nonce_hdr *)malloc(sizeof(thc_nonce_hdr))) == NULL)
    return NULL;
  nonce->type = 14;
  nonce->nonce[0] = nonce->nonce[3] = 0xa; 
  nonce->nonce[1] = nonce->nonce[4] = 0xc; 
  nonce->nonce[2] = nonce->nonce[5] = 0xe;
  nonce->len = sizeof(thc_nonce_hdr) / 8;
  return nonce;    
}

thc_rsa_hdr *thc_generate_rsa(char *data2sign, int data2sign_len, thc_cga_hdr *cga_hdr, thc_key_t *key) {
  thc_rsa_hdr *rsa_hdr;
  unsigned char md_value[EVP_MAX_MD_SIZE], hash[20];
  int rsa_hdr_len, sign_len, fd, ignore;
         
  if ((rsa_hdr = (thc_rsa_hdr *)malloc(sizeof(thc_rsa_hdr))) == NULL)
    return NULL;
  rsa_hdr->type = 12;
                    
  /* compute public key hash */
  SHA1(cga_hdr->pub_key, key->len, md_value);
  memcpy(rsa_hdr->key_hash, md_value, 16);
  
  /* If cga type tag's unknown set a bad RSA signature, e.g useful for DoS */
  if (data2sign_len > 0)
    SHA1(data2sign, data2sign_len, hash);
  else {
    fd = open("/dev/urandom", O_RDONLY);
    ignore = read(fd, hash, 20);
    close(fd);
  }

  sign_len = RSA_size(key->rsa);
  if ((rsa_hdr->sign = malloc(sign_len)) == NULL) {
    free(rsa_hdr); 
    return NULL; 
  }
  if (RSA_sign(NID_sha1, hash, 20, rsa_hdr->sign, &sign_len, key->rsa) == 0) {
    if (_thc_ipv6_showerrors)
      printf("Error during generating RSA signature! \n"); 
    free(rsa_hdr);
    return NULL;
  }
  rsa_hdr_len = 20 + sign_len;
  if (rsa_hdr_len % 8 == 0) {
    rsa_hdr->len = rsa_hdr_len / 8;
    rsa_hdr->pad = NULL;
  } else {
    rsa_hdr->len = rsa_hdr_len / 8 + 1;
    rsa_hdr->pad = malloc(rsa_hdr->len * 8 - rsa_hdr_len);
  }
   return rsa_hdr;
}
 
int thc_add_send(unsigned char *pkt, int *pkt_len, int type, int code, unsigned int flags, unsigned char *data, int data_len, thc_cga_hdr *cga_hdr, thc_key_t *key, unsigned char *tag, int checksum) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;
  thc_icmp6_hdr *ihdr = malloc(sizeof(thc_icmp6_hdr));
  thc_ipv6_ext_hdr *ehdr;
  thc_nonce_hdr *nonce_hdr = NULL;
  thc_timestamp_hdr *timestamp_hdr = NULL;
  thc_rsa_hdr *rsa_hdr = NULL;
  unsigned char *ndp_opt_buff, *data2sign = NULL;
  char *buff;
  int ndp_opt_len, data2sign_len, offset;
   
  /* build standard part of ND message */
  if (ihdr == NULL)
    return -1;
  memset(ihdr, 0, sizeof(thc_icmp6_hdr));

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *) hdr->final;
    ehdr->next_segment = (char *) ihdr;
    ehdr->next=NXT_ICMP6;
  } else {
    hdr->next_segment = (char *) ihdr;
    hdr->next=NXT_ICMP6;
  }
  hdr->final = (char *) ihdr;
  hdr->final_type=NXT_ICMP6;
 
  ihdr->type = type;
  ihdr->code = code;
  ihdr->flags = flags;
 
  if (checksum == 0) {
    ihdr->checksum = DO_CHECKSUM;
  } else
    ihdr->checksum = checksum;
     
  if (data_len > 0 && data != NULL)
    ndp_opt_len = data_len;
  else 
    ndp_opt_len = 0;
                           
  hdr->length += 8;
  *pkt_len += 8;
             
   /* add various security features to ND message */
   /* determine options' total length */
  if ((cga_hdr == NULL))
    return -1;
   
  ndp_opt_len += cga_hdr->len * 8;   
  if ((timestamp_hdr = generate_timestamp()) == NULL)
    return -1;  
  ndp_opt_len += timestamp_hdr->len * 8;
  if ((nonce_hdr = generate_nonce()) == NULL) {
    free(timestamp_hdr);
    return -1;
  }
  ndp_opt_len += nonce_hdr->len * 8; 
   
  /* create options buffer */
  if ((ndp_opt_buff = (char *)malloc(ndp_opt_len)) == NULL) {
    free(timestamp_hdr); 
    free(nonce_hdr); 
    return -1;
  } 
  
  offset = 0;
  if (data != NULL) {
    memcpy(ndp_opt_buff+offset, data, data_len);
    offset += data_len;
  }
   
  /* CGA option */
  memcpy(ndp_opt_buff+offset, cga_hdr, 29);
  memcpy(ndp_opt_buff+offset+29, cga_hdr->pub_key, key->len);
  offset += (cga_hdr->len * 8);
  /* timestamp option */
  memcpy(ndp_opt_buff+offset, timestamp_hdr, timestamp_hdr->len * 8);
  offset += timestamp_hdr->len * 8;
  free(timestamp_hdr);
  /* nonce option */
  memcpy(ndp_opt_buff+offset, nonce_hdr, nonce_hdr->len * 8);
  offset += nonce_hdr->len * 8;
  free(nonce_hdr);
      
  /* RSA signature   
   * If CGA message type tag given compute correct RSA signature
   * otherwise set option with incorrect one */
  if (tag != NULL) {
    data2sign_len = 52 + ndp_opt_len;
    if ((data2sign = (char *)malloc(data2sign_len)) == NULL) {
      free(ndp_opt_buff); 
      return -1;
    }
    memcpy(data2sign, tag, 16);
    memcpy(data2sign+16, hdr->src, 16);
    memcpy(data2sign+32, hdr->dst, 16);
       
    /* compute icmp checksum that is needed to compute rsa signature */
    if ((buff=malloc(8 + ndp_opt_len)) == NULL) {
      free(data2sign);
      free(ndp_opt_buff);
      return -1; 
    } 
    memcpy(buff, ihdr, 8);
    memcpy(buff+8, ndp_opt_buff, ndp_opt_len);
    ihdr->checksum = checksum_pseudo_header(hdr->src, hdr->dst, NXT_ICMP6, buff, 8 + ndp_opt_len);
    free(buff);
    memcpy(data2sign+48, &ihdr->type, 4);
    ihdr->checksum = 0;
    memcpy(data2sign+52, ndp_opt_buff, ndp_opt_len);
  } else
    data2sign_len = -1;
      
  if ((rsa_hdr = thc_generate_rsa(data2sign, data2sign_len, cga_hdr, key)) == NULL) {
    free(ndp_opt_buff);
    free(data2sign);
    return -1;
  }
  ihdr->data_len = ndp_opt_len + rsa_hdr->len * 8;
  free(data2sign);
   
  /* create 'real' buffer for NDP options */ 
  if ((ihdr->data = (unsigned char *)malloc(ihdr->data_len)) == NULL) {
    free(ndp_opt_buff); 
    free(rsa_hdr); 
    return -1;
  }
  memcpy(ihdr->data, ndp_opt_buff, ndp_opt_len);
  free(ndp_opt_buff);
   
  /* RSA signature option */
  memcpy(ihdr->data+ndp_opt_len, rsa_hdr, 20);
  memcpy(ihdr->data+ndp_opt_len+20, rsa_hdr->sign, rsa_hdr->len * 8 - 20);
  hdr->length += ihdr->data_len;
  *pkt_len += ihdr->data_len;
  free(rsa_hdr);
  return 0; 
}

int thc_bind_udp_port(int port) {
  int on = 1, s;
/*  int fromlen, error;
  struct ipv6_mreq mreq6;
  static struct iovec iov;
  struct sockaddr_storage from;
  struct msghdr mhdr;*/
  struct addrinfo hints, *res;
  char pbuf[16];
  
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_PASSIVE;
  sprintf(pbuf, "%d", port);
  if (getaddrinfo(NULL, pbuf, &hints, &res) < 0)
    return -1;
  if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
    return -1;
#ifdef SO_REUSEPORT
  setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
printf("reuseport\n");
#endif
#ifdef SO_REUSEADDR
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#endif
#ifdef IPV6_PKTINFO
  setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on));
#else
  setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
#endif
#ifdef IPV6_V6ONLY
  setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif
  if (bind(s, res->ai_addr, res->ai_addrlen) < 0)
    return -1;
  freeaddrinfo(res);

  return s;
}

int thc_bind_multicast_to_socket(int s, char *interface, char *src) {
  struct ipv6_mreq mreq6;
  if (src == NULL || interface == NULL || s < 0)
    return -1;
  memset(&mreq6, 0, sizeof(mreq6));
  mreq6.ipv6mr_interface = if_nametoindex(interface);
  memcpy(&mreq6.ipv6mr_multiaddr, src, 16);
  if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) < 0)
    return -1;
  return 0;
}
