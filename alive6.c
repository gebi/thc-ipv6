#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <netdb.h>
#include <pcap.h>
#include "thc-ipv6.h"

#define MAX_ALIVE   65536
#define MAX_VENDID  64
#define MAX_NETS    32

extern int debug;
unsigned char buf[8], *alive[MAX_ALIVE];
int alive_no = 0, resolve = 0, waittime = 10, scantypes = 5, rawmode = 0;
FILE *out = NULL;
struct hostent *he = NULL;
short int si, sp, sp2;

void help(char *prg) {
  printf("%s %s (c) 2010 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-dlmrS] [-W TIME] [-i FILE] [-o FILE] [-s NUMBER] interface [unicast-or-multicast-address [remote-router]]\n\n", prg);
  printf("Shows alive addresses in the segment. If you specify a remote router, the\n");
  printf("packets are sent with a routing header prefixed by fragmentation\n");
  printf("Options:\n");
  printf("  -i FILE    check systems from input file\n");
  printf("  -o FILE    write results to output file\n");
  printf("  -m         enumerate from hardware addresses in input fule\n");
  printf("  -l         use link-local address instead of global address\n");
  printf("  -r         use raw mode (for tunnels)\n");
  printf("  -d         resolve alive ipv6 addresses\n");
  printf("  -W TIME    time in ms to wait after sending a packet (default: %d)\n", waittime);
  printf("  -S         slow mode, get best router for each remote target or when proxy-NA\n");
  printf("  -n NUMBER  how often to send each packet (default: 1)\n");
  printf("  -s NUMBER  scan type, bit-wise add: 1-ping, 2-invalid header,\n");
  printf("             4-invalid hop-by-hop, 8-udp dns, 16-tcp ack highport,\n");
  printf("             32-tcp syn ssh, 64-tcp syn web, 128-tcp syn ssl; default: %d\n", scantypes);
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  int i, ok = 0, len = header->caplen, offset = 0;
  unsigned char *ptr = (unsigned char *)data;
  
  if (!rawmode) {
    ptr += 14;
    len -= 14;
  }

  if (debug)
    thc_dump_data(ptr, header->caplen - 14, "Received Packet");
    
  if (len < 48 + sizeof(buf))
    return;

  // if the destination system sends source routed packets back, unlikely though
  if (ptr[6] == 0x2b)
    if ((offset = (ptr[41] + 1) * 8) + 48 + sizeof(buf) > len)
      return;

  if (ptr[6 + offset] == NXT_ICMP6 && (scantypes & 15) > 0) {
    if (ptr[40 + offset] == ICMP6_PINGREPLY && (scantypes & 7) > 0) {
      if (memcmp(ptr + 50, (char*)&si, 2) == 0)
        ok = 1;
    } else // if not a ping reply, its an error packet and the size is larger
      if (len < 112 + sizeof(buf))
        return;
    if (ptr[40 + offset] == ICMP6_PARAMPROB && (scantypes & 6) > 0)
      if (memcmp(ptr + 116, (char*)&si, 2) == 0)
        ok = 1;
    if (ptr[40 + offset] == ICMP6_UNREACH && ptr[41 + offset] == 4 && (scantypes & 8) > 0)
      if (memcmp(ptr + 88, (char*)&sp2, 2) == 0)
        ok = 1;
  }
  
  if (ptr[6 + offset] == NXT_UDP && (scantypes & 8) > 0)
    if (memcmp(ptr + 42, (char*)&sp2, 2) == 0)
      ok = 1;
  
  if (ptr[6 + offset] == NXT_TCP && (scantypes & 240) > 0)
    if (memcmp(ptr + 42, (char*)&sp2, 2) == 0)
      ok = 1;
  
  i = 0;
  while (ok && i < alive_no) {
    if (memcmp(alive[i], ptr + 8, 16) == 0)
      ok = 0;
    i++;
  }

  if (ok) {
    if (resolve)
      he = gethostbyaddr(ptr + 8, 16, AF_INET6);
    printf("Alive: %s%s%s%s\n", thc_string2notation(thc_ipv62string(ptr + 8)), resolve ? " (" : "", resolve && he != NULL ? he->h_name : "", resolve ? ")": "" );
    if (out != NULL)
      fprintf(out, "%s%s%s%s\n", thc_string2notation(thc_ipv62string(ptr + 8)), resolve ? " (" : "", resolve && he != NULL ? he->h_name : "", resolve ? ")": "" );
    if (alive_no < MAX_ALIVE && (alive[alive_no] = malloc(16)) != NULL) {
      memcpy(alive[alive_no], ptr + 8, 16);
      alive_no++;
      if (alive_no == MAX_ALIVE)
        fprintf(stderr, "Warning: more than %d alive systems detected, disabling double results check!\n", MAX_ALIVE);
    }
  }
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, *router6 = NULL, *cur_dst;
  unsigned char *multicast6, *src6 = NULL, *mac = NULL, *rmac = NULL, *routers[2], string[64] = "ip6 and dst ";
  int pkt_len = 0, prefer = PREFER_GLOBAL;
  int enumerate = 0, i, j, list = 0, curr = 0, cur_enum = 0;
  int slow = 0, no_vendid = 0, no_nets = 0, local = -1, no_send = 1, nos = 0;
  char *interface, *input = NULL, *output = NULL, line[128], *ptr, do_router = 0, ok;
  unsigned char bh, bm, bl, restart;
  unsigned char vendid[MAX_VENDID][11], nets[MAX_NETS][8], orig_dst[16];
  unsigned char dnsbuf[] = { 0xde, 0xad, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
                    0x73, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01 };
  thc_ipv6_hdr *hdr;
  time_t passed;
  pcap_t *p;
  FILE *in = NULL;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  while ((i = getopt(argc, argv, "s:W:Sdmlri:o:n:")) >= 0) {
    switch(i) {
      case 's' : scantypes = atoi(optarg); break;
      case 'W' : waittime = atoi(optarg); break;
      case 'S' : slow = 1; break;
      case 'd' : resolve = 1; break;
      case 'r' : thc_ipv6_rawmode(1); rawmode = 1; break;
      case 'l' : prefer = PREFER_LINK; break;
      case 'm' : enumerate = 1; break;
      case 'n' : no_send = atoi(optarg); break;
      case 'i' : input = optarg; list++; curr = 1; break;
      case 'o' : output = optarg; break;
    }
  }

  if (no_send < 1 || no_send > 10) {
    fprintf(stderr, "Error: -n option may only be set between 1 and 10\n");
    exit(-1);
  }
  if (waittime < 0) {
    fprintf(stderr, "Error: -W wait time is not a positive value\n");
    exit(-1);
  }
  if (scantypes < 1 || scantypes > 255) {
    fprintf(stderr, "Error: -s scan type value must be between 1 and 255\n");
    exit(-1);
  }

  interface = argv[optind];
  if (argv[optind + 1] != NULL && argc >= optind + 2) {
    if ((multicast6 = thc_resolve6(argv[optind + 1])) == NULL) {
      fprintf(stderr, "Error: could not resolve %s\n", argv[optind + 1]);
      exit(-1);
    }
    curr = 0;
  } else
    multicast6 = thc_resolve6("ff02::1");
  src6 = thc_get_own_ipv6(interface, multicast6, prefer);
  if (src6 == NULL) {
    fprintf(stderr, "Error: no ipv6 address found for interface %s!\n", interface);
    exit(-1);
  }
  if (argv[optind + 2] != NULL && argc >= optind + 3) {
    router6 = thc_resolve6(argv[optind + 2]);
    do_router = 1;
    if ((mac = thc_get_mac(interface, src6, router6)) == NULL) {
      fprintf(stderr, "Error: could not resolve mac address for destination router %s\n", argv[optind + 2]);
      exit(-1);
    }
  }
  strcat(string, thc_string2notation(thc_ipv62string(src6)));
  if (enumerate && input == NULL && multicast6[0] == 0xff) {
    fprintf(stderr, "Warning: -m option does not make sense for multicast addresses, disabled\n");
    enumerate = 0;
  }
  
  // make the sending buffer unique
  si = getpid() % 65536;
  sp = 1200 + si % 30000;
  sp2 = htons(sp);
  memset(vendid, 0, sizeof(vendid));
  memset(nets, 0, sizeof(nets));
  for (i = 0; i < sizeof(buf) / 2; i++)
    memcpy(buf + i*2, (char*)&si, 2);

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n", interface, string);
    exit(-1);
  }

  if (input != NULL)
    if ((in = fopen(input, "r")) == NULL) {
      fprintf(stderr, "Error: coult not open file %s\n", input);
      exit(-1);
    }
  
  if (output != NULL)
    if ((out = fopen(output, "w")) == NULL) {
      fprintf(stderr, "Error: could not create output file %s\n", output);
      exit(-1);
    }

  while (curr <= list) {
    ok = 1;
    if (cur_enum == 0) { 
      if (curr == 0) { // the command line target first - if present
        if (enumerate) {
          if ((local = thc_is_dst_local(interface, multicast6)) > 0) {
            fprintf(stderr, "Warning: enumeration on local address %s disabled, use ff02::1!\n", thc_string2notation(thc_ipv62string(multicast6)));
            cur_dst = multicast6;
          } else {
            // enable dhcp address space scan
            cur_enum = 2;
            cur_dst = multicast6;
            memcpy(orig_dst, multicast6, 16);
            bl = bm = bh = 0;
            restart = 1;
            memcpy(nets[0], cur_dst, 8);
            no_nets++;
            fprintf(stderr, "Info: started dhcp6 address space scan on %s\n", thc_string2notation(thc_ipv62string(nets[0])));
          }
        } else {
          cur_dst = multicast6;
        }
      } else { // input file processing, if present
        if (feof(in))
          curr++;
        line[0] = 0;
        ptr = fgets(line, sizeof(line), in);
        ptr = NULL;
        if (strlen(line) > 0)
          if (line[strlen(line)-1] == '\n')
            line[strlen(line)-1] = 0;
        if (strlen(line) > 0)
          if (line[strlen(line)-1] == '\r')
            line[strlen(line)-1] = 0;
        if (strlen(line) > 0) {
          ptr = line + strlen(line) - 1;
          while (*ptr == ' ' || *ptr == '\t')
            *ptr-- = 0;
          ptr = line;
          while (*ptr == ' ' || *ptr == '\t')
            ptr++;
          if (*ptr == '#')
            ptr = NULL;
        }
        if ((cur_dst = thc_resolve6(ptr)) == NULL) {
          fprintf(stderr, "Warning: could not resolve %s, skipping\n", ptr);
          ok = 0;
        } else {
          if (enumerate) {
            if ((local = thc_is_dst_local(interface, cur_dst)) > 0) {
              fprintf(stderr, "Warning: enumeration on local address %s disabled, use ff02::1!\n", thc_string2notation(thc_ipv62string(cur_dst)));
            } else {
              i = 0;
              if (no_nets > 0)
                for (j = 0; j < no_nets; j++)
                  if (memcmp(nets[j], cur_dst, 8) == 0)
                    i = 1;
              if (i == 0) {
                cur_enum = 2;
                memcpy(orig_dst, multicast6, 16);
                bl = bm = bh = 0;
                if (no_nets < MAX_NETS) {
                  memcpy(nets[no_nets], cur_dst, 8);
                  no_nets++;
                  if (no_nets == MAX_NETS)
                    fprintf(stderr, "Warning: more than %d networks found, disabling double network check!\n", MAX_VENDID);
                }
                fprintf(stderr, "Info: started dhcp6 address space scan on %s\n", thc_string2notation(thc_ipv62string(nets[no_nets - 1])));
              } else {
                ok = 0; // already scanned
              }
            }
          } else
            local = -1;
        }
      }

      if (cur_enum == 0 && curr == 0)
        curr++;
    } else if (cur_enum == 1) {
      // enumeration of vendor-id keyspaces identified, lowest 3 bytes of ipv6
      if (restart) {
        restart = 0;
        bl = bm = bh = 0;
        memcpy(cur_dst, orig_dst, 16);
        memset(cur_dst + 13, 0, 3);
        fprintf(stderr, "Info: started autoconfiguration address space scan on %s\n", thc_string2notation(thc_ipv62string(cur_dst)));
        if (no_vendid < MAX_VENDID) {
          memcpy(vendid[no_vendid], cur_dst, 11);
          no_vendid++;
          if (no_vendid == MAX_VENDID)
            fprintf(stderr, "Warning: more than %d vendor ids found, disabling double vendor id check!\n", MAX_VENDID);
        }
      } else {
        if (bl == 255) {
          bl = 0;
          if (bm == 255) {
            bm = 0;
            bh++;
            cur_dst[13] = bh;
          } else {
            bm++;
          }
          cur_dst[14] = bm;
        } else {
          bl++;
          if (bh == 255 && bm == 255 && bl == 255) {
            cur_enum = 0;
            if (curr == 0)
              curr++;
          }
        }
      }
      cur_dst[15] = bl;
    } else if (cur_enum == 2) {
      // enumeration of common dhcp6 address space, currently covering:
      //    NET::0:0000 to NET::0:02ff
      //    NET::0:1000 to NET::0:10ff
      //    NET::0:2000 to NET::0:20ff
      //    NET::1:0000 to NET::0:02ff
      //    NET::1:1000 to NET::0:10ff
      //    NET::1:2000 to NET::0:20ff
      // == 2560 addresses == 10 IPv6 C-class networks
      if (restart) {
        memset(cur_dst + 8, 0, 8);
        restart = 0;
      } else {
        if (bl == 255) {
          bl = 0;
          switch(bm) {
            case 0: case 1: bm++; break;
            case 2: bm = 0x10; break;
            case 0x10: bm = 0x20; break;
            case 0x20: bm = 0; bh++; cur_dst[13] = bh; break;
            default: fprintf(stderr, "WTF...?!\n"); exit(-1);
          }
          cur_dst[14] = bm;
        } else {
          bl++;
          if (bh == 1 && bm == 0x20 && bl == 255) {
            if (orig_dst[11] == 0xff && orig_dst[12] == 0xfe) {
              i = 0;
              if (no_vendid > 0)
                for (j = 0; j < no_vendid; j++)
                  if (memcmp(vendid[j], orig_dst, 11) == 0)
                    i = 1;
              if (i == 0) {
                cur_enum = 1;
                restart = 1;
              } else
                cur_enum = 0;
            } else {
              cur_enum = 0;
            }
            if (curr == 0 && cur_enum == 0)
              curr++;
          }
        }
        cur_dst[15] = bl;
      }
    } else {
      fprintf(stderr, "Error: WTF?!\n");
      exit(-1);
    }

    // here we send the alive check packets - if we have a valid destination
    if (do_router) {
      routers[0] = cur_dst;
      routers[1] = NULL;
      cur_dst = router6; // switch destination and router
    }

    // central dst mac lookup and fast/slow implementation
    if (ok && rawmode == 0 && cur_dst != NULL && do_router == 0) {
      if (local == -1)
         local = thc_is_dst_local(interface, cur_dst);
      if (local == 0 && slow == 0) {
        if (rmac == NULL)
          rmac = thc_get_mac(interface, src6, cur_dst);
        mac = rmac;
      }
      if (local == 1 || slow)
        mac = thc_get_mac(interface, src6, cur_dst);
      if (local && mac != NULL && slow == 0 && cur_dst[0] != 0xff) {
        // if a local system has an ARP entry, assume its alive if the slow
        // mode is not set. so if proxy NA is present, use -S
        if (resolve)
          he = gethostbyaddr(cur_dst, 16, AF_INET6);
        printf("Alive: %s%s%s%s\n", thc_string2notation(thc_ipv62string(cur_dst)), resolve ? " (" : "", resolve && he != NULL ? he->h_name : "", resolve ? ")": "" );
        if (out != NULL)
          fprintf(out, "%s%s%s%s\n", thc_string2notation(thc_ipv62string(cur_dst)), resolve ? " (" : "", resolve && he != NULL ? he->h_name : "", resolve ? ")": "" );
        if (alive_no < MAX_ALIVE && (alive[alive_no] = malloc(16)) != NULL) {
          memcpy(alive[alive_no], cur_dst, 16);
          alive_no++;
          if (alive_no == MAX_ALIVE)
            fprintf(stderr, "Warning: more than %d alive systems detected, disabling double results check!\n", MAX_ALIVE);
        }
        ok = 0;
      }
      if (mac == NULL) {
        fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", thc_string2notation(thc_ipv62string(cur_dst)));
        ok = 0;
      }
    }

    if (ok && cur_dst != NULL) {
      if (debug)
        printf("DEBUG: sending alive check packets to %s\n", thc_string2notation(thc_ipv62string(cur_dst)));
      for (nos = 0; nos < no_send; nos++) { // send -n defined times, default: 1
        if (scantypes & 1) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, sizeof(buf), 0) < 0)
            return -1;
          if (thc_generate_pkt(interface, NULL, mac, pkt, &pkt_len) < 0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          }
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
          } else
            thc_send_pkt(interface, pkt, &pkt_len);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
        if (scantypes & 2) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_hdr_misc(pkt, &pkt_len, NXT_INVALID, -1, (unsigned char *) &buf, sizeof(buf)) < 0)
            return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, sizeof(buf), 0) < 0)
            return -1;
          thc_generate_pkt(interface, NULL, mac, pkt, &pkt_len);
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
          } else
            thc_send_pkt(interface, pkt, &pkt_len);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
        if (scantypes & 4) {
          buf[0] = NXT_INVALID;
          buf[1] = 1;
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *) &buf, sizeof(buf)) < 0)
            return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xdeadbeef, (unsigned char *) &buf, sizeof(buf), 0) < 0)
            return -1;
          thc_generate_pkt(interface, NULL, mac, pkt, &pkt_len);
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
          } else
            thc_send_pkt(interface, pkt, &pkt_len);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }  
        if (scantypes & 8) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_udp(pkt, &pkt_len, sp, 53, 0, dnsbuf, sizeof(dnsbuf)) < 0)
            return -1;
          if (thc_generate_pkt(interface, NULL, mac, pkt, &pkt_len) < 0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          } 
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
          } else
            thc_send_pkt(interface, pkt, &pkt_len);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
        if (scantypes & 16) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_tcp(pkt, &pkt_len, sp, sp, (sp << 16) + sp, (sp << 16) + sp, TCP_ACK, 5760, 0, NULL, 0, NULL, 0) < 0)
            return -1;
          if (thc_generate_pkt(interface, NULL, mac, pkt, &pkt_len) < 0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          }
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
          } else
            thc_send_pkt(interface, pkt, &pkt_len);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
        if (scantypes & 32) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_tcp(pkt, &pkt_len, sp, 22, (sp << 16) + sp, 0, TCP_SYN, 5760, 0, NULL, 0, NULL, 0) < 0)
            return -1;
          if (thc_generate_pkt(interface, NULL, mac, pkt, &pkt_len) < 0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          }
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
          } else
            thc_send_pkt(interface, pkt, &pkt_len);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
        if (scantypes & 64) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_tcp(pkt, &pkt_len, sp, 80, (sp << 16) + sp, 0, TCP_SYN, 5760, 0, NULL, 0, NULL, 0) < 0)
            return -1;
          if (thc_generate_pkt(interface, NULL, mac, pkt, &pkt_len) < 0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          }
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
          } else
            thc_send_pkt(interface, pkt, &pkt_len);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        } 
        if (scantypes & 128) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_tcp(pkt, &pkt_len, sp, 443, (sp << 16) + sp, 0, TCP_SYN, 5760, 0, NULL, 0, NULL, 0) < 0)
            return -1;
          if (thc_generate_pkt(interface, NULL, mac, pkt, &pkt_len) < 0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          } 
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + 14, hdr->pkt_len - 40 - 14, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8);
          } else
            thc_send_pkt(interface, pkt, &pkt_len);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
      }

      // cleanup
      if (cur_enum == 0 && cur_dst != multicast6)
        free(cur_dst);
      if (local)
        free(mac);

      if (cur_enum == 0 || cur_dst[15] == 0xff)
        while (thc_pcap_check(p, (char*)check_packets, NULL) > 0);
    }
  }

  passed = time(NULL);
  if (curr > 1 || ok)
    while (passed + 5 >= time(NULL) && (alive_no == 0 || multicast6[0] == 0xff || curr > 1))
      thc_pcap_check(p, (char*)check_packets, NULL);
  thc_pcap_close(p);
  if (out != NULL)
    fclose(out);
  printf("Found %d system%s alive\n", alive_no, alive_no == 1 ? "" : "s");

  return 0;
}
