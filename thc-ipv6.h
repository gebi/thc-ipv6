/*
 * (c) 2006 by van Hauser / THC
 *
 * THC IPv6 Attack Library Header Files
 *
 */

#ifndef _THC_IPV6_H

#define _THC_IPV6_H

#include <pcap.h>
#include <openssl/rsa.h>

#define VERSION 	"v0.7"
#define AUTHOR 		"van Hauser / THC <vh@thc.org>"
#define RESOURCE	"www.thc.org"

//#define MULTICAST_ALL_NODES

#define ICMP6_PINGREQUEST 128
#define ICMP6_PINGREPLY   129
#define ICMP6_NEIGHBORADV 136
#define ICMP6_NEIGHBORSOL 135
#define ICMP6_ROUTERADV   134
#define ICMP6_ROUTERSOL   133
#define ICMP6_UNREACH     1
#define ICMP6_TOOBIG      2
#define ICMP6_TTLEXEED    3
#define ICMP6_PARAMPROB   4
#define ICMP6_REDIR       137    
#define ICMP6_MLD_QUERY   130
#define ICMP6_MLD_REPORT  131
#define ICMP6_MLD_DONE    132

#define ICMP6_NEIGHBORADV_ROUTER   0x80000000
#define ICMP6_NEIGHBORADV_SOLICIT  0x40000000
#define ICMP6_NEIGHBORADV_OVERRIDE 0x20000000

#define PREFER_HOST     16
#define PREFER_LINK	32
#define PREFER_GLOBAL	 0

extern int thc_pcap_function(char *interface, unsigned char *capture, char *function);
extern pcap_t *thc_pcap_init(char *interface, unsigned char *capture);
extern void thc_ipv6_rawmode(int mode);
extern int thc_pcap_check(pcap_t *p, char *function);
extern void thc_pcap_close(pcap_t *p);
extern char *thc_resolve6(unsigned char *target);
extern unsigned char *thc_lookup_ipv6_mac(char *interface, unsigned char *dst);
extern unsigned char *thc_get_own_mac(char *interface);
extern unsigned char *thc_get_own_ipv6(char *interface, unsigned char *dst, int prefer);
extern unsigned char *thc_get_multicast_mac(unsigned char *dst);
extern unsigned char *thc_get_mac(char *interface, unsigned char *src, unsigned char *dst);

extern unsigned char *thc_inverse_packet(unsigned char *pkt, int pkt_len);

extern int thc_ping6(char *interface, unsigned char *src, unsigned char *dst, int size, int count);
extern int thc_neighboradv6(char *interface, unsigned char *src, unsigned char *dst, unsigned char *srcmac, unsigned char *dstmac, unsigned int flags, unsigned char *target);
extern int thc_neighborsol6(char *interface, unsigned char *src, unsigned char *dst, unsigned char *target, unsigned char *srcmac, unsigned char *dstmac);
extern int thc_routeradv6(char *interface, unsigned char *src, unsigned char *dst, unsigned char *srcmac, unsigned char default_ttl, int managed,  unsigned char *prefix, int prefixlen, int mtu, unsigned int lifetime);
extern int thc_routersol6(char *interface, unsigned char *src, unsigned char *dst, unsigned char *srcmac, unsigned char *dstmac);
extern int thc_toobig6(char *interface, unsigned char *src, unsigned char *srcmac, unsigned char *dstmac, unsigned int mtu, unsigned char *pkt, int pkt_len);
extern int thc_paramprob6(char *interface, unsigned char *src, unsigned char *srcmac, unsigned char *dstmac, unsigned char code, unsigned int pointer, unsigned char *pkt, int pkt_len);
extern int thc_unreach6(char *interface, unsigned char *src, unsigned char *srcmac, unsigned char *dstmac, unsigned char code, unsigned char *pkt, int pkt_len);
extern int thc_redir6(char *interface, unsigned char *src, unsigned char *srcmac, unsigned char *dstmac, unsigned char *newrouter, unsigned char *newroutermac, unsigned char *pkt, int pkt_len);
extern int thc_send_as_fragment6(char *interface, unsigned char *src, unsigned char *dst, unsigned char type, unsigned char *data, int data_len, int frag_len);

extern char *thc_create_ipv6(char *interface, int prefer, int *pkt_len, unsigned char *src, unsigned char *dst, int ttl, int length, int label, int class, int version);

extern int thc_add_hdr_misc(unsigned char *pkt, int *pkt_len, unsigned char type, int len, unsigned char *buf, int buflen);
extern int thc_add_hdr_route(unsigned char *pkt, int *pkt_len, unsigned char **routers, unsigned char routerptr);
extern int thc_add_hdr_fragment(unsigned char *pkt, int *pkt_len, int offset, char more_frags, unsigned int id);
extern int thc_add_hdr_dst(unsigned char *pkt, int *pkt_len, unsigned char *buf, int buflen);
extern int thc_add_hdr_hopbyhop(unsigned char *pkt, int *pkt_len, unsigned char *buf, int buflen);
extern int thc_add_hdr_nonxt(unsigned char *pkt, int *pkt_len, int hdropt);
extern int thc_add_icmp6(unsigned char *pkt, int *pkt_len, int type, int code, unsigned int flags, unsigned char *data, int data_len, int checksum);
extern int thc_add_data6(unsigned char *pkt, int *pkt_len, unsigned char type, unsigned char *data, int data_len);

extern int thc_generate_and_send_pkt(char *interface, unsigned char *srcmac, unsigned char *dstmac, unsigned char *pkt, int *pkt_len);
extern int thc_generate_pkt(char *interface, unsigned char *srcmac, unsigned char *dstmac, unsigned char *pkt, int *pkt_len);
extern int thc_send_pkt(char *interface, unsigned char *pkt, int *pkt_len);
unsigned char *thc_destroy_packet(unsigned char *pkt);

extern int thc_open_ipv6();
extern int checksum_pseudo_header(unsigned char *src, unsigned char *dst, unsigned char type, unsigned char *data, int length);
void thc_dump_data(unsigned char *buf, int len, char *text);
unsigned char *thc_ipv62string(unsigned char *ipv6);
unsigned char *thc_string2ipv6(unsigned char *string);
unsigned char *thc_string2notation(unsigned char *string);
unsigned char *thc_memstr(char *haystack, char *needle, int haystack_length, int needle_length);


#define DO_CHECKSUM 0xffff

#define NXT_IP6 41

#define NXT_INVALID 128
#define NXT_IGNORE 31

#define NXT_HDR 0
#define NXT_ROUTE 43
#define NXT_FRAG 44
#define NXT_NONXT 59 
#define NXT_OPTS 60 

#define NXT_ESP 50
#define NXT_AH 51

#define NXT_MIPV6 135
#define NXT_ICMP6 58
#define NXT_TCP 6
#define NXT_UDP 17

#define NXT_DATA 255

#define IPV6_FRAME_TYPE 0x86dd

typedef struct {
  unsigned char dst[6];
  unsigned char src[6];
  unsigned int type:16;
} thc_ethernet;


typedef struct {
  unsigned char *pkt;
  int pkt_len;
  char *next_segment;
  char *final;
  int final_type;
  unsigned int  version; // :4;
  unsigned char class;
  unsigned int  label;   // :20;
  unsigned int  length;  // :16;
  unsigned char next;
  unsigned char ttl;
  unsigned char src[16];
  unsigned char dst[16];
  unsigned char *final_dst;
  unsigned char *original_src;
} thc_ipv6_hdr;

typedef struct {
  char *next_segment;
  unsigned char next;
  unsigned char length;
  unsigned char *data;
  int           data_len;
} thc_ipv6_ext_hdr;

typedef struct {
  unsigned char type;
  unsigned char code;
  unsigned int  checksum:16;
  unsigned int  flags;
  unsigned char *data;
  int           data_len;
} thc_icmp6_hdr;

typedef struct {
  char *next_segment;
  char dummy[8];
} thc_dummy_hdr;

/*
typedef struct {
        unsigned int           nlmsg_len;
        unsigned short         nlmsg_type;
        unsigned short         nlmsg_flags;
        unsigned int           nlmsg_seq;
        unsigned int           nlmsg_pid;
} nlmsghdr;

typedef struct
{
        unsigned char           rtgen_family;
} rtgenmsg;

typedef struct {
  nlmsghdr nlh;
  rtgenmsg g;
} neigh_req;

typedef struct {
        unsigned short         nl_family;
        unsigned short         nl_pad;
        unsigned int           nl_pid;
        unsigned int           nl_groups;
} sockaddr_nl;
*/

typedef struct {
  unsigned char type;
  unsigned char len;
  unsigned char pad_len;
  unsigned char resv;
/* cga params */
  unsigned char modifier[16];
  unsigned char prefix[8];
  unsigned char collision_cnt;
  unsigned char coll2;
  unsigned char *pub_key; 
  unsigned char *exts;
/* end of cga params */
  unsigned char *pad;
} thc_cga_hdr;

typedef struct {
  unsigned char type;
  unsigned char len;
  unsigned char resv[6];
  unsigned long long timeval;
} thc_timestamp_hdr;

typedef struct {
  unsigned char type;
  unsigned char len;
  char nonce[6];
} thc_nonce_hdr;

typedef struct {
  unsigned char type;
  unsigned char len;
  short int resv;
  unsigned char key_hash[16];
  char *sign;
  char *pad;
} thc_rsa_hdr;       

typedef struct {
  RSA *rsa;
  int len;
} thc_key_t;

typedef struct {
  unsigned char *data;
  /* DER-encoded key length */
  int len;
} opt_t;

extern thc_key_t *thc_generate_key(int key_len);
extern thc_cga_hdr *thc_generate_cga(unsigned char *prefix, thc_key_t *key, unsigned char **cga);

#endif

