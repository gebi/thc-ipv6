/*
 * dnsdict6 is actually based on dnsmap with four changes:
 *   - threaded (way faster)
 *   - bugfixes
 *   - only prints ipv6 addresses
 *   - simplified options
 * have fun!     van Hauser / THC, May 2010
 *
 * ** dnsmap - DNS Network Mapper by pagvac
 * ** Copyright (C) 2010 gnucitizen.org
 * **
 * ** This program is free software; you can redistribute it and/or modify
 * ** it under the terms of the GNU General Public License as published by
 * ** the Free Software Foundation; either version 2 of the License, or
 * ** (at your option) any later version.
 * **
 * ** This program is distributed in the hope that it will be useful,
 * ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 * ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * ** GNU General Public License for more details.
 * **
 * ** You should have received a copy of the GNU General Public License
 * ** along with this program; if not, write to the Free Software
 * ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "thc-ipv6.h"
#include "dnsdict6.h" // built-in subdomains list

//#define DEBUG 1
#define FALSE 0
#define TRUE 1
#define MAXSTRSIZE 200
#define DEFAULT_THREADS 8
#define MAX_THREADS     32
#define MAX_UNIQUE 4096
#define MAX_WCARD  8

char domain[256];
unsigned short int filtIPcount = 0, milliseconds = 10, ipCount = 0;
unsigned short int intIPcount = 0, found = 0, txtResults = FALSE;
unsigned short int csvResults = FALSE, delay = FALSE, ucount = 0, wcard = 0;
char wildcardIpStr[MAX_WCARD][INET_ADDRSTRLEN], unique[MAX_UNIQUE][INET_ADDRSTRLEN];

void *help(char *prg) {
  printf("%s %s (c) 2010 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-t THREADS] domain [dictionary-file]\n\n", prg);
  printf("Enumerates a domain for DNS entries, it uses a dictionary file if supplied\n");
  printf("or a built-in list otherwise.\n");
  printf("Use -t to specify the number of threads to use (default: %d, max: %d).\n", DEFAULT_THREADS, MAX_THREADS);
  printf("Use just -D to dump the built-in list.\nTool based on dnsmap by pagvac@gnucitizen.org.\n");
  exit(-1);
}

// return true if domain wildcards are enabled
unsigned short int wildcarDetect(char *dom) {
  char s[MAXSTRSIZE] = "";
  unsigned short int i = 0, j, k, max = 8;
  struct addrinfo hints, *res, *p;
  void *addr;
  int status;
  char ipv6str[INET6_ADDRSTRLEN];
  struct sockaddr_in6 *ipv6, *q;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET6;   // AF_INET or AF_INET6 to force version
//  hints.ai_socktype = SOCK_STREAM;
  srand(time(NULL));

  // generate up to random digits subdomain string
  // e.g. 06312580442146732554
  for (i = 0; i < max; ++i)
    s[i] = '0' + (rand() % 10);
  s[max] = 0;
  strcat(s, "0193.");
  strcat(s, dom);
#if DEBUG
  printf("random subdomain for wildcard testing: %s\n", s);
#endif
  // random subdomain resolves, thus wildcards are enabled
  if ((status = getaddrinfo(dom, NULL, &hints, &res)) == 0) {
    fprintf(stderr, "Warning: wildcard domain configured\n");
    q = NULL;
    for (p = res; p != NULL; p = p->ai_next) {
      if (p->ai_family == AF_INET6) {       // IPv6
        ipv6 = (struct sockaddr_in6 *) p->ai_addr;
        addr = &(ipv6->sin6_addr);
        if (q == NULL || memcmp(&ipv6->sin6_addr, &q->sin6_addr, 16) != 0) {
          q = ipv6;
          if (wcard < MAX_WCARD) {
            memcpy(wildcardIpStr[wcard], addr, 16);
            wcard++;
          }
          inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
          printf("*.%s => %s\n", dom, ipv6str);
        }
      }
    }
    freeaddrinfo(res);
  }

  for (i = 0; i < max; ++i)
    s[i] = 'a' + (rand() % 26);
  s[max] = 'y';
  s[max+1] = 'c';
  s[max+2] = 'a';
  s[max+3] = 'y';
#if DEBUG
  printf("random subdomain for wildcard testing: %s\n", s);
#endif
  // random subdomain resolves, thus wildcards are enabled
  if ((status = getaddrinfo(dom, NULL, &hints, &res)) == 0) {
    if (wcard == 0)
      fprintf(stderr, "Warning: wildcard domain configured (2nd test)\n");
    q = NULL;
    for (p = res; p != NULL; p = p->ai_next) {
      if (p->ai_family == AF_INET6) {       // IPv6
        ipv6 = (struct sockaddr_in6 *) p->ai_addr;
        addr = &(ipv6->sin6_addr);
        if (q == NULL || memcmp(&ipv6->sin6_addr, &q->sin6_addr, 16) != 0) {
          q = ipv6;
          if (wcard < MAX_WCARD) {
            k = 1;
            if (wcard > 0)
              for (j = 0; j < wcard; j++)
                if (memcmp(wildcardIpStr[j], addr, 16) == 0)
                  k = 0;
            if (k) {
              memcpy(wildcardIpStr[wcard], addr, 16);
              wcard++;
              inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
              printf("*.%s => %s\n", dom, ipv6str);
            }
          }
        }
      }
    }
    freeaddrinfo(res);
  }

  if (wcard)
    return TRUE;
  else
    return FALSE;
}

// return number of milliseconds delayed
unsigned short int dodelay(unsigned short int maxmillisecs) {
  unsigned short int n = 0;

  srand(time(NULL));
  n = rand() % maxmillisecs;
  ++n;
  maxmillisecs = n;
#if DEBUG
  printf("sleeping %d milliseconds ...\n", maxmillisecs);
#endif
  usleep(maxmillisecs * 1000);
  return maxmillisecs;
}

// return true if domain is valid, false otherwise
unsigned short int isValidDomain(char *d) {
  unsigned int i = 0;
  char *tld;
  size_t len;

  if (d[strlen(d) - 1] == '.')
    d[strlen(d) - 1] = 0;
  if (strlen(d) < 4)            // smallest possible domain provided. e.g. a.pl
    return 0;
  if (!strstr(d, "."))          // target domain must have at least one dot. e.g. target.va, branch.target.va
    return 0;
  if (strlen(d) > 100)
    return 0;
  tld = strstr(d, ".");
  tld = tld + 1;
  while (strstr(tld, ".")) {
    tld = strstr(tld, ".");
    tld = tld + 1;
  }
#if DEBUG
  printf("tld\'s length: %d\n", strlen(tld));
  printf("dom: %s tld: %s\n", d, tld);
#endif
  if ((strlen(tld) < 2) || (strlen(tld) > 6))   // tld must be between 2-6 char. e.g. .museum, .uk
    return FALSE;
  // valid domain can only contain digits, letters, dot (.) and dash symbol (-)
  len = strlen(d);
  for (i = 0; i < len; ++i) {
    if (!(d[i] >= '0' && d[i] <= '9') && !(d[i] >= 'a' && d[i] <= 'z') && !(d[i] >= 'A' && d[i] <= 'Z') && !(d[i] >= '-' && d[i] <= '.'))
      return 0;
  }
  return TRUE;
}

// return true if usage of public DNS server is detected
// Note: right now this function only detects openDNS, but might be 
// updated in the future to detect other common public DNS servers
unsigned short int usesOpenDNS(char *ipstr) {
  char strTmp[30] = "", s[MAXSTRSIZE] = "", dummyLTD[4] = "xyz" /*, ipstr[INET_ADDRSTRLEN]={'\0'} */ ;
  char ips[][INET_ADDRSTRLEN] = { "67.215.65.132" };
  unsigned short int i = 0, j = 0, n = 0, max = 0;
  struct hostent *h;

  srand(time(NULL));
  max = rand() % 20;
  // max should be between 10 and 20
  if (max < 10)
    max = max + (10 - max);
  // generate up to random 20 digits-long subdomain
  // e.g. 06312580442146732554
  for (i = 0; i < max; ++i) {
    n = rand() % 10;
    sprintf(strTmp, "%d", n);
    if (i == 0) {
      strncpy(s, strTmp, MAXSTRSIZE - 1);
      s[MAXSTRSIZE - 1] = 0;
    } else
      strncat(s, strTmp, MAXSTRSIZE - strlen(s) - 1);
  }
  strncat(s, ".", MAXSTRSIZE - strlen(s) - 1);
  strncat(s, dummyLTD, MAXSTRSIZE - strlen(s) - 1);
#if DEBUG
  printf("random domain for public DNS testing: %s\n", s);
#endif
  // random invalid domain resolves, thus public DNS in use
  h = gethostbyname(s);
  if (h) {
    for (i = 0; h->h_addr_list[i]; ++i) {
      sprintf(ipstr, inet_ntoa(*((struct in_addr *) h->h_addr_list[i])), "%s");
#if DEBUG
      printf("public DNS server\'s default IP address #%d: %s\n", i + 1, ipstr);
#endif
      for (j = 0; i < (sizeof(ips) / INET_ADDRSTRLEN); ++j) {
        if (!strcmp(ips[i], ipstr))
          return TRUE;
      }
    }
    return TRUE;
  } else
    return FALSE;
}

void threaded_resolve(char *list[]) {
  unsigned short int i = 0, j, k;
  char dom[MAXSTRSIZE] = "";
  void *addr;
  struct addrinfo hints, *res, *p;
  int status;
  char ipv6str[INET6_ADDRSTRLEN];
  struct sockaddr_in6 *ipv6, *q;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET6;   // AF_INET or AF_INET6 to force version
//  hints.ai_socktype = SOCK_STREAM;

  while (list[i] != NULL && list[i][0] != 0) {
      strncpy(dom, list[i], MAXSTRSIZE - 1);
      dom[MAXSTRSIZE - 1] = 0;
      strncat(dom, ".", MAXSTRSIZE - strlen(dom) - 1);  //TEST
      strncat(dom, domain, MAXSTRSIZE - strlen(dom) - 1);
#if DEBUG
      printf("brute-forced domain: %s\n", dom);
#endif
      // ipv6 code modded from www.kame.net
      if ((status = getaddrinfo(dom, NULL, &hints, &res)) == 0) {
        q = NULL;
        for (p = res; p != NULL; p = p->ai_next) {
          if (p->ai_family == AF_INET6) {       // IPv6
            ipv6 = (struct sockaddr_in6 *) p->ai_addr;
            addr = &(ipv6->sin6_addr);
            // convert the IP to a string and print it:
            if (q == NULL || memcmp(&ipv6->sin6_addr, &q->sin6_addr, 16) != 0) {
              q = ipv6;
              k = 1;
              if (wcard)
                for (j = 0; j < wcard; j++)
                  if (memcmp(addr, wildcardIpStr[j], 16) == 0)
                    k = 0;
              if (k) {
                ++found;
                inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
                printf("%s => %s\n", dom, ipv6str);
                ++ipCount;
                if (ucount < MAX_UNIQUE) {
                  if (ucount)
                    for (j = 0; j < ucount; j++)
                       if (memcmp(addr, unique[j], 16) == 0)
                         k = 0;
                  if (k) {
                    memcpy(unique[ucount], addr, 16);
                    ucount++;
                  }
                }
              }
            }
          }
        }
        freeaddrinfo(res);      // free the linked list
      }                         // end of if conditional
      // user wants delay between DNS requests?
      if (delay)
        dodelay(milliseconds);
      i++;
    }
  return;
}

int main(int argc, char *argv[]) {
  unsigned short int i = 0, j = 0, k, wordlist = FALSE, threads = 8;
  unsigned long int wcount = 0;
  char dom[MAXSTRSIZE] = "", *wordlistFilename, invalidTldIpstr[INET_ADDRSTRLEN] = "";
  FILE *fpWords;
  char ***lists;
  unsigned short int listptr[MAX_THREADS];
  pthread_t thread[MAX_THREADS];

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0 || strncmp(argv[1], "--h", 3) == 0)
    help(argv[0]);

  if (strcmp(argv[1], "-t") == 0) {
    threads = atoi(argv[2]);
    if (threads < 1 || threads > MAX_THREADS) {
      fprintf(stderr, "Error: -t THREADS must be between 1 and %d: %s\n", MAX_THREADS, argv[2]);
      exit(-1);
    }
    argc -= 2;
    argv += 2;
  }

  if (argc > 1 && strcmp(argv[1], "-D") == 0) {
    i = 0;
    while (sub[i] != NULL && sub[i][0] != 0)
      printf("%s\n", sub[i++]);
    exit(0);
  }

  if (argc == 3) {
    wordlist = TRUE;
    wordlistFilename = argv[2];
  }

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "Error: invalid options, try \"-h\" for help!\n");
    exit(-1);
  }

  for (i = 0; argv[1][i]; ++i)  // convert domain to lower case
    argv[1][i] = (tolower(argv[1][i]));
#if DEBUG
  printf("domain: %s\n", argv[1]);
#endif

  if (!isValidDomain(argv[1])) {
    fprintf(stderr, "Error: domain seems not to be valid: %s\n", argv[1]);
    exit(-1);
  }

  lists = malloc(threads * sizeof(int));
  for (i = 0; i < threads; i++) {
    listptr[i] = 0;
    lists[i] = malloc(65536 * sizeof(int));
  }

  // split wordlist to thread lists
  if (wordlist) {
    fpWords = fopen(wordlistFilename, "r");
    if (fpWords) {
      i = 0;
      while (!feof(fpWords)) {
        j = fscanf(fpWords, "%100s", dom);  // wordlist subdomain not allowed to be more than 100 chars
        // put in list here
        lists[i][listptr[i]] = malloc(strlen(dom) + 1);
        strcpy(lists[i][listptr[i]], dom);
        listptr[i] += 1;
        if (listptr[i] >= 65534) {
          fprintf(stderr, "Error: wordlist too large (max: %d)!\n", 65536 * threads);
          exit(-1);
        }
        i++;
        wcount++;
        if (i >= threads)
          i = 0;
      }
    } else {
      fprintf(stderr, "Error: could not open file %s\n", wordlistFilename);
      exit(-1);
    }
    fclose(fpWords);
  } else {
    i = j = 0;
    while (sub[j] != NULL && sub[j][0] != 0) {
      lists[i][listptr[i]] = malloc(strlen(sub[j]) + 1);
      strcpy(lists[i][listptr[i]], sub[j]);
      listptr[i] += 1;
      i++;
      if (i >= threads)
        i = 0;
      wcount++;
      j++;
    }
  }
  for (k = 0; k < threads; k++) {
      lists[k][listptr[k]] = malloc(2);
      lists[k][listptr[k]][0] = 0;
      lists[k][listptr[k + 1]] = NULL;
  }

  strcpy(domain, argv[1]);
  strcat(domain, ".");
  if (wcount < threads)
    threads = wcount;

  printf("Starting enumerating %s - creating %d threads for %d words...\n", domain, threads, (int)wcount);
  printf("Estimated time to completion: %d to %d minute%s\n\n", (int)((wcount / 300) / threads) + 1, (int)((wcount / 90) / threads) + 1, ((wcount / 60) / threads) + 1 > 1 ? "s" : "");

  // openDNS detection
  if (usesOpenDNS(invalidTldIpstr))
    printf("Detected openDNS, this might increase performance\n");

  // wildcard detection
  wildcarDetect(domain);

  for (i = 0; i < threads; i++)
    pthread_create(&thread[i], NULL, (void*)threaded_resolve, (void*)lists[i]);

  for (i = 0; i < threads; i++)
    pthread_join(thread[i], NULL);

  printf("\nFound %d domain name%s and %d unique ipv6 address%s for %s\n", found, found == 1 ? "" : "s", ucount + wcard, (ucount + wcard) == 1 ? "" : "es", domain);

  return 0;
}
