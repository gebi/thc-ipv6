CC=gcc
#CFLAGS?=-Wall -ggdb
CFLAGS?=-O2
LDFLAGS+=-lpcap -lssl -lcrypto
PROGRAMS=parasite6 dos-new-ip6 detect-new-ip6 fake_router6 fake_advertise6 fake_mld6 fake_mld26 fake_mldrouter6 flood_mldrouter6 fake_mipv6 redir6 smurf6 alive6 toobig6 rsmurf6 implementation6 implementation6d sendpees6 sendpeesmp6 randicmp6 fuzz_ip6 flood_mld6 flood_mld26 flood_router6 flood_advertise6 flood_solicitate6 trace6 exploit6 denial6 fake_dhcps6 flood_dhcpc6 fake_dns6d fragmentation6 kill_router6 fake_dnsupdate6 ndpexhaust6
LIBS=thc-ipv6-lib.o

PREFIX=/usr/local
MANPREFIX=${PREFIX}/share/man

all:	$(LIBS) $(PROGRAMS) dnsdict6 thcping6

dnsdict6:	dnsdict6.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lpthread -lresolv

thcping6:	thcping6.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lrt

%:	%.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

strip:	all
	strip $(PROGRAMS) dnsdict6 thcping6

install: all strip
	install -m0755 -d ${DESTDIR}${PREFIX}/bin
	install -m0755 $(PROGRAMS) dnsdict6 thcping6 *.sh ${DESTDIR}${PREFIX}/bin
	install -m0755 -d ${DESTDIR}${MANPREFIX}/man8
	install -m0644 -D thc-ipv6.8 ${DESTDIR}${MANPREFIX}/man8

clean:
	rm -f $(PROGRAMS) dnsdict6 thcping6 $(LIBS) core DEADJOE *~

backup:	clean
	tar czvf ../thc-ipv6-bak.tar.gz *
	sync

.PHONY: all install clean 
