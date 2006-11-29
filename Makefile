CC=gcc
#OPT=-Wall -ggdb
OPT=-O2
LIB=-lpcap -lssl -lcrypto
PROGRAM=parasite6 dos-new-ip6 detect-new-ip6 fake_router6 fake_advertise6 fake_mld6 fake_mipv6 redir6 smurf6 alive6 toobig6 rsmurf6 test_implementation6 sendpees6

all:	thc-ipv6-lib.o $(PROGRAM)

debug:
	-$(CC) $(OPT) $(LIB) -o test test.c thc-ipv6-lib.o
	-$(CC) $(OPT) $(LIB) -o test2 test2.c thc-ipv6-lib.o
	-$(CC) $(OPT) $(LIB) -o test3 test3.c thc-ipv6-lib.o

parasite6:	parasite6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o parasite6 parasite6.c thc-ipv6-lib.o

dos-new-ip6:	dos-new-ip6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o dos-new-ip6 dos-new-ip6.c thc-ipv6-lib.o

detect-new-ip6:	detect-new-ip6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o detect-new-ip6 detect-new-ip6.c thc-ipv6-lib.o

fake_router6:	fake_router6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o fake_router6 fake_router6.c thc-ipv6-lib.o

fake_advertise6:	fake_advertise6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o fake_advertise6 fake_advertise6.c thc-ipv6-lib.o

fake_mld6:	fake_mld6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o fake_mld6 fake_mld6.c thc-ipv6-lib.o

fake_mipv6:	fake_mipv6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o fake_mipv6 fake_mipv6.c thc-ipv6-lib.o

redir6:	redir6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o redir6 redir6.c thc-ipv6-lib.o

smurf6:	smurf6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o smurf6 smurf6.c thc-ipv6-lib.o

rsmurf6:	rsmurf6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o rsmurf6 rsmurf6.c thc-ipv6-lib.o

alive6:	alive6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o alive6 alive6.c thc-ipv6-lib.o

toobig6:	toobig6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o toobig6 toobig6.c thc-ipv6-lib.o

test_implementation6:	test_implementation6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o test_implementation6 test_implementation6.c thc-ipv6-lib.o

sendpees6:	sendpees6.c thc-ipv6-lib.o
	$(CC) $(OPT) $(LIB) -o sendpees6 sendpees6.c thc-ipv6-lib.o

thc-ipv6-lib.o: thc-ipv6-lib.c
	$(CC) $(OPT) -c thc-ipv6-lib.c

strip:	all
	strip $(PROGRAM)

install: all strip
	cp -v $(PROGRAM) /usr/local/bin

clean:
	rm -vf $(PROGRAM) test thc-ipv6-lib.o test_implementation6 test test1 test2 test3 core DEADJOE *~

backup:	clean
	tar czvf ../thc-ipv6-bak.tar.gz *
	sync
