CC=gcc
CFLAGS=-O6 -s

forward-broadcasts: forward-broadcasts.c
	$(CC) $(CFLAGS) -o forward-broadcasts forward-broadcasts.c -lpcap
