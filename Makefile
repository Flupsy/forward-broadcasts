CC=gcc
CFLAGS=-O6 -s -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wconversion

forward-broadcasts: forward-broadcasts.c
	$(CC) $(CFLAGS) -o forward-broadcasts forward-broadcasts.c -lpcap

clean:
	rm -f forward-broadcasts
