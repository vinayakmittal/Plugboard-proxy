all: clean mydump

mydump: pbproxy.c
	gcc -g pbproxy.c -o pbproxy -lpthread -lcrypto

clean:
	rm -f *.o pbproxy
