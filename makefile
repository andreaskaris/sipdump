all:
	gcc -Wall sipdump.c -l pcap -l osip2 -o sipdump
clean:
	rm sipdump
