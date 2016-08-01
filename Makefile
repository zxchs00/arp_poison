arp_poison: arp_poison.c
	gcc -o arp_poison arp_poison.c -lpcap

clean:
	rm -f *.o
	rm -f arp_poison

