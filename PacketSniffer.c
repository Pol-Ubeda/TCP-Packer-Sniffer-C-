#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int TCPChecker(unsigned char*);
void PacketPrinter(unsigned char*, int);
void HexPrint(unsigned char*, int);

FILE *logfile=NULL;

int main(void){
	struct sockaddr saddr;
	int sckt, buffer_size;
	unsigned char *buffer = (unsigned char *)malloc(65536); //declare buffer with max possible packet size
	socklen_t saddr_size;

	logfile=fopen("log.txt", "w");
	if(logfile==NULL){
		printf("Error opening file!");
		return 1;
	}

	sckt = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(sckt<0){
		printf("Error creating socket variable");
		fclose(logfile);
		free(buffer);
		return 1;
	}

	while(1){
		saddr_size=sizeof(saddr);
		buffer_size=recvfrom(sckt, buffer, 65536, 0, &saddr, &saddr_size); //store packet data in buffer and returns its size in bytes
		if(buffer_size<0){
			printf("Error receiving packet");
			break;
		}

		//check packet is tcp
		int tcp = TCPChecker(buffer);
		if(tcp==1) PacketPrinter(buffer, buffer_size);
	}

	close(sckt);
	fclose(logfile);
	free(buffer);
	return 0;
}

int TCPChecker(unsigned char* buffer){
	struct iphdr *iph = (struct iphdr*)buffer; //convert buffer to ipheader structure
	int protocol = iph->protocol;
	if(protocol!=6){
		return 0;
	}
	return 1;
}

void PacketPrinter(unsigned char* buffer, int buffer_size){
	struct sockaddr_in src, dst;
	struct iphdr *iph= (struct iphdr *)buffer; //pointer to ip header
	unsigned short iphdr_length = iph->ihl*4; //size of IP header in bytes (recall ihl counts in 32 bit steps)
	struct tcphdr *tcph=(struct tcphdr *)(buffer+iphdr_length); //pointer to tcp header, which starts right after ip header
	
	//sanitise and set src and dst vars
	memset(&src, 0, sizeof(src));
	src.sin_addr.s_addr=iph->saddr;

	memset(&dst, 0, sizeof(dst));
	dst.sin_addr.s_addr=iph->daddr;

	fprintf(logfile, "\n********************TCP Packet********************\n\n");
	
	//start printing IP header
	fprintf(logfile, "*****IP Header\n");
	fprintf(logfile, " Version:           %u\n", (unsigned int)(iph->version));
	fprintf(logfile, " IP Header Length:  %u\n Bytes", iphdr_length);
	fprintf(logfile, " Type of Service:   %u\n", (unsigned int)(iph->tos));
	fprintf(logfile, " IP Total Length:   %u\n Bytes", ntohs(iph->tot_len)); //these ntoh* functions return unsigned 16 or 32 bits
	fprintf(logfile, " Identification:    %u\n", ntohs(iph->id));
	fprintf(logfile, " TTL:		      %u\n", (unsigned int)(iph->ttl));
	fprintf(logfile, " Checksum:          %u\n", ntohs(iph->check));
	fprintf(logfile, " Source IP:         %s\n", inet_ntoa(src.sin_addr));
	fprintf(logfile, " Destination IP:    %s\n", inet_ntoa(dst.sin_addr));


	//start printing TCP header
	fprintf(logfile, "\n*****TCP Header\n");
	fprintf(logfile, " Source Port:       %u\n", ntohs(tcph->source));
	fprintf(logfile, " Destination Port:  %u\n", ntohs(tcph->dest));
	fprintf(logfile, " Sequence Number:   %u\n", ntohl(tcph->seq));
	fprintf(logfile, " Ack Number:        %u\n", ntohl(tcph->ack_seq));
	fprintf(logfile, " TCP Header Length: %u\n", (unsigned int)((tcph->doff)*4));
	fprintf(logfile, " Flags:\n");
	if((tcph->urg)==1) fprintf(logfile, "	              URG");
	if((tcph->ack)==1) fprintf(logfile, "	ACK");
	if((tcph->psh)==1) fprintf(logfile, "	PSH");
	if((tcph->rst)==1) fprintf(logfile, "	RST");
	if((tcph->syn)==1) fprintf(logfile, "	SYN");
	if((tcph->fin)==1) fprintf(logfile, "	FIN");
	fprintf(logfile, "\n Window Size:       %u\n", ntohs(tcph->window));
	fprintf(logfile, " Checksum:          %u\n", ntohs(tcph->check));
	if((tcph->urg)==1) fprintf(logfile, " Urgent Pointer:    %u", ntohs(tcph->urg_ptr));
	
	//start hex dumping + ascii
	fprintf(logfile, "\n\n		-HEX DUMP-		");
	
	fprintf(logfile, "*****IP Header\n");
	HexPrint(buffer, iphdr_length);

	fprintf(logfile, "\n\n***** TCP Header\n");
	HexPrint(buffer + iphdr_length, (tcph->doff)*4);

	fprintf(logfile, "\n\n*****Payload\n");
	HexPrint(buffer + iphdr_length + (tcph->doff)*4, buffer_size - iphdr_length - (tcph->doff)*4);
}

void HexPrint(unsigned char* buffer, int size){
	int i, j;

	for(i=0; i<size; i++){
		if(i%16==0) fprintf(logfile, "	");
		fprintf(logfile, " %02X", buffer[i]);

		//Represent each line in ASCII
		fprintf(logfile, "    ");
		
		if((i+1)%16==0 || i==size-1){
			for(j=i-i%16; j<i; j++){
				unsigned char ch=buffer[j];
				if(ch>=32 && ch<=126) fprintf(logfile, "%c", ch);
				else fprintf(logfile, ".");
			}
			fprintf(logfile, "\n");
		}
	}
}
