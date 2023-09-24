#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct in_addr     iph_sourceip; //Source IP address
  struct in_addr     iph_destip;   //Destination IP address

};

/* TCP Header */
struct tcpheader {
    u_short th_sport;
    u_short th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
    u_char   th_offx2;
#define TH_OFF(th) (((th)->th_offx2 &0xf0) >>4)
    u_char   th_flags;
#define TH_FIN  	0x01	
#define TH_SYN		0x02	
#define TH_RST		0x04	
#define TH_PUSH	0x08	
#define TH_ACK		0x10	
#define TH_URG		0x20	
	u_short	th_win;
	u_short	th_sum;
	u_short	th_urp;

};

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { 
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

        if(ip->iph_protocol == IPPROTO_TCP){
            // TCP packet processing
            // ...
        }
        else if(ip->iph_protocol == IPPROTO_UDP){
            // UDP packet processing
            // ...
        }
        else if(ip->iph_protocol == IPPROTO_ICMP){
            struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
            
            printf("Ethernet Header\n");
            printf("   Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", 
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            
            printf("   Source MAC     : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", 
                eth->ether_shost[0], eth->ether_shost[1],eth -> ether_shost [1],
                eth -> ether_shost [3] ,eth -> ether_shost [4] ,eth -> ether_shost [5]);
            
            printf("\nIP Header\n");
            printf("   Source IP          : %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Destination IP : %s\n", inet_ntoa(ip->iph_destip));

	        printf("\nICMP Header\n");
	        printf("   Type: %d\n", icmp -> type);
	        printf("   Code: %d\n", icmp -> code);
	        // Print other fields of the ICMP header as needed

	    }
	    
	}
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp";
	bpf_u_int32 net;

	handle = pcap_open_live("ens33", BUFSIZ,1 ,10000,errbuf);

	pcap_compile(handle,&fp ,filter_exp ,0 ,net);
	pcap_setfilter(handle,&fp);

	pcap_loop(handle,-1,got_packet,NULL);

	return(0);
}
