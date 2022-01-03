#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

typedef struct tcphdr TCP;
typedef struct udphdr UDP;
typedef struct ip IP;
typedef struct ether_header Ethernet;
typedef struct ip6_hdr IP6;

void callback_packet_view(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static int packet_num = 0;

    const Ethernet *ethernet;	//The Ethernet header
	const IP *ip;				//The IP header
	const TCP *tcp;				//The TCP header
	const UDP *udp;				//The UDP header
    const IP6 *ip6;
	const char *payload;		//Packet payload

    struct tm *lt;
    char timestr[80];
	time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
	lt = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%c", lt);

    ethernet = (Ethernet*)(packet);
    packet_num++;

    printf("_____________________________________________\n");
    printf("Packet NO.%d:\n\n",packet_num);
    printf("\tTime stamp: %s\n",timestr);
    printf("---------------------------------------------\n");
    printf("\tSrc MAC Addr: ");
    for(int i = 0; i<6; i++){
        printf("%02x",ethernet->ether_shost[i]);
        if(i!=5) printf(":");
    }
    printf("\n\tDst MAC Addr: ");
    for(int i = 0; i<6; i++){
        printf("%02x",ethernet->ether_dhost[i]);
        if(i!=5) printf(":");
    }
    printf("\n---------------------------------------------\n");
    if(ntohs(ethernet->ether_type) == ETHERTYPE_IP){ //iPv4
        int size_ip;
        ip = (IP*)(packet + ETHER_HDR_LEN);
        size_ip = sizeof(IP);
        printf("\tEthernet type: 0x%04x | IPv4\n",ntohs(ethernet->ether_type));
        printf("\tSrc IP Addr: %s\n",inet_ntoa(ip->ip_src));
        printf("\tDst IP Addr: %s\n",inet_ntoa(ip->ip_dst));
        printf("\tTotal length: %d\n",ip->ip_len);
        printf("\tIdentification: %d\n",ip->ip_id);
        printf("\tChecksum: %d\n",ip->ip_sum);
        printf("\tTime to live: %d\n",ip->ip_ttl);
        

        if(ip->ip_p == IPPROTO_TCP){
            printf("---------------------------------------------\n");
            printf("\tProtocol: TCP/IP\n");
            tcp = (TCP*)(packet + ETHER_HDR_LEN + size_ip);
            printf("\tSrc Port: %d\n",ntohs(tcp->th_sport));
            printf("\tDst Port: %d\n",ntohs(tcp->th_dport));
            printf("\tSequence number: %d\n",ntohs(tcp->th_seq));
            printf("\tAcknowledgement number: %d\n",ntohs(tcp->th_ack));
            printf("\tWindow: %d\n",ntohs(tcp->th_win));
        }
        else if(ip->ip_p == IPPROTO_UDP){
            printf("---------------------------------------------\n");
            printf("\tProtocol: UCP/IP\n");
            udp = (UDP*)(packet + ETHER_HDR_LEN + size_ip);
            printf("\tSrc Port: %d\n",ntohs(udp->uh_sport));
            printf("\tDst Port: %d\n",ntohs(udp->uh_dport));
            printf("\tUDP Checksum: %d\n",ntohs(udp->uh_sum));
        }
    }
    else if(ntohs(ethernet->ether_type) == ETHERTYPE_IPV6){
        int size_ip6;
        ip6 = (IP6*)(packet + ETHER_HDR_LEN);
        size_ip6 = sizeof(IP6);
        static char ip6_str_src[INET6_ADDRSTRLEN];
        static char ip6_str_dst[INET6_ADDRSTRLEN];
        printf("\tEthernet type: 0x%04x | IPv6\n",ntohs(ethernet->ether_type));
        inet_ntop(AF_INET6,&ip6->ip6_src,ip6_str_src,INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6,&ip6->ip6_dst,ip6_str_dst,INET6_ADDRSTRLEN);
        printf("\tSrc IP Addr: %s\n",ip6_str_src);
        printf("\tDst IP Addr: %s\n",ip6_str_dst);

        if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP){
            printf("---------------------------------------------\n");
            printf("\tProtocol: TCP/IPv6\n");
            tcp = (TCP*)(packet + ETHER_HDR_LEN + size_ip6);
            printf("\tSrc Port: %d\n",ntohs(tcp->th_sport));
            printf("\tDst Port: %d\n",ntohs(tcp->th_dport));
            printf("\tSequence number: %d\n",ntohs(tcp->th_seq));
            printf("\tAcknowledgement number: %d\n",ntohs(tcp->th_ack));
            printf("\tWindow: %d\n",ntohs(tcp->th_win));
        }
        else if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP){
            printf("---------------------------------------------\n");
            printf("\tProtocol: UCP/IPv6\n");
            udp = (UDP*)(packet + ETHER_HDR_LEN + size_ip6);
            printf("\tSrc Port: %d\n",ntohs(udp->uh_sport));
            printf("\tDst Port: %d\n",ntohs(udp->uh_dport));
            printf("\tUDP Checksum: %d\n",ntohs(udp->uh_sum));
        }
    }
    else if(ntohs(ethernet->ether_type) == ETHERTYPE_AARP){
        printf("\n\tEthernet type: 0x%04x | AARP\n",ntohs(ethernet->ether_type));
    }
    else if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP){
        printf("\n\tEthernet type: 0x%04x | ARP\n",ntohs(ethernet->ether_type));
    }
    else if(ntohs(ethernet->ether_type) == ETHERTYPE_REVARP){
        printf("\n\tEthernet type: 0x%04x | RARP\n",ntohs(ethernet->ether_type));
    }
    else if(ntohs(ethernet->ether_type) == ETHERTYPE_IPX){
        printf("\n\tEthernet type: 0x%04x | IPX\n",ntohs(ethernet->ether_type));
    }
    else if(ntohs(ethernet->ether_type) == ETHERTYPE_VLAN){
        printf("\n\tEthernet type: 0x%04x | VLAN\n",ntohs(ethernet->ether_type));
    }
    else{
        printf("This type is not clarfied\n");
    }
}

int main(int argc, char **argv){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(argc!=2){
        fprintf(stderr,"Wrong argument input\n");
        return -1;
    }
    handle = pcap_open_offline(argv[1], errbuf);
    
    if(!handle){
        fprintf(stderr,"File load failed\n");
        return -1;
    }

    if(pcap_loop(handle,0,callback_packet_view,NULL)<0){
        fprintf(stderr,"Packet invaild\n");
        return -1;
    }
    printf("\nFinish capturing\n_____________________________________________\n");
    pcap_close(handle);

    return 0;
}
