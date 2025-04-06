#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>       
#include <netinet/tcp.h>      
#include <ctype.h>            

// Ethernet Header
struct ethheader {
    u_char ether_dhost[6];  
    u_char ether_shost[6];   
    u_short ether_type;      
};

// IP Header
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;    
    unsigned char iph_tos;                 
    unsigned short int iph_len;             
    unsigned short int iph_ident;          
    unsigned short int iph_flag:3, iph_offset:13; 
unsigned char iph_ttl;                  
    unsigned char iph_protocol;            
    unsigned short int iph_chksum;          
    struct in_addr iph_sourceip;           
    struct in_addr iph_destip;              
};

// TCP Header
struct tcpheader {
    u_short tcp_sport;   
    u_short tcp_dport;   
    u_int tcp_seq;       
    u_int tcp_ack;       
    u_char tcp_offx2;    
    u_char tcp_flags;   
    u_short tcp_win;     
    u_short tcp_sum;    
    u_short tcp_urp;    
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    
    printf("Ethernet Header:\n");
    printf("   From: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("     To: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    if (ntohs(eth->ether_type) == 0x0800) { 
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        
        printf("\nIP Header:\n");
        printf("   From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("     To: %s\n", inet_ntoa(ip->iph_destip));

        
int ip_header_len = ip->iph_ihl * 4; 
        printf("   IP Header Length: %d bytes\n", ip_header_len);

        if (ip->iph_protocol == IPPROTO_TCP) { 
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

            
            printf("\nTCP Header:\n");
            printf("   From port: %d\n", ntohs(tcp->tcp_sport));
            printf("     To port: %d\n", ntohs(tcp->tcp_dport));

            
            int ip_total_len = ntohs(ip->iph_len); 
            int tcp_header_len = (tcp->tcp_offx2 >> 4) * 4; 

            int data_len = ip_total_len - ip_header_len - tcp_header_len;
            if (data_len > 0) {
                const u_char *data = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
                printf("   Message: ");
 for (int i = 0; i < data_len && i < 50; i++) { 
                    if (isprint(data[i])) {
                        printf("%c", data[i]);
                    } else {
                        printf(".");
                    }
                }
                printf("\n");
            }
        }
    }
}


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; 
    bpf_u_int32 net;

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening pcap device: %s\n", errbuf);
        return 1;
    }

    
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        return 1;
    }

    
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); 
    return 0;
}
