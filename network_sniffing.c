#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct Ethernet_header {
        u_char ether_dhost[6]; // destination host address
        u_char ether_shost[6]; // source host address
        u_short ether_type;    // protocol type(IP, ARP, RARP ...)
};

/* IP header */
struct Ip_header {
        unsigned char iph_ihl:4, // ip header length
                     iph_ver:4; // ip version
        unsigned char iph_tos; // type of service
        unsigned short int iph_len; // ip packet length(data + header)
        unsigned short int iph_ident; // identification
        unsigned short int iph_flag:3, // fragmentation flags
                       iph_offset:13; // flags offset
        unsigned char iph_ttl; // time to live
        unsigned char iph_protocol; // protocol type
        unsigned short int iph_chksum; // ip datagram checksum
        struct in_addr iph_src; // source IP address
        struct in_addr iph_dst; // destination IP address
};

/* TCP header */
struct Tcp_header {
    unsigned short tcph_sport;      // source tcp port
    unsigned short tcph_dport;      // destination tcp port
    unsigned int tcph_seqNum;       // tcp sequence number
    unsigned int tcph_ackNum;       // tcp ack number
    unsigned char tcph_offsetx2:4;  // tcp offset
    unsigned char tcph_reversed:4;  // reversed bits
    unsigned char tcph_flags;       // tcp flags
    unsigned short tcph_window;     // window size
    unsigned short tcph_chksum;     // checksum
    unsigned short tcph_urgp;       // urgent pointer
};


/* got_packing function */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
        struct Ethernet_header *eth = (struct Ethernet_header *) packet;

        /* Query about Ip, Tcp and Message */
        if (ntohs(eth -> ether_type) == 0x0800) { // if packet is Ipv4


                // Ip address
                struct Ip_header *ip = (struct Ip_header *) (packet + sizeof(struct Ethernet_header));

                // Only Tcp address
                if (ip -> iph_protocol == IPPROTO_TCP) {

                        printf("==============================================\n");
                        // Mac address(from)
                        printf("Ethernet From: ");
                        for (int i = 0; i < 6; i++) {
                                printf("%02x", eth -> ether_shost[i]);
                                if (i == 5) break;
                                printf(":");
                        }
                        printf("\n");


                        // Mac address(to)
                        printf("Mac To: ");
                        for (int i = 0; i < 6; i++) {
                                printf("%02x", eth -> ether_dhost[i]);
                                if (i == 5) break;
                                printf(":");
                        }
                        printf("\n");
                        printf("\n");


                        // Ip address
                        int ip_packet_len = ntohs(ip -> iph_len);

                        printf("IP From: %s\n",inet_ntoa(ip -> iph_src));
                        printf("IP To: %s\n", inet_ntoa(ip -> iph_dst));
                        printf("\n");





                        int ip_header_len  = ip -> iph_ihl * 4;
                        struct Tcp_header *tcp = (struct Tcp_header *) (packet + sizeof(struct Ethernet_header) + ip_header_len);
                        printf("TCP From: %d\n", ntohs(tcp -> tcph_sport));
                        printf("TCP To: %d\n", ntohs(tcp -> tcph_dport));
                        printf("\n");

                        int tcp_header_len = (tcp-> tcph_offsetx2) * 4;

                        // Message
                        unsigned char *msg = (unsigned char *)(packet + sizeof(struct Ethernet_header) + ip_header_len + tcp_header_len);
                        unsigned int length = ip_packet_len - ip_header_len - tcp_header_len;

                        printf("Message: ");
                        for(int i = 0; i < length; i++) {
                                printf("%c", msg[i]);
                        }

                        printf("\n");
                        printf("==============================================\n");
                }

        }
}

int main()
{
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        char filter_exp[] = "tcp port 80";
        bpf_u_int32 net = 0;

        handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

        pcap_compile(handle, &fp, filter_exp, 0, net);
        if (pcap_setfilter(handle, &fp) != 0) {
                pcap_perror(handle, "Error:");
                exit(EXIT_FAILURE);
        }

        pcap_loop(handle, -1, got_packet, NULL);

        pcap_close(handle);
        return 0;
}