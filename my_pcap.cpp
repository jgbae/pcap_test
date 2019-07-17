#include "my_pcap.h"


void print_time(pcap_pkthdr* header)
{
    struct tm *tm;
    tm = localtime(&header->ts.tv_sec);
    printf("%d:%d:%d.%ld\n", tm->tm_hour, tm->tm_min, tm->tm_sec, header->ts.tv_usec);
}

void print_mac(const char* msg, unsigned char* mac)
{
    printf("%s%02X:%02X:%02X:%02X:%02X:%02X\n", msg, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ipv4(const char* msg, uint32_t ip)
{
    uint8_t parsed_ip[4] = {0};
    ip = ntohl(ip);
    parsed_ip[0] = (ip >> 24) & 0xff;
    parsed_ip[1] = (ip >> 16) & 0xff;
    parsed_ip[2] = (ip >>  8) & 0xff;
    parsed_ip[3] = (ip      ) & 0xff;
    printf("%s%u.%u.%u.%u\n", msg, parsed_ip[0], parsed_ip[1], parsed_ip[2], parsed_ip[3]);
}

void print_ipv6(const char* msg, uint16_t* ipv6)
{
    uint16_t t;
    printf("%s",msg);

    t = ntohs(*ipv6++); t ? printf("%x:", t) : printf(":");
    t = ntohs(*ipv6++); if(t) printf(":%x", t);
    t = ntohs(*ipv6++); if(t) printf(":%x", t);
    t = ntohs(*ipv6++); if(t) printf(":%x", t);
    t = ntohs(*ipv6++); if(t) printf(":%x", t);
    t = ntohs(*ipv6++); if(t) printf(":%x", t);
    t = ntohs(*ipv6++); if(t) printf(":%x", t);
    t = ntohs(*ipv6  ); t ? printf(":%x\n", t) : printf(":\n");

}

void print_port(const char *msg, uint16_t port)
{
    port = ntohs(port);
    printf("%s%u\n", msg, port);
}

void print_all_address(const u_char* packet)
{
    eth_hdr *eth_header = nullptr;
    ip_hdr *ip_headr = nullptr;
    ip6_hdr *ip6_header = nullptr;
    tcp_hdr *tcp_header = nullptr;
    udp_hdr *udp_header = nullptr;
    uint8_t L4_type = 0;
    uint16_t tcp_payload_len = 0;


    // Ethernet structure initialization & Print MAC address
    eth_header = const_cast<eth_hdr*>(reinterpret_cast<const eth_hdr*>(packet));
    memcpy(eth_header, packet, sizeof(eth_hdr));
    print_mac("  Src MAC : ", eth_header->src_mac);
    print_mac("  Dsr MAC : ", eth_header->dst_mac);
    packet += sizeof(eth_hdr);


    //Check L3 Type & IP structure initialization
    switch (ntohs(eth_header->type))
    {
    case 0x0800:
        ip_headr = const_cast<ip_hdr*>(reinterpret_cast<const ip_hdr*>(packet));
        packet += ip_headr->ihl * 4;
        print_ipv4("    Src IPv4 Address : ", ip_headr->src_addr);
        print_ipv4("    Dst IPv4 Address : ", ip_headr->dst_addr);
        L4_type = ip_headr->protocol;
        tcp_payload_len = ntohs(ip_headr->total_len) - ip_headr->ihl * 4;
        break;
    case 0x86DD:
        ip6_header = reinterpret_cast<ip6_hdr*>(malloc(sizeof(ip6_hdr)));
        memcpy(ip6_header, packet, sizeof(ip6_hdr));
        packet += sizeof(ip6_hdr);
        print_ipv6("    Src IPv6 Address : ", ip6_header->src_addr);
        print_ipv6("    Dst IPv6 Address : ", ip6_header->dst_addr);
        L4_type = ip6_header->nxt_hdr;
        tcp_payload_len = ntohs(ip6_header->pl_len) - sizeof(ip6_hdr);
        break;
    default:
        printf("Unsupported L3 formats..\n");
        break;
    }


    //Check L4 Type & TCP/UDP structure initialization
    switch(L4_type)
    {
    case 0x06:
        tcp_header = const_cast<tcp_hdr*>(reinterpret_cast<const tcp_hdr*>(packet));
        print_port("      Src TCP Port : ",tcp_header->src_port);
        print_port("      Dst TCP Port : ",tcp_header->dst_port);
        packet += tcp_header->HL * 4;
        tcp_payload_len -= tcp_header->HL * 4;
        if (ntohs(tcp_header->src_port) == 80 || ntohs(tcp_header->dst_port) == 80)
            if(tcp_payload_len > 10)
            {
                printf("        HTTP Payload : ");
                for(int i=0; i<10 && i < tcp_payload_len; i++)
                    printf("%c", packet[i]);
                printf("\n");
            }
        break;
    case 0x11:
        udp_header = const_cast<udp_hdr*>(reinterpret_cast<const udp_hdr*>(packet));
        memcpy(udp_header, packet, sizeof(udp_hdr));
        print_port("      Src UDP Port : ",udp_header->src_port);
        print_port("      Dst UDP Port : ",udp_header->dst_port);
        break;
    default:
        printf("Unsupported L4 formats..\n");
        break;
    }
}
