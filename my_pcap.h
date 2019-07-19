#pragma once
#include <time.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct _eth_hdr
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
}eth_hdr, *peth_hdr;

typedef struct _ip_hdr
{
    uint8_t ihl:4;
    uint8_t ver:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t fid;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_addr[4];
    uint8_t dst_addr[4];
}ip_hdr, *pip_hdr;

typedef struct _ip6_hdr
{
    uint32_t ver_trf_flw;
    uint16_t pl_len;
    uint8_t nxt_hdr;
    uint8_t hop_lim;
    uint16_t src_addr[8];
    uint16_t dst_addr[8];
}ip6_hdr, *pip6_hdr;

typedef struct _tcp_hdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t resrv:4;
    uint8_t HL:4;
    uint8_t flag;
    uint16_t win_size;
    uint16_t checksum;
    uint16_t Urg_pnt;
}tcp_hdr, *ptcp_hdr;

typedef struct _udp_hdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t pkt_len;
    uint16_t checksum;
}udp_hdr, *pudp_hdr;

void print_time(pcap_pkthdr* header);
void print_mac(const char* msg, unsigned char* mac);
void print_ipv4(const char* msg, uint8_t* ip);
void print_ipv6(const char* msg, struct in6_addr ipv6);
void print_port(const char *msg, uint16_t port);
void print_all_address(const u_char* packet);
