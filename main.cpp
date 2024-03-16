#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define LIBNET_LIL_ENDIAN 1

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];
    u_int8_t  ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
        ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
        ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,
        th_off:4;
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,
        th_x2:4;
#endif
    u_int8_t  th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void print_packet_info(const u_char* packet) {
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr *)packet;
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
    u_char* payload = (u_char*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + tcp_hdr->th_off * 4); // TCP 헤더 이후의 위치

    // 이더넷 헤더 출력
    printf("Ethernet Header\n");
    printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
           eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
           eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

    // IP 헤더 출력
    printf("IP Header\n");
    printf("Source IP Address: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Destination IP Address: %s\n", inet_ntoa(ip_hdr->ip_dst));

    // TCP 헤더 출력
    printf("TCP Header\n");
    printf("Source Port: %u\n", ntohs(tcp_hdr->th_sport));
    printf("Destination Port: %u\n", ntohs(tcp_hdr->th_dport));

    // Payload 데이터의 hexadecimal value 출력
    printf("Payload(Data) hexadecimal value\n");
    // printf("ip_len : %x, ip_hl : %x, th_off : %x\n", ntohs(ip_hdr->ip_len), ip_hdr->ip_hl, tcp_hdr->th_off);
    int payload_length = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - (tcp_hdr->th_off * 4); // IP 전체 길이에서 IP 헤더와 TCP 헤더 길이를 뺀 것이 페이로드 길이
    if (payload_length > 0) {
        for (int i = 0; i < 10 && i < payload_length; ++i) {
            printf("%02x ", payload[i]);
        }
    } else {
        printf("No payload data");
    }
    printf("\n\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        print_packet_info(packet);

    }

    pcap_close(pcap);
}
