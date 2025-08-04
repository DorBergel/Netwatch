#ifndef NET_UTILS_H
#define NET_UTILS_H

#define MAX_INTERFACE_NAME_LEN 16

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define MAX_RECENT 20
#define MAX_CONNECTIONS 256

enum Protocol {
	TCP,
	UDP,
	ICMP,
	OTHER
};

typedef struct {
	unsigned long tcp_packets;
	unsigned long udp_packets;
	unsigned long icmp_packets;
	unsigned long other_packets;
	unsigned long total_bytes;
	unsigned long total_packets;
} ProtocolStats;

typedef struct {
	char src_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	int src_port;
	int dest_port;
	enum Protocol proto;
	unsigned long bytes; 
	unsigned long packets;
} FlowStats;

typedef struct Packet {
	enum Protocol proto;
	char src_mac[18];
	char dest_mac[18]; // TODO change to defined var
	char src_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	int src_port;
	int dest_port;
	char extra [64];
} Packet;


int init_raw_socket(const char *iface);
void close_socket(int sockfd);

void capture_packets(int sockfd, ProtocolStats *stats, Packet* recent, int* recent_index, FILE* log_pointer);

void parse_eth_header(struct Packet* packet, struct ethhdr* eth);
void parse_ip_header(struct Packet* packet, struct iphdr* tcp);
void parse_tcp_header(struct Packet* packet, struct tcphdr* tcp);
void parse_udp_header(struct Packet* packet, struct udphdr* udp);
void parse_icmp_header(struct Packet* packet, struct icmphdr* icmp);

const char* proto_to_str(enum Protocol proto);
void update_connections_table(FlowStats* table, int* connections_count, struct Packet* curr_pkt, size_t pkt_size);
short proto_color(enum Protocol proto);

#endif
