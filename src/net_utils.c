#include "net_utils.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>

#define DEBUG 0  // gcc -DDEBUG=0 -o netwatch main.c net_utils.c



/**
* Initializes a raw socket bound to all network traffic via a specific interface.
**/
int init_raw_socket(const char *iface) {
	
	int res; 
	
	struct sockaddr_ll socketAddress;		
		
	// init socket, bind it to interface, start listen
	int socketId = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(socketId == -1) {
		printf("ERROR: Failed to init raw socket\n");
		return -1;
	}
	
	memset(&socketAddress, 0, sizeof(struct sockaddr_ll));
	socketAddress.sll_family = AF_PACKET;
	socketAddress.sll_protocol = htons(ETH_P_ALL);
	socketAddress.sll_ifindex = if_nametoindex(iface);
	
	if(socketAddress.sll_ifindex == 0) {
		printf("ERROR: Could not get index for interface '%s' \n", iface);
		close(socketId);
		return -1;
	}	
		
	res = bind(socketId, (struct sockaddr *)&socketAddress, sizeof(socketAddress));
	if(res == -1) {
		printf("ERROR: Failed to bind to raw socket\n");
		close(socketId);
		return -1;
	}
	
	return socketId;
}


void close_socket(int socketId) {
	close(socketId);
}


void capture_packets(int sockId, ProtocolStats *stats, Packet* recent, int* recent_index, FILE* log_pointer) {
	
	struct ethhdr* eth;
	struct iphdr* ip;
	struct tcphdr* tcp;
	struct udphdr* udp;
	struct icmphdr* icmp;
	
	int offset;
	unsigned char buffer[2048]; // enough for full Ethernet frame
	ssize_t num_bytes = recvfrom(sockId, buffer, sizeof(buffer), 0, NULL, NULL);
	
	extern FlowStats connections[MAX_CONNECTIONS];
	extern int conn_count;
	
	Packet currentPacket;
	
	// Set eth pointer to buffer with offset
	eth = (struct ethhdr*)buffer;
	
	// Condition to ensure bytes recieved
	if (num_bytes <= 0) {
		perror("recvfrom");
		return;
	}
	stats->total_bytes += num_bytes;
	//// parse_eth_header(eth, stats);
	parse_eth_header(&currentPacket, eth);
	
	
	//Condition to ensure not parsing non-ipv4 packets
	if (ntohs(eth->h_proto) != ETH_P_IP) {
	    return;
	}
	
	// Condition to ensure packet not truncted
	if(num_bytes < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
		return;
	}
	// Set ip pointer to buffer with offset
	ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	//// parse_ip_header(ip, stats);
	parse_ip_header(&currentPacket, ip);
	
	offset = sizeof(struct ethhdr) + (ip->ihl * 4);
	
	switch(ip->protocol) {
	case IPPROTO_TCP:		
		tcp = (struct tcphdr*)(buffer + offset);
		parse_tcp_header(&currentPacket, tcp);
		stats->tcp_packets++;
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr*)(buffer + offset);
		parse_udp_header(&currentPacket, udp);
		stats->udp_packets++;
		break;
	case IPPROTO_ICMP:
		icmp = (struct icmphdr*)(buffer + offset);
		parse_icmp_header(&currentPacket, icmp);
		stats->icmp_packets++;
		break;
	default:
		currentPacket.proto = OTHER;
		stats->other_packets++;
		break;
	}
	
	stats->total_packets++;
	
	recent[(*recent_index) % MAX_RECENT] = currentPacket;
	(*recent_index)++;
	
	update_connections_table(connections, &conn_count, &currentPacket, num_bytes);
	
	if(log_pointer) {
		fprintf(log_pointer, "%s,%s,%d,%s,%d,%s,%zu\n", 
			proto_to_str(currentPacket.proto),
			currentPacket.src_ip, currentPacket.src_port,
			currentPacket.dest_ip, currentPacket.dest_port,
			currentPacket.extra,
			(size_t)num_bytes);
		fflush(log_pointer);
	}
}

void parse_eth_header(struct Packet* packet, struct ethhdr* eth) {
	
	snprintf(packet->src_mac, sizeof(packet->src_mac),
			"%02x:%02x:%02x:%02x:%02x:%02x", 
			eth->h_source[0], eth->h_source[1], eth->h_source[2], 
			eth->h_source[3], eth->h_source[4], eth->h_source[5]);
			
	snprintf(packet->dest_mac, sizeof(packet->dest_mac),
			"%02x:%02x:%02x:%02x:%02x:%02x", 
			eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
			eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	
}

void parse_ip_header(struct Packet* packet, struct iphdr* ip) {
	inet_ntop(AF_INET, &ip->saddr, packet->src_ip, sizeof(packet->src_ip));
	inet_ntop(AF_INET, &ip->daddr, packet->dest_ip, sizeof(packet->dest_ip)); // Humen read string
}


void parse_tcp_header(struct Packet* packet, struct tcphdr* tcp) {
	packet->proto = TCP;
	packet->src_port = ntohs(tcp->source);
	packet->dest_port = ntohs(tcp->dest);
	
	packet->extra[0] = '\0';
	
	// Append flags
	if (tcp->syn) strcat(packet->extra, "SYN,");
	if (tcp->ack) strcat(packet->extra, "ACK,");
	if (tcp->fin) strcat(packet->extra, "FIN,");
	if (tcp->rst) strcat(packet->extra, "RST,");
	if (tcp->psh) strcat(packet->extra, "PSH,");
	if (tcp->urg) strcat(packet->extra, "URG,");
	
	// Remove trailing comma
	size_t len = strlen(packet->extra);
	if (len > 0 && packet->extra[len - 1] == ',') {
		packet->extra[len - 1] = '\0';
	}
}


void parse_udp_header(struct Packet* packet, struct udphdr* udp) {
	packet->proto = UDP;
	packet->src_port = ntohs(udp->source);
	packet->dest_port = ntohs(udp->dest);
	
	snprintf(packet->extra, sizeof(packet->extra), "len=%d", ntohs(udp->len));
	
}

void parse_icmp_header(struct Packet* packet, struct icmphdr* icmp) {
	
	packet->proto = ICMP;
	packet->src_port = 0;
	packet->dest_port = 0;
	
	switch (icmp->type) {
	case 8:
		snprintf(packet->extra, sizeof(packet->extra), "Echo Request");
		break;
	case 0:
		snprintf(packet->extra, sizeof(packet->extra), "Echo Reply");
		break;
	default:
		snprintf(packet->extra, sizeof(packet->extra), "Type %d Code %d", icmp->type, icmp->code);
		break;
	}
}



void update_connections_table(FlowStats* table, int* connections_count, Packet* curr_pkt, size_t pkt_size) {

	for(int i=0; i<(*connections_count); i++) {
		FlowStats* f = &table[i];
		if(table[i].proto == curr_pkt->proto && 
			strcmp(f->src_ip, curr_pkt->src_ip) == 0 &&
			strcmp(f->dest_ip, curr_pkt->dest_ip) == 0 &&
			f->src_port == curr_pkt->src_port && 
			f->dest_port == curr_pkt->dest_port) {
			
			f->packets++;
			f->bytes += pkt_size;
			return;
		}
	}	
	
	if(*connections_count < MAX_CONNECTIONS) {
		FlowStats* f = &table[(*connections_count)++];
		strcpy(f->src_ip, curr_pkt->src_ip);
		strcpy(f->dest_ip, curr_pkt->dest_ip);
		f->src_port = curr_pkt->src_port;
		f->dest_port = curr_pkt->dest_port;
		f->packets = 1;
		f->bytes = pkt_size;
		f->proto = curr_pkt->proto;
	}
	
}


short proto_color(enum Protocol proto) {
    switch(proto) {
        case TCP: return 1;
        case UDP: return 2;
        case ICMP: return 3;
        default: return 4;
    }
}

