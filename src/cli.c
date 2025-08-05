#include <stdio.h>
#include <stdlib.h>
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
#include "net_utils.h"
#include <ncurses.h>

void print_packet_line(struct Packet* p) {
	switch (p->proto) {
        case TCP:
		
		printf("TCP %s:%d -> %s:%d (MAC %s -> %s)\t",
			p->src_ip, p->src_port, p->dest_ip, p->dest_port,
			p->src_mac, p->dest_mac);
		if(strlen(p->extra) > 0){
			printf(" [%s]", p->extra);
		}
		printf("\n");
		break;
        
        case UDP:
        	
        	printf("UDP %s:%d -> %s:%d (MAC %s -> %s)\n",
			p->src_ip, p->src_port, p->dest_ip, p->dest_port,
			p->src_mac, p->dest_mac);
		if(strlen(p->extra) > 0){
			printf(" [%s]", p->extra);
		}
		printf("\n");
		break;
		
        case ICMP:
        
        	printf("ICMP %s:%d -> %s:%d (MAC %s -> %s)\n",
			p->src_ip, p->src_port, p->dest_ip, p->dest_port,
			p->src_mac, p->dest_mac);
		if(strlen(p->extra) > 0){
			printf(" [%s]", p->extra);
		}
		printf("\n");
		break;
        
        default:
            printf("OTHER %s -> %s\n", p->src_ip, p->dest_ip);
            break;
    }
}

const char* proto_to_str(enum Protocol proto) {
	switch(proto) {
		case TCP: return("TCP");
		case UDP: return("UDP");
		case ICMP: return("ICMP");
		default: return("Other");
	}
}

void draw_dashboard(const ProtocolStats* stats,
                    Packet* recent,
                    int* recent_index,
                    int MAX_COUNT,
                    int verbose,
                    FlowStats* connections,
                    int conn_count)
{
    erase();

    // ----- Header -----
    attron(A_BOLD | COLOR_PAIR(5));
    mvprintw(0, 0, "NETWATCH DASHBOARD");
    attroff(A_BOLD | COLOR_PAIR(5));

    attron(A_BOLD);
    mvprintw(1, 0, "Total Packets: %lu  Bytes: %lu",
             stats->total_packets, stats->total_bytes);
    mvprintw(2, 0, "TCP: %lu  UDP: %lu  ICMP: %lu  Other: %lu",
             stats->tcp_packets,
             stats->udp_packets,
             stats->icmp_packets,
             stats->other_packets);
    mvprintw(3, 0, "Bandwidth: TCP: %.2f kbps  UDP: %.2f kbps  ICMP: %.2f kbps",
             stats->tcp_bandwidth_kbps,
             stats->udp_bandwidth_kbps,
             stats->icmp_bandwidth_kbps);
    attroff(A_BOLD);

    

    // Separator under header/stats
    mvhline(4, 0, 0, COLS);

    // ----- Recent Packets -----
    mvprintw(5, 0, "Recent Packets (latest first):");
    mvhline(6, 0, 0, COLS);

    int total = *recent_index;
    if (total > MAX_COUNT) total = MAX_COUNT;

    int max_lines = (LINES - 5) / 2; // half screen for recent
    if (total > max_lines) total = max_lines;

    int start = (*recent_index - total + MAX_COUNT) % MAX_COUNT;
    int line = 7;

    // Print aligned columns
    for (int i = 0; i < total; i++) {
        int idx = (start + i) % MAX_COUNT;
        Packet* p = &recent[idx];

        short color = proto_color(p->proto);
        attron(COLOR_PAIR(color));
        
        if (verbose) {
            mvprintw(line++, 0,
                     "%-4s %-15s:%-5d -> %-15s:%-5d (MAC %-17s -> %-17s) [%s]",
                     proto_to_str(p->proto),
                     p->src_ip, p->src_port,
                     p->dest_ip, p->dest_port,
                     p->src_mac, p->dest_mac,
                     p->extra);
        } else {
            mvprintw(line++, 0,
                     "%-4s %-15s:%-5d -> %-15s:%-5d [%s]",
                     proto_to_str(p->proto),
                     p->src_ip, p->src_port,
                     p->dest_ip, p->dest_port,
                     p->extra);
        }

        attroff(COLOR_PAIR(color));
    }

    // Separator before top connections
    mvhline(line++, 0, 0, COLS);

    qsort(connections, conn_count, sizeof(FlowStats), compare_by_bytes);

    // ----- Top Connections -----
    mvprintw(line++, 0, "Top Connections (by packets):");

    int top_max = LINES - line - 1;
    if (conn_count < top_max) top_max = conn_count;

    for (int i = 0; i < top_max && i < 10; i++) {
        FlowStats *f = &connections[i];
        short color = proto_color(f->proto);
        attron(COLOR_PAIR(color));
        
        if(f->bandwidth_kbps > HIGH_BANDWIDTH_THRESHOLD) {
            attron(COLOR_PAIR(10)); // Use your red color pair number
        }

        // Bold the first line
        if (i == 0) {
            attron(A_BOLD);
        }

        mvprintw(line++, 0,
                 "%s %s:%d -> %s:%d  pkts=%lu bytes=%lu bandwidth=%.2f kbps",
                 proto_to_str(f->proto),
                 f->src_ip, f->src_port,
                 f->dest_ip, f->dest_port,
                 f->packets, f->bytes,
                 f->bandwidth_kbps);


        if(f->bandwidth_kbps > HIGH_BANDWIDTH_THRESHOLD) {
            attroff(COLOR_PAIR(10));
        }
        if (i == 0) {
            attroff(A_BOLD);
        }
        attroff(COLOR_PAIR(color));
    }

    refresh();
}
