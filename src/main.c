#include <stdio.h>
#include "net_utils.h"
#include "cli.h"
#include <ncurses.h>
#include <stdlib.h>
#include <signal.h>

#define TEST_INTERFACE "enp1s0"

FlowStats connections[MAX_CONNECTIONS];
int conn_count = 0;

ProtocolStats stats = {0};
int sockId = -1;


void signal_handler(int sig) {
	endwin();
	system("clear");
	printf("\nCaught SIGINT, shutting down...\n");
	printf("Final summary:\n");
	printf("Total Packets: %lu, Bytes: %lu\n", stats.total_packets, stats.total_bytes);
	printf("TCP: %lu  UDP: %lu  ICMP: %lu  Other: %lu\n",
		stats.tcp_packets, stats.udp_packets,
		stats.icmp_packets, stats.other_packets);
	
	if(sockId != -1) {	
		close_socket(sockId);
	}
	
	exit(0);
	
}


int main(int argc, char** argv)
{

	char* iface = NULL;
	int max_packets = -1;
	int verbose = 0;
	char* log_filename = NULL;
	Packet recent[MAX_RECENT];
	int recent_index = 0;
	FILE* log_pointer = NULL;
	PacketFilter filter = {.type = FILTER_NONE };
	
	signal(SIGINT, signal_handler);

	
	for(int i=1; i<argc; i++) {
		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			return 0;
		}
		else if(strcmp(argv[i], "-i") == 0 && i+1 < argc) {
			iface = argv[++i];
		}
		else if(strcmp(argv[i], "-n") == 0 && i+1 < argc) {
			max_packets = atoi(argv[++i]);
		}
		else if(strcmp(argv[i], "-v") == 0) {
			verbose = 1;
		} else if(strcmp(argv[i], "-o") == 0) {
			log_filename = argv[++i];
		}
		else if(strcmp(argv[i], "-f") == 0 && i+1 < argc) {
			char* expr = argv[++i];
			if(strcmp(expr, "tcp") == 0) {
				filter.type = FILTER_PROTO;
				filter.proto = TCP;
			} else if(strcmp(expr, "udp") == 0) {
				filter.type = FILTER_PROTO;
				filter.proto = UDP;
			} else if(strcmp(expr, "icmp") == 0) {
				filter.type = FILTER_PROTO;
				filter.proto = ICMP;
			} else if(strcmp(expr, "host") == 0 && i+1 < argc) {
				filter.type = FILTER_HOST;
				strncpy(filter.ip, argv[++i], INET_ADDRSTRLEN);
			} else if(strcmp(expr, "port") == 0 && i+1 < argc) {
				filter.type = FILTER_PORT;
				filter.port = atoi(argv[++i]);
			} else {
				printf("Unknown filter expression: %s\n", expr);
			}
			printf("Unknown options %s\n", argv[i]);
		}
	}
	
	if(log_filename) {
		log_pointer = fopen(log_filename, "w");
		if(!log_pointer) {
			perror("Failed to open log file");
			exit(1);
		}

		fprintf(log_pointer, "Protocol,SrcIP,SrcPort,DestIP,DestPort,Extra,Bytes,Bandwidth\n");
		fflush(log_pointer);
	}
	
	sockId = init_raw_socket(iface == NULL ? TEST_INTERFACE : iface);
	
	if(sockId != -1) {
		initscr();
		noecho();
		curs_set(FALSE);
		timeout(0);
		start_color();
		use_default_colors();
		
		init_pair(1, COLOR_GREEN, -1); // TCP
		init_pair(2, COLOR_YELLOW, -1); // UDP
		init_pair(3, COLOR_CYAN, -1); // ICMP
		init_pair(4, COLOR_RED, -1); // Other
		init_pair(5, COLOR_WHITE, -1); // Default
	}
	
	while(max_packets == -1 || stats.total_packets < max_packets) {
		capture_packets(sockId, &stats, recent, &recent_index, log_pointer, &filter);
		draw_dashboard(&stats, recent, &recent_index, MAX_RECENT, verbose, connections, conn_count);
		
		if(getch() == 'q') break;
	}
	
	endwin();
	close_socket(sockId);
	
	if(log_pointer) {
		fprintf(log_pointer, "\nFinal summary:\nTotal Packets: %lu, Bytes: %lu\n", 
			stats.total_packets, stats.total_bytes);
    		fclose(log_pointer);
    	}
	
	return 0;
}
