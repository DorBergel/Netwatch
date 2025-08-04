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
#include <ncurses.h>

void print_packet_line(struct Packet* p);
void draw_dashboard(const ProtocolStats* stats, Packet* recent, int* recent_count, int MAX_COUNT, int verbose, FlowStats* connections, int conn_count);
