#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>

int main(int argc, char *argv[]) {

	// Get command-line arguments
	if (argc != 4)
	{
		printf("Invalid number of arguments! (Expected 3, got %d)\n", argc - 1);
		printf("Arguments should be interface_name, packet_file_name, number_of_packets_to_send (in that order)\n");
		return EINVAL;
	}
	char INTERFACE[50];
	char PACKET_FILE_NAME[50];
	int NUM_PACKETS_TO_SEND = atoi(argv[3]);
	strcpy(INTERFACE, argv[1]);
	strcpy(PACKET_FILE_NAME, argv[2]);
	
	// Open file where raw packet data is stored
	FILE* packet_file = fopen(PACKET_FILE_NAME,"rb");
	if (packet_file < 0)
		printf("Error opening file \"%s\"\n", PACKET_FILE_NAME);
	
	// Determine size of packet (filesize)
	fseek(packet_file, 0L, SEEK_END);
	const int SIZE_OF_PACKET = ftell(packet_file);
	rewind(packet_file);
	
	// Allocate space for raw packet data
	unsigned char* raw_packet_data = (unsigned char*)malloc(SIZE_OF_PACKET*sizeof(unsigned char));
	
	// Read raw packet data into raw_packet_data
	fread(raw_packet_data, SIZE_OF_PACKET, 1, packet_file);

	// Create raw socket
	int sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)
		printf("Error \"%d\" creating socket!\n", sock);
	
	// Get index of interface
	struct ifreq ifreq_i;
	memset(&ifreq_i, 0, sizeof(ifreq_i));
	strncpy(ifreq_i.ifr_name, INTERFACE, IFNAMSIZ-1);
	if ((ioctl(sock, SIOCGIFINDEX, &ifreq_i)) < 0)
		printf("Error getting index of \"%s\" using ioctl\n", INTERFACE);
	
	// Get MAC address of the interface
    struct ifreq ifreq_m;
	memset(&ifreq_m, 0, sizeof(ifreq_m));
	strncpy(ifreq_m.ifr_name, INTERFACE, IFNAMSIZ-1);
	if((ioctl(sock, SIOCGIFHWADDR, &ifreq_m)) < 0 )
		printf("Error in getting MAC address of \"%s\" using ioctl\n", INTERFACE);
		
	// Fill in socket address structure
	struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_ifindex = ifreq_i.ifr_ifindex;
    socket_address.sll_halen = ETHER_ADDR_LEN;
	memcpy(socket_address.sll_addr, ifreq_m.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	
	// Actually send the packet
	for (int i = 0; i < NUM_PACKETS_TO_SEND; i++)
	{
		int num_char_sent = sendto(sock, raw_packet_data, SIZE_OF_PACKET, 0, (const struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
	
		if (num_char_sent < 0)
			printf("Error sending packet!\n");
		else
			printf("Just sent %d characters!\n", num_char_sent);
	}

	// Free packet buffer
	free(raw_packet_data);
	
	return 0;
};
