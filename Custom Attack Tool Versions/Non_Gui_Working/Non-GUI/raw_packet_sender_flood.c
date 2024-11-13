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
#include <sys/time.h>
#include <threads.h>

#define THREAD_COUNT 12

// Global mutex varibale used
// to prevent goofy race conditions
mtx_t counter_mtx;

// Used to pass all the required data to the thread
// as a single argument
struct ThreadData {
	int sock;
	char* data;
	int size;
	struct sockaddr_ll socket_address;
	int* num_packets_sent;
	int* done;
};

// Just sends the packet in a loop until the done
// signal is sent (by updating the done variable)
int sendPacket(void* arg)
{
	// Cast the arg correctly
	struct ThreadData* threadData = (struct ThreadData*)arg;
	
	// Keep spewing packets until the done
	// variable is set to 1
	int num_packets_sent = 0;
	while (!(*threadData->done))
	{
		sendto(threadData->sock, threadData->data, threadData->size, 0, (const struct sockaddr*)&threadData->socket_address, sizeof(struct sockaddr_ll));
		num_packets_sent++;
	}

	// Before exiting, update the global count variable
	// with our count varible
	mtx_lock(&counter_mtx);
	(*threadData->num_packets_sent) = (*threadData->num_packets_sent) + num_packets_sent;
	mtx_unlock(&counter_mtx);

	return 0;
}

int main(int argc, char *argv[]) {

	// Get command-line arguments (interface and file name)
	if (argc != 3)
	{
		printf("Invalid number of arguments! (Expected 2, got %d)\n", argc - 1);
		printf("Arguments should be interface_name and packet_file_name (in that order)\n");
		return EINVAL;
	}
	char INTERFACE[50];
	char PACKET_FILE_NAME[50];
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
	
	// Special timing stuff
	struct timeval stop, start;
	int done = 0;
	unsigned int num_packets_sent = 0;
	
	// Thread stuff
	mtx_init(&counter_mtx, mtx_plain);
	thrd_t t[THREAD_COUNT];
	
    // Create threadData struct
	struct ThreadData threadData;
	threadData.sock = sock;
	threadData.data = raw_packet_data;
	threadData.size = SIZE_OF_PACKET;
	threadData.socket_address = socket_address;
	threadData.num_packets_sent = &num_packets_sent;
	threadData.done = &done;

	// Start timer
	gettimeofday(&start, NULL);
	
	// Launch the threads
	for (int i = 0; i < THREAD_COUNT; i++)
		thrd_create(&t[i], sendPacket, &threadData);

	// Get done signal from user
	//printf("Press enter to stop flood..."); // UNCOMMENT THIS FOR INDEPENDENT USE
	getchar();
	done = 1;

	// Stop timer
	gettimeofday(&stop, NULL);

	// Join all the threads
	int res;
	for (int i = 0; i < THREAD_COUNT; i++)
		thrd_join(t[i], &res);

	// Print info
	float timeTaken = (stop.tv_sec - start.tv_sec) + (float)(stop.tv_usec - start.tv_usec) / 1000000;
	printf("Just sent %u packets in %f seconds!\n", num_packets_sent, timeTaken);
	
	// Properly dispose of mutex
	mtx_destroy(&counter_mtx);

	// Free packet buffer
	free(raw_packet_data);
	
	return 0;
};
