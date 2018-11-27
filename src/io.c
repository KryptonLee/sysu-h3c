/*
 * Filename: io.c
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      IO methods for network, terminal and log
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "io.h"
#include "packet.h"
#include "status.h"

static int sockfd;
static struct sockaddr_ll addr;

/*
 * Set echo off in terminal
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
int echo_off()
{
    struct termios flags;
	// Get terminal IO flags
	if (tcgetattr(fileno(stdin), &flags) == -1)
	{
		fprintf(stderr, "Failed to echo_off: %s", strerror(errno));
		return -1;
	}

	// Set ECHO flag off
	flags.c_lflag &= ~ECHO;

	// Set terminal IO flags
	if (tcsetattr(fileno(stdin), TCSANOW, &flags) == -1)
	{
		fprintf(stderr, "Failed to echo_off: %s", strerror(errno));
		return -1;
	}

	return SUCCESS;
}

/*
 * Set echo on in terminal
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
int echo_on()
{
	// Get terminal IO flags
	struct termios flags;
	if (tcgetattr(fileno(stdin), &flags) == -1)
	{
		fprintf(stderr, "Failed to echo_on: %s", strerror(errno));
		return -1;
	}

	// Set ECHO flag on
	flags.c_lflag |= ECHO;

	// Set terminal IO flags
	if (tcsetattr(fileno(stdin), TCSANOW, &flags) == -1)
	{
		fprintf(stderr, "Failed to echo_on: %s", strerror(errno));
		return -1;
	}

	return SUCCESS;
}

/*
 * Initialize a socket bind to the ethernet interface ifname, and fitch its
 * MAC address to hwaddr
 * 
 * Parameters:
 *      ifname: pointer to interface name string
 *      hwaddr: pointer to the buffer where the MAC address is stored
 * 		to_secs: timeout value in seconds
 * 
 * Return Value:
 *      If success, return SUCCESS, else return the No. of the error message.
 */
int init_net(const char *ifname, uint8_t *hwaddr, time_t to_secs)
{
	struct ifreq ifr;
	struct timeval timeout;
	timeout.tv_sec = to_secs;
	timeout.tv_usec = 0;
	
	// Open a socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE_PAE))) == -1)
		return SOCKET_OPEN_ERR;
	
	// Get interface index by name
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
		return SOCKET_SET_IF_ERR;
	else
		addr.sll_ifindex = ifr.ifr_ifindex;
	
	// Get interface MAC address
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
		return SOCKET_GET_HWADDR_ERR;
	
	// Set socket receive timeout
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
		return SOCKET_SET_TIMEO_ERR;
	
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

	return SUCCESS;
}

/*
 * Close the socket.
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
int close_net()
{
	return close(sockfd);
}

/*
 * Send out data to the opened socket.
 * 
 * Parameters:
 *      buf: pointer to the buffer where the data is stored
 *      len: length of the data
 * 
 * Return Value:
 *      If success, return SUCCESS, else return the No. of the SEND_ERR.
 */
int sendout(const void *buf, size_t len)
{
	if (sendto(sockfd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		return SEND_ERR;
	
	return SUCCESS;
}

/*
 * Receive in data from the opened socket.
 * 
 * Parameters:
 *      buf: pointer to the buffer where the data is to be stored
 *      len: length of the data received
 * 
 * Return Value:
 *      If success, return SUCCESS, else return the No. of the RECV_ERR.
 */
int recvin(void *buf, size_t len)
{
	socklen_t addr_len = sizeof(addr);
	if (recvfrom(sockfd, buf, len, 0, (struct sockaddr *)&addr, &addr_len) == -1)
	{
		if (errno == EWOULDBLOCK)
			return RECV_TIMEOUT;
		
		return RECV_ERR;
	}
	
	return SUCCESS;
}

/*
 * Print the usage of this program to stream.
 */
void print_usage(FILE *stream)
{
	fprintf(stream, "Usage: sysu-h3c [OPTION]...\n");
	fprintf(stream, "  -i <interface>\tspecify interface, required\n");
	fprintf(stream, "  -u <username>\t\tspecify username, required\n");
	fprintf(stream, "  -p <password>\t\tspecify password, optional\n");
	fprintf(stream, "  -m <md5 method>\tspecify xor or md5 to calculate \
MD5-Challenge value, \n\t\t\toptional, default is xor\n");
	fprintf(stream, "  -D <DHCP command>\tspecify DHCP command to get IP, \
such as 'dhclient' and 'udhcpc' \n\t\t\toptional, default is 'dhclient'\n");
	fprintf(stream, "  -d \t\t\trun as daemon\n");
	fprintf(stream, "  -h\t\t\tshow this message\n");
}