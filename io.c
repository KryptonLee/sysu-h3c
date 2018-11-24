/*
 * Filename: io.c
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      IO methods for terminal and log
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#include "io.h"
#include "packet.h"
#include "status.h"

int echo_off()
{
    struct termios flags;
	if (tcgetattr(fileno(stdin), &flags) == -1)
	{
		fprintf(stderr, "Failed to echo_off: %s", strerror(errno));
		return -1;
	}

	flags.c_lflag &= ~ECHO;

	if (tcsetattr(fileno(stdin), TCSANOW, &flags) == -1)
	{
		fprintf(stderr, "Failed to echo_off: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int echo_on()
{
	struct termios flags;
	if (tcgetattr(fileno(stdin), &flags) == -1)
	{
		fprintf(stderr, "Failed to echo_on: %s", strerror(errno));
		return -1;
	}

	flags.c_lflag |= ECHO;

	if (tcsetattr(fileno(stdin), TCSANOW, &flags) == -1)
	{
		fprintf(stderr, "Failed to echo_on: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int init_net(const char *ifname, uint8_t *hwaddr)
{
	struct ifreq ifr;
	
	strcpy(ifr.ifr_name, ifname);
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE_PAE))) == -1)
		return SOCKET_OPEN_ERR;
	
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
		return SOCKET_SET_IF_ERR;
	else
		addr.sll_ifindex = ifr.ifr_ifindex;
	
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
		return SOCKET_GET_HWADDR_ERR;
	
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

	return SUCCESS;
}

int close_net()
{
	return close(sockfd);
}

int sendout(const void *buf, size_t len)
{
	if (sendto(sockfd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		return SEND_ERR;
	
	return SUCCESS;
}

int recvin(void *buf, size_t len)
{
	socklen_t addr_len = sizeof(addr);
	if (recvfrom(sockfd, buf, len, 0, (struct sockaddr *)&addr, &addr_len) == -1)
		return RECV_ERR;
	
	return SUCCESS;
}

int usage(FILE *stream)
{
	fprintf(stream, "Usage: sysu-h3c [OPTION]...\n");
	fprintf(stream, "  -i <interface>\tspecify interface, required\n");
	fprintf(stream, "  -u <username>\t\tspecify username, required\n");
	fprintf(stream, "  -p <password>\t\tspecify password, optional\n");
	fprintf(stream, "  -m <md5 method>\tspecify xor or md5 to calculate MD5-Challenge value, optional, default is xor\n");
	fprintf(stream, "  -h\t\t\tshow this message\n");
}