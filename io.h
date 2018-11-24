/*
 * Filename: io.h
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      IO methods for terminal and log
 * 
 */

#ifndef IO_H
#define IO_H

#include <stdio.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

static int sockfd;
static struct sockaddr_ll addr;

int echo_off();
int echo_on();

int init_net(const char *ifname, uint8_t *hwaddr);
int close_net();
int sendout(const void *buf, size_t len);
int recvin(void *buf, size_t len);

int usage(FILE *stream);

#endif // IO_H