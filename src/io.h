/*
 * Filename: io.h
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      IO methods for network, terminal and log
 */

#ifndef IO_H
#define IO_H

#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

/*
 * Set echo off in terminal
 * 
 * Return Value:
 *      If success, return 0, else return -1
 */
int echo_off();
/*
 * Set echo on in terminal
 * 
 * Return Value:
 *      If success, return 0, else return -1
 */
int echo_on();

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
int init_net(const char *ifname, uint8_t *hwaddr, time_t to_secs);
/*
 * Close the socket.
 * 
 * Return Value:
 *      If success, return SUCCESS, otherwise return -1
 */
int close_net();

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
int sendout(const void *buf, size_t len);
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
int recvin(void *buf, size_t len);

/*
 * Print the usage of this program to stream.
 */
void print_usage(FILE *stream);

/*
 * Get the info string of the status code
 * 
 * Parameters:
 *      statno: status code
 * Return Value:
 *      The info string of statno
 */
const char *str_statno(int statno);

#endif // IO_H