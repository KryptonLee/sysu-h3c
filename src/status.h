/*
 * Filename: status.h
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Define the status code
 */

#define SUCCESS 0
#define USR_TOO_LONG 1
#define PWD_TOO_LONG 2
#define DHCP_CMD_TOO_LONG 3

#define BPF_OPEN_ERR 11
#define BPF_SET_BUF_LEN_ERR 12
#define BPF_SET_IF_ERR 13
#define BPF_SET_FILTER_ERR 14
#define BPF_SET_IMMEDIATE_ERR 15
#define BPF_SET_DIRECTION_ERR 16

#define SOCKET_OPEN_ERR 21
#define SOCKET_SET_IF_ERR 22
#define SOCKET_GET_HWADDR_ERR 23
#define SOCKET_SET_TIMEO_ERR 24
#define SEND_ERR 25
#define RECV_ERR 26
#define RECV_TIMEOUT_ERR 27