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

#define SOCKET_OPEN_ERR 11
#define SOCKET_SET_IF_ERR 12
#define SOCKET_GET_HWADDR_ERR 13
#define SOCKET_SET_TIMEO_ERR 14
#define SEND_ERR 15
#define RECV_ERR 16
#define RECV_TIMEOUT 17

#define AUTH_FAILURE 21