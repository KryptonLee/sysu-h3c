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
#define BPF_OPEN_ERR 3
#define BPF_SET_BUF_LEN_ERR 4
#define BPF_SET_IF_ERR 5
#define BPF_SET_FILTER_ERR 6
#define BPF_SET_IMMEDIATE_ERR 7
#define BPF_SET_DIRECTION_ERR 8
#define SOCKET_OPEN_ERR 9
#define SOCKET_SET_IF_ERR 10
#define SOCKET_GET_HWADDR_ERR 11
#define SEND_ERR 12
#define RECV_ERR 13
#define EAPOL_UNHANDLED 14
#define EAP_UNHANDLED 15
#define SUCCESS_UNHANDLED 16
#define FAILURE_UNHANDLED 17
#define RESPONSE_UNHANDLED 18