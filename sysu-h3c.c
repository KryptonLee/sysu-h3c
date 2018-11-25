/*
 * Filename: sysu-h3c.c
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Main program to run.
 */

#include <signal.h>
#include <errno.h>
#include <unistd.h> 
#include <netinet/in.h>

#include "sysu-h3c.h"
#include "md5.h"
#include "h3c_encrypt.h"
#include "packet.h"
#include "status.h"
#include "io.h"

// Macro for convenient operation
#define send_pkt_header ((struct packet_header *)send_buf)
#define recv_pkt_header ((struct packet_header *)recv_buf)

// Buffers for username and password
static char username[USR_LEN];
static char password[PWD_LEN];

// Buffers for outgoing and incoming packet
static uint8_t send_buf[PACKET_BUF_SIZE];
static uint8_t recv_buf[PACKET_BUF_SIZE];

// Buffer for IP address info in EAP identifier packet
static uint8_t ip_info[IP_INFO_BUF_SIZE];
static size_t ip_info_len = 0;
// Buffer for version ciphertext in EAP identifier packet
static uint8_t ver_cipher[VER_CIPHER_BUF_SIZE];
static size_t ver_cipher_len = 0;

// Record whether the server address is recevived
static int recev_server_addr = 0;
// Record which MD5-Challenge method should be used
static int md5_method = MD5_METHOD_XOR;

// Constant value for H3C version and key
static const uint8_t H3C_VERSION[] = {'E', 'N', ' ', 'V', '5', '.', '2', '0',
								'-', '0', '4', '0', '8', 0x00, 0x00, 0x00};
const static uint8_t H3C_KEY[] = {'H', 'u', 'a', 'W', 'e', 'i',
                                '3', 'C', 'O', 'M', '1', 'X'};

/*
 * Set username to buffer
 * 
 * Parameters:
 *      usr: pointer to the username string
 * 
 * Return Value:
 *      If success return SUCCESS, else return USR_TOO_LONG
 */
static int set_usr(const char *usr)
{
    size_t len = strlen(usr);
    if (len > USR_LEN - 1)
        return USR_TOO_LONG;
    
    strcpy(username, usr);
    return SUCCESS;
}

/*
 * Set password to buffer
 * 
 * Parameters:
 *      usr: pointer to the password string
 * 
 * Return Value:
 *      If success return SUCCESS, else return PWD_TOO_LONG
 */
static int set_pwd(const char *pwd)
{
    size_t len = strlen(pwd);
    if (len > PWD_LEN - 1)
        return PWD_TOO_LONG;
    
    strcpy(password, pwd);
    return SUCCESS;
}

/*
 * Initialize a socket bind to the ethernet interface ifname, and set
 * the ethernet header of outgoing packet buffer
 * 
 * Parameters:
 *      ifname: pointer to interface name string
 * 
 * Return Value:
 *      If success, return SUCCESS, else return the No. of the error message
 */
static int init(const char *ifname)
{
    uint8_t hwaddr[ETHER_ADDR_LEN];
    int flag = init_net(ifname, hwaddr);
    if (flag == SUCCESS)
        set_ether_header(send_pkt_header, PAE_GROUP_ADDR, hwaddr);

    return flag;
}

/*
 * Send a EAPOL start packet to initialize authorization
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static inline int start()
{
    recev_server_addr = 0;
    encrypt_h3c_ver(ver_cipher, &ver_cipher_len, H3C_VERSION,
        sizeof(H3C_VERSION), H3C_KEY, sizeof(H3C_KEY));

    set_eapol_header(send_pkt_header, EAPOL_TYPE_START, 0);
    return sendout(send_buf, EAPOL_START_PKT_SIZE);
}

/*
 * Send a EAPOL logoff packet to logoff
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static inline int logoff()
{
    // EAP logoff packet should use PAE boardcast address
    set_ether_header(send_pkt_header,
        send_pkt_header->ether_header.ether_dhost, PAE_GROUP_ADDR);
    set_eapol_header(send_pkt_header, EAPOL_TYPE_LOGOFF, 0);
    return sendout(send_buf, EAPOL_LOGOFF_PKT_SIZE);
}

/*
 * Send a EAP identifier packet
 * 
 * Parameters:
 *      pkt_id: packet id
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static int send_id_pkt(uint8_t pkt_id)
{
    size_t usr_len = strlen(username);
    uint16_t len = EAP_HEADER_SIZE + EAP_TYPE_SIZE
        + ver_cipher_len + usr_len;
    
    set_eapol_header(send_pkt_header, EAPOL_TYPE_EAPPACKET, len);
    set_eap_header(send_pkt_header, EAP_CODE_RESPONSE, pkt_id, len);
    set_eap_id_info(send_pkt_header, ver_cipher,
        ver_cipher_len, username, usr_len);
    
    return sendout(send_buf, ETHER_HEADER_SIZE + EAPOL_HEADER_SIZE + len);
}

/*
 * Send a EAP MD5-Challenge packet
 * 
 * Parameters:
 *      pkt_id: packet id
 *      md5_value: pointer to the buffer where MD5-value in incoming
 *                 packet is stored
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static int send_md5_pkt(uint8_t pkt_id, uint8_t *md5_value)
{
    int i;
    size_t usr_len = strlen(username);
    uint8_t md5[EAP_MD5_VALUE_SIZE];
    uint16_t len = EAP_HEADER_SIZE + EAP_TYPE_SIZE
        + EAP_MD5_LEN_SIZE + EAP_MD5_VALUE_SIZE + usr_len;
    
    if (md5_method == MD5_METHOD_XOR)
    {
        // Use XOR method to get challenge value
        for(i = 0; i < EAP_MD5_VALUE_SIZE; i++)
            md5[i] = password[i] ^ md5_value[i];
    }
    else if (md5_method == MD5_METHOD_MD5)
    {
        // Use MD5 hash method to get challenge value
        size_t pwd_len = strlen(password);
        uint8_t msg_buf[64];
        uint8_t msg_len = EAP_ID_SIZE + pwd_len + EAP_MD5_VALUE_SIZE;
        msg_buf[0] = pkt_id;
        memcpy(msg_buf + EAP_ID_SIZE, password, pwd_len);
        memcpy(msg_buf + EAP_ID_SIZE + pwd_len, md5_value, EAP_MD5_VALUE_SIZE);
        get_md5(md5, msg_buf, msg_len);
    }
    
    set_eapol_header(send_pkt_header, EAPOL_TYPE_EAPPACKET, len);
    set_eap_header(send_pkt_header, EAP_CODE_RESPONSE, pkt_id, len);
    set_eap_md5_info(send_pkt_header, md5, username, usr_len);

    return sendout(send_pkt_header, ETHER_HEADER_SIZE + EAPOL_HEADER_SIZE + len);
}

/*
 * Send a EAP H3C packet
 * 
 * Parameters:
 *      pkt_id: packet id
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static int send_h3c_pkt(uint8_t pkt_id)
{
    size_t usr_len = strlen(username);
    size_t pwd_len = strlen(password);
    uint16_t len = EAP_HEADER_SIZE + EAP_TYPE_SIZE
        + EAP_H3C_PWLEN_SIZE + pwd_len + usr_len;
    
    set_eapol_header(send_pkt_header, EAPOL_TYPE_EAPPACKET, len);
    set_eap_header(send_pkt_header, EAP_CODE_RESPONSE, pkt_id, len);
    set_eap_h3c_info(send_pkt_header, password, pwd_len, username, usr_len);

    return sendout(send_buf, ETHER_HEADER_SIZE + EAPOL_HEADER_SIZE + len);
}

/*
 * Response a received packet
 * 
 * Parameters:
 *      success_callback: callback function for EAP success packet
 *      failure_callback: callback function for EAP failure packet
 *      unkown_eapol_callback: callback function for unknown EAPOL packet
 *      unkown_eap_callback: callback function for unknown EAP packet
 *      got_response_callback: callback function for EAP reponse packet
 * 
 * Return Value:
 *      Return the action status
 */
static int response(int (*success_callback)(void), int (*failure_callback)(void),
		int (*unkown_eapol_callback)(void), int (*unkown_eap_callback)(void),
		int (*got_response_callback)(void))
{
    if (recvin(recv_buf, PACKET_BUF_SIZE) == RECV_ERR)
        return RECV_ERR;
    
    if (memcmp(recv_pkt_header->ether_header.ether_dhost,
        send_pkt_header->ether_header.ether_shost, ETHER_ADDR_LEN) != 0)
        return SUCCESS;
    
    if (recev_server_addr == 0)
    {
        set_ether_header(send_pkt_header, recv_pkt_header->ether_header.ether_shost,
            send_pkt_header->ether_header.ether_shost);
        recev_server_addr = 1;
    }
    
    if (recv_pkt_header->eapol_header.type != EAPOL_TYPE_EAPPACKET)
    {
        // Got unknown EAPOL type
        if (unkown_eapol_callback != NULL)
            return unkown_eapol_callback();
        
        return EAPOL_UNHANDLED;
    }
    if (recv_pkt_header->eap_header.code == EAP_CODE_SUCCESS)
    {
        // Got EAP success
        if (success_callback != NULL)
            return success_callback();
        
        return SUCCESS_UNHANDLED;
    }
    else if (recv_pkt_header->eap_header.code == EAP_CODE_FAILURE)
    {
        // Got EAP failure
        if (failure_callback != NULL)
            return failure_callback();
        
        return FAILURE_UNHANDLED;
    }
    else if (recv_pkt_header->eap_header.code == EAP_CODE_REQUEST)
    {
        // Got EAP request, response according to request type
        switch (*get_eap_type(recv_pkt_header))
        {
            case EAP_TYPE_ID:
                return send_id_pkt(recv_pkt_header->eap_header.id);
            case EAP_TYPE_MD5:
                return send_md5_pkt(recv_pkt_header->eap_header.id,
                    get_eap_md5_value(recv_pkt_header));
            case EAP_TYPE_H3C:
                return send_h3c_pkt(recv_pkt_header->eap_header.id);
        }

        return EAP_UNHANDLED;
    }
    else if (recv_pkt_header->eap_header.code == EAP_CODE_RESPONSE)
    {
        // Got EAP response
        if (got_response_callback != NULL)
            return got_response_callback();
        
        return RESPONSE_UNHANDLED;
    }
    else
    {
        // Got unknown EAP type
        if (unkown_eap_callback != NULL)
            return unkown_eap_callback();

        return EAP_UNHANDLED;
    }
}

/*
 * Release the resource
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
static inline int cleanup()
{
    return close_net();
}

/*
 * Handler function for authorization success
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
static int success_handler()
{
	printf("You are now ONLINE.\n");
    // Run as a daemon
	daemon(0, 0);
	return SUCCESS;
}

/*
 * Handler function for keep alive failure
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
static int failure_handler()
{
	printf("You are now OFFLINE.\n");
	return SUCCESS;
}

/*
 * Handler function for exit while ONLINE
 * 
 * Parameters:
 *      arg: signal
 */
static void exit_handler(int arg)
{
	puts("\nExiting...\n");
	logoff();
	cleanup();
	exit(0);
}

/*
 * Handler function for exit while input
 * 
 * Parameters:
 *      arg: signal
 */
static void exit_while_input(int arg)
{
	putchar('\n');
	echo_on();
	exit(0);
}

/*
 * Default handler function
 * 
 * Return Value:
 *      SUCCESS
 */
static int default_handler()
{
    return SUCCESS;
}

/*
 * Main program entrance
 */
int main(int argc, char **argv)
{
    int opt;
    char *ifname = NULL;
    char *usr = NULL;
    char *pwd = NULL;
    char *md5_str = "md5";
    int alloc_pwd_mem = 0;

    while ((opt = getopt(argc, argv, "i:u:p:m:h")) != -1)
    {
		switch (opt)
        {
		case 'i':
			ifname = optarg;
			break;
		case 'u':
			usr = optarg;
			break;
		case 'p':
			pwd = optarg;
			break;
		case 'm':
			if (strcmp(optarg, md5_str) == 0)
				md5_method = MD5_METHOD_MD5;
			break;
		case 'h':
			usage(stdout);
			exit(0);
		default:
			usage(stderr);
			exit(-1);
		}
	}

    // Must run as root user
    if (geteuid() != 0)
    {
		fprintf(stderr, "Run as root, please.\n");
		exit(-1);
	}

	if (ifname == NULL || usr == NULL)
    {
		usage(stderr);
		exit(-1);
	}

	if (set_usr(usr) != SUCCESS)
    {
		fprintf(stderr, "Failed to set username.\n");
		exit(-1);
	}

    if (pwd == NULL)
    {
		if ((pwd = (char *) malloc(PWD_LEN)) == NULL)
        {
			fprintf(stderr, "Failed to malloc: %s\n", strerror(errno));
			exit(-1);
		}
		printf("Password for %s:", usr);

		signal(SIGINT, exit_while_input);
		signal(SIGTERM, exit_while_input);

		echo_off();
		fgets(pwd, PWD_LEN - 1, stdin);
		alloc_pwd_mem = 1;
		echo_on();

		// Replace '\n' with '\0', as it is NOT part of password
		pwd[strlen(pwd) - 1] = '\0';
		putchar('\n');
	}

	if (set_pwd(pwd) != SUCCESS)
    {
		fprintf(stderr, "Failed to set password.\n");
		if (alloc_pwd_mem)
			free(pwd);
		exit(-1);
	}
	if (alloc_pwd_mem)
		free(pwd);

    if (init(ifname) != SUCCESS)
    {
		fprintf(stderr, "Failed to initialize: %s\n", strerror(errno));
		exit(-1);
	}

	if (start() != SUCCESS)
    {
		fprintf(stderr, "Failed to start: %s\n", strerror(errno));
		exit(-1);
	}

	signal(SIGINT, exit_handler);
	signal(SIGTERM, exit_handler);

	for (;;)
    {
		if (response(success_handler, failure_handler, default_handler,
				default_handler, default_handler) != SUCCESS)
        {
			fprintf(stderr, "Failed to response: %s\n", strerror(errno));
			exit(-1);
		}
	}

	return 0;
}