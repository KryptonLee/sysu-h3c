/*
 * Filename: sysu-h3c.c
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Main program to run.
 * 
 */

#include <signal.h>
#include <errno.h>
#include <unistd.h> 
#include <netinet/in.h>

#include "sysu-h3c.h"
#include "base64.h"
#include "packet.h"
#include "status.h"
#include "io.h"

#define send_pkt_header ((struct packet_header *)send_buf)
#define recv_pkt_header ((struct packet_header *)recv_buf)
#define get

static char username[USR_LEN];
static char password[PWD_LEN];

static uint8_t send_buf[BUF_SIZE];
static uint8_t recv_buf[BUF_SIZE];

static uint8_t ip_addr_info[IP_ADDR_INFO_SIZE];
//static uint8_t encry_ver_info[ENCRY_VER_INFO_SIZE];
static const unsigned char encry_ver_info[] = {0x06, 0x07, 'b', 'j', 'Q', '7', 'S', 'E',
									'8', 'B', 'Z', '3', 'M', 'q', 'H', 'h', 's', '3', 'c', 'l', 'M', 'r',
									'e', 'g', 'c', 'D', 'Y', '3', 'Y', '=', 0x20, 0x20};

static void print_send_buf()
{
    int i = 0;
    for(i = 0; i < BUF_SIZE; i++)
        printf("%02x", send_buf[i]);
    printf("\n");
}

static int set_usr(const char *usr)
{
    size_t len = strlen(usr);
    if (len > USR_LEN - 1)
        return USR_TOO_LONG;
    
    strcpy(username, usr);
    return SUCCESS;
}

static int set_pwd(const char *pwd)
{
    size_t len = strlen(pwd);
    if (len > PWD_LEN - 1)
        return PWD_TOO_LONG;
    
    strcpy(password, pwd);
    return SUCCESS;
}

static int init(const char *ifname)
{
    uint8_t hwaddr[ETHER_ADDR_LEN];
    int flag = init_net(ifname, hwaddr);
    if (flag == SUCCESS)
        set_ether_header(send_pkt_header, PAE_GROUP_ADDR, hwaddr);

    return flag;
}

static inline int start()
{
    set_eapol_header(send_pkt_header, EAPOL_TYPE_START, 0);
    return sendout(send_buf, EAPOL_START_PKT_SIZE);
}

static inline int logoff()
{
    set_eapol_header(send_pkt_header, EAPOL_TYPE_LOGOFF, 0);
    return sendout(send_buf, EAPOL_LOGOFF_PKT_SIZE);
}

static int send_id_pkt(uint8_t pkt_id)
{
    int usr_len = strlen(username);
    uint16_t len = EAP_HEADER_SIZE + EAP_TYPE_SIZE
         + ENCRY_VER_INFO_SIZE + usr_len;
    printf("len = %04x\n", len);
    
    set_eapol_header(send_pkt_header, EAPOL_TYPE_EAPPACKET, len);
    print_send_buf();
    set_eap_header(send_pkt_header, EAP_CODE_RESPONSE, pkt_id, len);
    print_send_buf();
    set_eap_id_info(send_pkt_header, encry_ver_info, username, usr_len);
    print_send_buf();
    return sendout(send_buf, ETHER_HEADER_SIZE + EAPOL_HEADER_SIZE + len);
}

static int send_md5_pkt(uint8_t pkt_id, uint8_t *md5_value, int md5_method)
{
    int i;
    int usr_len = strlen(username);
    uint8_t md5[EAP_MD5_VALUE_SIZE];
    uint16_t len = EAP_HEADER_SIZE + EAP_TYPE_SIZE
        + EAP_MD5_LEN_SIZE + EAP_MD5_VALUE_SIZE + usr_len;
    
    for(i = 0; i < EAP_MD5_VALUE_SIZE; i++)
        md5[i] = password[i] ^ md5_value[i];

    set_eapol_header(send_pkt_header, EAPOL_TYPE_EAPPACKET, len);
    set_eap_header(send_pkt_header, EAP_CODE_RESPONSE, pkt_id, len);
    set_eap_md5_info(send_pkt_header, md5, username, usr_len);

    return sendout(send_pkt_header, ETHER_HEADER_SIZE + EAPOL_HEADER_SIZE + len);
}

static int send_h3c_pkt(uint8_t pkt_id)
{
    int usr_len = strlen(username);
    int pwd_len = strlen(password);
    uint16_t len = EAP_HEADER_SIZE + EAP_TYPE_SIZE
        + EAP_H3C_PWLEN_SIZE + pwd_len + usr_len;
    
    set_eapol_header(send_pkt_header, EAPOL_TYPE_EAPPACKET, len);
    set_eap_header(send_pkt_header, EAP_CODE_RESPONSE, pkt_id, len);
    set_eap_h3c_info(send_pkt_header, password, pwd_len, username, usr_len);

    return sendout(send_buf, ETHER_HEADER_SIZE + EAPOL_HEADER_SIZE + len);
}

static int response(int (*success_callback)(void), int (*failure_callback)(void),
		int (*unkown_eapol_callback)(void), int (*unkown_eap_callback)(void),
		int (*got_response_callback)(void), char md5_method)
{
    if (recvin(recv_buf, BUF_SIZE) == RECV_ERR)
        return RECV_ERR;
    
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
    else if (recv_pkt_header->eap_header.code == EAP_CODE_REQUEST)
    {
        // Got EAP request, response according to request type
        switch (*get_eap_type(recv_pkt_header))
        {
            case EAP_TYPE_ID:
                return send_id_pkt(recv_pkt_header->eap_header.id);
            case EAP_TYPE_MD5:
                return send_md5_pkt(recv_pkt_header->eap_header.id,
                    get_eap_md5_value(recv_pkt_header), md5_method);
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

static inline int cleanup()
{
    return close_net();
}

static int success_handler()
{
	printf("You are now ONLINE.\n");
	daemon(0, 0);
	return SUCCESS;
}

static int failure_handler()
{
	printf("You are now OFFLINE.\n");
	return SUCCESS;
}

static void exit_handler(int arg)
{
	puts("\nExiting...\n");
	logoff();
	cleanup();
	exit(0);
}

static void exit_with_echo_on(int arg)
{
	putchar('\n');
	echo_on();
	exit(0);
}

static int default_handler()
{
    return SUCCESS;
}

int main(int argc, char **argv)
{
    int opt;
    char *ifname = NULL;
    char *usr = NULL;
    char *pwd = NULL;
    char *md5_str = "md5";
    int alloc_pwd_mem = 0;
    int md5_method = MD5_METHOD_XOR;

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

		signal(SIGINT, exit_with_echo_on);
		signal(SIGTERM, exit_with_echo_on);

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
				default_handler, default_handler, md5_method) != SUCCESS)
        {
			fprintf(stderr, "Failed to response: %s\n", strerror(errno));
			exit(-1);
		}
	}

	return 0;
}