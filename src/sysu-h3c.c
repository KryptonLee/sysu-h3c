/*
 * Filename: sysu-h3c.c
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      H3C authentication module.
 */

#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>

#include "sysu-h3c.h"
#include "md5.h"
#include "h3c_encrypt.h"
#include "packet.h"
#include "status.h"
#include "io.h"

// Define the constants
#define PACKET_BUF_SIZE 256
#define DHCP_CMD_BUF_SIZE 32
#define VER_CIPHER_BUF_SIZE 64
#define IP_INFO_BUF_SIZE 6

#define MD5_METHOD_XOR 0
#define MD5_METHOD_MD5 1

// Timeout constants
#define MAX_RETRY_AFTER_SUCCESS 5
#define RETRY_INTER_BEFORE_SUCCESS 300
#define RECV_TIMEOUT_SECS 40

// Macro for convenient operation
#define send_pkt_header ((struct packet_header *)send_buf)
#define recv_pkt_header ((struct packet_header *)recv_buf)

// Buffers for username and password
static char username[USR_LEN];
static char password[PWD_LEN];

// Buffer for DHCP command
static char dhcp_cmd_buf[DHCP_CMD_BUF_SIZE];

// Buffers for outgoing and incoming packet
static uint8_t send_buf[PACKET_BUF_SIZE];
static uint8_t recv_buf[PACKET_BUF_SIZE];

// Buffer for IP address info in EAP identifier packet
static uint8_t ip_info[IP_INFO_BUF_SIZE];
static size_t ip_info_len = 0;
// Buffer for version ciphertext in EAP identifier packet
static uint8_t ver_cipher[VER_CIPHER_BUF_SIZE];
static size_t ver_cipher_len = 0;

// Record which MD5-Challenge method should be used
static int md5_method = MD5_METHOD_XOR;
// Record whether the server address is recevived
static bool recev_server_addr = false;
// Record whether authentication is success
static bool auth_success = true;
static bool as_daemon = false;
// Record the re-authentication time left (only used
// after authentication success)
static int reauth_time_left = 0;
// Record the last received packet arrival time
static time_t last_pkt_time;

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
int set_usr(const char *usr)
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
int set_pwd(const char *pwd)
{
    size_t len = strlen(pwd);
    if (len > PWD_LEN - 1)
        return PWD_TOO_LONG;
    
    strcpy(password, pwd);
    return SUCCESS;
}

/*
 * Set which MD5 method to be used
 * 
 * Parameters:
 *      method: pointer to the MD5 method string
 * 
 * Return Value:
 *      If success return SUCCESS, else return UNSUPPORT_MD5_METHOD
 */
int set_md5_method(const char *method)
{
    if (method == NULL || strcmp(method, "xor") == 0)
        md5_method = MD5_METHOD_XOR;
    else if (strcmp(method, "md5") == 0)
        md5_method = MD5_METHOD_MD5;
    else
        return UNSUPPORT_MD5_METHOD;
    
    return SUCCESS;
}

/*
 * Set dhcp command to buffer
 * 
 * Parameters:
 *      usr: pointer to the dhcp command string
 * 
 * Return Value:
 *      If success return SUCCESS, else return DHCP_CMD_TOO_LONG
 */
int set_dhcp_cmd(const char *dhcp_cmd)
{
    size_t len = strlen(dhcp_cmd);
    if (len > DHCP_CMD_BUF_SIZE - 1)
        return DHCP_CMD_TOO_LONG;
    
    strcpy(dhcp_cmd_buf, dhcp_cmd);
    return SUCCESS;
}

/*
 * Set to run as daemon
 */
int set_to_daemon()
{
    as_daemon = true;
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
int init(const char *ifname)
{
    uint8_t hwaddr[ETHER_ADDR_LEN];
    int statno = init_net(ifname, hwaddr, RECV_TIMEOUT_SECS);
    if (statno == SUCCESS)
        set_ether_header(send_pkt_header, PAE_GROUP_ADDR, hwaddr);

    return statno;
}

/*
 * Send a EAPOL start packet to initialize authentication
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
int start()
{
    recev_server_addr = false;
    auth_success = false;
    reauth_time_left = MAX_RETRY_AFTER_SUCCESS;
    last_pkt_time = time(NULL);
    
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
int logoff()
{
	printf("\nLogging off...\n");
    // EAP logoff packet should use PAE boardcast address
    set_ether_header(send_pkt_header, PAE_GROUP_ADDR,
        send_pkt_header->ether_header.ether_shost);
    set_eapol_header(send_pkt_header, EAPOL_TYPE_LOGOFF, 0);
    return sendout(send_buf, EAPOL_LOGOFF_PKT_SIZE);
}

/*
 * Try re-authenticate when receive no data from server
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static int reauth()
{
    if (auth_success == true && reauth_time_left-- > 0)
    {
        last_pkt_time = time(NULL);

        // After authentication success, try to re-authenticate inmediately
        recev_server_addr = false;
        encrypt_h3c_ver(ver_cipher, &ver_cipher_len, H3C_VERSION,
            sizeof(H3C_VERSION), H3C_KEY, sizeof(H3C_KEY));

        set_eapol_header(send_pkt_header, EAPOL_TYPE_START, 0);
        return sendout(send_buf, EAPOL_START_PKT_SIZE);
    }
    else
    {
        last_pkt_time = time(NULL);

        // If try re-authenticate more than RETRY_INTER_BEFORE_SUCCESS times
        // consider it as brand new authentication process
        if (reauth_time_left <= 0)
            auth_success = 0;
        // Before authentication success, try to re-authenticate after
        // RETRY_INTER_BEFORE_SUCCESS seconds
        sleep(RETRY_INTER_BEFORE_SUCCESS);
        return start();
    }
}

/*
 * Send a response EAP identifier packet
 * 
 * Parameters:
 *      pkt_id: packet id
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static int send_response_id(uint8_t pkt_id)
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
 * Send a response EAP-MD5-Challenge packet
 * 
 * Parameters:
 *      pkt_id: packet id
 *      md5_value: pointer to the buffer where MD5-value in incoming
 *                 packet is stored
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static int send_response_md5(uint8_t pkt_id, uint8_t *md5_value)
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
        // msg = pkt_id + password + md5_value
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
 * Send a response EAP H3C packet
 * 
 * Parameters:
 *      pkt_id: packet id
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
static int send_response_h3c(uint8_t pkt_id)
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
int response()
{
    time_t arri_time;

    int rs = recvin(recv_buf, PACKET_BUF_SIZE);
    if (rs == RECV_ERR)
        return RECV_ERR;
    else if (rs == RECV_TIMEOUT)
        return reauth();
    
    // There may be other devices in the network, the socket may catch
    // the EAP packets to them, even if this host is offline, it stiil
    // can catch those packets, so we cannot only use the socket
    // timeout to decide whether this host received heartbeat packets
    // from server.
    arri_time = time(NULL);
    if (difftime(arri_time, last_pkt_time) > RECV_TIMEOUT_SECS)
        return reauth();

    // If MAC address is not match, skip it
    if (memcmp(recv_pkt_header->ether_header.ether_dhost,
        send_pkt_header->ether_header.ether_shost, ETHER_ADDR_LEN) != 0)
        return SUCCESS;
    
    // Record the arrival time of the last packet to this host
    last_pkt_time = arri_time;
    // Save the MAC address of server from the first packet from server
    if (recev_server_addr == false)
    {
        set_ether_header(send_pkt_header, recv_pkt_header->ether_header.ether_shost,
            send_pkt_header->ether_header.ether_shost);
        recev_server_addr = true;
    }
    
    if (recv_pkt_header->eapol_header.type != EAPOL_TYPE_EAPPACKET)
    {
        // Got unknown EAPOL type
        // Some H3C version may use the info in these packets, 
        // but the version in SYSU east campus not, so just skip them
        return SUCCESS;
    }
    if (recv_pkt_header->eap_header.code == EAP_CODE_SUCCESS)
    {
        // Got EAP success, authentication success
        auth_success = true;
        // Run the DHCP command to get IP
        system(dhcp_cmd_buf);
        printf("Authentication suceess, you are now online.\n");
        // Run as a daemon if needed
        if (as_daemon)
        {
            printf("Run as daemon.\n");
            daemon(0, 0);
        }
        
        return SUCCESS;
    }
    else if (recv_pkt_header->eap_header.code == EAP_CODE_FAILURE)
    {
        // Got EAP failure, means authentication failure
	    printf("Authentication failure, check the username and password.\n");
        printf("If you ensure those info is correct, report an issue to me\
    on https://github.com/KryptonLee/sysu-h3c/issues, as the H3C authentication\
    version may change.\n");
        
        return AUTH_FAILURE;
    }
    else if (recv_pkt_header->eap_header.code == EAP_CODE_REQUEST)
    {
        // Got EAP request, response according to request type
        switch (*get_eap_type(recv_pkt_header))
        {
            case EAP_TYPE_ID:
                return send_response_id(recv_pkt_header->eap_header.id);
            case EAP_TYPE_MD5:
                return send_response_md5(recv_pkt_header->eap_header.id,
                    get_eap_md5_value(recv_pkt_header));
            case EAP_TYPE_H3C:
                return send_response_h3c(recv_pkt_header->eap_header.id);
        }
        // Some H3C version may use the info in packets of other EAP type, 
        // but the version in SYSU east campus not, so just skip them
        return SUCCESS;
    }
    else if (recv_pkt_header->eap_header.code == EAP_CODE_RESPONSE)
    {
        // Got EAP response
        // In the authentication process, the client never gets
        // response from server
        return SUCCESS;
    }
    else
    {
        // Got unknown EAP type
        // Some H3C version may use the info in these packets, 
        // but the version in SYSU east campus not, so just skip them
        return SUCCESS;
    }
}

/*
 * Release the resource
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
int cleanup()
{
    return close_net();
}