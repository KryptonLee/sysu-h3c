/*
 * Filename: sysu-h3c.h
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      H3C authentication module.
 */

#ifndef SYSU_H3C_H
#define SYSU_H3C_H

#define USR_LEN 32
#define PWD_LEN 32

/*
 * Set username to buffer
 * 
 * Parameters:
 *      usr: pointer to the username string
 * 
 * Return Value:
 *      If success return SUCCESS, else return USR_TOO_LONG
 */
int set_usr(const char *usr);

/*
 * Set password to buffer
 * 
 * Parameters:
 *      usr: pointer to the password string
 * 
 * Return Value:
 *      If success return SUCCESS, else return PWD_TOO_LONG
 */
int set_pwd(const char *pwd);

/*
 * Set which MD5 method to be used
 * 
 * Parameters:
 *      method: pointer to the MD5 method string
 * 
 * Return Value:
 *      If success return SUCCESS, else return UNSUPPORT_MD5_METHOD
 */
int set_md5_method(const char *method);

/*
 * Set dhcp command to buffer
 * 
 * Parameters:
 *      usr: pointer to the dhcp command string
 * 
 * Return Value:
 *      If success return SUCCESS, else return DHCP_CMD_TOO_LONG
 */
int set_dhcp_cmd(const char *dhcp_cmd);

/*
 * Set to run as daemon
 */
int set_to_daemon();

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
int init(const char *ifname);

/*
 * Send a EAPOL start packet to initialize authentication
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
int start();

/*
 * Send a EAPOL logoff packet to logoff
 * 
 * Return Value:
 *      If success, return SUCCESS, else return SEND_ERR
 */
int logoff();

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
int response();

/*
 * Release the resource
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
int cleanup();


#endif // SYSU_H3C_H