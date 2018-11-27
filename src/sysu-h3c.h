/*
 * Filename: sysu-h3c.h
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Main program to run.
 */

#ifndef SYSU_H3C_H
#define SYSU_H3C_H

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