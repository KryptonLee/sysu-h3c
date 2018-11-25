/*
 * Filename: status.h
 * Author: KryptonLee
 * Creation Time: 2018.11.25
 * 
 * Function:
 *      Handler function
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 

#include "status.h"
#include "io.h"
#include "sysu-h3c.h"

/*
 * Handler function for authorization success
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
int success_handler()
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
int failure_handler()
{
	printf("You are now OFFLINE.\n");
	return SUCCESS;
}

/*
 * Handler function for unknown EAPOL type packet
 * 
 * Return Value:
 *      SUCCESS
 */
int unkown_eapol_handler()
{
	// Directly skip it as it has no effect on the
	// authorization process
    return SUCCESS;
}

/*
 * Handler function for unknown EAP code packet
 * 
 * Return Value:
 *      SUCCESS
 */
int unkown_eap_handler()
{
	// Directly skip it as it has no effect on the
	// authorization process
    return SUCCESS;
}

/*
 * Handler function for EAP response packet
 * 
 * Return Value:
 *      SUCCESS
 */
int got_response_handler()
{
	// Directly skip it as it has no effect on the
	// authorization process
    return SUCCESS;
}

/*
 * Handler function for exit while ONLINE
 * 
 * Parameters:
 *      arg: signal
 */
void exit_handler(int arg)
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
void exit_while_input(int arg)
{
	putchar('\n');
	echo_on();
	exit(0);
}