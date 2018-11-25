/*
 * Filename: status.h
 * Author: KryptonLee
 * Creation Time: 2018.11.25
 * 
 * Function:
 *      Handler function
 */


/*
 * Handler function for authorization success
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
int success_handler();

/*
 * Handler function for keep alive failure
 * 
 * Return Value:
 *      If success, return SUCCESS, else return -1
 */
int failure_handler();

/*
 * Handler function for exit while ONLINE
 * 
 * Parameters:
 *      arg: signal
 */
void exit_handler(int arg);

/*
 * Handler function for exit while input
 * 
 * Parameters:
 *      arg: signal
 */
void exit_while_input(int arg);

/*
 * Default handler function
 * 
 * Return Value:
 *      SUCCESS
 */
int default_handler();