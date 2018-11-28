/*
 * Filename: sysu-h3c.c
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Main program to run.
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include "sysu-h3c.h"
#include "status.h"
#include "io.h"

/*
 * Handler function for exit while ONLINE
 * 
 * Parameters:
 *      arg: signal
 */
void exit_handler(int arg)
{
	logoff();
	cleanup();
	printf("Exiting...\n");
	exit(EXIT_SUCCESS);
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
	exit(EXIT_SUCCESS);
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
    char *dhcp_cmd = "dhclient";
    bool alloc_pwd_mem = false;
    int statno;

    while ((opt = getopt(argc, argv, "i:u:p:m:D:dh")) != -1)
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
			if ((statno = set_md5_method(optarg)) != SUCCESS)
            {
                fprintf(stderr, "Failed to set MD5 method: %s.\n", str_statno(statno));
                exit(EXIT_FAILURE);
            }
            break;
        case 'D':
            if (strcmp(optarg, dhcp_cmd) != 0)
                dhcp_cmd = optarg;
            break;
        case 'd':
            set_to_daemon();
            break;
		case 'h':
			print_usage(stdout);
			exit(EXIT_SUCCESS);
		default:
			print_usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

    // Must run as root user
    if (geteuid() != 0)
    {
		fprintf(stderr, "Run as root, please.\n");
		exit(EXIT_FAILURE);
	}

	if (ifname == NULL || usr == NULL)
    {
		print_usage(stderr);
		exit(EXIT_FAILURE);
	}

	if ((statno = set_usr(usr)) != SUCCESS)
    {
		fprintf(stderr, "Failed to set username: %s.\n", str_statno(statno));
		exit(EXIT_FAILURE);
	}

    if (pwd == NULL)
    {
		if ((pwd = (char *) malloc(PWD_LEN)) == NULL)
        {
			fprintf(stderr, "Failed to malloc: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		printf("Password for %s:", usr);

		signal(SIGINT, exit_while_input);
		signal(SIGTERM, exit_while_input);

		echo_off();
		fgets(pwd, PWD_LEN - 1, stdin);
		alloc_pwd_mem = true;
		echo_on();

		// Replace '\n' with '\0', as it is NOT part of password
		pwd[strlen(pwd) - 1] = '\0';
		putchar('\n');
	}

	if ((statno = set_pwd(pwd)) != SUCCESS)
    {
		fprintf(stderr, "Failed to set password: %s\n", str_statno(statno));
		if (alloc_pwd_mem)
			free(pwd);
		exit(EXIT_FAILURE);
	}
	if (alloc_pwd_mem)
		free(pwd);
    
    if ((statno = set_dhcp_cmd(dhcp_cmd)) != SUCCESS)
    {
        fprintf(stderr, "Failed to set DHCP command: %s\n", str_statno(statno));
        exit(EXIT_FAILURE);
    }

    if ((statno = init(ifname)) != SUCCESS)
    {
		fprintf(stderr, "Failed to initialize: %s\n", str_statno(statno));
		exit(EXIT_FAILURE);
	}

	if ((statno = start()) != SUCCESS)
    {
		fprintf(stderr, "Failed to start: %s\n", str_statno(statno));
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, exit_handler);
	signal(SIGTERM, exit_handler);

	while(true)
    {
		if ((statno = response()) != SUCCESS)
        {
			fprintf(stderr, "Failed to response: %s\n", str_statno(statno));
			exit(EXIT_FAILURE);
		}
	}

	return 0;
}