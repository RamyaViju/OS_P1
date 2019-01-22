/*###############################################################################
 * 	This file contains the code for the fend sandbox.
 * 	Some code used here is picked up from various online resources.
 * 	Please refer the REFERENCES file for the list of online resources used.
 *
 * 	--------------------------------------
 * 	Author: Ramya Vijayakumar
 * 	Unity Id: rvijaya4
 * 	Student Id: 200263962
 * 	--------------------------------------
 *###############################################################################
*/

#define _POSIX_SOURCE
#define _GNU_SOURCE
//#include <linux/ptrace.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>	//PTRACE_O_EXITKILL
#include <asm/ptrace.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include<time.h>		//time_t , time and ctime
#include <getopt.h>
#include <stdbool.h>		//bool datatype
#include <fnmatch.h>		//fnmatch function
#include <fcntl.h>
#include <linux/limits.h>	//PATH_MAX is defined
#include <sys/reg.h>
#include <sys/syscall.h>

#include "fend.h"	//including the local header

static void sandbox_kill(struct sandbox *fend, int exit_status) 
{
	//int status;
  	fprintf(logger,"%s sandbox_kill function called. Terminating fend!\n", ctime(&curr_time));
        kill(fend->pid, SIGKILL);
        fprintf(logger,"%s waiting for all the child process(es) to terminate\n", ctime(&curr_time)); 
	wait(NULL);
        if(exit_status == 13)
	{
		fprintf(stderr, "Access denied!\n");
	}
	exit(exit_status);
}

//Code re-used from reference [7]
char *read_string(pid_t child, unsigned long long int addr)
{
        char *val = malloc(4096);
        int allocated = 4096;
        int read = 0;
        unsigned long tmp;
        while (1) {
                if (read + sizeof tmp > allocated) {
                        allocated *= 2;
                        val = realloc(val, allocated);
                }
                tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
                if (errno != 0) {
                        val[read] = 0;
                        break;
                }
                memcpy(val + read, &tmp, sizeof tmp);
                if (memchr(&tmp, 0, sizeof tmp) != NULL)
                        break;
                read += sizeof tmp;
        }
        return val;
}

bool syscall_is_allowed(struct sandbox *fend, long syscall_num)
{
	bool allowed=true;
	char *strval;
        int flag,i;
	struct user_regs_struct regs;

	//fprintf(logger,"%s system call is %llu\n", ctime(&curr_time), regs->orig_rax);
	switch(syscall_num)
	{
		//case 2:
		//case 257:
		case SYS_open:
		case SYS_openat:
			//(regs->orig_rax) = 2 for open system call
			//(regs->orig_rax) = 257 for openat system call

			ptrace(PTRACE_GETREGS, fend->pid, NULL, &regs);

			strval = read_string(fend->pid, regs.rdi);
			fprintf(logger,"%s strval is %s\n", ctime(&curr_time), strval);
			flag = (regs.rsi & O_ACCMODE);

			for(i=0;i<lines_in_config;i++)
			{
                        	if(fnmatch(config[i].abspath, strval, FNM_PATHNAME) == 0)
				{
                                	//permi = config_array[i].permission;
                                	if(flag == O_RDONLY)
					{
                                        	if(config[i].perm[0] == '0')
						{
                                                	//sandbox_kill(fend);
                                                	fprintf(logger,"%s There is no read access!\n", ctime(&curr_time));
                                                	allowed=false;
                                        	}
                                	}
					else if(flag == O_WRONLY)
					{
                                        	if(config[i].perm[1] == '0')
						{
                                                	//sandbox_kill(fend);
                                                	fprintf(logger,"%s There is no write access!\n", ctime(&curr_time));
                                                	allowed=false;
                                        	}
                                	}
					else if(flag == O_RDWR)
					{
                                        	if(!(config[i].perm[0] == '1' && config[i].perm[1] == '1'))
						{
                                                	//sandbox_kill(fend);
                                                	fprintf(logger,"%s There is no read/write access!\n", ctime(&curr_time));
                                                	allowed=false;
                                        	}
                                	}
                        	}
                	}
			break;

		case 59:
			//execve system call
			strval = read_string(fend->pid, regs.rdi);
			if(strval != NULL)
			{
                        	for(i=0;i<lines_in_config;i++)
				{
                                	if((fnmatch(config[i].abspath, strval, FNM_PATHNAME) == 0))
					{
                                        	if(config[i].perm[2] == '0')
						{
                                                	//sandbox_kill(fend);
                                                	allowed=false;
                                        	}
                                	}
                        	}
                	}
			break;

		default:
			//allowed=false;
			break;
	}
	return allowed;
}

//Code re-used from reference [1]
/*void syscall_add_handler(int syscall_num, syscall_handler handler)
{
  	//if(syscall_num >= 0 && syscall_num < SYSCALLS)
	//{
  		g_syscalls[syscall_num].handler = handler;
	//}
}


//Code re-used from reference [1]
void syscall_exec_handler(int syscall_num, struct sandbox *fend, struct user_regs_struct *regs)
{
	//if(syscall_num >= 0 && syscall_num < SYSCALLS)
	//{
		if(g_syscalls[syscall_num].handler)
		{
			g_syscalls[syscall_num].handler(fend, regs);
  		}
	//}
}*/

static void sandbox_handle_syscall(struct sandbox *fend)
{
	struct user_regs_struct regs;
	//unsigned long long int syscall_num=0;
	long syscall_num;
	int i;

  	/*if((syscall_num = ptrace(PTRACE_PEEKUSER, fend->pid, 8*ORIG_RAX, NULL)) < 0)
    	{
		fprintf(logger, "%s Failed to PTRACE_GETREGS\n", ctime(&curr_time));
	}*/

	syscall_num = ptrace(PTRACE_PEEKUSER, fend->pid, 8*ORIG_RAX, NULL);

	//printf("\norig_rax has %d\n",regs.orig_rax);

	//syscall_num = system();

  	//syscall_num = GET_SYSCALL_REG(&regs);	//store the value of (regs)->orig_rax
	printf("\norig_rax has %d, pid %d\n",syscall_num, fend->pid);
  	//syscall_num = regs.orig_rax;
	//syscall_arg = GET_ARG1_REG(&regs);	//store the value of (regs)->rdi 

  	/*if((file = fopen(CONFIG_FILE, "r")) == NULL)
  	{
           LOG_ERR(stderr, "Failed to open %s", CONFIG_FILE);
        }*/

	//fprintf(logger,"%s System call number is %llu\n", ctime(&curr_time), syscall_num);

	if(syscall_num == SYS_execve)
	{
                if(CONFIG_FILE != NULL)
		{
                        for(i=0;i<lines_in_config;i++)
			{
                                if((fnmatch(config[i].abspath, CONFIG_FILE, FNM_PATHNAME) == 0))
				{
                                        if(config[i].perm[2] == '0')
					{
						fprintf(logger, "%s System call not allowed!\n", ctime(&curr_time));
                                                sandbox_kill(fend, EACCES);
                                        }
                                }
                        }
                }
        }

	//printf("\n Before syscall_is_allowed\n");
	if(!syscall_is_allowed(fend, syscall_num))
	{
    		fprintf(logger, "%s System call not allowed!\n", ctime(&curr_time));
    		//fprintf(stderr, "Access denied!\n");
		sandbox_kill(fend, EACCES);
  	}
	
	//execute the system call
	/*fprintf(logger, "%s Executing the system call\n", ctime(&curr_time));
	printf("\nExecuting system call\n");
	syscall_exec_handler(syscall_num, fend, &regs);*/
	//sandbox_kill(fend, EXIT_SUCCESS);
	//printf("\nAfter syscall_is_allowed\n");
}

static void set_ptrace_opts(pid_t pid)
{
	fprintf(logger, "%s Setting the ptrace options\n", ctime(&curr_time));
	if(ptrace(PTRACE_SETOPTIONS, pid, 0,
		(PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
		PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL) < 0))
	{
    		fprintf(logger, "%s Failed to PTRACE_SETOPTIONS - set ptrace options\n", ctime(&curr_time));
  	}
}

static void sandbox_step(struct sandbox *fend)
{
	fprintf(logger, "%s Tracing the input process\n", ctime(&curr_time));
	int status;

	//Code re-used from reference [1]
	if(ptrace(PTRACE_SYSCALL, fend->pid, NULL, NULL) < 0)
	{
		if(errno == ESRCH)
		{
      			waitpid(fend->pid, &status, __WALL | WNOHANG);
      			if(fend->pid == fend->main_pid)
			{
        			sandbox_kill(fend, EXIT_FAILURE);
      			}
      			fend->pid = wait(NULL);
      			return;
    		}
		else
		{
      			fprintf(logger, "%s Failed to PTRACE_SYSCALL\n", ctime(&curr_time));
    		}
  	}//

  	fend->pid = wait(&status);

  	if(WIFEXITED(status) && fend->pid == fend->main_pid)
	{
    		sandbox_kill(fend, EXIT_SUCCESS);
  	}

  	if(WIFSTOPPED(status))
	{
    		sandbox_handle_syscall(fend);

    		if(ptrace(PTRACE_SYSCALL, fend->pid, NULL, NULL) < 0)
		{
      			fprintf(logger, "%s Failed to PTRACE_SYSCALL\n", ctime(&curr_time));
    		}
    		fend->pid = wait(NULL);
		sandbox_kill(fend, EXIT_SUCCESS);
  	}
}

void sandbox_init(struct sandbox *fend)
{
	fprintf(logger, "%s Initializing the fend sandbox\n", ctime(&curr_time));
	fend->argv = NULL;
	fend->pid = -1;
	fend->main_pid = -1;
}

void sandbox_run(struct sandbox *fend)
{
	fprintf(logger, "%s Invoking the fend sandbox\n", ctime(&curr_time));
	fend->pid = fork();
	fend->main_pid = fend->pid;

	if(fend->pid == -1)
	{
		fprintf(logger, "%s Error on fork\n", ctime(&curr_time));
  	}
	if(fend->pid == 0)
	{
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
		{
      			fprintf(logger, "%s Failed to PTRACE_TRACEME\n", ctime(&curr_time));
			//exit(EXIT_FAILURE);
    		}

    		if(execvp(fend->argv[0], fend->argv) < 0)
		{
			fprintf(logger, "%s Failed to execv %s", ctime(&curr_time), fend->argv[0]);
			//exit(EXIT_FAILURE);
		}
	} 
	else 
	{
    		wait(NULL);
  	}

  	set_ptrace_opts(fend->pid);

  	for(;;)
	{
    		sandbox_step(fend);
		//printf("\nInside sandbox_run after sandbox_step\n");
  	}
}

static void usage(int exit_status)
{
	printf("\nUsage : ./fend [OPTIONS] <cmd> [<arg1>, ...]\n");
	printf("\nOPTIONS\n");
	printf("  --help, -h    Print this for help\n");
	printf("  --config, -c  <file>  Provide the config file\n");
	exit(exit_status);
}

static void load_config(const char *path)
{
	//char buffer[128];
  	FILE *file;
  	//char cwd[1024];
  	//int lines_in_config=0;
	char *line;
	size_t len = 0;
	ssize_t read_lines;
	int i=0;
	//config file has whitespaces as delimiter
	char delimit[] = " \t\n";
	char abs_pathname[PATH_MAX + 1];

	fprintf(logger,"%s Loading the config file .....\n", ctime(&curr_time));

  	if(path == NULL)
	{
    		//getcwd(cwd, sizeof(cwd));
    		path="./.fendrc";
    		if((file = fopen(path, "r")) == NULL)
		{
        		//struct passwd *pw = getpwuid(getuid());
        		//const char *homedir = pw->pw_dir;
        		path="~/.fendrc";
        		if((file = fopen(path, "r")) == NULL)
			{
          			fprintf(logger, "%s Must provide a config file\n", ctime(&curr_time));
				printf("\nMust provide a config file\n");
				exit(EXIT_FAILURE);
        		}
        		else
			{
          			CONFIG_FILE="~/.fendrc";
        		}
    		}
    		else
		{
        		CONFIG_FILE="./.fendrc";
    		}
  	}
  	else
	{
        	if((file = fopen(path, "r")) == NULL)
		{
           		fprintf(logger, "%s Failed to open %s", ctime(&curr_time), path);
			exit(EXIT_FAILURE);
        	}
        	else
		{
                	CONFIG_FILE=path;
        	}
  	}

	while ((read_lines = getline(&line, &len, file)) != -1)
	{
                lines_in_config++;
        }

	fprintf(logger,"%s number of line(s) in the config file is/are %d\n", ctime(&curr_time), lines_in_config);

	//Creating a dynamic array to store the contents of the Config file
	//config_contents *config 
	config = (config_contents *)malloc(sizeof(config_contents) * lines_in_config);

	//file is pointing to the last line of the config file, 
	//to populate the above structure,
	//we need to make file point to 
	//the first line of the config file
	rewind(file);

	//populating the config structure
	for (i=1;i<=lines_in_config;i++)
	{
                getline(&line, &len, file);
                char *permission = strtok(line, delimit);
                config[i].perm = strdup(permission);
		fprintf(logger,"%s file permission is %s\n", ctime(&curr_time), config[i].perm);

                char *pathname = strtok(NULL, delimit);
		fprintf(logger,"%s pathname is %s\n", ctime(&curr_time), pathname);
		char *ptr = realpath(pathname, abs_pathname);
		fprintf(logger,"%s absolute pathname is %s\n", ctime(&curr_time), abs_pathname);
		if(ptr!=NULL)
                {
			config[i].abspath = strdup(abs_pathname);
		}
        }

  	fclose(file);
}

int main(int argc, char **argv)
{
	struct sandbox fend;
	int opt;
  	struct option opts[] = {
    		{"help",	no_argument,		NULL, 'h'},
    		{"config",	required_argument,	NULL, 'c'},
		{NULL,		0,                 	NULL, 0}
	};
	logger=fopen(LOG_FILE, "a+");
	time(&curr_time);

	if(argc<2)
	{
		fprintf(logger,"%s Invalid usage of fend. Usage : ./fend [OPTIONS] <cmd> [<arg1>, ...]\n", ctime(&curr_time));
		usage(EXIT_FAILURE);
	}

	while((opt = getopt_long(argc, argv, "+hc", opts, NULL)) > 0)
	{
    		switch(opt)
		{
    			case 'h':
				fprintf(logger,"%s Launching fend .....\n", ctime(&curr_time));
				usage(EXIT_SUCCESS);
      				break;
    			case 'c':
      				//load_config(optarg);
      				break;
			default:
				fprintf(logger,"%s Invalid usage of fend. Usage : ./fend [OPTIONS] <cmd> [<arg1>, ...]\n", ctime(&curr_time));
      				usage(EXIT_FAILURE);
      				break;
    		}
  	}

	if(optind == argc)
	{
    		fprintf(logger,"%s Invalid usage of fend. Usage : ./fend [OPTIONS] <cmd> [<arg1>, ...]\n", ctime(&curr_time));
  		usage(EXIT_FAILURE);
	}

	load_config(optarg);

	argc = argc - optind;
  	fend.argv = argv + optind;

	//printf("\nInside main before sandbox_init\n");  	
	sandbox_init(&fend);

	//printf("\nInside main before sandbox_run\n");
	sandbox_run(&fend);

	return EXIT_SUCCESS;
}
