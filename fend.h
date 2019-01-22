/*#######################################################################################
 * 	This is a header file contaning the global variables and function declarations.
 * 	This header is included in the fend.c file
 *
 * 	---------------------------------------------
 * 	Author: Ramya Vijayakumar
 * 	Unity Id: rvijaya4
 * 	Student Id: 200263962
 * 	---------------------------------------------
 *#######################################################################################
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/user.h>
//#include<errno.h>

/* Permission denied */
#define EACCES	13

/* Failing exit status.  */
#define EXIT_FAILURE	1

/* Success exit status.  */
#define EXIT_SUCCESS    0

//#define SYSCALLS 512

//Declaring a log file
//the entire operation will be logged in this file
//which can be used for debugging
#define LOG_FILE "./fend.log"

//Using the x86-64 standard 
#define GET_SYSCALL_REG(regs) ((regs)->orig_rax)
//#define GET_ARG1_REG(regs) ((regs)->rdi)
//#define GET_ARG2_REG(regs) ((regs)->rsi)
//#define GET_ARG3_REG(regs) ((regs)->rdx)

/*#define SYSCALL_INIT(s) do {                               \
    g_syscalls[s].handler = NULL;                          \
  } while(0)

typedef void (*syscall_handler)(struct sandbox*, struct user_regs_struct*);

struct syscall {
  syscall_handler handler;
};

static struct syscall g_syscalls[SYSCALLS];
*/

//#define ORIG_RAX 15

FILE *logger;
time_t curr_time;
//time(&curr_time);
int lines_in_config = 0;

struct sandbox {
        pid_t pid;
        pid_t main_pid;
        char **argv;
};

const char *CONFIG_FILE;

typedef struct {
        char *perm;
        char *abspath;
}config_contents;

config_contents *config;

static void sandbox_kill(struct sandbox *fend, int exit_status);
//bool syscall_is_allowed(int syscall_num, int syscall_arg);
//bool syscall_is_allowed(struct sandbox *fend, struct user_regs_struct *regs);
bool syscall_is_allowed(struct sandbox *fend, long system_call_num);
//void syscall_add_handler(int syscall_num, syscall_handler handler);
//void syscall_exec_handler(int syscall_num, struct sandbox *fend, struct user_regs_struct *regs);
static void sandbox_handle_syscall(struct sandbox *fend);
static void set_ptrace_opts(pid_t pid);
static void sandbox_step(struct sandbox *fend);
void sandbox_init(struct sandbox *fend);
void sandbox_run(struct sandbox *fend);
static void usage(int exit_status);
static void load_config(const char *path);
