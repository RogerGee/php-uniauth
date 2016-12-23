/*
 * main.c
 *
 * This file is a part of uniauth/daemon.
 */

#define _GNU_SOURCE
#include "defs.h"
#include "clientbuf.h"
#include <dstructs/treemap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>

#define NAME    "uniauthd"
#define VERSION "0.0.0"
#define PATH    "@uniauth"
#define REALTIME_SIGNAL SIGRTMIN
static const char* const OPTSTRING = "n";
static const struct option LONGOPTS[] = {
    { "help", no_argument, NULL, 0 },
    { "version", no_argument, NULL, 1 },
    { "no-daemon", no_argument, NULL, 2 },
    { NULL, 0, NULL, 0 }
};

/* Represents the global set of information maintained by each instance of the
 * daemon.
 */
struct uniauth_daemon_globals
{
    int serverSocket; /* the server socket handle */
    sigset_t sigset;  /* the set of signals received upon I/O */
    bool running;     /* true if the server should still be running */

    struct treemap sessions;

    size_t clientsSize;
    size_t clientsAlloc;
    struct clientbuf* clients;

    struct uniauth_options
    {
        bool doHelp;
        bool doVersion;
        bool nodaemon;
    } options;
};

/* Function declarations */
static void daemonize();
static void globals_init(struct uniauth_daemon_globals* globals);
static void globals_delete(struct uniauth_daemon_globals* globals);
static int uniauth_storage_cmp(struct uniauth_storage*,struct uniauth_storage*);
static void uniauth_storage_free(struct uniauth_storage*);
static void parse_options(struct uniauth_daemon_globals* globals,int argc,char* argv[]);
static void create_server(struct uniauth_daemon_globals* globals);
static int run_server(struct uniauth_daemon_globals* globals);

static void fatal_error(const char* format, ...)
{
    char buf[4096];
    va_list va;

    va_start(va,format);
    vsnprintf(buf,sizeof(buf),format,va);
    va_end(va);

    fprintf(stderr,"%s: fatal error: %s\n",NAME,buf);
    exit(EXIT_FAILURE);
}

/* Entry point */
int main(int argc,char* argv[])
{
    struct uniauth_daemon_globals globals;

    globals_init(&globals);
    globals_delete(&globals);
    parse_options(&globals,argc,argv);

    /* Handle options that produce output on the terminal before becoming a
     * daemon.
     */
    if (globals.options.doVersion) {
        printf("%s %s\n",NAME,VERSION);
        exit(EXIT_SUCCESS);
    }
    if (globals.options.doHelp) {
        printf(
            "%s %s\n"
            "usage: %s [options...]\n"
            "\n"
            "options:\n"
            "  --help            Show this help text\n"
            "  --version         Print version info\n",
            NAME,VERSION,NAME);
        exit(EXIT_SUCCESS);
    }

    /* Become a daemon (unless specified otherwise) and begin main server
     * operation.
     */
    if (!globals.options.nodaemon) {
        daemonize();
    }
    create_server(&globals);
    run_server(&globals);

    return EXIT_SUCCESS;
}

void daemonize()
{
    int fd;
    int maxfd;
    pid_t pid;

    /* Ensure running as root. */
    if (geteuid() != 0) {
        fatal_error("%s must be run as root",NAME);
    }

    /* Create copy of process so we can detach from terminal (if any). */
    pid = fork();
    if (pid == -1) {
        fatal_error("fail fork(): %s",strerror(errno));
    }
    if (pid != 0) {
        _exit(EXIT_SUCCESS);
    }

    /* Ensure process is session leader in new session. */
    if (setsid() == (pid_t)-1) {
        fatal_error("fail setsid(): %s",strerror(errno));
    }
    pid = fork();
    if (pid == -1) {
        fatal_error("fail fork(): %s",strerror(errno));
    }
    if (pid != 0) {
        _exit(EXIT_SUCCESS);
    }

    umask(0);
    chdir("/");

    /* Close any file descriptors. */
    maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd == -1) {
        maxfd = 1000;
    }
    for (fd = 0;fd < maxfd;++fd) {
        close(fd);
    }

    /* Open standard descriptors. */
    fd = open("/dev/null",O_RDWR);
    if (fd == -1) {
        /* NOTE: cannot report error so just quit. */
        _exit(EXIT_FAILURE);
    }
    dup(fd);
    dup(fd);
}

void globals_init(struct uniauth_daemon_globals* globals)
{
    memset(globals,0,sizeof(struct uniauth_daemon_globals));
    globals->serverSocket = -1;
    treemap_init(&globals->sessions,
        (key_comparator)uniauth_storage_cmp,
        (destructor)uniauth_storage_free);
    globals->clientsAlloc = 0;
    globals->clientsSize = 0;
    globals->clients = NULL;
}

void globals_delete(struct uniauth_daemon_globals* globals)
{
    size_t i;

    treemap_delete(&globals->sessions);

    for (i = 0;i < globals->clientsSize;++i) {
        clientbuf_delete(globals->clients + i);
    }
    free(globals->clients);
}

int uniauth_storage_cmp(struct uniauth_storage* a,struct uniauth_storage* b)
{
    return strcmp(a->key,b->key);
}

void uniauth_storage_free(struct uniauth_storage* a)
{
    free(a->key);
    free(a->username);
    free(a->displayName);
    free(a->redirect);
    free(a);
}

void parse_options(struct uniauth_daemon_globals* globals,int argc,char* argv[])
{
    while (true) {
        int c;

        c = getopt_long(argc,argv,OPTSTRING,LONGOPTS,NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            globals->options.doHelp = true;
            break;
        case 1:
            globals->options.doVersion = true;
            break;
        case 2:
        case 'n':
            globals->options.nodaemon = true;
            break;
        }
    }
}

static void setup_socket(int sock)
{
    /* Modify socket to perform signal-drive, async I/O. */
    if (fcntl(sock,F_SETSIG,REALTIME_SIGNAL) == -1
        || fcntl(sock,F_SETOWN,getpid()) == -1
        || fcntl(sock,F_SETFL,fcntl(sock,F_GETFL) | O_ASYNC) == -1)
    {
        fatal_error("fail fcntl(): %s",strerror(errno));
    }
}

void create_server(struct uniauth_daemon_globals* globals)
{
    int sock;
    struct sockaddr_un addr;

    /* Create UNIX socket for accepting local stream connections. */
    sock = socket(AF_UNIX,SOCK_STREAM | SOCK_NONBLOCK,0);
    if (sock == -1) {
        fatal_error("fail socket(): %s",strerror(errno));
    }
    setup_socket(sock);

    /* Set up address and perform bind and listen. */
    memset(&addr,0,sizeof(struct sockaddr_un));
    strcpy(addr.sun_path,PATH);
    addr.sun_family = AF_UNIX;
    if (addr.sun_path[0] == '@') {
        /* Use abstract namespace. */
        addr.sun_path[0] = 0;
    }
    if (bind(sock,(const struct sockaddr*)&addr,sizeof(struct sockaddr_un)) == -1) {
        fatal_error("fail bind(): %s",strerror(errno));
    }
    if (listen(sock,SOMAXCONN) == -1) {
        fatal_error("fail listen(): %s",strerror(errno));
    }

    globals->serverSocket = sock;
}

static void pre_server(struct uniauth_daemon_globals* globals)
{
    size_t i;
    size_t tot;
    struct rlimit maxfd;

    globals->running = true;

    /* Allocate as many client structures as we can have file descriptors. This
     * allows us to create a mapping from file descriptor to client structure.
     */
    if (getrlimit(RLIMIT_NOFILE,&maxfd) == -1) {
        fatal_error("fail getrlimit(): %s\n",strerror(errno));
    }
    globals->clientsAlloc = maxfd.rlim_cur;
    tot = sizeof(struct clientbuf) * globals->clientsAlloc;
    globals->clients = malloc(tot);
    if (globals->clients == NULL) {
        fatal_error("fail malloc(): %s",strerror(errno));
    }

    /* Initialize client structures to default. Zero gets pretty much everything
     * except the file descriptor.
     */
    memset(globals->clients,0,tot);
    for (i = 0;i < globals->clientsAlloc;++i) {
        globals->clients[i].sock = -1;
    }

    /* Setup a realtime signal to synchronously wait for queued I/O
     * notifications.
     */
    sigemptyset(&globals->sigset);
    sigaddset(&globals->sigset,REALTIME_SIGNAL);
    if (sigprocmask(SIG_SETMASK,&globals->sigset,NULL) == -1) {
        fatal_error("fail sigprocmask(): %s",strerror(errno));
    }
}

static void accept_client(struct uniauth_daemon_globals* globals)
{
    int fd;

    fd = accept4(globals->serverSocket,NULL,NULL,SOCK_NONBLOCK);
    if (fd != -1) {
        struct clientbuf* cli = globals->clients + fd;

        setup_socket(fd);
        clientbuf_init(cli,fd,time(NULL));
        globals->clientsSize += 1;
    }
}

static void process_client(struct uniauth_daemon_globals* globals,
    struct clientbuf* client)
{
    int result;

    /* Let the buffer handle input/output from/to the client. */
    result = clientbuf_operation(client);
    if (result) {
        clientbuf_delete(client);
        return;
    }

    /* Check message status. */

}

int run_server(struct uniauth_daemon_globals* globals)
{
    int sock;
    const sigset_t* set;

    pre_server(globals);
    set = &globals->sigset;

    /* Accept and process clients while 'running' flag is set. A signal handler could change the flag*/
    while (globals->running) {
        siginfo_t info;

        /* Wait for I/O notification on any stream socket. */
        if (sigwaitinfo(set,&info) == -1) {
            if (errno == EINTR) {
                continue;
            }

            fatal_error("fail sigwaitinfo(): %s",strerror(errno));
        }

        /* If the notification was for the listen socket, try to accept a new
         * connection.
         */
        if (globals->serverSocket == info.si_fd) {
            accept_client(globals);
        }

        /* Otherwise it should be for an existing client. */
        else if ((size_t)info.si_fd < globals->clientsAlloc) {
            process_client(globals,globals->clients + info.si_fd);
        }

        /* We should never get here but for completion we close the
         * descriptor.
         */
        else {
            close(info.si_fd);
        }
    }

    return 0;
}
