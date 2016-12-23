/*
 * main.c
 *
 * This file is a part of uniauth/daemon.
 */

#include "defs.h"
#include "clientbuf.h"
#include <dstructs/treemap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>

#define NAME    "uniauthd"
#define VERSION "0.0.0"
static const char* const OPTSTRING = "";
static const struct option LONGOPTS[] = {
    { "help", no_argument, NULL, 0 },
    { "version", no_argument, NULL, 1 },
    { NULL, 0, NULL, 0 }
};

/* Represents the global set of information maintained by each instance of the
 * daemon.
 */
struct uniauth_daemon_globals
{
    int serverSocket;

    struct treemap sessions;

    size_t clientsSize;
    size_t clientsAlloc;
    struct clientbuf** clients;

    struct uniauth_options
    {
        bool doHelp;
        bool doVersion;

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

    /* Become a daemon and begin main server operation. */
    daemonize();

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
    globals->clientsAlloc = 16;
    globals->clients = malloc(sizeof(struct clientbuf*) * globals->clientsAlloc);
    if (globals->clients == NULL) {
        fatal_error("fail malloc(): %s",strerror(errno));
    }
}

void globals_delete(struct uniauth_daemon_globals* globals)
{
    size_t i;

    treemap_delete(&globals->sessions);

    for (i = 0;i < globals->clientsSize;++i) {
        clientbuf_delete(globals->clients[i]);
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
        }
    }
}
