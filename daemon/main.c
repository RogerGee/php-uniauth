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
#include <stddef.h>
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

#define NAME            "uniauthd"
#define VERSION         "0.0.0"
#define REALTIME_SIGNAL SIGRTMIN

static const char* const OPTSTRING = "n";
static const struct option LONGOPTS[] = {
    { "help", no_argument, NULL, 0 },
    { "version", no_argument, NULL, 1 },
    { "no-daemon", no_argument, NULL, 2 },
    { NULL, 0, NULL, 0 }
};

struct uniauth_storage_wrapper
{
    /* Store unique key per entry. */
    char* key;
    size_t keySz;

    /* Reference to storage record may be shared by other entries. */
    struct uniauth_storage* stor;
};

/* Represents the global set of information maintained by each instance of the
 * daemon.
 */
struct uniauth_daemon_globals
{
    int serverSocket; /* the server socket handle */
    sigset_t sigset;  /* the set of signals received upon I/O */
    bool running;     /* true if the server should still be running */

    struct treemap sessions; /* of 'struct uniauth_storage_wrapper' */

    size_t clientsSize;
    size_t clientsAlloc;
    struct clientbuf** clients;

    struct uniauth_options
    {
        bool doHelp;
        bool doVersion;
        bool nodaemon;
    } options;
};

static bool* g_SignalToggle = NULL;

/* Function declarations */
static void daemonize();
static void globals_init(struct uniauth_daemon_globals* globals);
static void globals_delete(struct uniauth_daemon_globals* globals);
static int uniauth_storage_wrapper_cmp(struct uniauth_storage_wrapper*,
    struct uniauth_storage_wrapper*);
static void uniauth_storage_wrapper_free(struct uniauth_storage_wrapper*);
static void parse_options(struct uniauth_daemon_globals* globals,int argc,char* argv[]);
static void create_server(struct uniauth_daemon_globals* globals);
static int run_server(struct uniauth_daemon_globals* globals);
static void term_signal(int signo);

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
    struct sigaction action;
    struct uniauth_daemon_globals globals;

    /* Create a signal handler for terminating the daemon. */
    memset(&action,0,sizeof(struct sigaction));
    action.sa_handler = term_signal;
    sigaction(SIGINT,&action,NULL);
    sigaction(SIGTERM,&action,NULL);
    sigaction(SIGQUIT,&action,NULL);

    globals_init(&globals);
    parse_options(&globals,argc,argv);

    g_SignalToggle = &globals.running;

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
            "  --no-daemon       Do not detach from controlling terminal\n"
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

    globals_delete(&globals);
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
    if (chdir("/") == -1) {
        fatal_error("fail chdir(): %s",strerror(errno));
    }

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
        (key_comparator)uniauth_storage_wrapper_cmp,
        (destructor)uniauth_storage_wrapper_free);
    globals->clientsSize = 0;
    globals->clientsAlloc = 0;
    globals->clients = NULL;
}

void globals_delete(struct uniauth_daemon_globals* globals)
{
    size_t i;

    close(globals->serverSocket);
    treemap_delete(&globals->sessions);

    for (i = 0;i < globals->clientsAlloc;++i) {
        if (globals->clients[i] != NULL) {
            clientbuf_delete(globals->clients[i]);
            free(globals->clients[i]);
        }
    }
    free(globals->clients);
}

int uniauth_storage_wrapper_cmp(struct uniauth_storage_wrapper* a,
    struct uniauth_storage_wrapper* b)
{
    return strcmp(a->key,b->key);
}

void uniauth_storage_wrapper_free(struct uniauth_storage_wrapper* a)
{
    struct uniauth_storage* stor = a->stor;
    if (--stor->ref <= 0) {
        free(stor->key); /* shouldn't be allocated */
        free(stor->username);
        free(stor->displayName);
        free(stor->redirect);
        free(stor->tag);
        free(stor);
    }
    free(a->key);
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
    /* Modify socket to perform signal-driven, async I/O. */
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
    socklen_t len;
    struct sockaddr_un addr;

    /* Create UNIX socket for accepting local stream connections. */
    sock = socket(AF_UNIX,SOCK_STREAM | SOCK_NONBLOCK,0);
    if (sock == -1) {
        fatal_error("fail socket(): %s",strerror(errno));
    }
    setup_socket(sock);

    /* Set up address and perform bind and listen. */
    memset(&addr,0,sizeof(struct sockaddr_un));
    strncpy(addr.sun_path,SOCKET_PATH,sizeof(SOCKET_PATH)-1);
    addr.sun_family = AF_UNIX;
    if (addr.sun_path[0] == '@') {
        /* Use abstract namespace. */
        addr.sun_path[0] = 0;
        len = offsetof(struct sockaddr_un,sun_path) + sizeof(SOCKET_PATH) - 1;
    }
    else {
        len = sizeof(struct sockaddr_un);
    }
    if (bind(sock,(const struct sockaddr*)&addr,len) == -1) {
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

    /* Allocate as many client structure pointers as we can have file
     * descriptors. This allows us to create a mapping from file descriptor to
     * client structure.
     */
    if (getrlimit(RLIMIT_NOFILE,&maxfd) == -1) {
        fatal_error("fail getrlimit(): %s\n",strerror(errno));
    }
    globals->clientsAlloc = maxfd.rlim_cur;
    tot = sizeof(struct clientbuf*) * globals->clientsAlloc;
    globals->clients = malloc(tot);
    if (globals->clients == NULL) {
        fatal_error("fail malloc(): %s",strerror(errno));
    }

    /* Initialize client structure pointers to NULL. */
    memset(globals->clients,0,tot);

    /* Setup a realtime signal to synchronously wait for queued I/O
     * notifications.
     */
    sigemptyset(&globals->sigset);
    sigaddset(&globals->sigset,REALTIME_SIGNAL);
    if (sigprocmask(SIG_SETMASK,&globals->sigset,NULL) == -1) {
        fatal_error("fail sigprocmask(): %s",strerror(errno));
    }
}

static void command_lookup(struct uniauth_daemon_globals* globals,
    struct clientbuf* client)
{
    struct uniauth_storage_wrapper* wrapper;
    struct uniauth_storage_wrapper lk;

    /* Do lookup. */
    lk.key = client->stor.key;
    wrapper = treemap_lookup(&globals->sessions,&lk);
    if (wrapper == NULL) {
        clientbuf_send_error(client,"no such record");
        return;
    }

    clientbuf_send_record(client,wrapper->key,wrapper->keySz,wrapper->stor);
}

static void copy_record_string(const char* s,size_t z,char** ps,size_t* pz)
{
    char* curbuf = *ps;
    if (curbuf != NULL) {
        /* NOTE: sizes of allocated buffers are *pz+1 and z+1 respectively. */
        if (*pz >= z) {
            goto a;
        }
        free(curbuf);
    }
    *ps = malloc(z+1);
a:

    strcpy(*ps,s);
    *pz = z;
}
static void copy_record(const struct uniauth_storage* src,
    struct uniauth_storage* dst)
{
    /* This function copies uniauth fields from one record to another but only
     * if the field in question is set. The field 'key' is not considered.
     */

    if (src->id > 0) {
        dst->id = src->id;
    }
    if (src->username != NULL) {
        copy_record_string(src->username,src->usernameSz,
            &dst->username,&dst->usernameSz);
    }
    if (src->displayName != NULL) {
        copy_record_string(src->displayName,src->displayNameSz,
            &dst->displayName,&dst->displayNameSz);
    }
    if (src->expire != 0) {
        dst->expire = src->expire;
    }
    if (src->redirect != NULL) {
        copy_record_string(src->redirect,src->redirectSz,
            &dst->redirect,&dst->redirectSz);
    }
    if (src->tag != NULL) {
        copy_record_string(src->tag,src->tagSz,&dst->tag,&dst->tagSz);
    }
}

static void command_commit(struct uniauth_daemon_globals* globals,
    struct clientbuf* client)
{
    struct uniauth_storage_wrapper* wrapper;
    struct uniauth_storage_wrapper lk;

    /* Do lookup. */
    lk.key = client->stor.key;
    wrapper = treemap_lookup(&globals->sessions,&lk);
    if (wrapper == NULL) {
        clientbuf_send_error(client,"no such record");
        return;
    }

    /* Apply fields that are set from the received structure to the stored
     * structure. This will apply all fields except key.
     */
    copy_record(&client->stor,wrapper->stor);
    clientbuf_send_message(client,"changes committed");
}

static void command_create(struct uniauth_daemon_globals* globals,
    struct clientbuf* client)
{
    struct uniauth_storage* record;
    struct uniauth_storage_wrapper* wrapper;

    /* Dynamically allocate the new record. Copy the buffer record into the new
     * structure.
     */
    record = malloc(sizeof(struct uniauth_storage));
    wrapper = malloc(sizeof(struct uniauth_storage_wrapper));
    memset(record,0,sizeof(struct uniauth_storage));
    memset(wrapper,0,sizeof(struct uniauth_storage_wrapper));
    copy_record(&client->stor,record);
    copy_record_string(client->stor.key,client->stor.keySz,
        &wrapper->key,&wrapper->keySz);
    record->ref = 1;
    wrapper->stor = record;

    /* Insert the new record into the treemap. */
    if (treemap_insert(&globals->sessions,wrapper) != 0) {
        clientbuf_send_error(client,"record already exists");
        uniauth_storage_wrapper_free(wrapper);
        return;
    }

    clientbuf_send_message(client,"record created");
}

static void command_transfer(struct uniauth_daemon_globals* globals,
    struct clientbuf* client)
{
    struct uniauth_storage* stor;
    struct uniauth_storage_wrapper lk[2];
    struct uniauth_storage_wrapper* src, *dst;

    lk[0].key = client->trans.src;
    lk[1].key = client->trans.dst;

    /* Look up both the source and destination records. */
    src = treemap_lookup(&globals->sessions,lk);
    if (src == NULL) {
        clientbuf_send_error(client,"no such source record to transfer");
        return;
    }
    dst = treemap_lookup(&globals->sessions,lk+1);
    if (dst == NULL) {
        clientbuf_send_error(client,"no such destination record for transfer");
        return;
    }

    /* Make sure source and destination records are distinct. */
    if (src != dst) {
        /* Delete the destination record and assign a reference to the source
         * record. This will effectively point the destination record at the source
         * record storage structure. We still have two record entries, but they
         * point to the same storage structure.
         */
        stor = dst->stor;
        if (--stor->ref <= 0) {
            free(stor->key);
            free(stor->username);
            free(stor->displayName);
            free(stor->redirect);
            free(stor->tag);
            free(stor);
        }
        dst->stor = src->stor;
        dst->stor->ref += 1;
    }

    clientbuf_send_message(client,"transfer completed");
}

static void process_command(struct uniauth_daemon_globals* globals,
    struct clientbuf* client)
{
    /* Verify that the client sent required fields. */
    if (client->opkind == UNIAUTH_PROTO_TRANSF) {
        if (client->trans.src == NULL || client->trans.dst == NULL) {
            client->status = error;
            clientbuf_send_error(client,"no key");
            return;
        }
    }
    else if (client->stor.key == NULL) {
        client->status = error;
        clientbuf_send_error(client,"no key");
        return;
    }

    /* Delegate control to the appropriate command handler. */
    switch (client->opkind) {
    case UNIAUTH_PROTO_LOOKUP:
        command_lookup(globals,client);
        break;
    case UNIAUTH_PROTO_COMMIT:
        command_commit(globals,client);
        break;
    case UNIAUTH_PROTO_CREATE:
        command_create(globals,client);
        break;
    case UNIAUTH_PROTO_TRANSF:
        command_transfer(globals,client);
        break;
    }
}

static void process_client(struct uniauth_daemon_globals* globals,
    struct clientbuf* client)
{
    int result;

    /* Let the buffer handle input/output from/to the client. */
    result = clientbuf_operation(client);
    if (result) {
        /* We are done communicating at this point. This is probably due to an
         * error or the client shutdown the connection without sending any
         * more bytes.
         */
        if (client->status == error) {
            clientbuf_send_error(client,"error");
        }
        globals->clientsSize -= 1;
        globals->clients[client->sock] = NULL;
        clientbuf_delete(client);
        free(client);
        return;
    }

    /* Check message status. If completed then process the message command. */
    if (client->iomode == 0) {
        if (client->status == complete) {
            process_command(globals,client);
        }
    }

    /* Any completed message prompts a reset. This ensures we have finished
     * flushing the output buffer before returning to input mode.
     */
    if (client->status == complete) {
        clientbuf_input_mode(client);
    }

    /* The clientbuf_operation() function call may have returned zero on end of
     * file if beforehand we read some bytes. In that case we need to check for
     * eof since we won't be getting another notification about this socket.
     */
    if (client->eof) {
        globals->clientsSize -= 1;
        globals->clients[client->sock] = NULL;
        clientbuf_delete(client);
        free(client);
    }
}

static void accept_client(struct uniauth_daemon_globals* globals)
{
    int fd;

    fd = accept4(globals->serverSocket,NULL,NULL,SOCK_NONBLOCK);
    if (fd != -1) {
        struct clientbuf* cli = malloc(sizeof(struct clientbuf));
        globals->clients[fd] = cli;

        setup_socket(fd);
        clientbuf_init(cli,fd,time(NULL));
        globals->clientsSize += 1;

        /* There may exist a race condition from when we accept the client
         * socket until when we set it to receive edge-triggered I/O
         * notifications.
         */
        process_client(globals,cli);
    }
}

int run_server(struct uniauth_daemon_globals* globals)
{
    int sock;
    const sigset_t* set;

    pre_server(globals);
    set = &globals->sigset;

    /* Accept and process clients while 'running' flag is set. A signal handler
     * could change the flag at any moment.
     */
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
        else if ((size_t)info.si_fd < globals->clientsAlloc
            && globals->clients[info.si_fd] != NULL)
        {
            process_client(globals,globals->clients[info.si_fd]);
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

void term_signal(int signo)
{
    if (g_SignalToggle == NULL) {
        _exit(0);
    }

    /* Toggle the run state for the current process. */
    *g_SignalToggle = false;
}
