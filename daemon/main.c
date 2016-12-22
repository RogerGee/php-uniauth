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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>

#define NAME    "uniauthd"
#define VERSION "0.0.0"

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
        bool doVersion;

    } options;
};

/* Function declarations */
static void globals_init(struct uniauth_daemon_globals* globals);
static void globals_delete(struct uniauth_daemon_globals* globals);
static int uniauth_storage_cmp(struct uniauth_storage*,struct uniauth_storage*);
static void uniauth_storage_free(struct uniauth_storage*);
static void parse_options(struct uniauth_daemon_globals* globals);
static void create_server(struct uniauth_daemon_globals* globals);
static int run_server(struct uniauth_daemon_globals* globals);

/* Entry point */
int main(int argc,char* argv[])
{
    struct uniauth_daemon_globals globals;

    globals_init(&globals);
    globals_delete(&globals);

    return EXIT_SUCCESS;
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
        perror(NULL);
        exit(EXIT_FAILURE);
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
