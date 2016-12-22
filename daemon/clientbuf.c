/*
 * clientbuf.c
 *
 * This file is a part of uniauth/daemon.
 */

#include "clientbuf.h"
#include <stdlib.h>
#include <string.h>

void clientbuf_init(struct clientbuf* client,int sock,time_t atm)
{
    client->sock = sock;
    client->conntm = atm;
    client->status = incomplete;
    memset(client->incoming,0,UNIAUTH_MAX_MESSAGE);
    memset(&client->stor,0,UNIAUTH_MAX_MESSAGE);
}

void clientbuf_delete(struct clientbuf* client)
{
    /* Nothing to do (yet) */

    (void)client;
}
