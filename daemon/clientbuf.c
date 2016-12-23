/*
 * clientbuf.c
 *
 * This file is a part of uniauth/daemon.
 */

#include "clientbuf.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void clientbuf_init(struct clientbuf* client,int sock,time_t atm)
{
    client->sock = sock;
    client->conntm = atm;
    client->status = incomplete;
    memset(client->iobuf,0,UNIAUTH_MAX_MESSAGE);
    memset(&client->stor,0,sizeof(struct uniauth_storage));
}

void clientbuf_delete(struct clientbuf* client)
{
    close(client->sock);
    client->sock = -1;
}

int clientbuf_operation(struct clientbuf* client)
{
    /* This function should be called when I/O notification is received for this
     * client's file descriptor.
     */

    return 0;
}
