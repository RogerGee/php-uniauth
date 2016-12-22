/*
 * clientbuf.h
 *
 * This file is a part of uniauth/daemon.
 */

#ifndef UNIAUTHD_CLIENTBUF_H
#define UNIAUTHD_CLIENTBUF_H
#include "defs.h"

enum message_status
{
    complete,
    incomplete,
    error
};

/* Represents a client connection and buffer for bytes sent to the server. The
 * uniauth_storage record refers to memory inside the buffer for the string
 * member allocations.
 */
struct clientbuf
{
    int sock;
    time_t conntm;
    enum message_status status;
    char incoming[UNIAUTH_MAX_MESSAGE];
    struct uniauth_storage stor;
};

void clientbuf_init(struct clientbuf* client,int sock,time_t atm);
void clientbuf_delete(struct clientbuf* client);

#endif
