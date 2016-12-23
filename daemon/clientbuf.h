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
    notset,
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
    int sock;                        /* client socket file descriptor */
    time_t conntm;                   /* connect time in UNIX time */

    enum message_status status;      /* the status of the input/output message */
    int opkind;                      /* the kind of message being read/written */
    int mode;                        /* non-zero output mode, zero input mode */

    char iobuf[UNIAUTH_MAX_MESSAGE]; /* store outcoming/incoming message */
    struct uniauth_storage stor;     /* cache uniauth fields interpreted from iobuf */
};

void clientbuf_init(struct clientbuf* client,int sock,time_t atm);
void clientbuf_delete(struct clientbuf* client);
int clientbuf_operation(struct clientbuf* client);

#endif
