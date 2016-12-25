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
    int iomode;                      /* zero=input, non-zero=output */

    bool eof;                        /* true if eof notification happened */
    size_t bufit;                    /* iterator into buffer */
    size_t bufsz;                    /* number of bytes used in buffer from buffer[0] */
    char buf[UNIAUTH_MAX_MESSAGE];   /* store outcoming/incoming message */
    struct uniauth_storage stor;     /* cache uniauth fields interpreted from iobuf */
};

void clientbuf_init(struct clientbuf* client,int sock,time_t atm);
void clientbuf_delete(struct clientbuf* client);
int clientbuf_operation(struct clientbuf* client);
void clientbuf_input_mode(struct clientbuf* client);
void clientbuf_output_mode(struct clientbuf* client);
int clientbuf_send_error(struct clientbuf* client,const char* text);
int clientbuf_send_message(struct clientbuf* client,const char* text);
int clientbuf_send_record(struct clientbuf* client,struct uniauth_storage* stor);

#endif
