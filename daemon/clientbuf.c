/*
 * clientbuf.c
 *
 * This file is a part of uniauth/daemon.
 */

#include "clientbuf.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

void clientbuf_init(struct clientbuf* client,int sock,time_t atm)
{
    /* Everything pretty much defaults to zero except a couple of fields. */

    memset(client,0,sizeof(struct clientbuf));
    client->sock = sock;
    client->conntm = atm;
    client->status = notset;
}

void clientbuf_delete(struct clientbuf* client)
{
    close(client->sock);
    client->sock = -1;
    client->status = notset;
}

static size_t read_string(struct clientbuf* client,size_t iter,char** dst,size_t* psz)
{
    size_t tmp = iter;
    char* save = client->buf + iter;

    /* Verify the buffer pointed to by 'iter' is a null terminated string. */
    while (iter < client->bufsz) {
        if (client->buf[iter] == 0) {
            /* Assign out parameters and return number of bytes in string
             * (including null terminator) since field was complete.
             */

            *dst = save;
            return (*psz = iter - tmp) + 1;
        }
        iter += 1;
    }

    /* Field is incomplete. Return zero. */
    return 0;
}

static int parse_buffer(struct clientbuf* client)
{
    size_t iter = client->bufit;

    if (client->bufsz <= 0) {
        return 0;
    }

    /* Read opkind byte if we haven't already. */
    if (client->status == notset || client->status == complete) {
        client->opkind = client->buf[iter];
        if (client->opkind < 0 || client->opkind >= UNIAUTH_OP_TOP) {
            client->status = error;
            return 1;
        }
        iter += 1;
        client->status = incomplete;
    }

    /* Otherwise the fields are sent in a straightforward manner. First comes a
     * byte representing the field code, then comes the field. Fields are either
     * integer or string. Strings are encoded in UTF-8 and integers in
     * little-endian.
     */

    while (iter < client->bufsz) {
        size_t nbytes;
        unsigned char field = client->buf[iter];

        /* If we read end-of-field then the message is complete. */
        if (field == UNIAUTH_PROTO_FIELD_END) {
            client->status = complete;
            iter += 1;
            break;
        }

        /* Read the field data. */
        switch (field) {
        case UNIAUTH_PROTO_FIELD_KEY:
            nbytes = read_string(client,iter+1,&client->stor.key,
                &client->stor.keySz);
            break;
        case UNIAUTH_PROTO_FIELD_ID:

            break;
        case UNIAUTH_PROTO_FIELD_USER:
            nbytes = read_string(client,iter+1,&client->stor.username,
                &client->stor.usernameSz);
            break;
        case UNIAUTH_PROTO_FIELD_DISPLAY:
            nbytes = read_string(client,iter+1,&client->stor.displayName,
                &client->stor.displayNameSz);
            break;
        case UNIAUTH_PROTO_FIELD_EXPIRE:

            break;
        case UNIAUTH_PROTO_FIELD_REDIRECT:
            nbytes = read_string(client,iter+1,&client->stor.redirect,
                &client->stor.redirectSz);
            break;
        default:
            client->status = error;
            return 1;
        }

        /* If field was incomplete we need to stop. */
        if (nbytes == 0) {
            break;
        }

        /* Advance iter past field code and field data. */
        iter += 1 + nbytes;
    }

    /* Update save iterator for another call. This should point to the beginning
     * of any incomplete field or to the next available position in the buffer.
     */
    client->bufit = iter;
    return 0;
}

static int flush_buffer(struct clientbuf* client)
{
    char* buf = client->buf + client->bufit;
    size_t sz = client->bufsz;
    size_t t = 0;

    /* Try to write as many bytes as possible to the buffer. */
    while (sz > 0) {
        ssize_t r = write(client->sock,buf + t,sz);

        if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            client->status = error;
            return 1;
        }

        t += r;
        sz -= r;
    }

    /* Transfer any remaining bytes to the front of the buffer to maximize
     * space.
     */
    memmove(client->buf,buf + t,sz);
    client->bufit = 0;
    client->bufsz = sz;
    if (sz == 0) {
        client->status = complete;
    }

    return 0;
}

int clientbuf_operation(struct clientbuf* client)
{
    /* This function should be called when I/O notification is received for this
     * client's file descriptor.
     */

    size_t initial = client->bufsz;

    if (client->eof) {
        return 1;
    }

    if (!client->iomode) {
        /* Input is edge-triggered, so read as many times as possible. */
        while (true) {
            ssize_t r;
            char* buf = client->buf + client->bufsz;
            size_t len = UNIAUTH_MAX_MESSAGE - client->bufsz;

            r = read(client->sock,buf,len);

            if (r == 0) {
                client->eof = true;
                if (initial == client->bufsz) {
                    /* We are done if no new bytes were read. */
                    return 1;
                }
                break;
            }
            if (r == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                client->status = error;
                return 1;
            }

            client->bufsz += r;
        }

        return parse_buffer(client);
    }

    return flush_buffer(client);
}

void clientbuf_input_mode(struct clientbuf* client)
{
    /* Go into input mode. */

    client->iomode = 0;
    client->bufsz = 0;
    client->bufit = 0;
    client->status = incomplete;
}

void clientbuf_output_mode(struct clientbuf* client)
{
    /* Go into output mode. */

    client->iomode = 1;
    client->bufsz = 0;
    client->bufit = 0;
    client->status = incomplete;
}

static char* get_output_buffer(struct clientbuf* client,size_t* outremain)
{
    /* Force I/O mode. This automatically disables further reads on the
     * object.
     */
    if (!client->iomode) {
        clientbuf_output_mode(client);
    }

    /* Get pointer to writable position and return number of bytes available. */
    if (!client->eof) {
        size_t remain = UNIAUTH_MAX_MESSAGE - client->bufsz;

        if (remain > 0) {
            *outremain = remain;
            client->status = incomplete;
            return client->buf + client->bufsz;
        }
    }

    *outremain = 0;
    return NULL;
}

static size_t transfer_string(char* buf,size_t remain,const char* src)
{
    size_t n = strlen(src) + 1;

    if (remain < n) {
        n = remain;
    }

    memcpy(buf,src,n);
    return n;
}

static size_t transfer_integer(char* buf,size_t remain,int value)
{


    return 4;
}

int clientbuf_send_error(struct clientbuf* client,const char* text)
{
    char* buf;
    size_t remain;

    if ((buf = get_output_buffer(client,&remain)) != NULL) {
        size_t n = 1;

        buf[0] = UNIAUTH_PROTO_RESPONSE_ERROR;
        n += transfer_string(buf+n,remain-n,text);
        client->bufsz += n;

        flush_buffer(client);
        return 0;
    }

    return 1;
}

int clientbuf_send_message(struct clientbuf* client,const char* text)
{
    char* buf;
    size_t remain;

    if ((buf = get_output_buffer(client,&remain)) != NULL) {
        size_t n = 1;

        buf[0] = UNIAUTH_PROTO_RESPONSE_MESSAGE;
        n += transfer_string(buf+n,remain-n,text);
        client->bufsz += n;

        flush_buffer(client);
        return 0;
    }

    return 1;
}

int clientbuf_send_record(struct clientbuf* client,struct uniauth_storage* stor)
{
    char* buf;
    size_t remain;

    if ((buf = get_output_buffer(client,&remain)) != NULL) {
        size_t n = 1;

        /* Write fields into the buffer. We expect there to be enough space. */
        buf[0] = UNIAUTH_PROTO_RESPONSE_RECORD;
        if (stor->key != NULL && remain-n > 0) {
            buf[n++] = UNIAUTH_PROTO_FIELD_KEY;
            n += transfer_string(buf+n,remain-n,stor->key);
        }
        if (stor->id > 0 && remain-n > 0) {
            buf[n++] = UNIAUTH_PROTO_FIELD_ID;
            n += transfer_integer(buf+n,remain-n,stor->id);
        }
        if (stor->username != NULL && remain-n > 0) {
            buf[n++] = UNIAUTH_PROTO_FIELD_USER;
            n += transfer_string(buf+n,remain-n,stor->username);
        }
        if (stor->displayName != NULL && remain-n > 0) {
            buf[n++] = UNIAUTH_PROTO_FIELD_DISPLAY;
            n += transfer_string(buf+n,remain-n,stor->displayName);
        }
        if (remain-n > 0) {
            buf[n++] = UNIAUTH_PROTO_FIELD_EXPIRE;
            n += transfer_integer(buf+n,remain-n,stor->expire);
        }
        if (stor->redirect != NULL && remain-n > 0) {
            buf[n++] = UNIAUTH_PROTO_FIELD_REDIRECT;
            n += transfer_string(buf+n,remain-n,stor->redirect);
        }

        flush_buffer(client);
        return 0;
    }

    return 1;
}
