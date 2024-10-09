/*
 * connect.c
 *
 * This file is a part of php-uniauth.
 *
 * Copyright (C) Roger P. Gee
 */

#include "connect.h"
#include "uniauth.h"
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>

/* NOTE: the following functions implement the uniauth connect api used by this
 * module's PHP functions. If an error occurs, we use php_error() to raise the
 * error, which bails out of the current script.
 */

/* Helper functions */

static int uniauth_connect()
{
    int sock;
    struct sockaddr* addr;
    struct sockaddr_un addr_un;
    struct sockaddr_in addr_in;
    socklen_t addr_len;
    int is_inet_socket;
    int* psock = &UNIAUTH_G(conn);
    struct pollfd pollInfo;
    const struct uniauth_socket_info* socket_info = &UNIAUTH_G(socket_info);

    /* See if we already have a connection. */
    sock = *psock;
    if (sock != -1) {
        /* Make sure the socket is still alive. If an event happens on the
         * socket then either the descriptor is invalid, an error occurred or a
         * hang up occurred on the connection.
         */
        pollInfo.fd = sock;
        pollInfo.events = POLLHUP | POLLERR | POLLNVAL;
        pollInfo.revents = 0;
        if (poll(&pollInfo,1,0) > 0) {
            php_error(E_WARNING,"[uniauth] Connection to uniauth daemon lost: attempting reconnect");
            close(sock);
        }
        else {
            return sock;
        }
    }

    /* Since we do not have a connection, attempt a connect to the uniauth
     * daemon based on the "socket_path" configuration from INI.
     */

    is_inet_socket = (strlen(socket_info->host) > 0);

    if (is_inet_socket) {
        sock = socket(AF_INET,SOCK_STREAM,0);
    }
    else {
        sock = socket(AF_UNIX,SOCK_STREAM,0);
    }

    if (sock == -1) {
        php_error(E_ERROR,"[uniauth] Fail socket(): %s",strerror(errno));
        return -1;
    }

    /* Do connect. */

    if (is_inet_socket) {
        int error;
        struct addrinfo* result;
        struct addrinfo hints;
        memset(&hints,0,sizeof(struct addrinfo));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;

        /* Look up address information for configured host/port. */
        error = getaddrinfo(socket_info->host,socket_info->port,&hints,&result);
        if (error != 0) {
            php_error(E_ERROR,"[uniauth] Cannot lookup server host: %s",gai_strerror(error));
            return -1;
        }

        addr = result->ai_addr;
        addr_len = result->ai_addrlen;
    }
    else {
        size_t socket_path_len;
        const char* socket_path;
        socket_path = (strlen(socket_info->path) > 0) ? socket_info->path : SOCKET_PATH_DEFAULT;
        socket_path_len = strlen(socket_path);

        addr = (struct sockaddr*)&addr_un;
        memset(&addr_un,0,sizeof(struct sockaddr_un));
        addr_un.sun_family = AF_UNIX;
        strncpy(addr_un.sun_path,socket_path,socket_path_len);

        /* Support the abstract socket path namespace on Linux. */
        if (addr_un.sun_path[0] == '@') {
            addr_un.sun_path[0] = 0;
            addr_len = offsetof(struct sockaddr_un,sun_path) + socket_path_len;
        }
        else {
            addr_len = sizeof(struct sockaddr_un);
        }
    }

    if (connect(sock,addr,addr_len) == -1) {
        php_error(E_ERROR,"[uniauth] Could not connect to uniauth daemon: %s",strerror(errno));
        return -1;
    }

    /* Assign socket to globals so we can look it back up later. */
    *psock = sock;
    return sock;
}

static int uniauth_connect_recv(int sock,char* buffer,size_t maxsz,size_t* iter)
{
    /* This function does a blocking read on the connect socket. When it gets
     * data back, it determines the state of the input buffer:
     *  0=complete
     *  1=incomplete
     *  2=error
     */

    size_t i = 0;
    size_t it = *iter;
    ssize_t r = read(sock,buffer+it,maxsz-it);

    if (r == -1) {
        php_error(E_ERROR,"[uniauth] Could not read from uniauth daemon: %s",strerror(errno));
        return 2; /* control would have jumped out of here */
    }
    it += r;
    *iter += r;

    /* Walk through the input buffer to determine if it is complete. We do some
     * quick checks to make sure the data is formatted correctly.
     */

    if (buffer[i] == UNIAUTH_PROTO_RESPONSE_MESSAGE
        || buffer[i] == UNIAUTH_PROTO_RESPONSE_ERROR)
    {
        /* Seek past null-terminated string. */

        i += 1;
        while (i < it) {
           if (buffer[i] == 0) {
               break;
           }
           i += 1;
        }

        return (i >= it);
    }

    if (buffer[i] == UNIAUTH_PROTO_RESPONSE_RECORD) {
        i += 1;
        while (i < it) {
            /* We have a complete message if we find the end field. */
            if (buffer[i] == UNIAUTH_PROTO_FIELD_END) {
                return 0;
            }

            /* Scan through the field. */
            switch (buffer[i++]) {
            case UNIAUTH_PROTO_FIELD_KEY:
            case UNIAUTH_PROTO_FIELD_USER:
            case UNIAUTH_PROTO_FIELD_DISPLAY:
            case UNIAUTH_PROTO_FIELD_REDIRECT:
            case UNIAUTH_PROTO_FIELD_TAG:
                /* Seek past null-terminated string. */
                while (true) {
                    if (i >= it) {
                        return 1;
                    }
                    if (buffer[i] == 0) {
                        break;
                    }
                    i += 1;
                }

                /* Seek past null terminator byte. */
                i += 1;
                break;
            case UNIAUTH_PROTO_FIELD_ID:
            case UNIAUTH_PROTO_FIELD_LIFETIME:
                i += 4;
                break;
            case UNIAUTH_PROTO_FIELD_EXPIRE:
                i += 8;
                break;
            default:
                return 2;
            }
        }

        return 1;
    }

    return 2;
}

static bool buffer_field_string(char* buffer,size_t maxsz,size_t* iter,
    int fieldType,const char* field,size_t fieldsz)
{
    size_t it = *iter;
    if (it + fieldsz + 2 <= maxsz) {
        buffer[it++] = fieldType;
        strncpy(buffer+it,field,fieldsz);
        it += fieldsz;
        buffer[it++] = 0;
        *iter = it;
        return true;
    }
    return false;
}

static bool buffer_field_integer(char* buffer,size_t maxsz,size_t* iter,
    int fieldType,int32_t value)
{
    int i;
    size_t it = *iter;
    if (it + 6 <= maxsz) {
        buffer[it++] = fieldType;

        /* Write the value using little endian. */
        for (i = 0;i < UNIAUTH_INT_SZ;++i) {
            buffer[it++] = (value >> (i*8)) & 0xff;
        }
        *iter = it;
        return true;
    }
    return false;
}

static bool buffer_field_time(char* buffer,size_t maxsz,size_t* iter,
    int fieldType,int64_t value)
{
    int i;
    size_t it = *iter;
    if (it + 10 <= maxsz) {
        buffer[it++] = fieldType;

        /* Write the value using little endian. */
        for (i = 0;i < UNIAUTH_TIME_SZ;++i) {
            buffer[it++] = (value >> (i*8)) & 0xff;
        }
        *iter = it;
        return true;
    }
    return false;
}

static inline bool buffer_field_end(char* buffer,size_t maxsz,size_t* iter)
{
    size_t i = *iter;
    if (i < maxsz) {
        buffer[i] = UNIAUTH_PROTO_FIELD_END;
        *iter = i + 1;
        return true;
    }
    return false;
}

static bool buffer_storage_record(char* buffer,size_t maxsz,size_t* iter,
    const struct uniauth_storage* stor)
{
    /* Write the uniauth structure fields into the buffer. All fields are
        * optional (except maybe key).
        */

    return ! ((stor->key != NULL && !buffer_field_string(buffer,maxsz,iter,
                UNIAUTH_PROTO_FIELD_KEY,stor->key,stor->keySz))
        || (stor->id != 0 && !buffer_field_integer(buffer,maxsz,iter,
                UNIAUTH_PROTO_FIELD_ID,stor->id))
        || (stor->username != NULL && !buffer_field_string(buffer,maxsz,iter,
                UNIAUTH_PROTO_FIELD_USER,stor->username,stor->usernameSz))
        || (stor->displayName != NULL && !buffer_field_string(buffer,maxsz,iter,
                UNIAUTH_PROTO_FIELD_DISPLAY,stor->displayName,stor->displayNameSz))
        || (stor->expire != 0 && !buffer_field_time(buffer,maxsz,iter,
                UNIAUTH_PROTO_FIELD_EXPIRE,stor->expire))
        || (stor->redirect != NULL && !buffer_field_string(buffer,maxsz,iter,
                UNIAUTH_PROTO_FIELD_REDIRECT,stor->redirect,stor->redirectSz))
        || (stor->tag != NULL && !buffer_field_string(buffer,maxsz,iter,
                UNIAUTH_PROTO_FIELD_TAG,stor->tag,stor->tagSz))
        || (stor->lifetime != 0 && !buffer_field_integer(buffer,maxsz,iter,
                UNIAUTH_PROTO_FIELD_LIFETIME,stor->lifetime))
        || !buffer_field_end(buffer,maxsz,iter));
}

static size_t read_field_string(char* buffer,size_t sz,char** dst,size_t* dstsz)
{
    size_t n = 0;
    char* result;

    while (n < sz && buffer[n] != 0) {
        n += 1;
    }

    if (n >= sz) {
        return 0;
    }

    result = emalloc(n+1);
    memcpy(result,buffer,n);
    result[n] = 0;

    *dst = result;
    *dstsz = n;
    return n+1;
}

static size_t read_field_integer(unsigned char* buffer,size_t sz,int32_t* dst)
{
    int i;
    uint32_t value = 0;

    if (sz < UNIAUTH_INT_SZ) {
        return 0;
    }

    for (i = 0;i < UNIAUTH_INT_SZ;++i) {
        value |= ((uint32_t)buffer[i] << (i*8));
    }

    *dst = value;
    return UNIAUTH_INT_SZ;
}

static size_t read_field_time(unsigned char* buffer,size_t sz,int64_t* dst)
{
    int i;
    uint64_t value = 0;

    if (sz < UNIAUTH_TIME_SZ) {
        return 0;
    }

    for (i = 0;i < UNIAUTH_TIME_SZ;++i) {
        value |= ((uint64_t)buffer[i] << (i*8));
    }

    *dst = value;
    return UNIAUTH_TIME_SZ;
}

static void read_storage_record(char* buffer,size_t sz,struct uniauth_storage* stor)
{
    /* Assume the message is a RESPONSE_RECORD and begin reading its fields
    * (which start at offset=1).
    */

    size_t iter = 1;

    while (iter < sz) {
        size_t n = 0;
        char* p;
        size_t z;

        if (buffer[iter] == UNIAUTH_PROTO_FIELD_END) {
            break;
        }

        /* Calculate address and length of next field in buffer. */
        p = buffer + iter + 1;
        z = sz - iter - 1;

        /* Read field. */
        switch (buffer[iter++]) {
        case UNIAUTH_PROTO_FIELD_KEY:
            n = read_field_string(p,z,&stor->key,&stor->keySz);
            break;
        case UNIAUTH_PROTO_FIELD_ID:
            n = read_field_integer((unsigned char*)p,z,&stor->id);
            break;
        case UNIAUTH_PROTO_FIELD_USER:
            n = read_field_string(p,z,&stor->username,&stor->usernameSz);
            break;
        case UNIAUTH_PROTO_FIELD_DISPLAY:
            n = read_field_string(p,z,&stor->displayName,&stor->displayNameSz);
            break;
        case UNIAUTH_PROTO_FIELD_EXPIRE:
            n = read_field_time((unsigned char*)p,z,&stor->expire);
            break;
        case UNIAUTH_PROTO_FIELD_REDIRECT:
            n = read_field_string(p,z,&stor->redirect,&stor->redirectSz);
            break;
        case UNIAUTH_PROTO_FIELD_TAG:
            n = read_field_string(p,z,&stor->tag,&stor->tagSz);
            break;
        case UNIAUTH_PROTO_FIELD_LIFETIME:
            n = read_field_integer((unsigned char*)p,z,&stor->lifetime);
            break;
        }

        /* Handle protocol errors. */
        if (n == 0) {
            php_error(E_ERROR,
            "[uniauth] read_storage_record(): communication error: server"
            " did not respond properly");
            break;
        }

        iter += n;
    }
}

/* Uniauth record functions */

void uniauth_storage_delete(struct uniauth_storage* stor)
{
    /* Free the members. Some members may not be allocated. The structure itself
     * is not free'd here (since it may be allocated on the stack).
     */

    efree(stor->key);
    efree(stor->username);
    efree(stor->displayName);
    efree(stor->redirect);
    efree(stor->tag);
}

 /* Connect API implementations */

struct uniauth_storage* uniauth_connect_lookup(
    const char* key,
    size_t keylen,
    struct uniauth_storage* backing)
{
    int sock;
    int status;
    char buffer[UNIAUTH_MAX_MESSAGE];
    size_t iter = 1;
    size_t sz = 0;

    /* Perform a lookup on the remote uniauth daemon. */
    buffer[0] = UNIAUTH_PROTO_LOOKUP;
    if (!buffer_field_string(buffer,sizeof(buffer),&iter,
            UNIAUTH_PROTO_FIELD_KEY,key,keylen)
        || !buffer_field_end(buffer,sizeof(buffer),&iter))
    {
        php_error(E_ERROR,"[uniauth] Protocol message is too large");
        return NULL;
    }
    sock = uniauth_connect();
    if (write(sock,buffer,iter) == -1) {
        php_error(E_ERROR,"[uniauth] Fail write(): %s",strerror(errno));
        return NULL;
    }

    /* Wait for and read the response. Hopefully this loop should never
    * reiterate.
    */
    do {
        status = uniauth_connect_recv(sock,buffer,sizeof(buffer),&sz);

        if (status == 2) {
            php_error(E_ERROR,"[uniauth] Protocol error: server message incorrectly formatted");
            return NULL;
        }
    } while (status != 0);

    /* An error response always means the record was not found. */
    if (buffer[0] == UNIAUTH_PROTO_RESPONSE_MESSAGE
        || buffer[0] == UNIAUTH_PROTO_RESPONSE_ERROR)
    {
        return NULL;
    }

    /* If we get here then response kind must be RESPONSE_RECORD. We'll now copy
    * the available fields into the uniauth_storage buffer provided and return
    * a pointer to it that indicates success.
    */
    memset(backing,0,sizeof(struct uniauth_storage));
    read_storage_record(buffer,sz,backing);
    return backing;
}

int uniauth_connect_commit(struct uniauth_storage* stor)
{
    int sock;
    int status;
    char buffer[UNIAUTH_MAX_MESSAGE];
    size_t iter = 1;
    size_t sz = 0;

    /* Prepare the commit message buffer to send to the uniauth daemon. */
    buffer[0] = UNIAUTH_PROTO_COMMIT;
    if (!buffer_storage_record(buffer,sizeof(buffer),&iter,stor)) {
        php_error(E_ERROR,"[uniauth] Protocol message is too large");
        return -1;
    }

    /* Send the request message to the uniauth daemon. */
    sock = uniauth_connect();
    if (write(sock,buffer,iter) == -1) {
        php_error(E_ERROR,"[uniauth] Fail write(): %s",strerror(errno));
    }

    /* Wait for and read the response. Hopefully this loop should never
     * reiterate.
     */
    do {
        status = uniauth_connect_recv(sock,buffer,sizeof(buffer),&sz);

        if (status == 2) {
            php_error(E_ERROR,"[uniauth] Protocol error: server message incorrectly formatted");
            return -1;
        }
    } while (status != 0);

    /* We should get pack RESPONSE_MESSAGE upon success. */
    if (buffer[0] == UNIAUTH_PROTO_RESPONSE_MESSAGE) {
        return 0;
    }

    /* Anything else is an error. */
    return -1;
}

int uniauth_connect_create(struct uniauth_storage* stor)
{
    int sock;
    int status;
    char buffer[UNIAUTH_MAX_MESSAGE];
    size_t iter = 1;
    size_t sz = 0;

    /* Prepare the create message buffer to send to the uniauth daemon. */
    buffer[0] = UNIAUTH_PROTO_CREATE;
    if (!buffer_storage_record(buffer,sizeof(buffer),&iter,stor)) {
        php_error(E_ERROR,"[uniauth] Protocol message is too large");
        return -1;
    }

    /* Send the request message to the uniauth daemon. */
    sock = uniauth_connect();
    if (write(sock,buffer,iter) == -1) {
        php_error(E_ERROR,"[uniauth] Fail write(): %s",strerror(errno));
    }

    /* Wait for and read the response. Hopefully this loop should never
     * reiterate.
     */
    do {
        status = uniauth_connect_recv(sock,buffer,sizeof(buffer),&sz);

        if (status == 2) {
            php_error(E_ERROR,"[uniauth] Protocol error: server message incorrectly formatted");
            return -1;
        }
    } while (status != 0);

    /* We should get pack RESPONSE_MESSAGE upon success. */
    if (buffer[0] == UNIAUTH_PROTO_RESPONSE_MESSAGE) {
        return 0;
    }

    /* Anything else is an error. */
    return -1;
}

int uniauth_connect_transfer(const char* src,const char* dst)
{
    int sock;
    int status;
    char buffer[UNIAUTH_MAX_MESSAGE];
    size_t iter = 1;
    size_t sz = 0;

    /* Prepare the transfer message buffer to send to the uniauth daemon. */
    buffer[0] = UNIAUTH_PROTO_TRANSF;
    if (!buffer_field_string(buffer,sizeof(buffer),&iter,
            UNIAUTH_PROTO_FIELD_TRANSSRC,src,strlen(src))
        || !buffer_field_string(buffer,sizeof(buffer),&iter,
            UNIAUTH_PROTO_FIELD_TRANSDST,dst,strlen(dst))
        || !buffer_field_end(buffer,sizeof(buffer),&iter))
    {
        php_error(E_ERROR,"[uniauth] Protocol message is too large");
        return -1;
    }

    /* Send the request message to the uniauth daemon. */
    sock = uniauth_connect();
    if (write(sock,buffer,iter) == -1) {
        php_error(E_ERROR,"[uniauth] Fail write(): %s",strerror(errno));
    }

    /* Wait for and read the response. Hopefully this loop should never
     * reiterate.
     */
    do {
        status = uniauth_connect_recv(sock,buffer,sizeof(buffer),&sz);

        if (status == 2) {
            php_error(E_ERROR,"[uniauth] Protocol error: server message incorrectly formatted");
            return -1;
        }
    } while (status != 0);

    /* We should get pack RESPONSE_MESSAGE upon success. */
    if (buffer[0] == UNIAUTH_PROTO_RESPONSE_MESSAGE) {
        return 0;
    }

    /* Anything else is an error. */
    return -1;
}
