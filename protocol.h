/*
 * protocol.h
 *
 * Copyright (C) Roger P. Gee
 */

#ifndef UNIAUTH_PROTOCOL_H
#define UNIAUTH_PROTOCOL_H
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Represents the auth record stored for each session. All strings are
 * null-terminated and have their lengths cached.
 */

struct uniauth_storage
{
    /* Key: the uniauth daemon reference counts storage records (i.e. so
     * multiple sessions can reference the same entry) and as such does not
     * store keys here.
     */

    char* key;            /* unique string key for uniauth record */
    size_t keySz;         /* cache length of key string */
    int ref;              /* reference counter */

    /* User information: this is provided by the registrar and is opaque to the
     * uniauth server and PHP extension.
     */

    int32_t id;           /* the user ID */
    char* username;       /* the user name */
    size_t usernameSz;    /* cache length of user name string */
    char* displayName;    /* the user display name */
    size_t displayNameSz; /* cache length of user display name string */

    /* Storage record lifetime information. */

    int64_t expire;       /* UNIX timestamp when the session is set to expire */
    int32_t lifetime;     /* number of seconds storage record is allowed to live */

    /* Redirect URI as provided by applicant. */

    char* redirect;       /* the URI string */
    size_t redirectSz;    /* cache length of URI string */

    /* Tag for application defined data. */

    char* tag;
    size_t tagSz;
};

/* Connection constants */

#define SOCKET_PATH     "@uniauth"

/* Protocol constants */

#define UNIAUTH_PROTO_LOOKUP 0x00
#define UNIAUTH_PROTO_COMMIT 0x01
#define UNIAUTH_PROTO_CREATE 0x02
#define UNIAUTH_PROTO_TRANSF 0x03
#define UNIAUTH_OP_TOP       0x04

#define UNIAUTH_PROTO_RESPONSE_MESSAGE 0x00
#define UNIAUTH_PROTO_RESPONSE_ERROR   0x01
#define UNIAUTH_PROTO_RESPONSE_RECORD  0x02

#define UNIAUTH_PROTO_FIELD_KEY      0x00
#define UNIAUTH_PROTO_FIELD_ID       0x01
#define UNIAUTH_PROTO_FIELD_USER     0x02
#define UNIAUTH_PROTO_FIELD_DISPLAY  0x03
#define UNIAUTH_PROTO_FIELD_EXPIRE   0x04
#define UNIAUTH_PROTO_FIELD_REDIRECT 0x05
#define UNIAUTH_PROTO_FIELD_TRANSSRC 0x06
#define UNIAUTH_PROTO_FIELD_TRANSDST 0x07
#define UNIAUTH_PROTO_FIELD_TAG      0x08
#define UNIAUTH_PROTO_FIELD_LIFETIME 0x09
#define UNIAUTH_PROTO_FIELD_END      (char)0xff

#define UNIAUTH_INT_SZ  4
#define UNIAUTH_TIME_SZ 8

#define UNIAUTH_MAX_MESSAGE 4096

/* Other macros */

/* In uniauth, an id is valid if it is a positive integer. */
#define IS_VALID_USER_ID(id) (id > 0)

#endif
