/*
 * defs.h
 */

#ifndef UNIAUTH_DEFS_H
#define UNIAUTH_DEFS_H
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Represents the auth record stored for each session. All strings are
 * null-terminated and have their lengths cached.
 */

struct uniauth_storage
{
    /* Key: needs to be first element for casting */

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

    /* UNIX time when this record should be forgotten. */

    int64_t expire;

    /* Redirect URI as provided by applicant. */

    char* redirect;       /* the URI string */
    size_t redirectSz;    /* cache length of URI string */
};

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
#define UNIAUTH_PROTO_FIELD_END      0xff

#define UNIAUTH_INT_SZ  4
#define UNIAUTH_TIME_SZ 8

#define UNIAUTH_MAX_MESSAGE 4096

#endif
