/*
 * defs.h
 */

#ifndef UNIAUTH_DEFS_H
#define UNIAUTH_DEFS_H
#include <time.h>

/* The auth record stored for each session */

struct uniauth_storage
{
    /* Key: needs to be first element for casting */

    char* key;            /* unique string key for uniauth record */
    size_t keySz;         /* cache length of key string */

    /* User information: this is provided by the registrar and is opaque to the
     * uniauth server and PHP extension.
     */

    long id;              /* the user ID */
    char* username;       /* the user name */
    size_t usernameSz;    /* cache length of user name string */
    char* displayName;    /* the user display name */
    size_t displayNameSz; /* cache length of user display name string */

    /* UNIX time when this record should be forgotten. */

    time_t expire;

    /* Redirect URI as provided by applicant. */

    char* redirect;    /* the URI string */
    size_t redirectSz; /* cache length of URI string */
};

/* Protocol constants */
#define UNIAUTH_PROTO_LOOKUP 0x00
#define UNIAUTH_PROTO_COMMIT 0x01
#define UNIAUTH_PROTO_CREATE 0x02

#endif
