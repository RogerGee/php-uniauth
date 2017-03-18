/*
 * connect.h
 *
 * This file is a part of php-uniauth.
 *
 * The functionality provided by this module includes the connection API used by
 * the PHP extension to fetch/commit uniauth records. Since these functions are
 * designed to be called within a request context, they use the PHP per-request
 * memory management functions (i.e. emalloc() and friends).
 */

#ifndef UNIAUTH_CONNECT_H
#define UNIAUTH_CONNECT_H
#include "daemon/defs.h"

/* Functions to manipulate a uniauth record in the PHP extension */
void uniauth_storage_delete(struct uniauth_storage* stor);

/* Routines for initializing global data. These are handled by the connect
 * module since we have a global socket connection that needs to be shutdown.
 */
void uniauth_globals_init();
void uniauth_globals_shutdown();

/* Connect commands; these wrap a protocol operation */
struct uniauth_storage* uniauth_connect_lookup(const char* key,size_t keylen,
    struct uniauth_storage* backing);
int uniauth_connect_commit(struct uniauth_storage* stor);
int uniauth_connect_create(struct uniauth_storage* stor);
int uniauth_connect_transfer(const char* src,const char* dst);

#endif
