/*
 * uniauth.h
 *
 * This file is a part of php-uniauth.
 *
 * Copyright (C) Roger P. Gee
 */

#ifndef UNIAUTH_H
#define UNIAUTH_H

/* Includes */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <php.h>
#include <ext/standard/info.h>
#include <ext/standard/head.h>
#include <ext/standard/html.h>
#include <ext/standard/url.h>
#include <ext/standard/base64.h>
#include <ext/standard/php_rand.h>
#include <ext/session/php_session.h>
#include <Zend/zend_exceptions.h>
#include <SAPI.h>
#ifdef ZTS
#include <TSRM.h>
#endif

/* Definitions */

#define PHP_UNIAUTH_EXTNAME "uniauth"
#define PHP_UNIAUTH_EXTVER  "1.2.0-dev"

#define LOCATION_HEADER "Location: "
#define UNIAUTH_QSTRING "?uniauth="

#define UNIAUTH_COOKIE_IDLEN 64

#define UNIAUTH_SOCKET_PATH_INI  "uniauth.socket_path"
#define UNIAUTH_SOCKET_HOST_INI  "uniauth.socket_host"
#define UNIAUTH_SOCKET_PORT_INI  "uniauth.socket_port"
#define UNIAUTH_LIFETIME_INI     "uniauth.lifetime"

/* Define type for storing socket connection information. */

struct uniauth_socket_info
{
    const char* path;
    const char* host;
    const char* port;
};

/* Uniauth module globals */

ZEND_BEGIN_MODULE_GLOBALS(uniauth)
  int conn;
  unsigned long use_cookie;
  struct uniauth_socket_info socket_info;
ZEND_END_MODULE_GLOBALS(uniauth)

extern ZEND_DECLARE_MODULE_GLOBALS(uniauth);

#ifdef ZTS
#include "TSRM.h"
#define UNIAUTH_G(v)                                    \
    TSRMG(uniauth_globals_id,zend_uniauth_globals*,v)
#else
#define UNIAUTH_G(v)                            \
    (uniauth_globals.v)
#endif

/* Routines for initializing global data. */

void uniauth_globals_init();
void uniauth_globals_request_init();
void uniauth_globals_shutdown();

#endif
