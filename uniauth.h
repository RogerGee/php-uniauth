/*
 * uniauth.h
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
#define PHP_UNIAUTH_EXTVER  "1.0.1"

#define LOCATION_HEADER "Location: "
#define UNIAUTH_QSTRING "?uniauth="

#define UNIAUTH_COOKIE_IDLEN 64

/* Uniauth module globals */

ZEND_BEGIN_MODULE_GLOBALS(uniauth)
  int conn;
  unsigned long useCookie;
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

#endif
