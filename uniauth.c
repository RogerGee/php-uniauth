/*
 * uniauth.c
 *
 * This file is a part of php-uniauth.
 *
 * Copyright (C) Roger P. Gee
 */

#include "uniauth.h"
#include "connect.h"
#include "uniauth_arginfo.h"

/* Lifetime: a session has indefinate lifetime if its value is less-than or
 * equal to zero. An indefinate session gets a lifetime of the
 * uniauth.lifetime value defined by the extension's initialization settings.
 */
#define LIFETIME(lifetime) (lifetime <= 0 ? INI_INT(UNIAUTH_LIFETIME_INI) : lifetime)

/* Module/request functions */
static PHP_MINIT_FUNCTION(uniauth);
static PHP_MINFO_FUNCTION(uniauth);
static PHP_MSHUTDOWN_FUNCTION(uniauth);
static PHP_RINIT_FUNCTION(uniauth);
static PHP_RSHUTDOWN_FUNCTION(uniauth);

/* PHP userspace functions */
static PHP_FUNCTION(uniauth);
static PHP_FUNCTION(uniauth_register);
static PHP_FUNCTION(uniauth_transfer);
static PHP_FUNCTION(uniauth_check);
static PHP_FUNCTION(uniauth_apply);
static PHP_FUNCTION(uniauth_purge);
static PHP_FUNCTION(uniauth_cookie);

/* Function entries */
static zend_function_entry php_uniauth_functions[] = {
    PHP_FE(uniauth,arginfo_uniauth)
    PHP_FE(uniauth_register,arginfo_uniauth_register)
    PHP_FE(uniauth_transfer,arginfo_uniauth_transfer)
    PHP_FE(uniauth_check,arginfo_uniauth_check)
    PHP_FE(uniauth_apply,arginfo_uniauth_apply)
    PHP_FE(uniauth_purge,arginfo_uniauth_purge)
    PHP_FE(uniauth_cookie,arginfo_uniauth_cookie)

    {NULL, NULL, NULL}
};

/* Class entry for exception type */
zend_class_entry* exception_ce = NULL;

/* Module entries */
zend_module_entry uniauth_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_UNIAUTH_EXTNAME,
    php_uniauth_functions,
    PHP_MINIT(uniauth),
    PHP_MSHUTDOWN(uniauth),
    PHP_RINIT(uniauth),
    PHP_RSHUTDOWN(uniauth),
    PHP_MINFO(uniauth),
    PHP_UNIAUTH_EXTVER,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_UNIAUTH
ZEND_GET_MODULE(uniauth)
#endif

/* Uniauth INI settings */

PHP_INI_BEGIN()
/* NOTE: Since the socket is cached, all socket INIs are system-level only. */
PHP_INI_ENTRY(UNIAUTH_SOCKET_PATH_INI, "", PHP_INI_SYSTEM, NULL)
PHP_INI_ENTRY(UNIAUTH_SOCKET_HOST_INI, "", PHP_INI_SYSTEM, NULL)
PHP_INI_ENTRY(UNIAUTH_SOCKET_PORT_INI, "7033", PHP_INI_SYSTEM, NULL)
PHP_INI_ENTRY(UNIAUTH_LIFETIME_INI, "86400", PHP_INI_ALL, NULL)
PHP_INI_END()

/* Implementation of module/request functions */

PHP_MINIT_FUNCTION(uniauth)
{
    zend_class_entry ce;

    REGISTER_INI_ENTRIES();
    uniauth_globals_init();

    /* Register constants */
    REGISTER_LONG_CONSTANT(
        "UNIAUTH_ERROR_INVALID_SERVERVARS",
        UNIAUTH_ERROR_INVALID_SERVERVARS,
        CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT(
        "UNIAUTH_ERROR_NO_SESSION",
        UNIAUTH_ERROR_NO_SESSION,
        CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT(
        "UNIAUTH_ERROR_SOURCE_NOT_EXIST",
        UNIAUTH_ERROR_SOURCE_NOT_EXIST,
        CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT(
        "UNIAUTH_ERROR_SOURCE_NOT_APPLY",
        UNIAUTH_ERROR_SOURCE_NOT_APPLY,
        CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT(
        "UNIAUTH_ERROR_DEST_NOT_EXIST",
        UNIAUTH_ERROR_DEST_NOT_EXIST,
        CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT(
        "UNIAUTH_ERROR_TRANSFER_FAILED",
        UNIAUTH_ERROR_TRANSFER_FAILED,
        CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT(
        "UNIAUTH_ERROR_MISSING_REDIRECT",
        UNIAUTH_ERROR_MISSING_REDIRECT,
        CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT(
        "UNIAUTH_ERROR_MISSING_UNIAUTH_PARAM",
        UNIAUTH_ERROR_MISSING_UNIAUTH_PARAM,
        CONST_CS|CONST_PERSISTENT);

    /* Register exception type */
    INIT_NS_CLASS_ENTRY(ce,"Uniauth","Exception",NULL);
    exception_ce = zend_register_internal_class_ex(&ce,spl_ce_RuntimeException);
    exception_ce->ce_flags |= ZEND_ACC_FINAL;

    return SUCCESS;
}

PHP_MINFO_FUNCTION(uniauth)
{
    php_info_print_table_start();
    php_info_print_table_row(2,PHP_UNIAUTH_EXTNAME,"enabled");
    php_info_print_table_row(2,"extension version",PHP_UNIAUTH_EXTVER);
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}

PHP_MSHUTDOWN_FUNCTION(uniauth)
{
    uniauth_globals_shutdown();
    UNREGISTER_INI_ENTRIES();

    return SUCCESS;
}

PHP_RINIT_FUNCTION(uniauth)
{
    uniauth_globals_request_init();

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(uniauth)
{

    return SUCCESS;
}

/* Define some helper functions for accessing/modifying superglobal
 * variables.
 */

static zend_bool check_global(const char* gbl,int gbllen)
{
    zval* entry;

    /* Make sure superglobal is auto-loaded already. */
    if (!zend_hash_str_exists(&EG(symbol_table),gbl,gbllen)) {
        entry = zend_hash_str_find(CG(auto_globals),gbl,gbllen);

        if (entry == NULL) {
            return FAILURE;
        }

        zend_auto_global* ag = Z_PTR_P(entry);
        ag->armed = ag->auto_global_callback(ag->name);
    }

    return SUCCESS;
}

static zval* get_global(const char* gbl,int gbllen,const char* key,int keylen)
{
    zval* entry;
    HashTable* bucket;

    if (check_global(gbl,gbllen) != SUCCESS) {
        return NULL;
    }

    /* Lookup element and return as string. */
    entry = zend_hash_str_find(&EG(symbol_table),gbl,gbllen);
    if (entry == NULL) {
        return NULL;
    }
    bucket = Z_ARRVAL_P(entry);
    entry = zend_hash_str_find(bucket,key,keylen);

    return entry;
}

/* Arguments to this macro should be string literals. */
#define GET_GLOBAL(g,e)                         \
    get_global(g,sizeof(g)-1,e,sizeof(e)-1)

static int set_global(const char* gbl,int gbllen,const char* key,int keylen,zval* value)
{
    zval* entry;
    HashTable* bucket;

    if (check_global(gbl,gbllen) != SUCCESS) {
        return FAILURE;
    }

    /* Lookup bucket for superglobal. */
    entry = zend_hash_str_find(&EG(symbol_table),gbl,gbllen);
    if (entry == NULL) {
        return FAILURE;
    }
    bucket = Z_ARRVAL_P(entry);

    /* Update zval in hashtable. */
    if (zend_hash_str_update(bucket,key,keylen,value) == NULL) {
        return FAILURE;
    }

    return SUCCESS;
}

#define SET_GLOBAL(g,k,v)                       \
    set_global(g,sizeof(g)-1,k,sizeof(k)-1,v)

/* Define a helper function for compiling the redirect uri to the current
 * request.
 */

static int set_redirect_uri(struct uniauth_storage* stor)
{
    zval* entry;
    char buf[4096];
    HashTable* server;
    int https = 0;
    char* host;
    char* port = NULL;
    char* uri;
    size_t len;

    /* Make sure $_SERVER is auto loaded already. */
    if (check_global("_SERVER",sizeof("_SERVER")-1) != SUCCESS) {
        zend_throw_exception(NULL,"[uniauth] Failed to activate $_SERVER",0);
        return FAILURE;
    }

    /* Get information about the protocol, host and port number from the _SERVER
     * superglobal. We use HTTPS, HTTP_HOST and SERVER_PORT keys to resolve the
     * scheme, host and port. I know of no better way to do this unfortunately
     * with the PHP/ZEND API. The sapi globals just don't have what I need.
     */

    entry = zend_hash_str_find(&EG(symbol_table),"_SERVER",sizeof("_SERVER")-1);
    if (entry == NULL) {
        zend_throw_exception(NULL,"[uniauth] Failed to look up $_SERVER",0);
        return FAILURE;
    }
    server = Z_ARRVAL_P(entry);

    entry = zend_hash_str_find(server,"HTTPS",sizeof("HTTPS")-1);
    if (entry != NULL) {
        if (Z_TYPE_P(entry) != IS_STRING || strcmp(Z_STRVAL_P(entry),"off") != 0) {
            https = 1;
        }
    }

    entry = zend_hash_str_find(server,"HTTP_HOST",sizeof("HTTP_HOST")-1);
    if (entry != NULL && Z_TYPE_P(entry) == IS_STRING) {
        host = Z_STRVAL_P(entry);
    }
    else {
        zend_throw_exception(
            exception_ce,
            "$_SERVER does not contain required 'HTTP_HOST' variable",
            UNIAUTH_ERROR_INVALID_SERVERVARS);
        return FAILURE;
    }

    entry = zend_hash_str_find(server,"SERVER_PORT",sizeof("SERVER_PORT")-1);
    if (entry != NULL) {
        /* Only set port if it is not well-known. If the host name contains a
         * ':' then we assume the port was encoded in the Host header. User
         * agents should do this but we still need make sure we get the port
         * number if not.
         */
        int i = 0;

        while (host[i] != 0) {
            if (host[i] == ':') {
                break;
            }
            i += 1;
        }

        if (host[i] == 0) {
            zend_string* str = zval_get_string(entry);
            if ((!https && strcmp(str->val,"80") != 0) || (https && strcmp(str->val,"443") != 0)) {
                port = estrdup(str->val);
            }
            zend_string_release(str);
        }
    }
    else {
        zend_throw_exception(
            exception_ce,
            "$_SERVER does not contain required 'SERVER_PORT' variable",
            UNIAUTH_ERROR_INVALID_SERVERVARS);
        return FAILURE;
    }

    /* Lookup request URI. This actually can be found in the sapi globals. */
    entry = zend_hash_str_find(server,"REQUEST_URI",sizeof("REQUEST_URI")-1);
    if (entry != NULL && Z_TYPE_P(entry) == IS_STRING) {
        uri = Z_STRVAL_P(entry);
    }
    else {
        zend_throw_exception(
            exception_ce,
            "$_SERVER does not contain required 'SERVER_PORT' variable",
            UNIAUTH_ERROR_INVALID_SERVERVARS);
        return FAILURE;
    }

    /* Format the URI to a temporary buffer. */
    if (port == NULL) {
        snprintf(buf,sizeof(buf),"%s://%s%s",https?"https":"http",host,uri);
    }
    else {
        snprintf(buf,sizeof(buf),"%s://%s:%s%s",https?"https":"http",host,port,uri);
    }

    /* Copy buffer into record structure. */
    len = strlen(buf);
    stor->redirect = estrndup(buf,len);
    stor->redirectSz = len;
    efree(port);

    return SUCCESS;
}

/* Define a helper function for setting uniauth cookies. */

static void set_uniauth_cookie(char* id,int id_len,time_t expires)
{
    zend_string* name;
    zend_string* value;
    zend_string* path;
    sapi_header_line line = {0};

    /* Delete any existing Set-Cookie headers so the extension can overwrite any
     * existing uniauth cookies.
     */
    line.line = "Set-Cookie";
    line.line_len = sizeof("Set-Cookie") - 1;
    sapi_header_op(SAPI_HEADER_DELETE,&line);

    name = zend_string_init("uniauth",sizeof("uniauth")-1,0);
    value = zend_string_init(id,id_len,0);
    path = zend_string_init("/",sizeof("/")-1,0);

    /* Set cookie header via 'standard' extension. */
#if PHP_API_VERSION > 20170718
    php_setcookie(name,value,expires,path,NULL,0,0,NULL,1);
#else
    php_setcookie(name,value,expires,path,NULL,0,1,0);
#endif

    zend_string_release(name);
    zend_string_release(value);
    zend_string_release(path);
}

/* Define a helper function for touching uniauth storage records. */

static inline int uniauth_set_expire(struct uniauth_storage* stor)
{
    time_t now = time(NULL);
    int lifetime = LIFETIME(stor->lifetime);
    int diff = stor->expire - now;

    if (stor->expire == 0 || (diff > 0 && diff < lifetime / 2)) {
        stor->expire = now + lifetime;
        return 1;
    }

    return 0;
}

static inline void uniauth_touch_record(struct uniauth_storage* stor)
{
    if (uniauth_set_expire(stor)) {
        struct uniauth_storage cpy;

        /* Make structure have the bare minimum. */
        memset(&cpy,0,sizeof(struct uniauth_storage));
        cpy.key = stor->key;
        cpy.keySz = stor->keySz;

        cpy.expire = stor->expire;
        uniauth_connect_commit(&cpy);
    }
}

/* Define a helper function for looking up the default session id. */

static char* get_default_sessid(size_t* out_len)
{
    /* Lookup session id from module globals or uniauth cookie. This requires
     * that the PHP session exist (via a call to session_start()) OR the uniauth
     * cookie being set via a call to uniauth_cookie(). This function throws if
     * no session was detected.
     */

    zval* zv;
    char* sessid;
    size_t sesslen;

    if (UNIAUTH_G(use_cookie)) {
        zv = GET_GLOBAL("_COOKIE","uniauth");
        if (zv == NULL) {
            zend_throw_exception(
                exception_ce,
                "Failed to load uniauth identifier from uniauth cookie",
                UNIAUTH_ERROR_NO_SESSION);
            return NULL;
        }
        sessid = Z_STRVAL_P(zv);
        sesslen = Z_STRLEN_P(zv);
    }
    else {
        if (PS(id) == NULL || PS(id)->len == 0) {
            zend_throw_exception(
                exception_ce,
                "Failed to load uniauth identifier from php session",
                UNIAUTH_ERROR_NO_SESSION);
            return NULL;
        }
        sessid = PS(id)->val;
        sesslen = PS(id)->len;
    }

    *out_len = sesslen;
    return sessid;
}

ZEND_DECLARE_MODULE_GLOBALS(uniauth);

static void php_uniauth_globals_ctor(zend_uniauth_globals* gbls)
{
    gbls->conn = -1;
    gbls->use_cookie = 0;

    memset(&gbls->socket_info,0,sizeof(struct uniauth_socket_info));
    gbls->socket_info.path = INI_STR(UNIAUTH_SOCKET_PATH_INI);
    gbls->socket_info.host = INI_STR(UNIAUTH_SOCKET_HOST_INI);
    gbls->socket_info.port = INI_STR(UNIAUTH_SOCKET_PORT_INI);
}

static void php_uniauth_globals_dtor(zend_uniauth_globals* gbls)
{
    if (gbls->conn != -1) {
        close(gbls->conn);
        gbls->conn = -1;
    }
}

void uniauth_globals_init()
{
#ifdef ZTS
    ts_allocate_id(&uniauth_globals_id,
        sizeof(zend_uniauth_globals),
        (ts_allocate_ctor)php_uniauth_globals_ctor,
        (ts_allocate_dtor)php_uniauth_globals_dtor);
#else
    php_uniauth_globals_ctor(&uniauth_globals);
#endif
}

void uniauth_globals_request_init()
{
    UNIAUTH_G(use_cookie) = 0;
}

void uniauth_globals_shutdown()
{
#ifndef ZTS
    php_uniauth_globals_dtor(&uniauth_globals);
#endif
}

/* Implementation of PHP userspace functions */

/* {{{ proto ?array uniauth([string url, string session_id])
   Looks up authentication session information or otherwise begins the uniauth
   flow if given authentication endpoint url. */
PHP_FUNCTION(uniauth)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* linebuf;
    char* url = NULL;
    size_t urllen = 0;
    char* sessid = NULL;
    size_t sesslen = 0;
    sapi_header_line ctr = {0};
    size_t bufsz;
    zend_string* encoded;

    /* Grab URL from userspace along with the session id if the user chooses to
     * specify it.
     */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s!s",&url,&urllen,
            &sessid,&sesslen) == FAILURE)
    {
        return;
    }

    if (sessid == NULL) {
        sessid = get_default_sessid(&sesslen);

        if (sessid == NULL) {
            /* Exception is thrown */
            return;
        }
    }

    /* Check to see if we have a user ID for the session. */
    stor = uniauth_connect_lookup(sessid,sesslen,&local);
    if (stor != NULL) {
        /* Check if user ID number is valid. */
        if (IS_VALID_USER_ID(stor->id)) {
            /* Touch the expire time so we keep the session alive. The daemon
             * does not set expire times.
             */
            uniauth_touch_record(stor);

            /* Return user info array to userspace. */
            array_init(return_value);
            add_assoc_long(return_value,"id",stor->id);
            if (stor->username != NULL) {
                add_assoc_string(return_value,"user",stor->username);
            }
            else {
                add_assoc_null(return_value,"user");
            }
            if (stor->displayName != NULL) {
                add_assoc_string(return_value,"display",stor->displayName);
            }
            else {
                add_assoc_null(return_value,"display");
            }
            add_assoc_long(return_value,"expire",stor->expire + 10);
            uniauth_storage_delete(stor);
            return;

            /* Control no longer in function. */
        }

        /* If no redirect URL was provided, then we just return null to indicate
         * that no session is available.
         */
        if (url == NULL) {
            uniauth_storage_delete(stor);
            RETURN_NULL();
        }

        /* If the ID was not set, then we update the redirect URI and continue
         * to redirect the script.
         */
        if (set_redirect_uri(stor) != SUCCESS) {
            /* Exception is thrown */
            uniauth_storage_delete(stor);
            return;
        }

        /* Commit redirect URI changes back to server. */
        uniauth_connect_commit(stor);
    }
    else {
        /* If no redirect URL was provided, then we just return null to indicate
         * that no session is available.
         */
        if (url == NULL) {
            RETURN_NULL();
        }

        /* Create a new entry. The expiration time and lifetime will be 0. This
         * means the session is marked as a temporary session until
         * authentication has been performed.
         */
        stor = &local;
        memset(stor,0,sizeof(struct uniauth_storage));
        stor->key = estrndup(sessid,sesslen);
        stor->keySz = sesslen;

        /* Fill out stor->redirect. */
        if (set_redirect_uri(stor) != SUCCESS) {
            /* Exception is thrown */
            uniauth_storage_delete(stor);
            return;
        }

        /* Send new record to the uniauth daemon. */
        uniauth_connect_create(stor);
    }

    /* URL-encode (via 'standard' extension) the key so we can safely pass it in
     * a query string.
     */
    encoded = php_url_encode(stor->key,stor->keySz);

    /* Allocate a buffer to hold the redirect header line. 'newlen' includes the
     * size needed for the trailing null character.
     */
    bufsz = encoded->len;
    bufsz += urllen + sizeof(LOCATION_HEADER) + sizeof(UNIAUTH_QSTRING) - 1;
    ctr.line = linebuf = emalloc(bufsz);

    /* Prepare the redirect header line. This will include a query parameter
     * that contains the uniauth session key.
     */
    snprintf(linebuf,bufsz,"%s%s%s%s",LOCATION_HEADER,url,UNIAUTH_QSTRING,encoded->val);
    ctr.line_len = bufsz - 1;
    sapi_header_op(SAPI_HEADER_REPLACE,&ctr);
    efree(linebuf);
    zend_string_release(encoded);

    /* Free memory allocated for uniauth record. */
    uniauth_storage_delete(stor);

    /* Terminate user script. */
    zend_bailout();
}
/* }}} */

/* {{{ proto void uniauth_register(int id, string name, string display_name [, string key, int lifetime])
   Registers user information with the current session */
PHP_FUNCTION(uniauth_register)
{
    struct uniauth_storage backing;
    struct uniauth_storage* stor;
    zend_long id;
    char* name;
    size_t namelen;
    char* displayname;
    size_t displaynamelen;
    char* sessid = NULL;
    size_t sesslen = 0;
    zend_long lifetime = 0;
    time_t expires = 0;

    /* Grab id parameter from userspace. */
    if (zend_parse_parameters(
            ZEND_NUM_ARGS(),
            "lss|s!l",
            &id,
            &name, &namelen,
            &displayname, &displaynamelen,
            &sessid, &sesslen,
            &lifetime) == FAILURE)
    {
        return;
    }

    if (sessid == NULL) {
        sessid = get_default_sessid(&sesslen);

        if (sessid == NULL) {
            /* Exception is thrown */
            return;
        }
    }

    if (lifetime < 0) {
        lifetime = 0;
    }

    /* Lookup the uniauth_storage for the session. Create one if does not
     * exist. Then assign the id to the structure. An expiration is created
     * since we want this session to live (so we can keep registering new
     * sessions with it). If the expiration exists we touch it so it updates.
     */
    stor = uniauth_connect_lookup(sessid,sesslen,&backing);
    if (stor != NULL) {
        /* Set storage parameters. We will always override any existing
         * values.
         */
        stor->id = (int32_t)id;
        if (stor->username != NULL) {
            efree(stor->username);
        }
        if (stor->displayName != NULL) {
            efree(stor->displayName);
        }
        stor->username = estrdup(name);
        stor->usernameSz = namelen;
        stor->displayName = estrdup(displayname);
        stor->displayNameSz = displaynamelen;
        stor->expire = time(NULL) + LIFETIME(lifetime);
        stor->lifetime = (int32_t)lifetime;
        if (lifetime == 0) {
            expires = stor->expire;
        }

        uniauth_connect_commit(stor);
    }
    else {
        stor = &backing;
        memset(stor,0,sizeof(struct uniauth_storage));
        stor->key = estrndup(sessid,sesslen);
        stor->keySz = sesslen;
        stor->id = (int32_t)id;
        stor->username = estrdup(name);
        stor->usernameSz = namelen;
        stor->displayName = estrdup(displayname);
        stor->displayNameSz = displaynamelen;
        stor->expire = time(NULL) + LIFETIME(lifetime);
        stor->lifetime = (int32_t)lifetime;
        if (lifetime == 0) {
            expires = stor->expire;
        }

        uniauth_connect_create(stor);
    }

    /* Update uniauth cookie expiration. The cookie expiration is only set
     * (i.e. positive) when we are creating a persistent session that has an
     * indefinate lifetime. Otherwise we always produce a session cookie with no
     * expiration.
     */
    if (UNIAUTH_G(use_cookie)) {
        set_uniauth_cookie(stor->key,stor->keySz,expires);
    }

    /* Free uniauth record fields. */
    uniauth_storage_delete(stor);
}
/* }}} */

/* {{{ proto void uniauth_transfer([string session_id])
   Completes the auth flow by transferring the current uniauth record into the
   awaiting applicant record */
PHP_FUNCTION(uniauth_transfer)
{
    struct uniauth_storage backing[2];
    struct uniauth_storage* src;
    struct uniauth_storage* dst;
    char* sessid = NULL;
    size_t sesslen = 0;
    char* foreignSession;
    size_t foreignSessionlen;
    sapi_header_line ctr = {0};

    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    if (sessid == NULL) {
        sessid = get_default_sessid(&sesslen);

        if (sessid == NULL) {
            /* Exception is thrown */
            return;
        }
    }

    /* Lookup the source session so that we can grab the foreign session
     * ID. This should have been recorded in the 'tag' field by a call to
     * uniauth_apply().
     */
    src = uniauth_connect_lookup(sessid,sesslen,backing);
    if (src == NULL) {
        zend_throw_exception(
            exception_ce,
            "Source registration does not exist",
            UNIAUTH_ERROR_SOURCE_NOT_EXIST);
        return;
    }
    if (src->tag == NULL) {
        zend_throw_exception(
            exception_ce,
            "Source registration did not apply",
            UNIAUTH_ERROR_SOURCE_NOT_APPLY);
        uniauth_storage_delete(backing);
        return;
    }
    foreignSession = src->tag;
    foreignSessionlen = src->tagSz;

    /* We have to lookup the destination record so we can grab its redirect URI
     * before it's overwritten.
     */
    dst = uniauth_connect_lookup(foreignSession,foreignSessionlen,backing+1);
    if (dst == NULL) {
        zend_throw_exception(
            exception_ce,
            "Destination registration does not exist",
            UNIAUTH_ERROR_DEST_NOT_EXIST);
        uniauth_storage_delete(backing);
        return;
    }

    /* Transfer the info from the source record to the destination record. The
     * uniauth daemon will do this for us.
     */
    if (uniauth_connect_transfer(sessid,foreignSession) == -1) {
        zend_throw_exception(
            exception_ce,
            "The transfer operation failed",
            UNIAUTH_ERROR_TRANSFER_FAILED);
        uniauth_storage_delete(backing);
        uniauth_storage_delete(backing+1);
        return;
    }

    /* Add header to redirect back to pending page. */
    if (dst->redirect != NULL) {
        char* linebuf;
        ctr.line = linebuf = emalloc(dst->redirectSz + sizeof(LOCATION_HEADER));
        strcpy(linebuf,LOCATION_HEADER);
        strcpy(linebuf + sizeof(LOCATION_HEADER) - 1,dst->redirect);
        ctr.line_len = (uint)dst->redirectSz + sizeof(LOCATION_HEADER) - 1;
        sapi_header_op(SAPI_HEADER_REPLACE,&ctr);
        efree(linebuf);
    }
    else {
        zend_throw_exception(
            exception_ce,
            "No redirect URI exists for the destination registration",
            UNIAUTH_ERROR_MISSING_REDIRECT);
        uniauth_storage_delete(backing);
        uniauth_storage_delete(backing+1);
        return;
    }

    /* Overwrite 'redirect' record field with token "transfer" to indicate the
     * transfer took place.
     */
    if (src->redirect) {
        efree(src->redirect);
    }
    src->redirect = estrdup("transfer");
    src->redirectSz = sizeof("transfer")-1;
    uniauth_connect_commit(src);

    uniauth_storage_delete(backing);
    uniauth_storage_delete(backing+1);

    /* Terminate user script to perform redirect. */
    zend_bailout();
}
/* }}} */

/* {{{ proto bool uniauth_check([string session_id])
   Determines if an authentication session exists */
PHP_FUNCTION(uniauth_check)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* sessid = NULL;
    size_t sesslen = 0;
    int result = 0;

    /* Grab parameters from userspace. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    if (sessid == NULL) {
        sessid = get_default_sessid(&sesslen);

        if (sessid == NULL) {
            /* Exception is thrown */
            return;
        }
    }

    /* Check to see if we have a user ID for the session. If so, return true. */
    stor = uniauth_connect_lookup(sessid,sesslen,&local);
    if (stor != NULL) {
        result = IS_VALID_USER_ID(stor->id);
        uniauth_storage_delete(stor);
    }
    if (result) {
        RETURN_TRUE;
    }
    RETURN_FALSE;
}
/* }}} */

/* {{{ proto void uniauth_apply([string session_id])
   Begins the application process by creating the registrar session and assigning
   the session ID passed in $_GET['uniauth'] to it. */
PHP_FUNCTION(uniauth_apply)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* sessid = NULL;
    size_t sesslen = 0;
    zval* zv;
    char* applicantID;
    int create;

    /* Grab parameters from userspace. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    if (sessid == NULL) {
        sessid = get_default_sessid(&sesslen);

        if (sessid == NULL) {
            /* Exception is thrown */
            return;
        }
    }

    /* Query the registrar session in case it already exists. We'll create it if
     * it does not.
     */
    stor = uniauth_connect_lookup(sessid,sesslen,&local);
    create = (stor == NULL);
    if (create) {
        stor = &local;
        memset(stor,0,sizeof(struct uniauth_storage));
        stor->key = estrndup(sessid,sesslen);
        stor->keySz = sesslen;
    }
    else if (stor->tag != NULL) {
        efree(stor->tag);
        stor->tag = NULL;
        stor->tagSz = 0;
    }

    /* Grab the applicant ID from the _GET superglobal array. Assign it to the
     * 'tag' field. We save this so we can reference the applicant session later
     * on in the flow.
     */
    zv = GET_GLOBAL("_GET","uniauth");
    applicantID = zv ? Z_STRVAL_P(zv) : NULL;
    if (applicantID == NULL) {
        if (!create) {
            uniauth_storage_delete(stor);
        }
        zend_throw_exception(
            exception_ce,
            "No 'uniauth' query parameter was specified",
            UNIAUTH_ERROR_MISSING_UNIAUTH_PARAM);
        return;
    }
    stor->tag = estrdup(applicantID);
    stor->tagSz = strlen(applicantID);

    /* Perform transaction. */
    if (create) {
        uniauth_connect_create(stor);
    }
    else {
        uniauth_connect_commit(stor);
        uniauth_storage_delete(stor);
    }
}
/* }}} */

/* {{{ proto bool uniauth_purge([string session_id])
   Ends the current uniauth session */
PHP_FUNCTION(uniauth_purge)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* sessid = NULL;
    size_t sesslen = 0;
    int result = 0;

    /* Grab session id from user space. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    if (sessid == NULL) {
        sessid = get_default_sessid(&sesslen);

        if (sessid == NULL) {
            /* Exception is thrown */
            return;
        }
    }

    /* If the session is valid, invalidate it. */
    stor = uniauth_connect_lookup(sessid,sesslen,&local);
    if (stor != NULL) {
        if (IS_VALID_USER_ID(stor->id)) {
            stor->id = -1;
            uniauth_connect_commit(stor);
            result = 1;
        }
        uniauth_storage_delete(stor);
    }

    if (result) {
        RETURN_TRUE;
    }
    RETURN_FALSE;
}
/* }}} */

/* {{{ proto string uniauth_cookie()
   Generates and/or retrieves a unique uniauth session and sets this session
   to be used instead of the PHP session */
PHP_FUNCTION(uniauth_cookie)
{
    zval sessid;
    zval* result;
    int touch = 1;
    time_t expires = 0;

    /* Get the session id from the cookie. If none was found then generate a new
     * session id.
     */
    result = GET_GLOBAL("_COOKIE","uniauth");
    if (result == NULL) {
        int i;
        size_t len;
        zend_string* encoded;
        unsigned char buf[UNIAUTH_COOKIE_IDLEN / 4 * 3];
        char output[UNIAUTH_COOKIE_IDLEN+1];

        i = 0;
        while (i < sizeof(buf)) {
            zend_long n;
#if PHP_API_VERSION >= 20180731
            n = php_mt_rand_range(0,0xff);
#else
            n = php_rand();
            RAND_RANGE(n,0,0xff,PHP_RAND_MAX);
#endif
            buf[i] = (unsigned char)n;
            i += 1;
        }

        memset(output,'0',sizeof(output));
        encoded = php_base64_encode(buf,sizeof(buf));
        if (encoded == NULL) {
            RETURN_FALSE;
        }
        len = (encoded->len > UNIAUTH_COOKIE_IDLEN ? UNIAUTH_COOKIE_IDLEN : encoded->len);
        memcpy(output,encoded->val,len);
        zend_string_release(encoded);

        output[UNIAUTH_COOKIE_IDLEN] = 0;
        ZVAL_STRING(&sessid,output);

        /* Go ahead and set the cookie in the superglobal so it is available for
         * userland. Subsequent calls to the uniauth extension could require the
         * global to be set.
         */
        if (SET_GLOBAL("_COOKIE","uniauth",&sessid) != SUCCESS) {
            zend_throw_exception(NULL,"[uniauth] Cannot set 'uniauth' in $_COOKIE",0);
            return;
        }
    }
    else {
        ZVAL_COPY(&sessid,result);

        /* If a cookie was already sent, then lookup the uniauth record to
         * determine the expires value and if we need to touch the cookie.
         */

        struct uniauth_storage local;
        struct uniauth_storage* stor;

        stor = uniauth_connect_lookup(Z_STRVAL(sessid),Z_STRLEN(sessid),&local);
        if (stor != NULL) {
            if (stor->expire > 0) {
                /* We touch the cookie if the redirect was set to transfer
                 * (indicating the session was just registered) or if the
                 * storage record's expiration should update.
                 */
                if (stor->redirect != NULL && strcmp(stor->redirect,"transfer") == 0) {
                    touch = 1;
                    stor->redirectSz = 0;
                    stor->redirect[0] = 0;
                    uniauth_connect_commit(stor);
                }
                else {
                    touch = uniauth_set_expire(stor);
                }

                /* Set cookie expiration if there is an indefinate lifetime on
                 * the record. This makes the cookie persistent with a lifetime
                 * aligned with the session record.
                 */
                if (stor->lifetime == 0) {
                    expires = stor->expire;
                }
            }

            uniauth_storage_delete(stor);
        }
    }

    /* Toggle global flag to indicate the extension should use the uniauth
     * cookie instead of the PHP session.
     */
    UNIAUTH_G(use_cookie) = 1;

    /* Create/touch the cookie. */
    if (touch) {
        set_uniauth_cookie(Z_STRVAL(sessid),Z_STRLEN(sessid),expires);
    }

    RETVAL_ZVAL(&sessid,0,0);
}
/* }}} */
