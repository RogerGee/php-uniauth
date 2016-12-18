/*
 * uniauth.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <php.h>
#include <ext/session/php_session.h>
#include <SAPI.h>
#ifdef ZTS
#include <TSRM.h>
#endif
#include <time.h>

#define LOCATION_HEADER "Location: "

struct uniauth_storage
{
    long id;
    time_t expire;
    char* redirect;
};

static void uniauth_storage_free(struct uniauth_storage** item)
{
    struct uniauth_storage* p = *item;
    if (p->redirect != NULL) {
        pefree(p->redirect,1);
    }
    pefree(p,1);
}

static PHP_MINIT_FUNCTION(uniauth);
static PHP_MSHUTDOWN_FUNCTION(uniauth);
static PHP_FUNCTION(uniauth);
static PHP_FUNCTION(uniauth_register);
static PHP_FUNCTION(uniauth_transfer);

static zend_function_entry php_uniauth_functions[] = {
    PHP_FE(uniauth,NULL)
    PHP_FE(uniauth_register,NULL)
    PHP_FE(uniauth_transfer,NULL)

    {NULL, NULL, NULL}
};

/* This variable stores the lookup information, mapping a session id to a user
 * id. It must be global to all threads.
 */
static HashTable g_Lookup;

/* We'll use this mutex for accessing the lookup table when doing a write. We
 * only do this for threaded SAPIs.
 */
#ifdef ZTS
static MUTEX_T g_Mutex;
#define LOCK_LOOKUP() zend_mutex_lock(g_Mutex)
#define UNLOCK_LOOKUP() zend_mutex_unlock(g_Mutex)
#else
#define LOCK_LOOKUP()
#define UNLOCK_LOOKUP()
#endif

zend_module_entry uniauth_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "uniauth",
    php_uniauth_functions,
    PHP_MINIT(uniauth),
    PHP_MSHUTDOWN(uniauth),
    NULL, /* RINIT */
    NULL, /* RSHUTDOWN */
    NULL, /* MINFO */
#if ZEND_MODULE_API_NO >= 20010901
    "0.0.0",
#endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_UNIAUTH
ZEND_GET_MODULE(uniauth)
#endif

PHP_MINIT_FUNCTION(uniauth)
{
#ifdef ZTS
    /* Create the mutex. */
    g_Mutex = tsrm_mutex_alloc();
#endif

    /* Create the lookup table. The structure itself is allocated in the data
     * segment. Since the memory allocations are persistent, then PHP will use
     * malloc()/free() for memory management.
     */
    zend_hash_init(&g_Lookup,262144,NULL,(void (*)(void*))uniauth_storage_free,1);

    /* TODO: Read any lookup data from disk. */

}

PHP_MSHUTDOWN_FUNCTION(uniauth)
{
    /* TODO: Dump the lookup data to disk. */
    

    /* Destroy the lookup table. */
    zend_hash_destroy(&g_Lookup);

#ifdef ZTS
    tsrm_mutex_free(g_Mutex);
#endif
}

static int set_redirect_uri(struct uniauth_storage* stor)
{
    char buf[4096];
    zend_auto_global* auto_global;
    HashTable* server;
    zval** arr;
    zval** val;
    int https = 0;
    char* host;
    char* port = NULL;
    char* uri;

    /* Make sure $_SERVER is auto loaded already. */
    if (!zend_hash_exists(&EG(symbol_table),"_SERVER",8)) {
        if (zend_hash_find(CG(auto_globals),"_SERVER",8,(void**)&auto_global) != FAILURE) {
            auto_global->armed = auto_global->auto_global_callback(auto_global->name,
                auto_global->name_len TSRMLS_CC);
        }
        else {
            zend_throw_exception(NULL,"could not activate _SERVER",0 TSRMLS_CC);
            return 0;
        }
    }

    /* Get information about the protocol, host and port number from the _SERVER
     * superglobal. We use HTTPS, HTTP_HOST and SERVER_PORT keys to resolve the
     * scheme, host and port. I know of no better way to do this unfortunately
     * with the PHP/ZEND API. The sapi globals just don't have what I need.
     */
    if (zend_hash_find(&EG(symbol_table),"_SERVER",8,(void**)&arr) == FAILURE) {
        zend_throw_exception(NULL,"no _SERVER superglobal",0 TSRMLS_CC);
        return 0;
    }
    server = Z_ARRVAL_PP(arr);
    if (zend_hash_find(server,"HTTPS",6,(void**)&val) != FAILURE) {
        if (Z_TYPE_PP(val) != IS_STRING || strcmp(Z_STRVAL_PP(val),"off") != 0) {
            https = 1;
        }
    }
    if (zend_hash_find(server,"HTTP_HOST",10,(void**)&val) != FAILURE
        && Z_TYPE_PP(val) == IS_STRING)
    {
        host = Z_STRVAL_PP(val);
    }
    else {
        zend_throw_exception(NULL,"no HTTP_HOST within _SERVER found",0 TSRMLS_CC);
    }
    if (zend_hash_find(server,"SERVER_PORT",12,(void**)&val) != FAILURE) {
        /* Only set port if it is not well-known. If the host name contains a
         * ':' then we assume the port was encoded in the Host header. User
         * agents should do this but we still need make sure we get the port
         * number if not.
         */
        int i = 0;
        char* p;

        while (host[i] != 0) {
            if (host[i] == ':') {
                break;
            }
            i += 1;
        }

        if (host[i] == 0) {
            convert_to_string(*val);
            p = Z_STRVAL_PP(val);
            if ((!https && strcmp(p,"80") != 0) || (https && strcmp(p,"443") != 0)) {
                port = p;
            }
        }
    }
    else {
        zend_throw_exception(NULL,"no SERVER_PORT within _SERVER found",0 TSRMLS_CC);
    }

    /* Lookup request URI. This actually can be found in the sapi globals. */
    uri = SG(request_info.request_uri);
    if (uri == NULL) {
        zend_throw_exception(NULL,"no request-uri available",0 TSRMLS_CC);
        return 0;
    }

    /* Format the URI to a temporary buffer. */
    if (port == NULL) {
        snprintf(buf,sizeof(buf),"%s://%s%s",https?"https":"http",host,uri);
    }
    else {
        snprintf(buf,sizeof(buf),"%s://%s:%s%s",https?"https":"http",host,port,uri);
    }

    /* Copy buffer (must be persistent). */
    stor->redirect = pemalloc(strlen(buf)+1,1);
    strcpy(stor->redirect,buf);

    return 1;
}

/* {{{ proto int uniauth(string url)
   Checks universal authentication for the given session */
PHP_FUNCTION(uniauth)
{
    struct uniauth_storage* stor;
    struct uniauth_storage** pstor;
    char* sessid = NULL;
    size_t sesslen = 0;
    char* url = NULL;
    size_t urllen = 0;
    sapi_header_line ctr = {0};

    /* Grab URL from userspace. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"s",&url,&urllen) == FAILURE) {
        return;
    }

    /* Lookup session id from module globals. This requires that the session
     * module is enabled. This function throws if there is no session.
     */
    sessid = PS(id);
    if (sessid == NULL) {
        zend_throw_exception(NULL,"no session-id available: is the session loaded?",0 TSRMLS_CC);
        return;
    }

    /* Check to see if we have a user ID for the session. */
    sesslen = strlen(sessid) + 1;
    LOCK_LOOKUP();
    if (zend_hash_find(&g_Lookup,sessid,sesslen,(void**)&pstor) != FAILURE) {
        stor = *pstor;
        if (stor->expire < time(NULL) && stor->id >= 0) {
            if (stor->redirect != NULL) {
                /* The redirect url cache is not needed anymore. */
                free(stor->redirect);
                stor->redirect = NULL;
            }
            RETVAL_LONG(stor->id);
            UNLOCK_LOOKUP();
            return;
        }
    }
    else {
        stor = pemalloc(sizeof(struct uniauth_storage),1);
        stor->id = -1;
        stor->expire = time(NULL) + PS(gc_maxlifetime);
        stor->redirect = NULL;

        zend_hash_add(&g_Lookup,sessid,sesslen,&stor,sizeof(struct uniauth_storage*),NULL);
    }
    UNLOCK_LOOKUP();

    /* Fill out stor->redirect. */
    if (!set_redirect_uri(stor)) {
        return;
    }

    /* Add a redirect header. TODO: add query parameter for session id. */
    ctr.line = emalloc(urllen + sizeof(LOCATION_HEADER));
    strcpy(ctr.line,LOCATION_HEADER);
    strcpy(ctr.line + sizeof(LOCATION_HEADER) - 1,url);
    ctr.line_len = (uint)urllen + sizeof(LOCATION_HEADER) - 1;
    sapi_header_op(SAPI_HEADER_REPLACE,&ctr);
    efree(ctr.line);

    /* Terminate user script. */
    zend_bailout();
}

/* {{{ proto void uniauth_register(string) */
PHP_FUNCTION(uniauth_register)
{
}

PHP_FUNCTION(uniauth_transfer)
{
}
