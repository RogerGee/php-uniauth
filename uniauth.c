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
#include "connect.h"

#define LOCATION_HEADER "Location: "

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
}

PHP_MSHUTDOWN_FUNCTION(uniauth)
{
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
    size_t len;

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

    /* Copy buffer into record structure. */
    len = strlen(buf);
    stor->redirect = estrndup(buf,len);
    stor->redirectSz = len;

    return 1;
}

/* {{{ proto int uniauth(string url [, string cookie])
   Checks universal authentication for the given session */
PHP_FUNCTION(uniauth)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* sessid = NULL;
    size_t sesslen = 0;
    char* url = NULL;
    size_t urllen = 0;
    sapi_header_line ctr = {0};

    /* Grab URL from userspace. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"s|s",&url,&urllen,
            &sessid,&sesslen) == FAILURE)
    {
        return;
    }

    /* Lookup session id from module globals if no cookie id was provided. This
     * requires that the session module is enabled. This function throws if
     * there is no session.
     */
    if (sessid == NULL) {
        sessid = PS(id);
        sesslen = strlen(sessid);
        if (sessid == NULL) {
            zend_throw_exception(NULL,"no session-id available: is the session loaded?",0 TSRMLS_CC);
            return;
        }
    }

    /* Check to see if we have a user ID for the session. */
    stor = uniauth_connect_lookup(sessid,&local);
    if (stor != NULL) {
        /* Touch the expire time so we keep the session alive. The daemon does
         * not set expire times.
         */
        stor->expire = time(NULL) + PS(gc_maxlifetime) + 10;

        /* Commit changes back to uniauth daemon and return id to userspace. */
        uniauth_connect_commit(stor);
        uniauth_storage_delete(stor);
        RETURN_LONG(stor->id);

        /* Control no longer in function. */
    }

    /* Create a new entry. We must set the expire time since the daemon does
     * not do it. Plus we want to align the lifetime with the session
     * lifetime as close as possible.
     */
    stor = &local;
    memset(stor,0,sizeof(struct uniauth_storage));
    stor->key = estrndup(sessid,sesslen);
    stor->keySz = sesslen;
    stor->expire = time(NULL) + PS(gc_maxlifetime) + 10;

    /* Fill out stor->redirect. */
    if (!set_redirect_uri(stor)) {
        return;
    }

    /* Send new record to the uniauth daemon. */
    uniauth_connect_create(stor);

    /* Add a redirect header. TODO: add query parameter for session id. */
    ctr.line = emalloc(urllen + sizeof(LOCATION_HEADER));
    strcpy(ctr.line,LOCATION_HEADER);
    strcpy(ctr.line + sizeof(LOCATION_HEADER) - 1,url);
    ctr.line_len = (uint)urllen + sizeof(LOCATION_HEADER) - 1;
    sapi_header_op(SAPI_HEADER_REPLACE,&ctr);
    efree(ctr.line);

    /* Free memory allocated for uniauth record. */
    uniauth_storage_delete(stor);

    /* Terminate user script. */
    zend_bailout();
}

/* {{{ proto void uniauth_register(int id, string name, string displayName [, string cookie])
   Registers a user-id with the current session */
PHP_FUNCTION(uniauth_register)
{
    struct uniauth_storage backing;
    struct uniauth_storage* stor;
    long id;
    char* name;
    size_t namelen;
    char* displayname;
    size_t displaynamelen;
    char* sessid = NULL;
    size_t sesslen = 0;

    /* Grab id parameter from userspace. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"lss|s",&id,&name,&namelen,
            &displayname,&displaynamelen,&sessid,&sesslen) == FAILURE)
    {
        return;
    }

    /* Lookup session id from module globals if no cookie id was provided. This
     * requires that the session module is enabled and session_start() has been
     * called. This function throws if there is no session.
     */
    if (sessid == NULL) {
        sessid = PS(id);
        sesslen = strlen(sessid);
        if (sessid == NULL) {
            zend_throw_exception(NULL,"no session-id available: is the session loaded?",0 TSRMLS_CC);
            return;
        }
    }

    /* Lookup the uniauth_storage for the session. Create one if does not
     * exist. Then assign the id to the structure.
     */
    stor = uniauth_connect_lookup(sessid,&backing);
    if (stor != NULL) {
        /* We will always override any current value. */
        stor->id = id;
        if (stor->username != NULL) {
            efree(stor->username);
        }
        if (stor->displayName != NULL) {
            efree(stor->displayName);
        }
        stor->username = estrndup(name,namelen);
        stor->usernameSz = namelen;
        stor->displayName = estrndup(displayname,displaynamelen);
        stor->displayNameSz = displaynamelen;
        stor->expire = time(NULL) + PS(gc_maxlifetime) + 10;

        uniauth_connect_commit(stor);
    }
    else {
        stor = &backing;
        memset(stor,0,sizeof(struct uniauth_storage));
        stor->key = estrndup(sessid,sesslen);
        stor->keySz = sesslen;
        stor->id = id;
        stor->username = estrndup(name,namelen);
        stor->usernameSz = namelen;
        stor->displayName = estrndup(displayname,displaynamelen);
        stor->displayNameSz = displaynamelen;
        stor->expire = time(NULL) + PS(gc_maxlifetime);

        uniauth_connect_create(stor);
    }

    /* Free uniauth record fields. */
    uniauth_storage_delete(stor);
}

static char* get_param(const char* gbl,int gbllen,const char* elem,int elemlen)
{
    zend_auto_global* auto_global;
    HashTable* bucket;
    zval** arr;
    zval** val;

    /* Make sure superglobal is auto loaded already. */
    if (!zend_hash_exists(&EG(symbol_table),gbl,gbllen)) {
        if (zend_hash_find(CG(auto_globals),gbl,gbllen,(void**)&auto_global) != FAILURE) {
            auto_global->armed = auto_global->auto_global_callback(auto_global->name,
                auto_global->name_len TSRMLS_CC);
        }
        else {
            zend_throw_exception(NULL,"could not activate auto global",0 TSRMLS_CC);
            return 0;
        }
    }

    /* Lookup element and return as string. */
    if (zend_hahs_find(&EG(symbol_table),gbl,gbllen,(void**)&arr) == FAILURE) {
        zend_throw_exception(NULL,"no such superglobal",0 TSRMLS_CC);
        return 0;
    }
    bucket = Z_ARRVAL_PP(arr);
    if (zend_hash_find(bucket,elem,elemlen,(void**)&val) != FAILURE) {
        if (Z_TYPE_PP(val) == IS_STRING) {
            return Z_STRVAL_PP(val);
        }
    }

    return NULL;
}

/* Arguments to this macro should be string literals. */
#define GET_PARAM(g,e) \
    get_param(g,sizeof(g),e,sizeof(e))

/* {{{ proto void uniauth_transfer([string cookie])
   Transfers a user id from the current session to the session referred to
   by $_GET['uniauth'] */
PHP_FUNCTION(uniauth_transfer)
{
    struct uniauth_storage backing[2];
    struct uniauth_storage* src;
    struct uniauth_storage* dst;
    char* sessid = NULL;
    size_t sesslen = 0;
    char* foreignSession;
    sapi_header_line ctr = {0};

    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    /* Lookup session id from module globals if no cookie id was provided. This
     * requires that the session module is enabled and a session has been
     * started. This function throws if there is no session.
     */
    if (sessid == NULL) {
        sessid = PS(id);
        sesslen = strlen(sessid);
        if (sessid == NULL) {
            zend_throw_exception(NULL,"no session-id available: is the session loaded?",0 TSRMLS_CC);
            return;
        }
    }

    /* Lookup the uniauth record for the session. It should already exist. */
    src = uniauth_connect_lookup(sessid,backing);
    if (src == NULL) {
        zend_throw_exception(NULL,"no uniauth registration found",0 TSRMLS_CC);
        return;
    }

    /* Lookup the foreign session into which we are transfering the user ID. The
     * foreign session id is sent in a GET query parameter.
     */
    foreignSession = GET_PARAM("GET","uniauth");
    if (foreignSession == NULL) {
        zend_throw_exception(NULL,"no 'uniauth' query parameter found",0 TSRMLS_CC);
        return;
    }
    dst = uniauth_connect_lookup(foreignSession,backing+1);

    /* Transfer the info from the source record to the destination record and
     * commit the changes. We'll just make the src record key and expire match
     * the dst record to avoid having to copy.
     */
    efree(src->key);
    src->key = dst->key;
    src->keySz = dst->keySz;
    dst->key = NULL;
    src->expire = dst->expire;
    if (src->redirect != NULL) {
        /* Just in case. We want to make sure we clear the redirect field. */
        efree(src->redirect);
        src->redirect = NULL;
    }
    uniauth_connect_commit(src);

    /* Add header to redirect back to pending page. */
    if (dst->redirect != NULL) {
        ctr.line = emalloc(dst->redirectSz + sizeof(LOCATION_HEADER));
        strcpy(ctr.line,LOCATION_HEADER);
        strcpy(ctr.line + sizeof(LOCATION_HEADER) - 1,dst->redirect);
        ctr.line_len = (uint)dst->redirectSz + sizeof(LOCATION_HEADER) - 1;
        sapi_header_op(SAPI_HEADER_REPLACE,&ctr);
        efree(ctr.line);
    }

    /* Free the uniauth record fields. */
    uniauth_storage_delete(backing);
    uniauth_storage_delete(backing+1);
}
