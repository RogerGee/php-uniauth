/*
 * uniauth.c
 */

#include "uniauth.h"
#include "connect.h"

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
    PHP_FE(uniauth,NULL)
    PHP_FE(uniauth_register,NULL)
    PHP_FE(uniauth_transfer,NULL)
    PHP_FE(uniauth_check,NULL)
    PHP_FE(uniauth_apply,NULL)
    PHP_FE(uniauth_purge,NULL)
    PHP_FE(uniauth_cookie,NULL)

    {NULL, NULL, NULL}
};

/* Module entries */
zend_module_entry uniauth_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "uniauth",
    php_uniauth_functions,
    PHP_MINIT(uniauth),
    PHP_MSHUTDOWN(uniauth),
    PHP_RINIT(uniauth),
    PHP_RSHUTDOWN(uniauth),
    PHP_MINFO(uniauth),
#if ZEND_MODULE_API_NO >= 20010901
    PHP_UNIAUTH_EXTVER,
#endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_UNIAUTH
ZEND_GET_MODULE(uniauth)
#endif

/* Implementation of module/request functions */

PHP_MINIT_FUNCTION(uniauth)
{
    uniauth_globals_init();

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

    return SUCCESS;
}

PHP_RINIT_FUNCTION(uniauth)
{

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(uniauth)
{

    return SUCCESS;
}

/* Define some helper functions for accessing/modifying superglobal
 * variables.
 */

static zval* get_global(const char* gbl,int gbllen,const char* key,int keylen)
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
            return NULL;
        }
    }

    /* Lookup element and return as string. */
    if (zend_hash_find(&EG(symbol_table),gbl,gbllen,(void**)&arr) == FAILURE) {
        return NULL;
    }
    bucket = Z_ARRVAL_PP(arr);
    if (zend_hash_find(bucket,key,keylen,(void**)&val) != FAILURE) {
        return *val;
    }

    return NULL;
}

/* Arguments to this macro should be string literals. */
#define GET_GLOBAL(g,e)                         \
    get_global(g,sizeof(g),e,sizeof(e))

static int set_global(const char* gbl,int gbllen,const char* key,int keylen,zval* value)
{
    zend_auto_global* auto_global;
    HashTable* bucket;
    zval** arr;

    /* Make sure superglobal is auto loaded already. */
    if (!zend_hash_exists(&EG(symbol_table),gbl,gbllen)) {
        if (zend_hash_find(CG(auto_globals),gbl,gbllen,(void**)&auto_global) != FAILURE) {
            auto_global->armed = auto_global->auto_global_callback(auto_global->name,
                auto_global->name_len TSRMLS_CC);
        }
        else {
            return FAILURE;
        }
    }

    /* Lookup bucket for superglobal. */
    if (zend_hash_find(&EG(symbol_table),gbl,gbllen,(void**)&arr) == FAILURE) {
        return FAILURE;
    }
    bucket = Z_ARRVAL_PP(arr);

    /* Update zval in hashtable. */
    zend_hash_update(bucket,key,keylen,&value,sizeof(zval*),NULL);

    return SUCCESS;
}

#define SET_GLOBAL(g,k,v)                       \
    set_global(g,sizeof(g),k,sizeof(k),v)

/* Define a helper function for compiling the redirect uri to the current
 * request.
 */

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
    if (zend_hash_find(server,"REQUEST_URI",12,(void**)&val) != FAILURE
        && Z_TYPE_PP(val) == IS_STRING)
    {
        uri = Z_STRVAL_PP(val);
    }
    else {
        zend_throw_exception(NULL,"no REQUEST_URI within _SERVER found",0 TSRMLS_CC);
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

/* Implementation of PHP userspace functions */

/* {{{ proto array uniauth(string url [, string key])
   Looks up authentication session information or begins the uniauth flow if none found */
PHP_FUNCTION(uniauth)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* sessid = NULL;
    int sesslen = 0;
    char* url = NULL;
    int urllen = 0;
    sapi_header_line ctr = {0};
    char* encoded;
    int newlen = 0;
    zval* zv;

    /* Grab URL from userspace along with the session id if the user chooses to
     * specify it.
     */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"s|s",&url,&urllen,
            &sessid,&sesslen) == FAILURE)
    {
        return;
    }

    /* Lookup session id from module globals or uniauth cookie if no explicit
     * key id was provided. This requires that the PHP session exist (via a call
     * to session_start()) OR the uniauth cookie being set via a call to
     * uniauth_cookie(). This function throws if no session was detected.
     */
    if (sessid == NULL) {
        if (UNIAUTH_G(useCookie)) {
            zv = GET_GLOBAL("_COOKIE","uniauth");
            if (zv == NULL) {
                zend_throw_exception(
                    NULL,
                    "no uniauth cookie session available",
                    0 TSRMLS_CC);
                return;
            }
            sessid = Z_STRVAL_P(zv);
            sesslen = Z_STRLEN_P(zv);
        }
        else {
            sessid = PS(id);
            if (sessid == NULL) {
                zend_throw_exception(
                    NULL,
                    "no PHP session is available",
                    0 TSRMLS_CC);
                return;
            }
            sesslen = strlen(sessid);
        }
    }

    /* Check to see if we have a user ID for the session. */
    stor = uniauth_connect_lookup(sessid,sesslen,&local);
    if (stor != NULL) {
        /* Touch the expire time so we keep the session alive. The daemon does
         * not set expire times.
         */
        stor->expire = time(NULL) + PS(gc_maxlifetime);

        /* ID must be set. */
        if (stor->id >= 1) {
            /* Commit changes back to uniauth daemon and return user info to
             * userspace.
             */
            uniauth_connect_commit(stor);
            array_init(return_value);
            add_assoc_long(return_value,"id",stor->id);
            if (stor->username != NULL) {
                add_assoc_string(return_value,"user",stor->username,1);
            }
            else {
                add_assoc_null(return_value,"user");
            }
            if (stor->displayName != NULL) {
                add_assoc_string(return_value,"display",stor->displayName,1);
            }
            else {
                add_assoc_null(return_value,"display");
            }
            add_assoc_long(return_value,"expire",stor->expire + 10);
            uniauth_storage_delete(stor);
            return;

            /* Control no longer in function. */
        }

        /* If the ID was not set, then we update the redirect URI and continue
         * to redirect the script.
         */
        if (!set_redirect_uri(stor)) {
            uniauth_storage_delete(stor);
            return;
        }
        uniauth_connect_commit(stor);
    }
    else {
        /* Create a new entry. The expiration time will be 0. This means the
         * session is marked as a temporary session until authentication has
         * been performed.
         */
        stor = &local;
        memset(stor,0,sizeof(struct uniauth_storage));
        stor->key = estrndup(sessid,sesslen);
        stor->keySz = sesslen;

        /* Fill out stor->redirect. */
        if (!set_redirect_uri(stor)) {
            uniauth_storage_delete(stor);
            return;
        }

        /* Send new record to the uniauth daemon. */
        uniauth_connect_create(stor);
    }

    /* URL-encode the key so we can safely pass it in a query string. */
    encoded = php_url_encode(stor->key,stor->keySz,&newlen);

    /* Allocate a buffer to hold the redirect header line. 'newlen' includes the
     * size needed for the trailing null character.
     */
    newlen += urllen + sizeof(LOCATION_HEADER) + sizeof(UNIAUTH_QSTRING) - 1;
    ctr.line = emalloc(newlen);

    /* Prepare the redirect header line. This will include a query parameter
     * that contains the uniauth session key.
     */
    snprintf(ctr.line,newlen,"%s%s%s%s",LOCATION_HEADER,url,UNIAUTH_QSTRING,encoded);
    ctr.line_len = newlen - 1;
    sapi_header_op(SAPI_HEADER_REPLACE,&ctr);
    efree(ctr.line);
    efree(encoded);

    /* Free memory allocated for uniauth record. */
    uniauth_storage_delete(stor);

    /* Terminate user script. */
    zend_bailout();
}

/* {{{ proto void uniauth_register(int id, string name, string displayName [, string key])
   Registers user information with the current session */
PHP_FUNCTION(uniauth_register)
{
    struct uniauth_storage backing;
    struct uniauth_storage* stor;
    long id;
    char* name;
    int namelen;
    char* displayname;
    int displaynamelen;
    char* sessid = NULL;
    int sesslen = 0;
    zval* zv;

    /* Grab id parameter from userspace. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"lss|s",&id,&name,&namelen,
            &displayname,&displaynamelen,&sessid,&sesslen) == FAILURE)
    {
        return;
    }

    /* Lookup session id from module globals or uniauth cookie if no explicit
     * key id was provided. This requires that the PHP session exist (via a call
     * to session_start()) OR the uniauth cookie being set via a call to
     * uniauth_cookie(). This function throws if no session was detected.
     */
    if (sessid == NULL) {
        if (UNIAUTH_G(useCookie)) {
            zv = GET_GLOBAL("_COOKIE","uniauth");
            if (zv == NULL) {
                zend_throw_exception(
                    NULL,
                    "no uniauth cookie session is available",
                    0 TSRMLS_CC);
                return;
            }
            sessid = Z_STRVAL_P(zv);
            sesslen = Z_STRLEN_P(zv);
        }
        else {
            sessid = PS(id);
            if (sessid == NULL) {
                zend_throw_exception(
                    NULL,
                    "no PHP session is available",
                    0 TSRMLS_CC);
                return;
            }
            sesslen = strlen(sessid);
        }
    }

    /* Lookup the uniauth_storage for the session. Create one if does not
     * exist. Then assign the id to the structure. An expiration is created
     * since we want this session to live (so we can keep registering new
     * sessions with it). If the expiration exists we touch it so it updates.
     */
    stor = uniauth_connect_lookup(sessid,sesslen,&backing);
    if (stor != NULL) {
        /* We will always override any current value. */
        stor->id = id;
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
        stor->expire = time(NULL) + PS(gc_maxlifetime);

        uniauth_connect_commit(stor);
    }
    else {
        stor = &backing;
        memset(stor,0,sizeof(struct uniauth_storage));
        stor->key = estrndup(sessid,sesslen);
        stor->keySz = sesslen;
        stor->id = id;
        stor->username = estrdup(name);
        stor->usernameSz = namelen;
        stor->displayName = estrdup(displayname);
        stor->displayNameSz = displaynamelen;
        stor->expire = time(NULL) + PS(gc_maxlifetime);

        uniauth_connect_create(stor);
    }

    /* Free uniauth record fields. */
    uniauth_storage_delete(stor);
}

/* {{{ proto void uniauth_transfer([string key])
   Completes the auth flow by transferring the current uniauth record into the
   awaiting applicant record */
PHP_FUNCTION(uniauth_transfer)
{
    struct uniauth_storage backing[2];
    struct uniauth_storage* src;
    struct uniauth_storage* dst;
    char* sessid = NULL;
    int sesslen = 0;
    char* foreignSession;
    size_t foreignSessionlen;
    sapi_header_line ctr = {0};
    zval* zv;

    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    /* Lookup session id from module globals or uniauth cookie if no explicit
     * key id was provided. This requires that the PHP session exist (via a call
     * to session_start()) OR the uniauth cookie being set via a call to
     * uniauth_cookie(). This function throws if no session was detected.
     */
    if (sessid == NULL) {
        if (UNIAUTH_G(useCookie)) {
            zv = GET_GLOBAL("_COOKIE","uniauth");
            if (zv == NULL) {
                zend_throw_exception(
                    NULL,
                    "no uniauth cookie session available",
                    0 TSRMLS_CC);
                return;
            }
            sessid = Z_STRVAL_P(zv);
            sesslen = Z_STRLEN_P(zv);
        }
        else {
            sessid = PS(id);
            if (sessid == NULL) {
                zend_throw_exception(
                    NULL,
                    "no PHP session is available",
                    0 TSRMLS_CC);
                return;
            }
            sesslen = strlen(sessid);
        }
    }

    /* Lookup the source session so that we can grab the foreign session
     * ID. This should have been recorded in the 'tag' field by a call to
     * uniauth_begin().
     */
    src = uniauth_connect_lookup(sessid,sesslen,backing);
    if (src == NULL) {
        zend_throw_exception(NULL,"source registration does not exist",0 TSRMLS_CC);
        return;
    }
    if (src->tag == NULL) {
        zend_throw_exception(NULL,"source registration did not apply",0 TSRMLS_CC);
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
        zend_throw_exception(NULL,"destination registration does not exist",0 TSRMLS_CC);
        uniauth_storage_delete(backing);
        return;
    }

    /* Transfer the info from the source record to the destination record. The
     * uniauth daemon will do this for us.
     */
    if (uniauth_connect_transfer(sessid,foreignSession) == -1) {
        zend_throw_exception(NULL,"transfer failed",0 TSRMLS_CC);
        uniauth_storage_delete(backing);
        uniauth_storage_delete(backing+1);
        return;
    }

    /* Add header to redirect back to pending page. */
    if (dst->redirect != NULL) {
        ctr.line = emalloc(dst->redirectSz + sizeof(LOCATION_HEADER));
        strcpy(ctr.line,LOCATION_HEADER);
        strcpy(ctr.line + sizeof(LOCATION_HEADER) - 1,dst->redirect);
        ctr.line_len = (uint)dst->redirectSz + sizeof(LOCATION_HEADER) - 1;
        sapi_header_op(SAPI_HEADER_REPLACE,&ctr);
        efree(ctr.line);
    }
    else {
        zend_throw_exception(NULL,"no redirect URI exists for the destination registration",0 TSRMLS_CC);
        uniauth_storage_delete(backing);
        uniauth_storage_delete(backing+1);
        return;
    }

    uniauth_storage_delete(backing);
    uniauth_storage_delete(backing+1);

    /* Terminate user script to perform redirect. */
    zend_bailout();
}

/* {{{ proto bool uniauth_check([string key])
   Determines if an authentication session exists */
PHP_FUNCTION(uniauth_check)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* sessid = NULL;
    int sesslen = 0;
    int result = 0;
    zval* zv;

    /* Grab parameters from userspace. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    /* Lookup session id from module globals or uniauth cookie if no explicit
     * key id was provided. This requires that the PHP session exist (via a call
     * to session_start()) OR the uniauth cookie being set via a call to
     * uniauth_cookie(). This function throws if no session was detected.
     */
    if (sessid == NULL) {
        if (UNIAUTH_G(useCookie)) {
            zv = GET_GLOBAL("_COOKIE","uniauth");
            if (zv == NULL) {
                zend_throw_exception(
                    NULL,
                    "no uniauth cookie session available",
                    0 TSRMLS_CC);
                return;
            }
            sessid = Z_STRVAL_P(zv);
            sesslen = Z_STRLEN_P(zv);
        }
        else {
            sessid = PS(id);
            if (sessid == NULL) {
                zend_throw_exception(
                    NULL,
                    "no PHP session is available",
                    0 TSRMLS_CC);
                return;
            }
            sesslen = strlen(sessid);
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

/* {{{ proto void uniauth_apply([string key])
   Begins the application process by creating the registrar session and assigning
   the session ID passed in $_GET['uniauth'] to it. */
PHP_FUNCTION(uniauth_apply)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* sessid = NULL;
    int sesslen = 0;
    zval* zv;
    char* applicantID;
    int create;

    /* Grab parameters from userspace. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    /* Lookup session id from module globals or uniauth cookie if no explicit
     * key id was provided. This requires that the PHP session exist (via a call
     * to session_start()) OR the uniauth cookie being set via a call to
     * uniauth_cookie(). This function throws if no session was detected.
     */
    if (sessid == NULL) {
        if (UNIAUTH_G(useCookie)) {
            zv = GET_GLOBAL("_COOKIE","uniauth");
            if (zv == NULL) {
                zend_throw_exception(
                    NULL,
                    "no uniauth cookie session available",
                    0 TSRMLS_CC);
                return;
            }
            sessid = Z_STRVAL_P(zv);
            sesslen = Z_STRLEN_P(zv);
        }
        else {
            sessid = PS(id);
            if (sessid == NULL) {
                zend_throw_exception(
                    NULL,
                    "no PHP session is available",
                    0 TSRMLS_CC);
                return;
            }
            sesslen = strlen(sessid);
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
        zend_throw_exception(NULL,"no 'uniauth' query parameter was specified",0 TSRMLS_CC);
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
    }
}

/* {{{ proto void uniauth_purge([string key])
   Ends the current uniauth session */
PHP_FUNCTION(uniauth_purge)
{
    struct uniauth_storage local;
    struct uniauth_storage* stor;
    char* sessid = NULL;
    int sesslen = 0;
    int result = 0;
    zval* zv;

    /* Grab session id from user space. */
    if (zend_parse_parameters(ZEND_NUM_ARGS(),"|s",&sessid,&sesslen) == FAILURE) {
        return;
    }

    /* Lookup session id from module globals or uniauth cookie if no explicit
     * key id was provided. This requires that the PHP session exist (via a call
     * to session_start()) OR the uniauth cookie being set via a call to
     * uniauth_cookie(). This function throws if no session was detected.
     */
    if (sessid == NULL) {
        if (UNIAUTH_G(useCookie)) {
            zv = GET_GLOBAL("_COOKIE","uniauth");
            if (zv == NULL) {
                zend_throw_exception(
                    NULL,
                    "no uniauth cookie session available",
                    0 TSRMLS_CC);
                return;
            }
            sessid = Z_STRVAL_P(zv);
            sesslen = Z_STRLEN_P(zv);
        }
        else {
            sessid = PS(id);
            if (sessid == NULL) {
                zend_throw_exception(
                    NULL,
                    "no PHP session is available",
                    0 TSRMLS_CC);
                return;
            }
            sesslen = strlen(sessid);
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

/* {{{ proto string uniauth_cookie()
   Generates and/or retrieves a unique uniauth session and sets this session
   to be used instead of the PHP session */
PHP_FUNCTION(uniauth_cookie)
{
    zval* sessid;

    /* Get the session id from the cookie. If none was found then generate a new
     * session id.
     */
    sessid = GET_GLOBAL("_COOKIE","uniauth");
    if (sessid == NULL) {
        int i, j;
        int outlen;
        unsigned char* outbuf;
        unsigned char buf[UNIAUTH_COOKIE_IDLEN / 4 * 3];
        char output[UNIAUTH_COOKIE_IDLEN+1];

        i = 0;
        while (i < sizeof(buf)) {
            long n;
            n = php_rand(TSRMLS_C);
            RAND_RANGE(n,0,0xff,PHP_RAND_MAX);
            buf[i] = (unsigned char)n;
            i += 1;
        }

        memset(output,'0',sizeof(output));
        outbuf = php_base64_encode(buf,sizeof(buf),&outlen);
        if (outbuf == NULL) {
            RETURN_FALSE;
        }
        outlen = (outlen > UNIAUTH_COOKIE_IDLEN ? UNIAUTH_COOKIE_IDLEN : outlen);
        memcpy(output,outbuf,outlen);
        efree(outbuf);

        output[UNIAUTH_COOKIE_IDLEN] = 0;
        ALLOC_INIT_ZVAL(sessid);
        ZVAL_STRING(sessid,output,1);

        /* Go ahead and set the cookie in the superglobal so it is available for
         * this script. Subsequent calls to the uniauth extension could require
         * the global to be set.
         */
        SET_GLOBAL("_COOKIE","uniauth",sessid);
    }

    /* Toggle global flag to indicate the extension should use the uniauth
     * cookie instead of the PHP session.
     */
    UNIAUTH_G(useCookie) = 1;

    /* Create/touch the cookie. */
    php_setcookie(
        "uniauth", sizeof("uniauth") - 1,
        Z_STRVAL_P(sessid), Z_STRLEN_P(sessid),
        time(NULL) + PS(gc_maxlifetime),
        "/", sizeof("/") - 1,
        NULL,0,
        0,1,0 TSRMLS_CC);

    /* Return a copy of the zval. We need to preserve the sessid zval since it
     * lives in the _COOKIE hashtable.
     */
    RETVAL_ZVAL(sessid,1,0);
}
