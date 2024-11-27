/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: ec70e9c53c37197c421b8a9fc2e49020afa3fa29 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_uniauth, 0, 0, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, url, IS_STRING, 0, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, session_id, IS_STRING, 0, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, redirect_url, IS_STRING, 0, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_uniauth_register, 0, 3, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, id, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, display_name, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, session_id, IS_STRING, 0, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, lifetime, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_uniauth_transfer, 0, 0, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, session_id, IS_STRING, 0, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_uniauth_check, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, session_id, IS_STRING, 0, "null")
ZEND_END_ARG_INFO()

#define arginfo_uniauth_apply arginfo_uniauth_transfer

#define arginfo_uniauth_purge arginfo_uniauth_check

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_uniauth_cookie, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()
