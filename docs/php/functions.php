<?php

/**
 * Look up the registered uniauth session.
 *
 * @param string $url
 *  (optional) The URL of the registrar endpoint. If provided, the function will
 *  redirect to this endpoint when no registered session is found; in this case,
 *  the program will end before this function returns.
 * @param string $session_id
 *  (optional) The session ID to use instead of the default ID.
 * @param string $redirect_url
 *  (optional) The URL to which the registrar endpoint redirects upon success.
 *  If omitted, then the redirect URL will be generated from the server
 *  environment automatically.
 *
 * @return ?array
 *  Returns the login array if there is a registered session. Otherwise NULL is
 *  returned if and only if $url is not set. A login array has the following
 *  structure:
 *    array (
 *      'id' => 1000,
 *      'user' => 'name',
 *      'display' => 'User Name',
 *    )
 *
 * @throws \Exception If superglobals cannot be activated.
 * @throws \Uniauth\Exception
 *  Having codes:
 *   - UNIAUTH_ERROR_NO_SESSION
 */
function uniauth(string $url = null,string $session_id = null,string $redirect_url = null) : ?array {}

/**
 * Registers an existing uniauth session using the indicated user information.
 *
 * @param int $id
 *  The user ID to store in the registration.
 * @param string $name
 *  The user name (i.e. handle) to store in the registration.
 * @param string $display_name
 *  The user display name to store in the registration.
 * @param string $session_id
 *  (optional) The session ID to use instead of the default ID.
 * @param int $lifetime
 *  (optional) Defines the session lifetime value (in seconds).
 *
 *  If this value is omitted or a non-positive number, then the session will
 *  have a lifetime equal to the value of the php.ini option "uniauth.cookie"
 *  and the uniauth cookie (if enabled) is a persistent cookie. Otherwise the
 *  uniauth session has the specified lifetime and the cookie is
 *  non-persistent.
 *
 * @throws \Exception If superglobals cannot be activated.
 * @throws \Uniauth\Exception
 *  Having codes:
 *   - UNIAUTH_ERROR_INVALID_SERVERVARS
 *   - UNIAUTH_ERROR_NO_SESSION
 */
function uniauth_register(int $id,string $name,string $display_name,string $session_id = null,int $lifetime = 0) : void {}

/**
 * Links the current, registered session with its applicant session. Control
 * is redirected back to the applicant upon success.
 *
 * @param string $session_id
 *  (optional) The session ID to use instead of the default ID.
 *
 * @return never
 *  This function does not return. It bails out when redirecting upon success
 *  and raises exceptions/errors upon failure.
 *
 * @throws \Exception If superglobals cannot be activated.
 * @throws \Uniauth\Exception
 *  Having codes:
 *   - UNIAUTH_ERROR_NO_SESSION
 *   - UNIAUTH_ERROR_SOURCE_NOT_EXIST
 *   - UNIAUTH_ERROR_SOURCE_NOT_APPLY
 *   - UNIAUTH_ERROR_DEST_NOT_EXIST
 *   - UNIAUTH_ERROR_TRANSFER_FAILED
 *   - UNIAUTH_ERROR_MISSING_REDIRECT
 */
function uniauth_transfer(string $session_id = null) : never {}

/**
 * Determines if a registered session exists.
 *
 * @param string $session_id
 *  (optional) The session ID to use instead of the default ID.
 *
 * @return bool
 *  Returns TRUE if a registered session exists; FALSE otherwise.
 *
 * @throws \Exception If superglobals cannot be activated.
 * @throws \Uniauth\Exception
 *  Having codes:
 *   - UNIAUTH_ERROR_NO_SESSION
 */
function uniauth_check(string $session_id = null) : bool {}

/**
 * Applies a foreign session ID from $_GET['uniauth'] to the current session to
 * prepare for a future transfer operation. The current session is created if it
 * does not exist.
 *
 * @param string $session_id
 *  (optional) The session ID to use instead of the default ID.
 *
 * @throws \Exception If superglobals cannot be activated.
 * @throws \Uniauth\Exception
 *  Having codes:
 *   - UNIAUTH_ERROR_NO_SESSION
 *   - UNIAUTH_ERROR_MISSING_UNIAUTH_PARAM
 */
function uniauth_apply(string $session_id = null) : void {}

/**
 * Unregisters the current session.
 *
 * @param string $session_id
 *  (optional) The session ID to use instead of the default ID.
 *
 * @return bool
 *  Returns TRUE if the session was valid and was invalidated, FALSE otherwise.
 *
 * @throws \Exception If superglobals cannot be activated.
 * @throws \Uniauth\Exception
 *  Having codes:
 *   - UNIAUTH_ERROR_NO_SESSION
 */
function uniauth_purge(string $session_id = null) : bool {}

/**
 * Enables use of a uniauth cookie. This overrides the default behavior of
 * utilizing the PHP session.
 *
 * @return string
 *  Returns the randomly-generated ID for the cookie (i.e. the value assigned
 *  to $_COOKIE['uniauth']).
 *
 * @throws \Exception If superglobals cannot be activated.
 */
function uniauth_cookie() : string {}
