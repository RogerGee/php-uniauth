<?php

/**
 * One or more $_SERVER variables are missing or incorrect.
 */
define('UNIAUTH_ERROR_INVALID_SERVERVARS',100);

/**
 * The uniauth session identifier could not be loaded from either the PHP
 * session or the uniauth cookie.
 */
define('UNIAUTH_ERROR_NO_SESSION',101);

/**
 * The source (i.e. registrar) session of a transfer operation does not exist.
 */
define('UNIAUTH_ERROR_SOURCE_NOT_EXIST',102);

/**
 * The source (i.e. registrar) session of a transfer operation has not applied.
 */
define('UNIAUTH_ERROR_SOURCE_NOT_APPLY',103);

/**
 * The destination (i.e. applicant) session of a transfer operation does not exist.
 */
define('UNIAUTH_ERROR_DEST_NOT_EXIST',104);

/**
 * An unspecified error occurred during the transfer operation.
 */
define('UNIAUTH_ERROR_TRANSFER_FAILED',105);

/**
 * The destination session did not supply a redirect URL and the system cannot
 * complete the transfer.
 */
define('UNIAUTH_ERROR_MISSING_REDIRECT',106);

/**
 * The apply operation could not determine the applicant session ID using the
 * uniauth query parameter.
 */
define('UNIAUTH_ERROR_MISSING_UNIAUTH_PARAM',107);
