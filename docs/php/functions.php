<?php

/**
 * Look up a uniauth session. If a $url is provided, the function redirects if no session was found.
 */
function uniauth(string $url = null,string $session_id = null) : ?array {}

/**
 *
 */
function uniauth_register(int $id,string $name,string $display_name,string $session_id = null,int $lifetime = 0) : void {}

/**
 *
 */
function uniauth_transfer(string $session_id = null) : void {}

/**
 *
 */
function uniauth_check(string $session_id = null) : bool {}

/**
 *
 */
function uniauth_apply(string $session_id = null) : void {}

/**
 *
 */
function uniauth_purge(string $session_id = null) : bool {}

/**
 *
 */
function uniauth_cookie() : string {}
