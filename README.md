# php-uniauth

This project provides a PHP extension that implements a `uniauth` client. `uniauth` is a client-server protocol used to implement single, universal sign-on for applications that utilize a common `uniauth` server instance.

The implementation consists of an extension that provides PHP userspace with a high-level interface for connecting with a `uniauth` server and manipulating sessions.

### Primary Author

> [Roger Gee](https://github.com/RogerGee)

## About Uniauth

`uniauth` for PHP is an alternative to using the built in `session` extension for managing user authentication sessions (although it can be used alongside `session` if needed). It is a simple, client-server protocol that allows the client to create and manage authentication sessions within a remote server. The server can "link" multiple sessions together so that they refer to the same authentication record. This allows applications to share authentication even if they exist on different cookie domains or subpaths.

> `uniauth` should only be used within an internal, trusted network. It is not designed to authenticate external applications to implement SSO (e.g. as in `oauth2`).

### Uniauth Authentication Flow

`uniauth` implements a user authentication flow for web applications. This flow involves a persistent `uniauth` server and a stateless client. Whenever the client needs to check user authentication, it connects to the server and queries a session record by ID. Likewise, when the client needs to create and authenticate a session, it uses the server to store and update the session information.

There are two distinct application roles involved in the flow:

1. Applicant
2. Registrar

The _applicant_ endpoint queries an authentication session and, if no registered session is found, redirects to the registrar endpoint for registration. If the user authenticates successfully, the registrar registers a new session record (if needed) and transfers (i.e. links) its registered session into the applicant session. The registrar then redirects the user-agent back to the applicant, at which time the applicant retrieves its registered session. This entire process happens transparently in the applicant: the applicant does not have to handle both cases separately.

The _registrar_ endpoint provides a means to collect user credentials and authenticate users. Once the registrar has verified user credentials, it commits the collected user ID and name (along with a display name) to its session. At this point, the session is considered registered.

While the specifics of `uniauth` sessions may differ between server implementations, the basic idea is that a single registration is maintained among all applicants targeting the same registrar. The means that the server internally connects the applicant and registrar sessions so that they point at the same registration. This allows applicants from different domains (i.e. having different session IDs) to utilize the same sign-on.

### Server Implementations

The following projects provide `uniauth` servers:

| Platform | Networking Domain | Session Persistence? | URL                                          |
| -------- | ----------------- | -------------------- | -------------------------------------------- |
| Linux    | AF_UNIX           | No                   | https://git.rserver.us/network/uniauthd.git  |
| Node.js  | AF_INET, AF_UNIX  | Yes (SQLite)         | https://github.com/RogerGee/node-uniauth.git |

## Building

The project is built in the usual way of PHP extensions. You must have the PHP development system installed and be using PHP 8. (See other branches for earlier versions of PHP.)

~~~shell
# Generate build files:
phpize

# Configure as needed:
./configure

# Compile:
make
~~~

## Configuring

Enable the extension in your `php.ini` file like so:

~~~ini
[PHP]
extension = uniauth
~~~

The extension has a few initialization properties you may configure. These are configured in `php.ini` under the `uniauth` section.

| Property Name         | Type    | Meaning                                                                                                           | Default Value |
| --------------------- | ------- | ----------------------------------------------------------------------------------------------------------------- | ------------- |
| `uniauth.socket_path` | String  | The path of the UNIX socket used to connect to the server (use the `@` prefix to indicate the abstract namespace) |               |
| `uniauth.socket_host` | String  | The host name of the INET server                                                                                  |               |
| `uniauth.socket_port` | Integer | The port number of the INET server                                                                                | `7033`        |
| `uniauth.lifetime`    | Integer | Defines the lifetime (in seconds) for persistent sessions                                                         | `86400`       |

## Usage

### Applicants

The core function used by applicants is `uniauth()`, which checks to see if a registration exists for the current session (i.e. checks if the session is authenticated). If not, it transparently redirects the user-agent to the registrar endpoint (if specified) or returns `NULL` if no endpoint was provided. Otherwise, the function returns the login array for the session. The login array is an associative array having `id`, `user` and `display` fields:

~~~php
<?php

$login = uniauth('http://auth.localhost/login.php');
/* Control no longer in program if redirected
   (i.e. we don't have a valid session). */

var_export($login);
/*
array (
  'id' => 33,
  'user' => 'roger',
  'display' => 'Roger Gee',
)
*/
~~~

When an applicant redirects to a registrar, it passes its `uniauth` session ID via a `GET` query parameter named `uniauth`. This allows the registrar to identify the target session that is to be associated with the registration should authentication be successful.

### Registrars

The registrar's job is to register sessions after successfully authenticating users. It can then transfer (i.e. link) its session registration in the registrar domain to a foreign session in the applicant domain. (It is also valid for the registrar and applicant domains to be the same; the transfer works in the same way, even though it is effectively a no-op.)

The first call a registrar should make is to `uniauth_apply()`. This call creates a new session if one did not already exist. The registrar session is annotated with the session ID of the applicant. (The extension pulls this value automatically from `$_GET['uniauth']`.) The applicant ID is used later when transferring (i.e. linking) the session.

If the registrar session is not authenticated, then the registrar should validate user credentials and register the session with `uniauth_register()`. The `uniauth_check()` function can be used to determine whether a session is valid.

Once the registrar has determined that it has a valid registration session, it can then transfer (i.e. link) the sessions via `uniauth_transfer()`. The transfer function utilizes the annotation previously established via `uniauth_apply()` to determine the applicant session.

Example usage:

~~~php
function get() {
  uniauth_apply();
  if (uniauth_check()) {
    // If the session is already registered, transfer.
    uniauth_transfer();
    // Control no longer in this program.
  }

  // Render login form...
}

function post() {
  // Handle user authentication; if failed, render login form and exit...

  $lt = $is_persistent ? 0 : 1800;
  uniauth_register($id,$user,$display,lifetime: $lt);
  uniauth_transfer();
  // Control no longer in this program.
}

// Enable session management: one or the other
//session_start();
uniauth_cookie();

// routing goes here... call get() or post()
~~~

One common idiom is to redirect after `uniauth_apply()` in order to hide the `uniauth` query parameter. It is no longer needed after the apply operation since it is stored in the registrar session.

#### Logging Out

To explicitly invalidate a `uniauth` session, the `uniauth_purge()` function may be employed. This function clears out the registration associated with the session ID so the user login status is void. Note that this will log out all services (i.e. applicants) that have sessions referencing the registration. The session record is not technically freed until it expires naturally. This means the same session IDs can be reused for future authentications until the user-agent drops the cookie.

### Sessions

The extension provides two mechanisms for allocating and tracking sessions. One is to utilize the PHP built-in `session` functionality so that the `uniauth` session has the same identifier as the PHP session. The other method is for the extension to generate its own `uniauth` cookie (i.e. `$_COOKIE['uniauth']`) that is used to track the `uniauth` session ID.

> Note: when using PHP sessions, only the session ID is employed. The PHP session storage is _not_ utilized to store any `uniauth` session information. You are free to use `$_SESSION` according to your needs. We recommend using PHP sessions only if you need to use the storage. Otherwise, `uniauth_cookie()` is preferred.

To utilize the PHP session, you must call `session_start()` to allocate/load the PHP session; otherwise you must call `uniauth_cookie()` to allocate/load a `uniauth` cookie. Note that - by default - the extension will check the PHP session; you must call `uniauth_cookie()` before making calls to other extension functions to override this behavior.

Cookies created by the extension are only available on the single domain, but to all subpaths.

~~~php
<?php

// This call will use the PHP session ID.
session_start();
uniauth("http://localhost/auth.php");

// This call will use the generated uniauth cookie.
uniauth_cookie();
uniauth("http://localhost/auth.php");
~~~

### API Reference

See the `docs/php` directory for in-depth API documentation. You can target this directory to provide stubs for a code editor.
