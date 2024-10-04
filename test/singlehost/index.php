<?php

/**
 * index.php - uniauth/test
 *
 * Run the PHP CLI SAPI in the test directory on localhost, port 8080. This
 * application will use a 'uniauth' cookie to store the session id.
 */

if (!function_exists('uniauth')) {
    throw new Error("uniauth extension is not enabled");
}

error_log('uniauth_cookie()');
uniauth_cookie();

error_log('uniauth()');
$info = uniauth("http://localhost:8080/login.php");
error_log('  => ' . var_export($info,true));

?>
<!doctype>
<html>
  <head>
    <meta charset="utf-8">
    <title>uniauth/test</title>
  </head>
  <body>
    <h1>Congratulations - you passed and have a session!</h1>
    <h2>Uniauth session info</h2>
    <table>
      <tr><td>ID</td><td><?php print $info['id'];?></td></tr>
      <tr><td>Username</td><td><?php print $info['user'];?></td></tr>
      <tr><td>Display Name</td><td><?php print $info['display'];?></td></tr>
    </table>
    <p>
      Click <a href="/signout.php">here</a> to sign out.
    </p>
  </body>
</html>
