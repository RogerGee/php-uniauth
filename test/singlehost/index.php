<?php

/**
 * index.php - uniauth/test
 *
 * Run the PHP CLI SAPI in the test directory on localhost, port 8080. This
 * application will use a 'uniauth' cookie to store the session id.
 */

if (!function_exists('uniauth')) {
    error_log("uniauth extension is not enabled");
    exit(1);
}

uniauth_cookie();
$info = uniauth("http://localhost:8080/login.php");

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
