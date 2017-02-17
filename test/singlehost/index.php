<?php

/**
 * index.php - uniauth/test
 *
 * Run the PHP CLI SAPI in the test directory on localhost, port 8080. This
 * application will create two cookies, one for the index page and another for
 * the login page.
 */

if (!function_exists('uniauth')) {
    error_log("uniauth extension is not enabled");
    exit(1);
}

if (!isset($_COOKIE['uniauth'])) {
    $id = uniqid('uniauth');

    /* We need to go ahead and set the cookie. This allows us to still use
     * uniauth on the same host (if need would be).
     */
    setcookie('uniauth',$id,0);
}
else {
    $id = $_COOKIE['uniauth'];
}

$info = uniauth("http://localhost:8080/login.php",$id);
setcookie('uniauth',$id,$info['expire']);

?>
<!doctype>
<html>
  <head>
    <title>Uniauth test</title>
  </head>
  <body>
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
