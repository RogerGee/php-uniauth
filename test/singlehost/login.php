<?php

function d() {
    global $blocked;
    if (isset($blocked) && $blocked) {
        print 'disabled';
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $blocked = false;
    if (!isset($_POST['user'],$_POST['pass'],$_COOKIE['uniauth'])) {
        http_response_code(403);
        $blocked = true;
        $fail = 'The session or request is invalid. Please begin the auth flow again.';
    }
    else {
        list($user,$pass,$id) = array($_POST['user'],$_POST['pass'],$_COOKIE['uniauth']);
        if ($user == "john" && $pass == "alphabet") {
            try {
                error_log('register');
                uniauth_register(1,'john','John Doe',$id);
                error_log('transfer');
                uniauth_transfer($id);
                exit;
            } catch (Exception $ex) {
                http_response_code(403);
                $blocked = true;
                $fail = 'You session window expired. Please try again.';
                setcookie('uniauth',false,1);
            }
        }
        else {
            /* Bad login: show the form again to let the user have another go. */
            http_response_code(403);
            $fail = "Bad username or password";
        }
    }
}
else if (isset($_GET['uniauth'])) {
    /* Do application step. */

    if (isset($_COOKIE['uniauth'])) {
        if (uniauth_check($_COOKIE['uniauth'])) {
            error_log("transfer");
            uniauth_transfer($_COOKIE['uniauth']);
            exit;
        }

        $id = $_COOKIE['uniauth'];
        error_log("got cookie $id");
    }
    else {
        error_log('setting registrar cookie');
        $id = uniqid('uniauth');
        setcookie('uniauth',$id,0);
    }

    error_log('apply');
    uniauth_apply($id);

    // Force another redirect to hide query parameter.
    $uri = explode('?',$_SERVER['REQUEST_URI'],2)[0];
    error_log("redir to $uri");
    header("Location: $uri");
    exit;
}
?>
<!doctype>
<html>
  <head>
    <meta charset="utf-8">
    <title>uniauth/test - login</title>
  </head>
  <body>
    <center style="margin:10% 20%">
      <form action="/login.php" method="post" style="margin:50 auto;padding:10px;width:465px">
        <div style="padding:10px;width:100%;">
          <label style="float:left">username:</label><br>
          <input type="text" name="user" style="width:100%" <?php d();?>>
        </div>

        <div style="padding:10px;width:100%">
          <label style="float:left">password:</label><br>
          <input style="width:100%" type="text" name="pass" <?php d();?>>
        </div>

        <div style="padding:10px;float:right">
          <input type="submit" value="Log in" <?php d();?>>
        </div>
      </form>
      <div style="max-width:465px;color:#ff0000;text-align:left">
        <?php if (isset($fail)) print $fail?>
      </div>
      <?php if (isset($blocked) && $blocked):?>
        <div style="max-width:465px;color:#ff0000;text-align:left">
          You can return to the index <a href="/">here</a>.
        </div>
      <?php endif;?>
    </center>
  </body>
</html>
