<?php

function d() {
    global $blocked;
    if ($blocked) {
        print 'disabled';
    }
}

// We use uniauth cookies to track uniauth sessions. The cookie will be shared
// between the applicant/registrar endpoints.
uniauth_cookie();

$blocked = false;
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Make sure the request was good.
    if (!isset($_POST['user'],$_POST['pass'])) {
        http_response_code(403);
        $blocked = true;
        $fail = 'The session or request is invalid. Please begin the auth flow again.';
    }
    else {
        // Try to perform sign in.
        list($user,$pass) = array($_POST['user'],$_POST['pass']);
        if ($user == "john" && $pass == "alphabet") {
            try {
                error_log('register');
                uniauth_register(1,'john','John Doe',null,30);
                error_log('transfer');
                uniauth_transfer();

                // Control no longer in this program.
                exit;
            } catch (Exception $ex) {
                http_response_code(403);
                $blocked = true;
                $fail = 'You session window expired. Please try again.';
            }
        }
        else {
            /* Bad login: show the form again to let the user have another go. */
            http_response_code(403);
            $fail = "Bad username or password";
        }
    }
}
else {
    /* Do application step. */

    // If we have a valid session, just transfer it immediately.
    if (uniauth_check()) {
        error_log("immediate transfer");
        uniauth_transfer();

        // Control no longer in this program.
        exit;
    }

    if (isset($_GET['uniauth'])) {
        error_log('apply');
        uniauth_apply();

        // Force another redirect to hide query parameter.
        $uri = explode('?',$_SERVER['REQUEST_URI'],2)[0];
        error_log("redir to $uri");
        header("Location: $uri");
        exit;
    }
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
