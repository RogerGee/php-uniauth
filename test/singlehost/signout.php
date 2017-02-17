<?php

if (isset($_COOKIE['uniauth'])) {
    uniauth_purge($_COOKIE['uniauth']);
    header('Location: /');
    exit;
}

header('Content-Type: text/plain');
echo 'No uniauth context' . PHP_EOL;
