<?php

include_once("../src/snapchat.php");


echo "\n\nUsername: ";
$username = trim(fgets(STDIN));

echo "\nPassword: ";
$password = trim(fgets(STDIN));

echo "\Phone number: ";
$phone = trim(fgets(STDIN));

$snapchat = new Snapchat($username, true);

$snapchat->login($username, $password);

$snapchat->sendPhoneVerification($phone);

echo "\Code: ";
$code = trim(fgets(STDIN));

$snapchat->verifyPhoneNumber($code);
