<?php

include_once("../src/snapchat.php");


echo "\n\nUsername: ";
$username = trim(fgets(STDIN));

echo "\nPassword: ";
$password = trim(fgets(STDIN));

echo "\nGmail account: ";
$gEmail = trim(fgets(STDIN));

echo "\nGmail password: ";
$gPasswd = trim(fgets(STDIN));

echo "\nCasper key: ";
$casperKey = trim(fgets(STDIN));

echo "\nCasper secret: ";
$casperSecret = trim(fgets(STDIN));

echo "\nPhone number: ";
$phone = trim(fgets(STDIN));

$snapchat = new Snapchat($username, $gEmail, $gPasswd, $casperKey, $casperSecret, true);

$snapchat->login($password);

$snapchat->sendPhoneVerification($phone);

echo "\nCode: ";
$code = trim(fgets(STDIN));

$snapchat->verifyPhoneNumber($code);
