<?php

include_once('/Users/mgp25/Desktop/Snap-API/src/snapchat.php');


echo "\n\nUsername: ";
$username = trim(fgets(STDIN));

echo "\n\Password: ";
$password = trim(fgets(STDIN));

echo "\n\Email: ";
$email = trim(fgets(STDIN));

echo "\n\Birthday (yyyy-mm-dd): ";
$birthday = trim(fgets(STDIN));

$snapchat = new Snapchat($username, $auth_token, true);


$id = $snapchat->register($username, $password, $email, $birthday);

echo "You should have a file called 'captcha.zip' in your snap api folder, unzip it.\n";
echo "9 images. If there is a ghost in a image means 1, if not 0\n";
echo "The result should be like the following one: 110000101\n\n";

echo "\n\Result: ";
$result = trim(fgets(STDIN));

$snapchat->sendCaptcha($result, $id, $username);
