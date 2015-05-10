<?php

include_once("../src/snapchat.php");


echo "\n\nUsername: ";
$username = trim(fgets(STDIN));

echo "\nPassword: ";
$password = trim(fgets(STDIN));

echo "\nEmail: ";
$email = trim(fgets(STDIN));

echo "\nBirthday (yyyy-mm-dd): ";
$birthday = trim(fgets(STDIN));

echo "\nGmail address: ";
$gMail = trim(fgets(STDIN));

echo "\nGmail password: ";
$gPasswd = trim(fgets(STDIN));

$snapchat = new Snapchat($username, $gMail, $gPasswd, true);


$id = $snapchat->register($username, $password, $email, $birthday);

echo "\nYou should have a file called '{$id}' in your snap api folder, unzip it.\n";
echo "9 images. If there is a ghost in a image means 1, if not 0\n";
echo "The result should be like the following one: 110000101\n";
echo "After completion, the zip file will be deleted automatically.\n\n";

echo "\nResult: ";
$result = trim(fgets(STDIN));

$result = $snapchat->sendCaptcha($result, $id);
unlink(__DIR__."{$id}");
if ($result == null)
{
    echo "Account successfully created\n";
    echo "\nUsername: $username\n";
    echo "Password: $password\n";
    echo "Email: $email\n";
}
else {
    echo "There was an error registering your account\n";
    echo "Error code: " . $result['code'];
}
