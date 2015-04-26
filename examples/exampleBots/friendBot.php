<?php

include_once("../../src/snapchat.php");

/////////// DATA /////////////
$username = '';
$password = '';
$gEmail   = '';
$gPasswd  = '';
$debug    = false;
//////////////////////////////

// Login
$snapchat = new Snapchat($username, $gEmail, $gPasswd, $debug);
$snapchat->login($password);

// Get unconfirmed friends
$unconfirmed = $snapchat->getUnconfirmedFriends();

// Add them
if (!is_null($unconfirmed))
{
  print_r($unconfirmed);
  foreach($unconfirmed as $friend)
      $snapchat->addFriendBack($friend);
}

$snapchat->closeAppEvent();
