<?php

require_once("../src/snapchat.php");

//////////// CONFIG ////////////
$username = ""; // Your snapchat username
$password = ""; // Your snapchat password
$gEmail   = ""; // Gmail account
$gPasswd  = ""; // Gmail account password
$debug = false; // Set this to true if you want to see all outgoing requests and responses from server
////////////////////////////////


$imagePath = ""; // URL or local path to a media file (image or video)
$sendTo = array();

$snapchat = new Snapchat($username, $gEmail, $gPasswd, $debug);

//Login to Snapchat with your username and password
$snapchat->login($password);

// Get your friends in an array
$friends = $snapchat->getFriends();

echo "My friends: ";
print_r($friends);

// Send snap adding text to your image and 10 seconds
$snapchat->send($imagePath, $sendTo, "this is a test :D", 10);

// Set a story
// $snapchat->setStory($imagePath);

// Set a story adding text to the image and 5 seconds
$snapchat->setStory($imagePath, 5, "This is my story");


// Get snaps data (Without storing them)
//$snapchat->getSnaps();

// Automatically downloads Snaps and store it in 'Snaps' folder
$snapchat->getSnaps(true);

// Send chat message to "username"
$snapchat->sendMessage("username", "hello from Snap-API!");

$snapchat->closeAppEvent();

?>
