<?php

require_once('../src/snapchat.php');


//////////// CONFIG ////////////
$username = ''; // Your snapchat username
$password = ''; // Your snapchat password
$debug = false; // Set this to true if you want to see all outgoing requests and responses from server
////////////////////////////////


$path = ''; // URL or local path to a media file (image or video)
$to = ''; // the username you want to send the media to


$snapchat = new Snapchat($username, $auth_token, $debug);

//Login to Snapchat with your username and password
$snapchat->login($username, $password);

// This send a media with default time 3 seconds
$snapchat->send($path, $to);

// Send snap adding text to your image and 10 seconds
$snapchat->send($path, $to, 'This is a test :D', 10);

// Set a story
$snapchat->setStory($path);

// Set a story adding text to the image and 5 seconds
$snapchat->setStory($path, 5, 'This is my story');

?>
