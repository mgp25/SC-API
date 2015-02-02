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

$snapchat->login($username, $password);

$snapchat->send($path, $to); // This send the media with default time 3 seconds

// if you have a previously $media_id, you can use it directly in the function. 10 seconds media.
$snapchat->send($path, $to, 10, $media_id);

?>
