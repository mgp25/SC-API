<?php
function text($image, $text)
{
    //create resource from image page
    $image = imagecreatefromjpeg($image);
    $font = __DIR__ . '/fonts/Roboto-Light.ttf';
    //leftmost side of image
    $leftX = 0;
    //width of image
    $rightX = imagesx($image);
    //half the height of the image
    $leftY = imagesy($image) / 2;
    //high with padding added for text height, scaled
    $rightY = $leftY - (0.04 * imagesy($image));
    //create rgb(0, 0, 0) with 0.75 alpha for opacity for box background
    $black = imagecolorallocatealpha($image, 0, 0, 0, 75);
    //create rgb(255, 255, 255) for text color
    $whiteText = imagecolorallocate($image, 255, 255, 255);
    //add rectangle
    imagefilledrectangle($image, $leftX, $leftY, $rightX, $rightY, $black);
    //get bounding box for text
    $boundingBox = imagettfbbox((0.03 * imagesy($image)), 0, $font, $text);
    //calculate leftmost x position for text placement to be in center
    $x = ($rightX - ($boundingBox[0] + $boundingBox[2])) / 2;
    //add text to image in box
    imagettftext($image, (0.03 * imagesy($image)), 0, $x, ($leftY - ($leftY * 0.015)), $whiteText, $font, $text);
    //save new image with text as jpeg
    imagejpeg($image, __DIR__ . "/cache/image.jpg");
    //get image data
    $fileData = file_get_contents(__DIR__ . "/cache/image.jpg");
    //remove image from memory and remove from disk
    imagedestroy($image);
    unlink(__DIR__ . '/cache/image.jpg');
    //return jpeg data
    return $fileData;
}
