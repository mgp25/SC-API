<?php

function text($image, $text, $leftY = 500, $png=false){
	$leftY = $leftY + (0.054 * imagesy($image))/2;
    $font = __DIR__ . '/fonts/Roboto-Light.ttf';
    $leftX = 0;
    $rightX = imagesx($image);
    $rightY = $leftY - (0.054 * imagesy($image));
    $black = imagecolorallocatealpha($image, 0, 0, 0, 50);
    $whiteText = imagecolorallocate($image, 255, 255, 255);
    imagefilledrectangle($image, $leftX, $leftY, $rightX, $rightY, $black);
    $boundingBox = imagettfbbox((0.021 * imagesy($image)), 0, $font, $text);
    $box = imagettfbbox((0.021 * imagesy($image)), 0, $font, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"); //Tallest character
    $textheight = abs($box[3] - $box[5]);
    $x = ($rightX - ($boundingBox[0] + $boundingBox[2])) / 2;
    imagettftext($image, (0.021 * imagesy($image)), 0, $x, $leftY - (((0.054 * imagesy($image)) - $textheight) /2), $whiteText, $font, $text);
    ob_start();
    if ($png){
        imagepng($image);
    }else{
        imagejpeg($image);
    }
    $image_data = ob_get_contents();
    ob_end_clean();
    imagedestroy($image);
    return $image_data;
}
?>
