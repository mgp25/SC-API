<?php

function text($image, $text, $type="png")
{
  $image = imagecreatefromjpeg($image);
  $font = __DIR__ . '/fonts/Roboto-Light.ttf';
  $pos_x1 = 0;
  $pos_x2 = 1300;
  $pos_y1 = 1600;
  $pos_y2 = 1700;
  $black = imagecolorallocatealpha($image, 0, 0, 0, 75);
  $whiteText = imagecolorallocate($image, 250, 250, 250);
  imagefilledrectangle($image, $pos_x1, $pos_y1, $pos_x2, $pos_y2, $black);
  $bbox = imagettfbbox(50, 0, $font, $text);
  $x = (imagesx($image)/2 - 15*strlen($text));
  imagettftext($image, 50, 0, $x, 1675, $whiteText, $font, $text);
  $res = imagepng($image, __DIR__ . '/cache/image.png');
  ob_start()
  if ($type == "png"){
    imagepng($image);
  }elseif($type == "gif"){
    imagegif($image);
  }else{
    imagejpeg($image);
  }
  $res = ob_get_contents()
  imagedestroy($image);
  return $res;
}
?>
