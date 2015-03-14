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

if(!function_exists('mime_content_type')) {

    function mime_content_type($filename) {

        $mime_types = array(

            'txt' => 'text/plain',
            'htm' => 'text/html',
            'html' => 'text/html',
            'php' => 'text/html',
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'xml' => 'application/xml',
            'swf' => 'application/x-shockwave-flash',
            'flv' => 'video/x-flv',

            // images
            'png' => 'image/png',
            'jpe' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'jpg' => 'image/jpeg',
            'gif' => 'image/gif',
            'bmp' => 'image/bmp',
            'ico' => 'image/vnd.microsoft.icon',
            'tiff' => 'image/tiff',
            'tif' => 'image/tiff',
            'svg' => 'image/svg+xml',
            'svgz' => 'image/svg+xml',

            // archives
            'zip' => 'application/zip',
            'rar' => 'application/x-rar-compressed',
            'exe' => 'application/x-msdownload',
            'msi' => 'application/x-msdownload',
            'cab' => 'application/vnd.ms-cab-compressed',

            // audio/video
            'mp3' => 'audio/mpeg',
            'qt' => 'video/quicktime',
            'mov' => 'video/quicktime',

            // adobe
            'pdf' => 'application/pdf',
            'psd' => 'image/vnd.adobe.photoshop',
            'ai' => 'application/postscript',
            'eps' => 'application/postscript',
            'ps' => 'application/postscript',

            // ms office
            'doc' => 'application/msword',
            'rtf' => 'application/rtf',
            'xls' => 'application/vnd.ms-excel',
            'ppt' => 'application/vnd.ms-powerpoint',

            // open office
            'odt' => 'application/vnd.oasis.opendocument.text',
            'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
        );

        $ext = strtolower(array_pop(explode('.',$filename)));
        if (array_key_exists($ext, $mime_types)) {
            return $mime_types[$ext];
        }
        elseif (function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME);
            $mimetype = finfo_file($finfo, $filename);
            finfo_close($finfo);
            return $mimetype;
        }
        else {
            return 'application/octet-stream';
        }
    }
}

?>
