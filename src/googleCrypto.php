<?php

require 'phpseclib/Crypt/RSA.php';
require 'phpseclib/Math/BigInteger.php';

define ('GOOGLE_DEFAULT_PUBLIC_KEY', 'AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==');

class Encrypt
{
  protected $gmail;
  protected $gpasswd;

  public function __construct($gmail, $gpasswd)
  {
    $this->gmail = $gmail;
    $this->gpasswd = $gpasswd;
  }

  public function encrypt()
  {
    $binaryKey = bin2hex(base64_decode(GOOGLE_DEFAULT_PUBLIC_KEY));

    $half = substr($binaryKey, 8, 256);
    $modulus  = new Math_BigInteger(hex2bin($half), 256);

    $half = substr($binaryKey, 272, 6);
    $exponent = new Math_BigInteger(hex2bin($half), 256);

    $sha1  = sha1(base64_decode(GOOGLE_DEFAULT_PUBLIC_KEY), true);
    $signature = '00' . bin2hex(substr($sha1, 0, 4));

    $rsa = new Crypt_RSA();

    $rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
    $rsa->setPublicKey();
    $publicKey = $rsa->getPublicKey();

    $plain = $this->gmail . chr(0) . $this->gpasswd;
    $rsa->setHash('sha1');
    $rsa->setMGFHash('sha1');
    $rsa->setEncryptionMode('CRYPT_RSA_ENCRYPTION_OAEP');
    $encrypted = bin2hex($rsa->encrypt($plain));

    $output = "";
    $output .= $signature;
    $output .= $encrypted;

    return str_replace(array('+', '/'), array('-', '_'), base64_encode(hex2bin($output)));;
  }
}
