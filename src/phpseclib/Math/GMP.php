<?php
/**
 * Crypt_RSA allows to do following operations:
 *     - key pair generation
 *     - encryption and decryption
 *     - signing and sign validation
 *
 * PHP versions 4 and 5
 *
 * LICENSE: This source file is subject to version 3.0 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_0.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 *
 * @category   Encryption
 * @package    Crypt_RSA
 * @author     Alexander Valyalkin <valyala@gmail.com>
 * @copyright  2005, 2006 Alexander Valyalkin
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @version    1.2.0b
 * @link       http://pear.php.net/package/Crypt_RSA
 */

/**
 * Crypt_RSA_Math_GMP class.
 *
 * Provides set of math functions, which are used by Crypt_RSA package
 * This class is a wrapper for PHP GMP extension.
 * See http://php.net/gmp for details.
 *
 * @category   Encryption
 * @package    Crypt_RSA
 * @author     Alexander Valyalkin <valyala@gmail.com>
 * @copyright  2005, 2006 Alexander Valyalkin
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @link       http://pear.php.net/package/Crypt_RSA
 * @version    @package_version@
 * @access     public
 */
class Crypt_RSA_Math_GMP
{
    /**
     * error description
     *
     * @var string
     * @access public
     */
    var $errstr = '';

    /**
     * Crypt_RSA_Math_GMP constructor.
     * Checks an existance of PHP GMP package.
     * See http://php.net/gmp for details.
     *
     * On failure saves error description in $this->errstr
     *
     * @access public
     */
    function Crypt_RSA_Math_GMP()
    {
        if (!extension_loaded('gmp')) {
            if (!@dl('gmp.' . PHP_SHLIB_SUFFIX) && !@dl('php_gmp.' . PHP_SHLIB_SUFFIX)) {
                // cannot load GMP extension
                $this->errstr = 'Crypt_RSA package requires PHP GMP package. ' .
                     'See http://php.net/gmp for details';
                return;
            }
        }
    }

    /**
     * Transforms binary representation of large integer into its native form.
     * 
     * Example of transformation:
     *    $str = "\x12\x34\x56\x78\x90";
     *    $num = 0x9078563412;
     *
     * @param string $str
     * @return gmp resource
     * @access public
     */
    function bin2int($str)
    {
        $result = 0;
        $n = strlen($str);
        do {
            // dirty hack: GMP returns FALSE, when second argument equals to int(0).
            // so, it must be converted to string '0'
            $result = gmp_add(gmp_mul($result, 256), strval(ord($str{--$n})));
        } while ($n > 0);
        return $result;
    }

    /**
     * Transforms large integer into binary representation.
     * 
     * Example of transformation:
     *    $num = 0x9078563412;
     *    $str = "\x12\x34\x56\x78\x90";
     *
     * @param gmp resource $num
     * @return string
     * @access public
     */
    function int2bin($num)
    {
        $result = '';
        do {
            $result .= chr(gmp_intval(gmp_mod($num, 256)));
            $num = gmp_div($num, 256);
        } while (gmp_cmp($num, 0));
        return $result;
    }

    /**
     * Calculates pow($num, $pow) (mod $mod)
     *
     * @param gmp resource $num
     * @param gmp resource $pow
     * @param gmp resource $mod
     * @return gmp resource
     * @access public
     */
    function powmod($num, $pow, $mod)
    {
        return gmp_powm($num, $pow, $mod);
    }

    /**
     * Calculates $num1 * $num2
     *
     * @param gmp resource $num1
     * @param gmp resource $num2
     * @return gmp resource
     * @access public
     */
    function mul($num1, $num2)
    {
        return gmp_mul($num1, $num2);
    }

    /**
     * Calculates $num1 % $num2
     *
     * @param string $num1
     * @param string $num2
     * @return string
     * @access public
     */
    function mod($num1, $num2)
    {
        return gmp_mod($num1, $num2);
    }

    /**
     * Compares abs($num1) to abs($num2).
     * Returns:
     *   -1, if abs($num1) < abs($num2)
     *   0, if abs($num1) == abs($num2)
     *   1, if abs($num1) > abs($num2)
     *
     * @param gmp resource $num1
     * @param gmp resource $num2
     * @return int
     * @access public
     */
    function cmpAbs($num1, $num2)
    {
        return gmp_cmp($num1, $num2);
    }

    /**
     * Tests $num on primality. Returns true, if $num is strong pseudoprime.
     * Else returns false.
     *
     * @param string $num
     * @return bool
     * @access private
     */
    function isPrime($num)
    {
        return gmp_prob_prime($num) ? true : false;
    }

    /**
     * Generates prime number with length $bits_cnt
     * using $random_generator as random generator function.
     *
     * @param int $bits_cnt
     * @param string $rnd_generator
     * @access public
     */
    function getPrime($bits_cnt, $random_generator)
    {
        $bytes_n = intval($bits_cnt / 8);
        $bits_n = $bits_cnt % 8;
        do {
            $str = '';
            for ($i = 0; $i < $bytes_n; $i++) {
                $str .= chr(call_user_func($random_generator) & 0xff);
            }
            $n = call_user_func($random_generator) & 0xff;
            $n |= 0x80;
            $n >>= 8 - $bits_n;
            $str .= chr($n);
            $num = $this->bin2int($str);

            // search for the next closest prime number after [$num]
            if (!gmp_cmp(gmp_mod($num, '2'), '0')) {
                $num = gmp_add($num, '1');
            }
            while (!gmp_prob_prime($num)) {
                $num = gmp_add($num, '2');
            }
        } while ($this->bitLen($num) != $bits_cnt);
        return $num;
    }

    /**
     * Calculates $num - 1
     *
     * @param gmp resource $num
     * @return gmp resource
     * @access public
     */
    function dec($num)
    {
        return gmp_sub($num, 1);
    }

    /**
     * Returns true, if $num is equal to one. Else returns false
     *
     * @param gmp resource $num
     * @return bool
     * @access public
     */
    function isOne($num)
    {
        return !gmp_cmp($num, 1);
    }

    /**
     * Finds greatest common divider (GCD) of $num1 and $num2
     *
     * @param gmp resource $num1
     * @param gmp resource $num2
     * @return gmp resource
     * @access public
     */
    function GCD($num1, $num2)
    {
        return gmp_gcd($num1, $num2);
    }

    /**
     * Finds inverse number $inv for $num by modulus $mod, such as:
     *     $inv * $num = 1 (mod $mod)
     *
     * @param gmp resource $num
     * @param gmp resource $mod
     * @return gmp resource
     * @access public
     */
    function invmod($num, $mod)
    {
        return gmp_invert($num, $mod);
    }

    /**
     * Returns bit length of number $num
     *
     * @param gmp resource $num
     * @return int
     * @access public
     */
    function bitLen($num)
    {
        $tmp = $this->int2bin($num);
        $bit_len = strlen($tmp) * 8;
        $tmp = ord($tmp{strlen($tmp) - 1});
        if (!$tmp) {
            $bit_len -= 8;
        }
        else {
            while (!($tmp & 0x80)) {
                $bit_len--;
                $tmp <<= 1;
            }
        }
        return $bit_len;
    }

    /**
     * Calculates bitwise or of $num1 and $num2,
     * starting from bit $start_pos for number $num1
     *
     * @param gmp resource $num1
     * @param gmp resource $num2
     * @param int $start_pos
     * @return gmp resource
     * @access public
     */
    function bitOr($num1, $num2, $start_pos)
    {
        $start_byte = intval($start_pos / 8);
        $start_bit = $start_pos % 8;
        $tmp1 = $this->int2bin($num1);

        $num2 = gmp_mul($num2, 1 << $start_bit);
        $tmp2 = $this->int2bin($num2);
        if ($start_byte < strlen($tmp1)) {
            $tmp2 |= substr($tmp1, $start_byte);
            $tmp1 = substr($tmp1, 0, $start_byte) . $tmp2;
        }
        else {
            $tmp1 = str_pad($tmp1, $start_byte, "\0") . $tmp2;
        }
        return $this->bin2int($tmp1);
    }

    /**
     * Returns part of number $num, starting at bit
     * position $start with length $length
     *
     * @param gmp resource $num
     * @param int start
     * @param int length
     * @return gmp resource
     * @access public
     */
    function subint($num, $start, $length)
    {
        $start_byte = intval($start / 8);
        $start_bit = $start % 8;
        $byte_length = intval($length / 8);
        $bit_length = $length % 8;
        if ($bit_length) {
            $byte_length++;
        }
        $num = gmp_div($num, 1 << $start_bit);
        $tmp = substr($this->int2bin($num), $start_byte, $byte_length);
        $tmp = str_pad($tmp, $byte_length, "\0");
        $tmp = substr_replace($tmp, $tmp{$byte_length - 1} & chr(0xff >> (8 - $bit_length)), $byte_length - 1, 1);
        return $this->bin2int($tmp);
    }

    /**
     * Returns name of current wrapper
     *
     * @return string name of current wrapper
     * @access public
     */
    function getWrapperName()
    {
        return 'GMP';
    }
}

?>