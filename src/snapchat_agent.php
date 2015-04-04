<?php

/**
 * @file
 *   Provides the Snapchat class with a lower-level API layer to handle
 *   requests and decrypt responses.
 */
abstract class SnapchatAgent {

	/*
	 * Before updating this value, confirm
	 * that the library requests everything in the same way as the app.
	 */
	const VERSION = 'Snapchat/9.0.2.0';

	/*
	 * The API URL. We're using the /bq endpoint, the one that the iPhone
	 * uses. Android clients still seem to be using the /ph endpoint.
	 *
	 * @todo
	 *   Make library capable of using different endpoints (some of the
	 *   resource names are different, so they aren't interchangeable).
	 */
	const URL = 'https://feelinsonice-hrd.appspot.com';

	/*
	 * The API secret. Used to create access tokens.
	 */
	const SECRET = 'iEk21fuwZApXlz93750dmW22pw389dPwOk';

	/*
	 * The static token. Used when no session is available.
	 */
	const STATIC_TOKEN = 'm198sOkJEn37DjqZ32lpRu76xmw288xSQ9';

	/*
	 * The blob encryption key. Used to encrypt and decrypt media.
	 */
	const BLOB_ENCRYPTION_KEY = 'M02cnQ51Ji97vwT4';

	/*
	 * The hash pattern.
	 *
	 * @see self::hash()
	 */
	const HASH_PATTERN = '0001110111101110001111010101111011010001001110011000110001000110'; // Hash pattern

	protected $proxyServer;

	/**
	 * Default cURL options. It doesn't appear that the UA matters, but
	 * authenticity, right?
	 */
	public static $CURL_OPTIONS = array(
		CURLOPT_CONNECTTIMEOUT => 5,
		CURLOPT_RETURNTRANSFER => TRUE,
		CURLOPT_TIMEOUT => 10,
		CURLOPT_USERAGENT => 'Snapchat/9.3.1.0 (HTC One; Android 4.4.2#302626.7#19; gzip',
		CURLOPT_HTTPHEADER => array('Accept-Language: en', 'Accept-Locale: en_US'),
	);

	public static $CURL_HEADERS = array(
		'Accept-Language: en',
		'Accept-Locale: en_US'
	);

	/**
	 * Returns the current timestamp.
	 *
	 * @return int
	 *   The current timestamp, expressed in milliseconds since epoch.
	 */
	public function timestamp()
	{
		return round(microtime(TRUE) * 1000);
	}

	/**
	 * Pads data using PKCS5.
	 *
	 * @param data $data
	 *   The data to be padded.
	 * @param int $blocksize
	 *   The block size to pad to. Defaults to 16.
	 *
	 * @return data
	 *   The padded data.
	 */
	public function pad($data, $blocksize = 16)
	{
		$pad = $blocksize - (strlen($data) % $blocksize);
		return $data . str_repeat(chr($pad), $pad);
	}

	/**
	 * Decrypts blob data for standard images and videos.
	 *
	 * @param data $data
	 *   The data to decrypt.
	 *
	 * @return data
	 *   The decrypted data.
	 */
	public function decryptECB($data)
	{
		return mcrypt_decrypt(MCRYPT_RIJNDAEL_128, self::BLOB_ENCRYPTION_KEY, self::pad($data), MCRYPT_MODE_ECB);
	}

	/**
	 * Encrypts blob data for standard images and videos.
	 *
	 * @param data $data
	 *   The data to encrypt.
	 *
	 * @return data
	 *   The encrypted data.
	 */
	public function encryptECB($data)
	{
		return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, self::BLOB_ENCRYPTION_KEY, self::pad($data), MCRYPT_MODE_ECB);
	}

	/**
	 * Decrypts blob data for stories.
	 *
	 * @param data $data
	 *   The data to decrypt.
	 * @param string $key
	 *   The base64-encoded key.
	 * @param string $iv
	 *   $iv The base64-encoded IV.
	 *
	 * @return data
	 *   The decrypted data.
	 */
	public function decryptCBC($data, $key, $iv)
	{
		// Decode the key and IV.
		$iv = base64_decode($iv);
		$key = base64_decode($key);

		// Decrypt the data.
		$data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
		$padding = ord($data[strlen($data) - 1]);

		return substr($data, 0, -$padding);
	}

	/**
	 * Implementation of Snapchat's hashing algorithm.
	 *
	 * @param string $first
	 *   The first value to use in the hash.
	 * @param string $second
	 *   The second value to use in the hash.
	 *
	 * @return string
	 *   The generated hash.
	 */
	public function hash($first, $second)
	{
		// Append the secret to the values.
		$first = self::SECRET . $first;
		$second = $second . self::SECRET;

		// Hash the values.
		$hash = hash_init('sha256');
		hash_update($hash, $first);
		$hash1 = hash_final($hash);
		$hash = hash_init('sha256');
		hash_update($hash, $second);
		$hash2 = hash_final($hash);

		// Create a new hash with pieces of the two we just made.
		$result = '';
		for($i = 0; $i < strlen(self::HASH_PATTERN); $i++)
		{
			$result .= substr(self::HASH_PATTERN, $i, 1) ? $hash2[$i] : $hash1[$i];
		}

		return $result;
	}

	/**
	 * Checks to see if a blob looks like a media file.
	 *
	 * @param data $data
	 *   The blob data (or just the header).
	 *
	 * @return bool
	 *   TRUE if the blob looks like a media file, FALSE otherwise.
	 */
	function isMedia($data)
	{
		// Check for a JPG header.
		if($data[0] == chr(0xFF) && $data[1] == chr(0xD8))
		{
			return TRUE;
		}

		// Check for a MP4 header.
		if($data[0] == chr(0x00) && $data[1] == chr(0x00))
		{
			return TRUE;
		}

		return FALSE;
	}

	/**
	 * Checks to see if a blob looks like a compressed file.
	 *
	 * @param data $data
	 *   The blob data (or just the header).
	 *
	 * @return bool
	 *   TRUE if the blob looks like a compressed file, FALSE otherwise.
	 */
	function isCompressed($data)
	{
		// Check for a PK header.
		if($data[0] == chr(0x50) && $data[1] == chr(0x4B))
		{
			return TRUE;
		}

		return FALSE;
	}

	/**
	 * Uncompress the blob and put the data into an Array.
	 * 	Array(
	 * 		overlay~zip-CE6F660A-4A9F-4BD6-8183-245C9C75B8A0	=> overlay_file_data,
	 *		media~zip-CE6F660A-4A9F-4BD6-8183-245C9C75B8A0		=> m4v_file_data
	 * 	)
	 *
	 * @param data $data
	 *   The blob data (or just the header).
	 *
	 * @return array
	 *   Array containing both file contents, or FALSE if couldn't extract.
	 */
	function unCompress($data)
	{
		if(!file_put_contents("./temp", $data))
		{
			exit('Should have write access to own folder');
		}
		$resource = zip_open("./temp");
		$result = FALSE;
		if(is_resource($resource))
		{
			while($zip_entry = zip_read($resource))
			{
				$filename = zip_entry_name($zip_entry);
				if(zip_entry_open($resource, $zip_entry, "r"))
				{
					$result[$filename] = zip_entry_read($zip_entry, zip_entry_filesize($zip_entry));
					zip_entry_close($zip_entry);
				}
				else
				{
				    unlink("./temp");
						return FALSE;
				}
			}
			zip_close($resource);
		}
    unlink("./temp");

		return $result;
	}

	/**
	 * Performs a GET request. Currently only used for story blobs.
	 *
	 * @todo
	 *   cURL-ify this and maybe combine with the post function.
	 *
	 * @param string $endpoint
	 *   The address of the resource being requested (e.g. '/story_blob' or
	 *   '/story_thumbnail').
	 *
	 * @return data
	 *   The retrieved data.
	 */
	public function get($endpoint)
	{
		$ch = curl_init();
		curl_setopt_array($ch, array(CURLOPT_RETURNTRANSFER => 1, CURLOPT_USERAGENT => 'Snapchat/9.2.0.0 (A0001; Android 4.4.4#5229c4ef56#19; gzip)', CURLOPT_HTTPHEADER => array('Accept-Language: en', 'Accept-Locale: en_US'),CURLOPT_URL => self::$URL . $endpoint, CURLOPT_CAINFO => dirname(__FILE__) . '/ca_bundle.crt'));
		return curl_exec($ch);
	}

	/**
	 * Performs a POST request. Used for pretty much everything.
	 *
	 * @todo
	 *   Replace the blob endpoint check with a more robust check for
	 *   application/octet-stream.
	 *
	 * @param string $endpoint
	 *   The address of the resource being requested (e.g. '/update_snaps' or
	 *   '/friend').
	 * @param array $data
	 *   An dictionary of values to send to the API. A request token is added
	 *   automatically.
	 * @param array $params
	 *   An array containing the parameters used to generate the request token.
	 * @param bool $multipart
	 *   If TRUE, sends the request as multipart/form-data. Defaults to FALSE.
	 *
	 * @return mixed
	 *   The data returned from the API (decoded if JSON). Returns FALSE if
	 *   the request failed.
	 */
	public function post($endpoint, $data, $params, $multipart = FALSE, $debug = FALSE)
	{
		$ch = curl_init();

		$data['req_token'] = self::hash($params[0], $params[1]);
        $boundary = "Boundary+0xAbCdEfGbOuNdArY";//md5(time());
		if(!$multipart)
		{
			$data = http_build_query($data);
		}
		else
		{
            $datas = "--".$boundary."\r\n" . 'Content-Disposition: form-data; name="req_token"' . "\r\n\r\n" . self::hash($params[0], $params[1]) . "\r\n";
            foreach($data as $key => $value)
            {
                if($key == "req_token") continue;

                if($key != 'data')
                {
                    $datas .= "--".$boundary."\r\n" . 'Content-Disposition: form-data; name="' . $key . '"' . "\r\n\r\n" . $value . "\r\n";
                }
                else
                {
                    $datas .= "--".$boundary."\r\n" . 'Content-Disposition: form-data; name="data"; filename="data"'."\r\n" . 'Content-Type: application/octet-stream'."\r\n\r\n" . $value . "\r\n";
                }
            }
            $data = $datas . "--".$boundary."--";
		}
		$options = self::$CURL_OPTIONS;

		if($debug)
		{
			curl_setopt($ch, CURLINFO_HEADER_OUT, true);
		}

		if($endpoint == "/loq/login")
		{
			$headers = array_merge(self::$CURL_HEADERS, array(
				"X-Snapchat-Client-Auth-Token: Bearer {$params[2]}",
				"Accept-Encoding: gzip"));
		}
		else
		{
			$headers = self::$CURL_HEADERS;
		}

		if($multipart)
		{
			$headers = array_merge($headers, array("X-Timestamp: 0","Content-Type: multipart/form-data; boundary=$boundary"));
		}

		if($endpoint == '/ph/blob' || $endpoint == '/bq/blob' || $endpoint == '/bq/chat_media')
		{
		    $headers = array_merge($headers, array("X-Timestamp: " . $params[1]));
				$options += array(
					CURLOPT_URL => self::URL . $endpoint . "?{$data}"
				);
		}
		else
		{
			$options += array(
				CURLOPT_POST => TRUE,
				CURLOPT_POSTFIELDS => $data,
				CURLOPT_URL => self::URL . $endpoint
			);
		}
		curl_setopt_array($ch, $options);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		$headerBuff = tmpfile();
		curl_setopt($ch, CURLOPT_WRITEHEADER, $headerBuff);
		curl_setopt($ch, CURLOPT_PROXY, $this->proxyServer);
		$result = curl_exec($ch);

		if($endpoint == "/loq/login") $result = gzdecode($result);

		if($debug)
		{
			$info = curl_getinfo($ch);
			echo "\nREQUEST TO: " .self::URL . $endpoint . "\n";
			if(isset($info['request_header']))
					echo "\nSent Request info: " .print_r($info['request_header'], true). "\n";
			if(is_array($data))
			{
				echo 'DATA: ' . print_r($data) . "\n";
			}
			else
			{
				echo 'DATA: ' . $data . "\n";
			}

			if($endpoint == "/loq/login" || $endpoint == "/all_updates")
			{
				$jsonResult = json_decode($result);
				echo 'RESULT: ' . print_r($jsonResult) . "\n";
			}
			else
			{
				echo 'RESULT: ' . $result . "\n";
			}

			if($endpoint == '/loq/register_username' || $endpoint == '/loq/register')
			{
				$jsonResult = json_decode($result);
				if(isset($jsonResult->logged) && $jsonResult->logged == false)
				{
					echo "\n" . 'ERROR: There was an error registering your account: ' . $jsonResult->message . "\n";
					exit();
				}
			}

			if($endpoint == "/bq/get_captcha")
			{
				file_put_contents(__DIR__."/captcha.zip", $result);
				rewind($headerBuff);
				$headers = stream_get_contents($headerBuff);
				if(preg_match('/^Content-Disposition: .*?filename=(?<f>[^\s]+|\x22[^\x22]+\x22)\x3B?.*$/m', $headers, $matches))
				{
					$filename = trim($matches['f'],' ";');
					rename(__DIR__."/captcha.zip", __DIR__."/{$filename}");
					return $filename;
				}
				fclose($headerBuff);
				return "captcha.zip";
			}
		}

		// If cURL doesn't have a bundle of root certificates handy, we provide
		// ours (see http://curl.haxx.se/docs/sslcerts.html).
		if (curl_errno($ch) == 60) {
			curl_setopt($ch, CURLOPT_CAINFO, dirname(__FILE__) . '/ca_bundle.crt');
			$result = curl_exec($ch);
		}

		$gi = curl_getinfo($ch);
		// If the cURL request fails, return FALSE. Also check the status code
		// since the API generally won't return friendly errors.
		if($result === FALSE)
		{
			curl_close($ch);

			return $result;
		}

		if(curl_getinfo($ch, CURLINFO_HTTP_CODE) != 200)
		{
				$return['data'] = $result;
				$return['test'] = 1;
				$return['code'] = curl_getinfo($ch, CURLINFO_HTTP_CODE);

				curl_close($ch);

				return $return;
		}

		curl_close($ch);

		$return['error'] = 0;

		if($endpoint == '/ph/blob' || $endpoint == '/bq/blob' || $endpoint == "/bq/snaptag_download" || $endpoint == '/bq/chat_media')
		{
			$return['data'] = $result;
			return $result;
		}

		// Add support for foreign characters in the JSON response.
		$result = iconv('UTF-8', 'UTF-8//IGNORE', utf8_encode($result));

		$return['data'] = json_decode($result);

		return $return;
	}

	public function posttourl($url, $data) {
		$ch = curl_init();
		$options = self::$CURL_OPTIONS + array(
			CURLOPT_POST => TRUE,
			CURLOPT_POSTFIELDS => $data,
			CURLOPT_URL => $url,
		);
		curl_setopt_array($ch, $options);
		curl_setopt($ch, CURLOPT_HTTPHEADER, self::$CURL_HEADERS);

		$result = curl_exec($ch);
		if (curl_errno($ch) == 60) {
			curl_setopt($ch, CURLOPT_CAINFO, dirname(__FILE__) . '/ca_bundle.crt');
			$result = curl_exec($ch);
		}
		if ($result === FALSE)
		{
			curl_close($ch);
			return $result;
		}
		if(curl_getinfo($ch, CURLINFO_HTTP_CODE) != 200)
		{
				$return['data'] = $result;
				$return['test'] = 1;
				$return['code'] = curl_getinfo($ch, CURLINFO_HTTP_CODE);
				curl_close($ch);
				return $return;
		}
		curl_close($ch);
		$return['error'] = 0;
		$result = iconv('UTF-8', 'UTF-8//IGNORE', utf8_encode($result));
		$return['data'] = json_decode($result);
		return $return;
	}

	public function setProxyServer ($proxyServer)
	{
			$this->proxyServer = $proxyServer;
	}
}
