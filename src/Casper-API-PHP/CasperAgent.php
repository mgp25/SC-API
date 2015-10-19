<?php

/**
 * @file
 * Base methods of the CasperAPI class.
 */
abstract class CasperAgent {

	/**
	 * @var string Your Casper API Key
	 */
	public $API_KEY;

	/**
	 * @var string Your Casper API Secret
	 */
	public $API_SECRET;

	/**
	 * The User-Agent used in requests to the Casper API
	 */
	const USER_AGENT = "Casper-API-PHP/1.0.0";

	/*
	 * The Casper API URL.
	 */
	const URL = "https://api.casper.io";

	/**
	 * Default cURL headers.
	 */
	public static $CURL_HEADERS = array(

	);

	/**
	 * Default cURL options.
	 */
	public static $CURL_OPTIONS = array(
		CURLOPT_TIMEOUT => 10,
		CURLOPT_CONNECTTIMEOUT => 10,
		CURLOPT_USERAGENT => self::USER_AGENT,
		CURLOPT_HEADER => false,
		CURLINFO_HEADER_OUT => true,
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_ENCODING => "gzip"
	);

	public function setAPIKey($api_key = null){
		$this->API_KEY = $api_key;
	}

	public function setAPISecret($api_secret = null){
		$this->API_SECRET = $api_secret;
	}

	/**
	 * Performs a GET request.
	 *
	 * @param string $endpoint
	 *   Endpoint to make GET request to.
	 *
	 * @param array $headers
	 *   An array of parameters to send in the request.
	 *
	 * @return data
	 *   The response data.
	 *
	 * @throws CasperException
	 *   An exception is thrown if an error occurs.
	 */
	public function get($endpoint, $headers = array()){
		return $this->request($endpoint, $headers);
	}

	/**
	 * Performs a POST request.
	 *
	 * @param string $endpoint
	 *   Endpoint to make POST request to.
	 *
	 * @param array $headers
	 *   An array of parameters to send in the request.
	 *
	 * @param array $params
	 *   An array of parameters to send in the request.
	 *
	 * @return data
	 *   The response data.
	 *
	 * @throws CasperException
	 *   An exception is thrown if an error occurs.
	 */
	public function post($endpoint, $headers = array(), $params = array()){
		return $this->request($endpoint, $headers, $params, true);
	}

	/**
	 * Performs a POST request.
	 *
	 * @param string $endpoint
	 *   Endpoint to make request to.
	 *
	 * @param array $headers
	 *   An array of parameters to send in the request.
	 *
	 * @param array $params
	 *   An array of parameters to send in the request.
	 *
	 * @param boolean $post
	 *   true to make a POST request, else a GET request will be made.
	 *
	 * @return stdClass
	 *   The JSON data returned from the API.
	 *
	 * @throws CasperException
	 *   An exception is thrown if an error occurs.
	 */
	public function request($endpoint, $headers = array(), $params = array(), $post = false){

		$ch = curl_init();

		if($headers == null){
			$headers = array();
		}

		if($params == null){
			$params = array();
		}

		$headers = array_merge(self::$CURL_HEADERS, $headers);

		$headers[] = "X-Casper-API-Key: " . $this->API_KEY;
		$headers[] = "X-Casper-Signature: " . $this->generateRequestSignature($params, $this->API_SECRET);

		curl_setopt_array($ch, self::$CURL_OPTIONS);
		curl_setopt($ch, CURLOPT_URL, self::URL . $endpoint);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

		//curl_setopt($ch, CURLOPT_PROXY, "http://localhost:8888");

		if($post){
			if(is_array($params)){
				$params = http_build_query($params);
			}
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
		}

		$result = curl_exec($ch);

		//If cURL doesn't have a bundle of root certificates handy,
		//we provide ours (see http://curl.haxx.se/docs/sslcerts.html).
		if(curl_errno($ch) == 60){
			curl_setopt($ch, CURLOPT_CAINFO, __DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."ca_bundle.crt");

			$result = curl_exec($ch);
		}

		//If the cURL request fails, return FALSE.
		if($result === FALSE){
			$error = curl_error($ch);
			curl_close($ch);
			throw new CasperException($error);
		}

		$json = json_decode($result);
		if($json == null){
			curl_close($ch);
			throw new CasperException("Failed to decode response!");
		}

		$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		if($code != 200){

			curl_close($ch);

			if(isset($json->code) && isset($json->message)){
				throw new CasperException("API Response: [{$json->code}] {$json->message}");
			} else {
				throw new CasperException("API Response: [{$code}] Unknown Error Message");
			}

		}

		curl_close($ch);

		return $json;

	}

	/**
	 * Performs a POST request.
	 *
	 * @param string $url
	 *   Url to make request to.
	 *
	 * @param array $headers
	 *   An array of parameters to send in the request.
	 *
	 * @param array $params
	 *   An array of parameters to send in the request.
	 *
	 * @param boolean $post
	 *   true to make a POST request, else a GET request will be made.
	 *
	 * @return stdClass
	 *   The JSON data returned from the API.
	 *
	 * @throws CasperException
	 *   An exception is thrown if an error occurs.
	 */
	public function externalRequest($url, $headers = array(), $params = array(), $post = false){

		$ch = curl_init();

		if($headers == null){
			$headers = array();
		}

		if($params == null){
			$params = array();
		}

		curl_setopt_array($ch, self::$CURL_OPTIONS);
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

		if($post){
			if(is_array($params)){
				$params = http_build_query($params);
			}
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
		}

		$result = curl_exec($ch);

		//If cURL doesn't have a bundle of root certificates handy,
		//we provide ours (see http://curl.haxx.se/docs/sslcerts.html).
		if(curl_errno($ch) == 60){
			curl_setopt($ch, CURLOPT_CAINFO, __DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."ca_bundle.crt");
			$result = curl_exec($ch);
		}

		//If the cURL request fails, return FALSE.
		if($result === FALSE){
			curl_close($ch);
			throw new CasperException("cURL request failed!");
		}

		if(curl_getinfo($ch, CURLINFO_HTTP_CODE) != 200){

			curl_close($ch);
			throw new CasperException("External Request Failed!");

		}

		curl_close($ch);

		return $result;

	}


	/**
	 *
	 * Generates an HMAC Signature of the Request Parameters
	 * Parameter Keys need to be in alphabetical order.
	 * Values are then appended to the end.
	 *
	 * @param array $parameters Parameters sent in your Request
	 * @param string $secret Your Casper API Secret
	 * @return string
	 */
	public function generateRequestSignature($parameters = array(), $secret){

		ksort($parameters);

		$string = "";
		foreach($parameters as $key => $value){
			$string .= $key.$value;
		}
		return "v1:".hash_hmac("sha256", $string, $secret);
	}

}
