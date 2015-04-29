<?php

include_once dirname(__FILE__) . '/snapchat_agent.php';
include_once dirname(__FILE__) . '/snapchat_cache.php';
include_once dirname(__FILE__) . '/func.php';

/**
 * @file
 *   Provides an implementation of the undocumented Snapchat API.
 */
class Snapchat extends SnapchatAgent {

	/**
	 * The media types for snaps from confirmed friends.
	 */
	const MEDIA_IMAGE = 0;
	const MEDIA_VIDEO = 1;
	const MEDIA_VIDEO_NOAUDIO = 2;

	/**
	 * The media type for a friend request (not technically media, but it
	 * shows up in the feed).
	 */
	const MEDIA_FRIEND_REQUEST = 3;

	/**
	 * The media types for snaps from unconfirmed friends.
	 */
	const MEDIA_FRIEND_REQUEST_IMAGE = 4;
	const MEDIA_FRIEND_REQUEST_VIDEO = 5;
	const MEDIA_FRIEND_REQUEST_VIDEO_NOAUDIO = 6;

	/**
	 * Snap statuses.
	 */
	const STATUS_NONE = -1;
	const STATUS_SENT = 0;
	const STATUS_DELIVERED = 1;
	const STATUS_OPENED = 2;
	const STATUS_SCREENSHOT = 3;

	/**
	 * Friend statuses.
	 */
	const FRIEND_CONFIRMED = 0;
	const FRIEND_UNCONFIRMED = 1;
	const FRIEND_BLOCKED = 2;
	const FRIEND_DELETED = 3;

	/**
	 * Privacy settings.
	 */
	const PRIVACY_EVERYONE = 0;
	const PRIVACY_FRIENDS = 1;

	protected $auth_token;
	protected $chat_auth_token;
	protected $username;
	protected $debug;
	protected $gEmail;
	protected $gPasswd;

	/**
	 * Sets up some initial variables. If a username and password are passed in,
	 * we attempt to log in. If a username and auth token are passed in, we'll
	 * bypass the login process and use those values.
	 *
	 * @param string $username
	 *   The username for the Snapchat account.
	 * @param string $password
	 *   The password associated with the username, if logging in.
	 */
	public function __construct($username = NULL, $gEmail, $gPasswd, $debug = FALSE)
	{
		$this->username = $username;
		$this->debug = $debug;
		$this->gEmail = $gEmail;
		$this->gPasswd = $gPasswd;

		if (file_exists(__DIR__ . "/auth-$this->username.dat"))
		{
			$this->auth_token = file_get_contents(__DIR__ . "/auth-$this->username.dat");
		}
	}

	public function getDeviceToken()
	{
		$timestamp = parent::timestamp();

		$result = parent::post(
			'/loq/device_id',
			array(
				'timestamp' => $timestamp,
			),
			array(
				parent::STATIC_TOKEN,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}

	public function device()
	{
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/all_updates',
			array(
				'type' => "android",
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}

	public function getAuthToken()
	{
		if(($this->gEmail != null) && ($this->gPasswd != null))
		{
				$ch = curl_init();
				$postfields = array(
					'device_country' => 'us',
					'operatorCountry' => 'us',
					'lang' => 'en_US',
					'sdk_version' => '19',
					'google_play_services_version' => '7097038',
					'accountType' => 'HOSTED_OR_GOOGLE',
					'Email' => $this->gEmail,
					'service' => 'audience:server:client_id:694893979329-l59f3phl42et9clpoo296d8raqoljl6p.apps.googleusercontent.com',
					'source' => 'android',
					'androidId' => '378c184c6070c26c',
					'app' => 'com.snapchat.android',
					'client_sig' => '49f6badb81d89a9e38d65de76f09355071bd67e7',
					'callerPkg' => 'com.snapchat.android',
					'callerSig' => '49f6badb81d89a9e38d65de76f09355071bd67e7'
				);

				exec('java -version', $output, $returnCode);
				if ($returnCode === 0)
				{
						exec("java -jar " . __DIR__ . "/encrypter.jar $this->gEmail $this->gPasswd", $result);
						$postfields['EncryptedPasswd'] = array_shift(array_slice($result, 0, 1));
				}
				else
				{
						$postfields['Passwd'] = $this->gPasswd;
				}

			$headers = array(
				'device: 378c184c6070c26c',
				'app: com.snapchat.android',
				'User-Agent: GoogleAuth/1.4 (mako JDQ39)',
				'Accept-Encoding: gzip'
			);

			curl_setopt($ch, CURLOPT_URL, "https://android.clients.google.com/auth");
			curl_setopt($ch, CURLOPT_POST, TRUE);
			curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postfields));
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
			curl_setopt($ch, CURLOPT_ENCODING, "gzip");
			curl_setopt($ch, CURLINFO_HEADER_OUT, true);

			$result = curl_exec($ch);

			if($this->debug)
			{
				echo "\nREQUEST TO: https://android.clients.google.com/auth\n";
				echo 'DATA: ' . print_r($postfields) . "\n";
				echo 'RESULT: ' . $result . "\n";
			}

			if(curl_getinfo($ch, CURLINFO_HTTP_CODE) != 200)
			{
				$return['error'] = 1;
				$return['data'] = $result;

				return $return;
			}

			curl_close($ch);

			$return['error'] = 0;
			$exploded = explode("\n", $result);
			$return['auth'] = substr($exploded[1], 5);
		}
		else
		{
			$return['error'] = 1;
			$return['data'] = "Email: $this->gEmail Passwd: $this->gPasswd";
		}

		return $return;
	}

	private function getGCMToken()
	{
		$ch = curl_init();
		$timestamp = parent::timestamp() / 1000;
		$timestamp = (int) $timestamp;
		$postfields = array(
			'device' => '3847872624728098287',
			'sender' => '191410808405',
			'app_ver' => '564',
			'gcm_ver' => '7097038',
			'app' => 'com.snapchat.android',
			'iat' => $timestamp,
			'cert' => '49f6badb81d89a9e38d65de76f09355071bd67e7'
		);

		$headers = array(
			'app: com.snapchat.android',
			'User-Agent: Android-GCM/1.5 (m7 KOT49H)',
			'Authorization: AidLogin 3847872624728098287:1187196130325105010'
		);

		curl_setopt($ch, CURLOPT_URL, "https://android.clients.google.com/c2dm/register3");
		curl_setopt($ch, CURLOPT_POST, TRUE);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postfields));
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($ch, CURLOPT_ENCODING, "gzip");
		curl_setopt($ch, CURLINFO_HEADER_OUT, true);

		$result = curl_exec($ch);

		if($this->debug)
		{
			echo "\nREQUEST TO: https://android.clients.google.com/c2dm/register3\n";
			echo 'DATA: ' . print_r($postfields) . "\n";
			echo 'RESULT: ' . $result . "\n";
		}

		if(curl_getinfo($ch, CURLINFO_HTTP_CODE) != 200)
		{
			$return['error'] = 1;
			$return['data'] = $result;

			return $return;
		}

		curl_close($ch);

		$return['error'] = 0;
		$return['token'] = substr($result, 6);

		return $return;
	}

	/**
	 * Handles login.
	 *
	 * @param string $password
	 *   The password associated with the username.
	 *
	 * @return mixed
	 *   The data returned by the service or FALSE if the request failed.
	 *   Generally, returns the same result as self::getUpdates().
	 */
	public function login($password, $force = FALSE)
	{
		$do = ($force && file_exists(__DIR__ . "/auth-$this->username.dat")) ? 1 : 0;

		if(($do == 1) || (!(file_exists(__DIR__ . "/auth-$this->username.dat"))))
		{
				$dtoken = $this->getDeviceToken();

				if($dtoken['error'] == 1)
				{
						$return['message'] = "Failed to get new Device token set.";
						return $return;
				}

				$timestamp = parent::timestamp();
				$req_token = parent::hash(parent::STATIC_TOKEN, $timestamp);
				$string = $this->username . "|" . $password . "|" . $timestamp . "|" . $req_token;

				$auth = $this->getAuthToken();

				if($auth['error'] == 1)
				{
						return $auth;
				}

				$result = parent::post(
					'/loq/login',
					array(
						'username' => $this->username,
						'password' => $password,
						'height' => 1280,
						'width' => 720,
						'max_video_height' => 640,
						'max_video_width' => 480,
						'dsig' => substr(hash_hmac('sha256', $string, $dtoken['data']->dtoken1v), 0, 20),
						'dtoken1i' => $dtoken['data']->dtoken1i,
						'ptoken' => "ie",
						'timestamp' => $timestamp,
						'req_token' => $req_token,
					),
					array(
						parent::STATIC_TOKEN,
						$timestamp,
						$auth['auth']
					),
					$multipart = false,
					$debug = $this->debug
				);


				if($result['error'] == 1)
				{
					return $result;
				}

				if(isset($result['data']->updates_response->logged) && $result['data']->updates_response->logged)
				{
					$this->auth_token = $result['data']->updates_response->auth_token;
					$this->device();

					$authFile = fopen(__DIR__ . "/auth-$this->username.dat", "w");
					fwrite($authFile, $this->auth_token);
					fclose($authFile);
				}

				return $result;
		} else {
				$this->openAppEvent();
		}
	}

	/**
	 * Logs out the current user.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function logout()
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/ph/logout',
			array(
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		// Clear out the cache in case the instance is recycled.
		$this->cache = NULL;

		unlink(__DIR__ . "/auth-$this->username.dat");

		return is_null($result);
	}

	/**
	 * Creates a user account.
	 *
	 * @todo
	 *   Add better validation.
	 *
	 * @param string $username
	 *   The desired username.
	 * @param string $password
	 *   The password to associate with the account.
	 * @param string $email
	 *   The email address to associate with the account.
	 * @param $birthday string
	 *   The user's birthday (yyyy-mm-dd).
	 * @param string $phone_verification
	 *   Whether to use phone verification or not.
	 * @param string $phone_number
	 *   Phone number to use if using phone verification. (country code and phone number. with or without +)
	 *
	 * @return mixed
	 *   The data returned by the service or FALSE if registration failed.
	 *   Generally, returns the same result as calling self::getUpdates().
	 */
	public function register($username, $password, $email, $birthday, $phone_verification = FALSE, $phone_number = NULL)
	{
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/register',
			array(
				'birthday' => $birthday,
				'password' => $password,
				'email' => $email,
				'timestamp' => $timestamp,
			),
			array(
				parent::STATIC_TOKEN,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		if(!isset($result["data"]->auth_token))
		{
			return FALSE;
		}
		$this->auth_token = $result['data']->auth_token;

		$timestamp = parent::timestamp();
		parent::post(
			'/loq/register_username',
			array(
				'username' => $email,
				'selected_username' => $username,
				'timestamp' => $timestamp,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);
		$result = $result["data"];

		// If registration is successful, set the username and auth_token.
		if(isset($result->logged) && $result->logged)
		{
			$this->auth_token = $result->auth_token;
			$this->username = $username;

			if($phone_verification)
			{
				if(!is_null($phone_number))
				{
					return $this->sendPhoneVerification($phone_number);
				}
				else
				{
					echo "\nYou must provide a phone number to verify with.";
					return FALSE;
				}
			}
			else
			{
				return $this->getCaptcha();
			}
		}
		else
		{
			return FALSE;
		}
	}

	/**
	 * Sends SMS verification.
	 *
	 * @param string $phone_number
	 *   Phone number to use if using phone verification.
	 *
	 */
	public function sendPhoneVerification($phone_number)
	{
		$ch = curl_init();
		curl_setopt_array($ch, array(CURLOPT_RETURNTRANSFER => 1, CURLOPT_HTTPHEADER => array("X-Mashape-Key: wiwbql3AxwmshuZzEIxVNI9olPZlp1KsrBAjsnfJpLBkxzaEhq"),CURLOPT_URL => "https://metropolis-api-phone.p.mashape.com/analysis?telephone={$phone_number}", CURLOPT_CAINFO => dirname(__FILE__) . '/ca_bundle.crt'));
		$result = curl_exec($ch);
		$result = json_decode($result, true);

		if($result["valid"])
		{
			$phone_number = str_replace(" ", "", $result["formatted-number"]);
			$countryCode = $result["iso-code"];
		}
		else
		{
			echo "\nInvalid phone number.";
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			"/bq/phone_verify",
			array(
				"timestamp" => $timestamp,
				"username" => $this->username,
				"phoneNumber" => $phone_number,
				"action" => "updatePhoneNumber",
				"countryCode" => $countryCode,
				"skipConfirmation" => true
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return $result;
	}

	/**
	 * Verifies phone number.
	 *
	 * @param string $code
	 *   Code sent for verification by Snapchat.
	 *
	 */
	public function verifyPhoneNumber($code)
	{
		$timestamp = parent::timestamp();
		$req_token = parent::hash(parent::STATIC_TOKEN, $timestamp);
		$result = parent::post(
			"/bq/phone_verify",
			array(
				"timestamp" => $timestamp,
				"action" => "verifyPhoneNumber",
				"username" => $this->username,
				"code" => $code
			),
			array(
				$req_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);
		$result = $result["data"];
		return (isset($result->logged) && $result->logged);
	}

	public function getCaptcha()
	{
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/get_captcha',
			array(
			  'username' => $this->username,
			  'timestamp' => $timestamp,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);
		return $result;
	}

	public function sendCaptcha($result, $id)
	{
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/solve_captcha',
			array(
				'username' => $this->username,
				'timestamp' => $timestamp,
				'captcha_id' => substr($id, 0, strlen($id) - 4),
				'captcha_solution' => $result
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}

	public function getConversationAuth($to)
	{
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/conversation_auth_token',
			array(
				'username' => $this->username,
				'timestamp' => $timestamp,
				'conversation_id' => implode('~', array($this->username, $to))
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}


	public function getConversationInfo($to)
	{
		$authInfo = $this->getConversationAuth($to);

		//if user is even a friend
		if(property_exists($authInfo["data"], "messaging_auth"))
		{
			$payload = $authInfo["data"]->messaging_auth->payload;
			$mac = $authInfo["data"]->messaging_auth->mac;

			$genID = md5(uniqid());
			$id = strtoupper(sprintf('%08s-%04s-%04x-%04x-%12s', substr($genID, 0, 8), substr($genID, 8, 4), substr($genID, 12, 4), substr($genID, 16, 4), substr($genID, 20, 12)));

			$messagesArray = array(
				array(
					"presences" => array(
						$this->username => true,
						$to => false
					),
					"receiving_video" => false,
					"supports_here" => true,
					"header" => array(
						"auth" => array(
							"mac" => $mac,
							"payload" => $payload
						),
						"to" => array(
							$to
						),
						"conv_id" => implode('~', array($this->username, $to)),
						"from" => $this->username,
						"conn_sequence_number" => 0
					),
					"retried" => false,
					"id" => $id,
					"type" => "presence"
				)
			);

			$messages = json_encode($messagesArray);
			$timestamp = parent::timestamp();
			$result = parent::post(
				'/loq/conversation_post_messages',
				array(
					'auth_token' => $this->auth_token,
					'messages' => $messages,
					'timestamp' => $timestamp,
					'username' => $this->username,
				),
				array(
					$this->auth_token,
					$timestamp,
				),
				$multipart = false,
				$debug = $this->debug
			);

			//check if chat id might be in reverse order
			if(!array_key_exists("0", $result["data"]->conversations))
			{
				$messagesArray[0]["header"]["conv_id"] = implode('~', array($to, $this->username));

				$messages = json_encode($messagesArray);
				$timestamp = parent::timestamp();
				$result = parent::post(
					'/loq/conversation_post_messages',
					array(
						'auth_token' => $this->auth_token,
						'messages' => $messages,
						'timestamp' => $timestamp,
						'username' => $this->username,
					),
					array(
						$this->auth_token,
						$timestamp,
					),
					$multipart = false,
					$debug = $this->debug
				);
			}
		}
		else
		{
			//simulate server response to trigger error message
			$data = new stdClass();
			$data->conversations = array();
			$result = array(
				"error" => 1,
				"data" => $data
			);
		}

		return $result;
	}

	public function sendMessage($to, $text)
	{
		$authInfo = $this->getConversationInfo($to);
		if(!array_key_exists("0", $authInfo["data"]->conversations))
		{
			$authInfo = $this->getConversationAuth($to);
			if(!property_exists($authInfo["data"], "messaging_auth"))
			{
				echo "\nYou must add {$to} to your friends list first!\n";
				return null;
			}
			else
			{
				//new conversation
				$payload = $authInfo["data"]->messaging_auth->payload;
				$mac = $authInfo["data"]->messaging_auth->mac;
				$seq_num = 0;
				$conv_id = implode('~', array($to, $this->username));
			}
		}
		else
		{
			//conversation already exists
			$payload = $authInfo["data"]->conversations[0]->conversation_messages->messaging_auth->payload;
			$mac = $authInfo["data"]->conversations[0]->conversation_messages->messaging_auth->mac;
			$name = $this->username;
			$seq_num = $authInfo["data"]->conversations[0]->conversation_state->user_sequences->$name;
			$conv_id = $authInfo["data"]->conversations[0]->id;
		}

		$genID = md5(uniqid());
		$chatID = strtoupper(sprintf('%08s-%04s-%04x-%04x-%12s', substr($genID, 0, 8), substr($genID, 8, 4), substr($genID, 12, 4), substr($genID, 16, 4), substr($genID, 20, 12)));
		$genID = md5(uniqid());
		$id = strtoupper(sprintf('%08s-%04s-%04x-%04x-%12s', substr($genID, 0, 8), substr($genID, 8, 4), substr($genID, 12, 4), substr($genID, 16, 4), substr($genID, 20, 12)));

		$timestamp = parent::timestamp();
		$messagesArray = array(
			array(
				'body' => array(
					'text' => $text,
					'type' => 'text'
				),
				'chat_message_id' => $chatID,
				'seq_num' => $seq_num + 1,
				'timestamp' => $timestamp,
				'header' => array(
					'auth' => array(
						'mac' => $mac,
						'payload' => $payload
					),
					'to' => array(
						$to
					),
					'conv_id' => $conv_id,
					'from' => $this->username,
					'conn_seq_num' => 1
				),
				'retried' => false,
				'id' => $id,
				'type' => 'chat_message'
			)
		);

		$messages = json_encode($messagesArray);
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/conversation_post_messages',
			array(
				'auth_token' => $this->auth_token,
				'messages' => $messages,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}

	public function getConversations()
	{
		$updates = $this->getUpdates();
		$offset = end($updates['data']->conversations_response)->iter_token;
		$convos = $updates['data']->conversations_response;
		while(strlen($offset) > 0){
			$timestamp = parent::timestamp();
			$result = parent::post(
				'/loq/conversations',
				array(
					'username' => $this->username,
					'timestamp' => $timestamp,
					'checksum' => md5($this->username),
					'offset' => $offset,
					'features_map' => '{}'
				),
				array(
					$this->auth_token,
					$timestamp,
				),
				$multipart = false
			);
			$convos = array_merge($convos, $result['data']->conversations_response);
			$last = json_decode(json_encode(end($result['data']->conversations_response)), true);
			$offset = (array_key_exists("iter_token", $last)) ? $last['iter_token'] : "";
		}
		return $convos;
	}

	/**
	 * Retrieves general user, friend, and snap updates.
	 *
	 * @param bool $force
	 *   Forces an update even if there's fresh data in the cache. Defaults
	 *   to FALSE.
	 *
	 * @return mixed
	 *   The data returned by the service or FALSE on failure.
	 */
	public function getUpdates($force = TRUE)
	{
		if(!$force)
		{
			$result = $this->cache->get('updates');
			if($result)
			{
				return $result;
			}
		}

		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/all_updates',
			array(
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		if(!empty($result->updates_response))
		{
			$this->auth_token = $result->updates_response->auth_token;
			$this->cache->set('updates', $result->updates_response);
			return $result->updates_response;
		}

		return $result;
	}

	/**
	 * Gets the user's snaps.
	 *
	 * @return mixed
	 *   An array of snaps or FALSE on failure.
	 */
	public function getSnaps($save = FALSE, $subdir = null)
	{
		$updates = $this->getUpdates();
		if(empty($updates))
		{
			return FALSE;
		}

		$snaps = array();
		$conversations = $this->getConversations();
	    foreach($conversations as &$conversation)
	    {
			$pending_received_snaps = $conversation->pending_received_snaps;
			foreach($pending_received_snaps as &$snap)
			{
			    $snaps[] = (object) array(
					'id' => $snap->id,
					'media_id' => empty($snap->c_id) ? FALSE : $snap->c_id,
					'media_type' => $snap->m,
					'time' => empty($snap->t) ? FALSE : $snap->t,
					'sender' => empty($snap->sn) ? $this->username : $snap->sn,
					'recipient' => empty($snap->rp) ? $this->username : $snap->rp,
					'status' => $snap->st,
					'screenshot_count' => empty($snap->c) ? 0 : $snap->c,
					'sent' => $snap->sts,
					'opened' => $snap->ts,
					'broadcast' => empty($snap->broadcast) ? FALSE : (object)
					array(
						'url' => $snap->broadcast_url,
						'action_text' => $snap->broadcast_action_text,
						'hide_timer' => $snap->broadcast_hide_timer,
					),
				);
			}
		}

		if($save)
		{
			foreach($snaps as $snap)
			{
				$id = $snap->id;
				$from = $snap->sender;
				$time = $snap->sent;

				$this->getMedia($id, $from, $time, $subdir);
			}
		}

		return $snaps;
	}

	/**
	 * Gets friends' stories.
	 *
	 * @param bool $force
	 *   Forces an update even if there's fresh data in the cache. Defaults
	 *   to FALSE.
	 *
	 * @return mixed
	 *   An array of stories or FALSE on failure.
	 */
	function getFriendStories($save = FALSE)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$updates = $this->getUpdates();
		if(empty($updates))
		{
			return FALSE;
		}

		$stories = array();
		foreach ($updates['data']->stories_response->friend_stories as $group) {
				foreach ($group->stories as $story) {
						$stories[] = $story->story;
				}
		}

		if($save)
		{
			foreach($stories as $story)
			{
				$id = $story->media_id;
				$from = $story->username;
				$mediaKey = $story->media_key;
				$mediaIV = $story->media_iv;

				$this->getStory($id, $mediaKey, $mediaIV, $from, $save);
			}
		}

		return $stories;
	}

	/**
	 * Queries the friend-finding service.
	 *
	 * @todo
	 *   If over 30 numbers are passed in, spread the query across multiple
	 *   requests. The API won't return more than 30 results at once.
	 *
	 * @param array $numbers
	 *   An array of phone numbers.
	 *   FORMATTING: array("name" => "number") !! VERY IMPORTANT !!
	 *
	 * @return mixed
	 *   An array of user objects or FALSE on failure.
	 */
	public function findFriends($numbers)
	{
		$updates = $this->getUpdates();

		if(empty($updates))
		{
			return FALSE;
		}

		$itsVerified = $updates['data']->updates_response->should_send_text_to_verify_number;
		if (!$itsVerified)
		{
			$batches = array_chunk(array_flip($numbers), 30, TRUE);
			$country = $updates['data']->updates_response->country_code;

			// Make sure we're logged in and have a valid access token.
			if(!$this->auth_token || !$this->username)
			{
				return FALSE;
			}

			$results = array();
			foreach($batches as $batch)
			{
				$timestamp = parent::timestamp();
				$result = parent::post(
					'/ph/find_friends',
					array(
						'countryCode' => $country,
						'numbers' => json_encode($batch, JSON_FORCE_OBJECT),
						'timestamp' => $timestamp,
						'username' => $this->username,
					),
					array(
						$this->auth_token,
						$timestamp,
					),
					$multipart = false,
					$debug = $this->debug
				);

				if (isset($result->results)) {
						$results = $results + $result->results;
					}
				}

				return $results;
		}
		else if ($this->debug)
				echo 'DEBUG: You need to verify your phone number';
	}

	public function searchFriend($friend)
	{
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/friend_search',
			array(
				'query' => $friend,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}


	public function userExists($user)
	{
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/user_exists',
			array(
				'request_username' => $user,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}

	/**
	 * Gets the user's friends.
	 *
	 * @return mixed
	 *   An array of friends
	 */
	public function getFriends()
	{
		$updates = $this->getUpdates();

		if(empty($updates))
		{
			return FALSE;
		}

		$friends = array();
		$friends = $updates['data']->friends_response;
		$friends = $friends->friends;

		foreach($friends as $friend)
		{
				$friendList[] = $friend->name;
		}

		return $friendList;
	}

	/**
	 * Gets the user's added friends.
	 *
	 * @return mixed
	 *   An array of friends or FALSE on failure.
	 */
	public function getAddedFriends()
	{
		$updates = $this->getUpdates();

		if(empty($updates))
		{
			return FALSE;
		}

		$friends = array();
		$friends = $updates['data']->friends_response->added_friends;
		foreach($friends as $friend)
		{
				$friendList[] = $friend->name;
		}

		return $friendList;
	}

	/**
	* Gets unconfirmed friends.
	*
	* @return mixed
	*   An array of friends or FALSE on failure.
	*/
	public function getUnconfirmedFriends()
	{
		$updates = $this->getUpdates();

		if(empty($updates))
		{
			return FALSE;
		}

		$friends = array();
		$friends = $updates['data']->friends_response->added_friends;
		foreach($friends as $friend)
		{
				if ($friend->type == 1)
				{
					if (($friend->name != 'array') && ($friend->is_shared_story != 1))
							$unconfirmedList[] = $friend->name;
				}
		}

		return $unconfirmedList;
	}

	/**
	 * Adds a friend.
	 *
	 * @param string $username
	 *   The username of the friend to add.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function addFriend($username)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/friend',
			array(
				'action' => 'add',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
				'friend_source' => 'ADDED_BY_USERNAME'
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		// Sigh...
		if(strpos($result["data"]->message, 'Sorry! Couldn\'t find') === 0)
		{
			return FALSE;
		}

		return !empty($result->message);
	}

	/**
	 * Adds multiple friends.
	 *
	 * @param array $usernames
	 *   Usernames of friends to add.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function addFriends($usernames)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		if(!is_array($usernames))
		{
			$usernames = array($usernames);
		}

		$friends = array();
		foreach($usernames as $username)
		{
			$friends[] = (object) array(
				'display' => '',
				'name' => $username,
				'type' => self::FRIEND_UNCONFIRMED,
			);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/friend',
			array(
				'action' => 'multiadddelete',
				'friend' => json_encode(
						array(
								'friendsToAdd' => $friends,
								'friendsToDelete' => array(),
						)),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return !empty($result->message);
	}

	/**
	* Accept an user friend request.
	*
	* @param string $username
	*   The username of the friend to add.
	*
	* @return bool
	*   TRUE if successful, FALSE otherwise.
	*/
	public function addFriendBack($username)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/friend',
			array(
				'action' => 'add',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
				'added_by' => 'ADDED_BY_ADDED_ME_BACK'
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		// Sigh...
		if(strpos($result["data"]->message, 'Sorry! Couldn\'t find') === 0)
		{
			return FALSE;
		}

		return !empty($result->message);
	}

	/**
	 * Deletes a friend.
	 *
	 * @todo
	 *   Investigate deleting multiple friends at once.
	 *
	 * @param string $username
	 *   The username of the friend to delete.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function deleteFriend($username)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/friend',
			array(
				'action' => 'delete',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return !empty($result->message);
	}

	/**
	 * Sets a friend's display name.
	 *
	 * @param string $username
	 *   The username of the user to modify.
	 * @param string $display
	 *   The new display name.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function setDisplayName($username, $display) {
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/friend',
			array(
				'action' => 'display',
				'display' => $display,
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return !empty($result->message);
	}

	/**
	 * Blocks a user.
	 *
	 * @param string $username
	 *   The username of the user to be blocked.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function block($username)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/friend',
			array(
				'action' => 'block',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return !empty($result->message);
	}

	/**
	 * Unblocks a user.
	 *
	 * @param string $username
	 *   The username of the user to unblock.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function unblock($username)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/friend',
			array(
				'action' => 'unblock',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return !empty($result->message);
	}


	/**
	 * Downloads a snap.
	 *
	 * @param string $id
	 *   The snap ID.
	 *
	 * @return mixed
	 *   The snap data or FALSE on failure.
	 *     Snap data can returned as an Array of more than one file.
	 * 	array(
	 * 		overlay~zip-CE6F660A-4A9F-4BD6-8183-245C9C75B8A0    => overlay_file_data,
	 *		media~zip-CE6F660A-4A9F-4BD6-8183-245C9C75B8A0	    => m4v_file_data
	 * 	)
	 */
	function getMedia($id, $from = null, $time = null, $subdir = null)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();

		$result = parent::post(
			'/bq/blob',
				array(
					'id' => $id,
					'timestamp' => $timestamp,
					'username' => $this->username,
				),
				array(
					$this->auth_token,
					$timestamp,
				),
				$multipart = false,
				$debug = $this->debug
			);

		if(parent::isMedia(substr($result, 0, 2)))
		{
			if($from != null && $time != null)
			{

				if ($subdir == null) {
					$subdir = $this->username;
				}

				$path = __DIR__ . DIRECTORY_SEPARATOR . "snaps" . DIRECTORY_SEPARATOR . $subdir . DIRECTORY_SEPARATOR .  $from;
				if(!file_exists($path))
				{
					mkdir($path, 0777, true);
				}
				$file = $path . DIRECTORY_SEPARATOR . date("Y-m-d H:i:s", (int) ($time / 1000));
				file_put_contents($file, $result);
				$finfo = finfo_open(FILEINFO_MIME_TYPE);
				$finfo = finfo_file($finfo, $file);
				switch($finfo)
				{
					case "image/jpeg":
						$ext = ".jpg";
						break;
					case "image/png":
						$ext = ".png";
						break;
					case "video/mp4";
						$ext = ".mp4";
						break;
					default:
						$ext = null;
				}

				if($ext != null)
				{
					rename($file, $file . $ext);
				}
			}

			return $result;
		}
		else
		{
			$result = parent::decryptECB($result);
			if(parent::isMedia(substr($result, 0, 2)))
			{
				return $result;
			}

			//When a snapchat video is sent with "text" or overlay
			//the overlay is a transparent PNG file Zipped together
			//with the M4V file.
			//First two bytes are "PK" x50x4B; thus the previous media check
			//will fail and would've returned a FALSE on an available media.
			if(parent::isCompressed(substr($result, 0, 2)))
			{
				//Uncompress
				$result = parent::unCompress($result);
				//Return Media and Overlay
			}
		}

		return FALSE;
	}

	/**
	 * Sends event information to Snapchat.
	 *
	 * @param array $events
	 *   An array of events. This seems to be used only to report usage data.
	 * @param array $snap_info
	 *   Data to send along in addition to the event array. This is used to
	 *   mark snaps as viewed. Defaults to an empty array.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function sendEvents($events, $snap_info = array())
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/update_snaps',
			array(
				'events' => json_encode($events),
				'json' => json_encode($snap_info),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}

	/**
	 * Called for every shared story in the story view to provide a description to the user
	 *
	 * @param string $sharedId
	 *   An array of events. This seems to be used only to report usage data.
	 *
	 * @return
	 *   {} if successful, FALSE otherwise.
	 */
	public function provideSharedDescription($sharedId)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/shared/description',
			array(
				'shared_id' => $sharedId,
				'features_map' => '{}',
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}

	/**
	 * Marks a snap as viewed.
	 *
	 * Snaps can be downloaded an (apparently) unlimited amount of times before
	 * they are viewed. Once marked as viewed, they are deleted.
	 *
	 * It's worth noting that it seems possible to mark others' snaps as viewed
	 * as long as you know the ID. This hasn't been tested thoroughly, but it
	 * could be useful if you send a snap that you immediately regret.
	 *
	 * @param string $id
	 *   The snap to mark as viewed.
	 * @param int $time
	 *   The amount of time (in seconds) the snap was viewed. Defaults to 1.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function markSnapViewed($id, $time = 1)
	{
		$snap_info = array(
			$id => array(
				// Here Snapchat saw fit to use time as a float instead of straight milliseconds.
				't' => microtime(TRUE),
				// We add a small variation here just to make it look more realistic.
				'sv' => $time + (mt_rand() / mt_getrandmax() / 10),
			),
		);

		$events = array(
			array(
				'eventName' => 'SNAP_VIEW',
				'params' => array(
					'id' => $id,
					// There are others, but it wouldn't be worth the effort to put them in here since they likely don't matter.
				),
				'ts' => time() - $time,
			),
			array(
				'eventName' => 'SNAP_EXPIRED',
				'params' => array(
					'id' => $id,
				),
				'ts' => time()
			),
		);

		return $this->sendEvents($events, $snap_info);
	}

	/**
	 * Sends a screenshot event.
	 *
	 * @param string $id
	 *   The snap to mark as shot.
	 * @param int $time
	 *   The amount of time (in seconds) the snap was viewed. Defaults to 1.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function markSnapShot($id, $time = 1)
	{
		$snap_info = array(
			$id => array(
				// We use the same time values as in markSnapViewed, but add in the screenshot status.
				't' => microtime(TRUE),
				'sv' => $time + (mt_rand() / mt_getrandmax() / 10),
				'c' => self::STATUS_SCREENSHOT,
			),
		);

		$events = array(
			array(
				'eventName' => 'SNAP_SCREENSHOT',
				'params' => array(
					'id' => $id,
				),
				'ts' => time() - $time,
			),
		);

		return $this->sendEvents($events, $snap_info);
	}

	/**
	* Whenever a story is viewed by the user the application notifies the server of the view,
	* the time of viewing and the amount of screenshots taken.
	*
	* @param Array $friendStories
	*   The snap to mark as shot.
	*			friend_stories : Array
	*							Array
  *      							id : Story snap id
  *      							screenshot-count : Integer
  *      							timestamp : Time viewed
	*
	* @return
	* 	If your request was successful, you'll get back a 200 OK with no body content.
	*/
	public function updateStories($friendStories)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/update_stories',
			array(
				'friend_stories' => json_encode($friendStories),
				'features_map' => '{}',
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}

	/**
	* Accept terms and conditions of SnapCash and Square
	*
	* @param bool $acceptSnapCashV2Tos
	*
	* @param bool $acceptSnapCashTos
	*
	* @param bool $acceptSquareTos
	**/
	public function updateUser($acceptSnapCashV2Tos = true, $acceptSnapCashTos = true, $acceptSquareTos = false)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$acceptSnapCashV2Tos = ($acceptSnapCashV2Tos) ? 'true' : 'false';
		$acceptSnapCashTos = ($acceptSnapCashTos) ? 'true' : 'false';
		$acceptSquareTos = ($acceptSquareTos) ? 'true' : 'false';

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/update_user',
			array(
				'client_properties' => json_encode(array(
						'snapcash_tos_v2_accepted' => $acceptSnapCashV2Tos,
						'snapcash_new_tos_accepted' => $acceptSnapCashTos,
						'square_tos_accepted' => $acceptSquareTos
				)),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}

	/**
	 * Uploads a snap.
	 *
	 * @todo
	 *   Fix media ID generation; it looks like they're GUIDs now.
	 *
	 * @param int $type
	 *   The media type, i.e. MEDIA_IMAGE or MEDIA_VIDEO.
	 * @param data $data
	 *   The file data to upload.
	 *
	 * @return mixed
	 *   The ID of the uploaded media or FALSE on failure.
	 */
	public function upload($data, $media)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$finfo = finfo_open(FILEINFO_MIME_TYPE);
		$mime = finfo_file($finfo, $media);

		if(strstr($mime, "video/"))
		{
			$type = Snapchat::MEDIA_VIDEO;
		}
		else if(strstr($mime, "image/"))
		{
			$type = Snapchat::MEDIA_IMAGE;
		}
		else
		{
			return false;
		}

		/*
		// To make cURL happy, we write the data to a file first.
		$temp = tempnam(sys_get_temp_dir(), 'Snap');
		file_put_contents($temp, parent::encryptECB($data));

		if(version_compare(PHP_VERSION, '5.5.0', '>='))
		{
			$cfile = curl_file_create($temp, ($type == self::MEDIA_IMAGE ? 'image/jpeg' : 'video/quicktime'), 'snap');
		}
		*/

		$uniId = md5(uniqid());
		$media_id = strtoupper($this->username . '~' . sprintf('%08s-%04s-%04x-%04x-%12s', substr($uniId, 0, 8), substr($uniId, 8, 4), substr($uniId, 12, 4), substr($uniId, 16, 4), substr($uniId, 20, 12)));
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/ph/upload',
			array(
				'media_id' => $media_id,
				'type' => $type,
				'data' => $data,
				'timestamp' => $timestamp,
				'username' => $this->username,
				'zipped' => '0'
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = true,
			$debug = $this->debug
		);

		//unlink($temp);

		//TODO IF ERROR
		return $media_id;
	}
	/**
	 * Sends a snap.
	 *
	 * @param string $media_id
	 *   The media ID of the snap to send.
	 * @param array $recipients
	 *   An array of recipient usernames.
	 * @param int $type
	 *   The type of the media being sent.
	 * @param int $time
	 *   The time in seconds the snap should be available (1-10). Defaults to 3.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	 public function send_retry($media, $recipients, $type = 0, $time = 10) {
		// Make sure we're logged in and have a valid access token.
		if (!$this->auth_token || !$this->username) {
			return FALSE;
		}
		$uniId = md5(uniqid());
		$media_id = strtoupper($this->username . '~' . sprintf('%08s-%04s-%04x-%04x-%12s', substr($uniId, 0, 8), substr($uniId, 8, 4), substr($uniId, 12, 4), substr($uniId, 16, 4), substr($uniId, 20, 12)));
		if(!is_array($recipients)) $recipients = array($recipients);
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/retry',
			array(
				'camera_front_facing' => rand(0,1),
				'country_code' => 'US',
				'media_id' => $media_id,
				'recipients' => '["' . implode('","', $recipients) . '"]',
				'reply' => '0',
				'time' => $time,
				'timestamp' => $timestamp,
				'type' => $type,
				'username' => $this->username,
				'zipped' => '0',
				'data' => $media
			),
			array(
				$this->auth_token,
				$timestamp,
			),  $multipart = true
		);

		return $result;
	}
	/**
	 * Sends a snap.
	 *
	 * @param string $media
	 *   The path to the media to send.
	 * @param array $recipients
	 *   An array of recipient usernames.
	 * @param string $text
	 *   Text to add to image.
	 * @param int $time
	 *   The time in seconds the snap should be available (1-10). Defaults to 3.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function send($media, $recipients, $text = null, $time = 3)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}
		if(!is_array($recipients)) $recipients = array($recipients);
		$recipients = '["' . implode('","', $recipients) . '"]';

		if(!is_null($text))
		{
			$mediaData = text($media, $text);
		}
		else
		{
			$mediaData = file_get_contents($media);
		}

		$media_id = $this->upload($mediaData, $media);

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/send',
			array(
				'media_id' => $media_id,
				'zipped' => '0',
				'recipients' => $recipients,
				'username' => $this->username,
				'time' => $time,
				'timestamp' => $timestamp,
				'features_map' => '{}'
			),
			array(
				$this->auth_token,
				$timestamp
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}

	/**
	 * Send to recipients a typing status.
	 *
	 * @param array $recipients
	 *   An array of recipient usernames.
	 */
	public function sendTyping($recipients)
	{
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$recipientsString = "[";
		if(is_array($recipients))
		{
			foreach($recipients as $user)
			{
				$recipientsString .= "\"{$user}\",";
			}
			$recipientsString = rtrim($recipientsString, ',');
			$recipientsString .=  "]";
		}
		else
		{
			$recipientsString .= "\"{$recipients}\"]";
		}
		$recipients = $recipientsString;

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/chat_typing',
			array(
				'recipient_usernames' => $recipients,
				'timestamp' => $timestamp,
				'username' => $this->username
			),
			array(
				$this->auth_token,
				$timestamp
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}

	/**
	 * Sets a story.
	 *
	 * @param string $media_id
	 *   The media ID of the story to set.
	 * @param int $media_type
	 *   The media type of the story to set (i.e. MEDIA_IMAGE or MEDIA_VIDEO).
	 * @param int $time
	 *   The time in seconds the story should be available (1-10). Defaults to 3.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function setStory($media, $time = 10, $text = null)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}


		$finfo = finfo_open(FILEINFO_MIME_TYPE);
		$mime = finfo_file($finfo, $media);

		if(strstr($mime, "video/"))
		{
			$type = Snapchat::MEDIA_VIDEO;
		}
		else if (strstr($mime, "image/"))
		{
			$type = Snapchat::MEDIA_IMAGE;
		}

		if (($text != null) && ($type == Snapchat::MEDIA_IMAGE))
		{
				$media = text($media, $text);
		}
		else
		{
				$media = file_get_contents($media);
		}

		$temp = tempnam(sys_get_temp_dir(), 'Snap');
		file_put_contents($temp, $media);
		if(false && version_compare(PHP_VERSION, '5.5.0', '>='))
		{
			$cfile = curl_file_create($temp, ($type == self::MEDIA_IMAGE ? 'image/jpeg' : 'video/quicktime'), 'snap');
		}
		else
		{
			$cfile = file_get_contents($temp);
		}

		$timestamp = parent::timestamp();
		$uniId = md5(uniqid());
		$media_id = strtoupper($this->username . '~' . sprintf('%08s-%04s-%04x-%04x-%12s', substr($uniId, 0, 8), substr($uniId, 8, 4), substr($uniId, 12, 4), substr($uniId, 16, 4), substr($uniId, 20, 12)));
		$result = parent::post(
			'/bq/retry_post_story',
			array(
				'client_id' => $media_id,
				'shared_ids' => '{}',
				'story_timestamp' => parent::timestamp(),
				'media_id' => $media_id,
				'zipped' => 0,
				'camera_front_facing' => rand(0, 1),
				'my_story' => true,
				'caption_text_display' => $text,
				'timestamp' => $timestamp,
				'time' => $time,
				'type' => $type,
				'username' => strtolower($this->username),
				'data' => $cfile
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = true,
			$debug = $this->debug
		);

		return $result;
	}

	public function deleteStory($storyId)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/delete_story',
			array(
				'story_id' => $storyId,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}

	public function getStoriesByUsername($friend, $save = false)
	{
		$stories = $this->getFriendStories();
		$friendStories = array();

		foreach ($stories as $story)
		{
			if ($story->username == $friend)
			{
				$friendStories[] = $story;
			}
		}

		if($save)
		{
			foreach($friendStories as $story)
			{
				$id = $story->media_id;
				$from = $story->username;
				$mediaKey = $story->media_key;
				$mediaIV = $story->media_iv;
				$timestamp = $story->timestamp;

				$this->getStory($id, $mediaKey, $mediaIV, $from, $timestamp, $save);
			}
		}

		return $friendStories;
	}

	/**
	 * Downloads a story.
	 *
	 * @param string $media_id
	 *   The media ID of the story.
	 * @param string $key
	 *   The base64-encoded key of the story.
	 * @param string $iv
	 *   The base64-encoded IV of the story.
	 *
	 * @return mixed
	 *   The story data or FALSE on failure.
	 */
	public function getStory($media_id, $key, $iv, $from, $timestamp, $save = FALSE, $subdir = null)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		// Retrieve encrypted story and decrypt.
		$blob = parent::get('/bq/story_blob?story_id=' . $media_id);

		if(!empty($blob))
		{

			$result = parent::decryptCBC($blob, $key, $iv);

			if(parent::isCompressed(substr($result, 0, 2)))
			{
				$result = parent::unCompress($result);
			}

			if($save)
			{

				if ($subdir == null) {
					$subdir = $this->username;
				}

				$path = __DIR__ . DIRECTORY_SEPARATOR . "stories" . DIRECTORY_SEPARATOR . $subdir . DIRECTORY_SEPARATOR .  $from;

				if(!file_exists($path))
				{
					mkdir($path, 0777, true);
				}

				if(is_array($result))
				{
					foreach ($result as &$value)
					{
				    $file = $path . DIRECTORY_SEPARATOR . date("Y-m-d H:i:s", (int) ($timestamp / 1000)) . "-story-" . $media_id;

						if(!file_exists($file))
						{
							file_put_contents($file, $value);
							$finfo = finfo_open(FILEINFO_MIME_TYPE);
							$finfo = finfo_file($finfo, $file);
							switch($finfo)
							{
								case "image/jpeg":
										$ext = ".jpg";
										break;
								case "image/png":
										$ext = ".png";
										break;
								case "video/mp4";
										$ext = ".mp4";
										break;
								default:
										$ext = null;
							}

							if($ext != null)
							{
								rename($file, $file . $ext);
							}
						}
					}
				}else{
					$file = $path . DIRECTORY_SEPARATOR . date("Y-m-d H:i:s", (int) ($timestamp / 1000)) . "-story-" . $media_id;
					if(!file_exists($file))
					{
						file_put_contents($file, $result);
						$finfo = finfo_open(FILEINFO_MIME_TYPE);
						$finfo = finfo_file($finfo, $file);
						switch($finfo)
						{
							case "image/jpeg":
									$ext = ".jpg";
									break;
							case "image/png":
									$ext = ".png";
									break;
							case "video/mp4";
									$ext = ".mp4";
									break;
							default:
									$ext = null;
						}

						if($ext != null)
						{
							rename($file, $file . $ext);
						}
					}
				}
			}

			return $result;
		}

		return FALSE;
	}

	/**
	 * Downloads a story's thumbnail.
	 *
	 * @param string $media_id
	 *   The media_id of the story.
	 * @param string $key
	 *   The base64-encoded key of the story.
	 * @param string $iv
	 *   The base64-encoded IV of the thumbnail.
	 *
	 * @return mixed
	 *   The thumbnail data or FALSE on failure.
	 */
	public function getStoryThumb($media_id, $key, $iv)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		// Retrieve encrypted story and decrypt.
		$blob = parent::get('/bq/story_thumbnail?story_id=' . $media_id);

		if(!empty($blob))
		{
			return parent::decryptCBC($blob, $key, $iv);
		}

		return FALSE;
	}

	/**
	 * Marks a story as viewed.
	 *
	 * @param string $id
	 *   The ID of the story.
	 * @param int $screenshot_count
	 *   Amount of times screenshotted. Defaults to 0.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function markStoryViewed($id, $screenshot_count = 0)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		// Mark story as viewed.
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/update_stories',
			array(
				'friend_stories' => json_encode(array(
					array(
						'id' => $id,
						'screenshot_count' => $screenshot_count,
						'timestamp' => $timestamp,
					),
				)),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}

	/**
	 * Gets the best friends and scores of the specified users.
	 *
	 * @param array $friends
	 *   An array of usernames for which to retrieve best friend information.
	 *
	 * @return mixed
	 *   An dictionary of friends by username or FALSE on failure.
	 */
	public function getBests($friends)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		if(!is_array($friends))
		{
			$friends = array($friends);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/bests',
			array(
				'friend_usernames' => json_encode($friends),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		if(empty($result))
		{
			return FALSE;
		}

		$friends = array();
		foreach((array) $result as $friend => $bests)
		{
			$friends[$friend] = (array) $bests;
		}

		return $friends;
	}

	/**
	* Sets the number of best friends to display for your username
	*
	* @param int $num
	*   Number from 3 to 7.
	*
	* @return array
	*   Array of best friend usernames.
	*/
	public function setBestFriends($num)
	{
		if (!$this->auth_token || !$this->username) {
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/set_num_best_friends',
			array(
				'num_best_friends' => $num,
				'features_map' => '{}',
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}

	public function clearConvo($id) {
		// Make sure we're logged in and have a valid access token.
		if (!$this->auth_token || !$this->username) {
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/clear_conversation',
			array(
			    'conversation_id' => $id,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}
	/**
	 * Clears the current user's feed.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function clearFeed()
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/ph/clear',
			array(
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return is_null($result);
	}

	/**
	 * Updates the current user's privacy setting.
	 *
	 * @param string $setting
	 *   The privacy setting, i.e. all or friends
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function updatePrivacy($setting)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		if(strcasecmp($setting, 'all'))
		{
			$setting = Snapchat::PRIVACY_EVERYONE;
		}
		elseif(strcasecmp($setting, 'friends'))
		{
			$setting = Snapchat::PRIVACY_FRIENDS;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/settings',
			array(
				'action' => 'updatePrivacy',
				'privacySetting' => $setting,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return isset($result->param) && $result->param == $setting;
	}

	/**
	 * Updates the current user's email address.
	 *
	 * @param string $email
	 *   The new email address.
	 *
	 * @return bool
	 *   TRUE if successful, FALSE otherwise.
	 */
	public function updateEmail($email)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/settings',
			array(
				'action' => 'updateEmail',
				'email' => $email,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return isset($result->param) && $result->param == $email;
	}

	/**
	* Updates if the user can be searchable by phone number.
	*
	* @param bool $searchable
	*   The new email address.
	*
	* @return bool
	*   TRUE if successful, FALSE otherwise.
	*/
	public function updateSearchableByPhoneNumber($searchable)
	{
		// Make sure we're logged in and have a valid access token.
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/settings',
			array(
				'action' => 'updateSearchableByPhoneNumber',
				'searchable' => $searchable,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return isset($result->param) && $result->param == $bool;
	}

	public function openAppEvent()
	{
    	$timestamp = parent::timestamp();
    	$uniId = md5(uniqid());
    	$updates = $this->getUpdates();
			$updates = $updates['data'];
			$fc = -1;
			if ($updates != "")
			{
    			$friends = $updates->friends_response;
					foreach($friends->friends as &$friend) if (strval($friend->type) == 0) $fc++;
			}

			$uuid4 = sprintf('%08s-%04s-%04x-%04x-%12s', substr($uniId, 0, 8), substr($uniId, 8, 4), substr($uniId, 12, 4), substr($uniId, 16, 4), substr($uniId, 20, 12));
    	$data = '{"common_params":{"user_id":"' . hash("sha256",strtolower($this->username)) . '","city":"Unimplemented","sc_user_agent":"' . str_replace("/", "\/", parent::USER_AGENT) . '","session_id":"00000000-0000-0000-0000-000000000000","region":"Unimplemented","latlon":"Unimplemented","friend_count":' . $fc . ',"country":"Unimplemented"},"events":[{"event_name":"APP_OPEN","event_timestamp":' . $timestamp . ',"event_params":{"open_state":"NORMAL","intent_action":"null"}}],"batch_id":"' . $uuid4 . '-' . preg_replace("/[^a-zA-Z0-9]+/", "", parent::USER_AGENT) . $timestamp . '"}';
      $result = parent::posttourl('https://sc-analytics.appspot.com/post_events',$data);

			if ($this->debug)
			{
					echo "REQUEST TO: https://sc-analytics.appspot.com/post_events\n\n";
					echo "DATA: " . $data . "\n";
			}

	  	return $result;
  }

	public function closeAppEvent()
	{
		$events = array(
			array(
				'eventName' => 'CLOSE',
				'params' => array(),
				'ts' => time()
			),
		);
		return $this->sendEvents($events);
	}

	/**
	* Updates extra feature settings.
	*
	* @param bool $frontFacingFlash
	*   Enable / Disable.
	*
	* @param bool $replaySnap
	*   Enable / Disable.
	*
	* @param bool $smartFilter
	*   Enable / Disable.
	*
	* @param bool $visualFilters
	*   Enable / Disable.
	*
	* @return
	*   If your request was successful, you'll get back a 200 OK with no body content.
	*/
	public function updateFeatureSettings($frontFacingFlash, $replaySnap, $smartFilter, $visualFilters)
	{
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/update_feature_settings',
			array(
				'settings' => json_encode(array(
						'front_facing_flash' => $frontFacingFlash,
						'replay_snaps' => $replaySnap,
						'smart_filters' => $smartFilter,
						'visual_filters' => $visualFilters
				)),
				'timestamp' => $timestamp,
				'username' => $this->username,
				'features_map' => '{}'
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}

	/**
	* Download the user's Snaptag, a jazzed up QR code with a ghost in the middle.
	*
	* @return data
	*   Snaptag data
	*/
	public function getSnaptag()
	{
		$updates = $this->getUpdates();
		if(empty($updates))
		{
			return FALSE;
		}

		$snaps = array();
		$qr = $updates['data']->updates_response->qr_path;

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bq/snaptag_download',
			array(
				'image' => $qr,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			$multipart = false,
			$debug = $this->debug
		);

		return $result;
	}
}
