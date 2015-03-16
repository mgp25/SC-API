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

	/**
	 * Sets up some initial variables. If a username and password are passed in,
	 * we attempt to log in. If a username and auth token are passed in, we'll
	 * bypass the login process and use those values.
	 *
	 * @param string $username
	 *   The username for the Snapchat account.
	 * @param string $password
	 *   The password associated with the username, if logging in.
	 * @param string $auth_token
	 *   The auth token, if already logged in.
	 */
	public function __construct($username = NULL, $auth_token = NULL, $debug = FALSE)
	{
		$this->auth_token = $auth_token;
		$this->username = $username;
		$this->debug = $debug;
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

	public function device($device_token)
	{
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/loq/all_updates',
			array(
				'device_token' => $device_token,
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

	private function getAuthToken()
	{
		$ch = curl_init();
		$postfields = array(
			'device_country' => 'nl',
			'operatorCountry' => 'nl',
			'lang' => 'en_US',
			'sdk_version' => '16',
			'google_play_services_version' => '6599036',
			'accountType' => 'HOSTED_OR_GOOGLE',
			'Email' => 'test@gmail.com',
			'service' => 'audience:server:client_id:694893979329-l59f3phl42et9clpoo296d8raqoljl6p.apps.googleusercontent.com',
			'source' => 'android',
			'androidId' => '378c184c6070c26c',
			'app' => 'com.snapchat.android',
			'client_sig' => '49f6badb81d89a9e38d65de76f09355071bd67e7',
			'callerPkg' => 'com.snapchat.android',
			'callerSig' => '49f6badb81d89a9e38d65de76f09355071bd67e7',
			'EncryptedPasswd' => 'oauth2rt_1/6YQ6444lgGwYt3zB5DbnCI6rqZq2wo6PszKF8RjGa74'
		);

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

		return $return;
	}

	private function getGCMToken()
	{
		$ch = curl_init();
		$postfields = array(
			'X-GOOG.USER_AID' => '3538080729494335741',
			'app' => 'com.snapchat.android',
			'sender' => '191410808405',
			'cert' => '49f6badb81d89a9e38d65de76f09355071bd67e7',
			'device' => '3538080729494335741',
			'app_ver' => '545',
			'info' => '',
		);

		$headers = array(
			'app: com.snapchat.android',
			'User-Agent: Android-GCM/1.4 (A0001 KTU84Q)',
			'Authorization: AidLogin 3538080729494335741:629201482958995543'
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
	 * @param string $username
	 *   The username for the Snapchat account.
	 * @param string $password
	 *   The password associated with the username.
	 *
	 * @return mixed
	 *   The data returned by the service or FALSE if the request failed.
	 *   Generally, returns the same result as self::getUpdates().
	 */
	public function login($username, $password)
	{
		$dtoken = $this->getDeviceToken();

		if($dtoken['error'] == 1)
		{
			$return['message'] = "Failed to get new Device token set.";
			return $return;
		}

		$ptoken = $this->getGCMToken();

		if($ptoken['error'] == 1)
		{
			$return['message'] = "Failed to get GCM token.";
			return $return;
		}

		$timestamp = parent::timestamp();
		$req_token = parent::hash(parent::STATIC_TOKEN, $timestamp);
		$string = $username . "|" . $password . "|" . $timestamp . "|" . $req_token;

		$auth = $this->getAuthToken();

		if($auth['error'] == 1)
		{
			return $auth;
		}

		$result = parent::post(
			'/loq/login',
			array(
				'username' => $username,
				'password' => $password,
				'height' => 1280,
				'width' => 720,
				'max_video_height' => 640,
				'max_video_width' => 480,
				'dsig' => substr(hash_hmac('sha256', $string, $dtoken['data']->dtoken1v), 0, 20),
				'dtoken1i' => $dtoken['data']->dtoken1i,
				'ptoken' => $ptoken['token'],
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
			$this->username = $result['data']->updates_response->username;
			$this->device($ptoken['token']);
		}

		return $result;
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
			'/logout',
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
				echo "\nGo to <insert verification site URL here> to finish the verification process.\nNOTE: Your new account will not be usable until you complete verification!";
			}
		}
		else
		{
			return FALSE;
		}

		return $result;
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
		$opts = array(
			"http" => array(
				"method" => "GET",
				"header" => "X-Mashape-Key: wiwbql3AxwmshuZzEIxVNI9olPZlp1KsrBAjsnfJpLBkxzaEhq\r\n"
			)
		);

		$context = stream_context_create($opts);

		$result = file_get_contents("https://metropolis-api-phone.p.mashape.com/analysis?telephone={$phone_number}", false, $context);
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
			)
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
	public function getSnaps($save = FALSE)
	{
		$updates = $this->getUpdates();
		if(empty($updates))
		{
			return FALSE;
		}

		$snaps = array();
		$conversations = $updates['data']->conversations_response;
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

				$this->getMedia($id, $from, $time);
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
	 * @param string $country
	 *   The country code. Defaults to US.
	 *
	 * @return mixed
	 *   An array of user objects or FALSE on failure.
	 */
	public function findFriends($numbers, $country = 'US') {

		$batches = array_chunk(array_flip($numbers), 30, TRUE);

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
				'/bq/find_friends',
				array(
					'countryCode' => $country,
					'numbers' => json_encode($batch),
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

		return $updates->added_friends;
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
			'/friend',
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
			'/friend',
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
			'/friend',
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
	function getMedia($id, $from = null, $time = null)
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
				$path = __DIR__ . DIRECTORY_SEPARATOR . "snaps" . DIRECTORY_SEPARATOR .  $from;
				if(!file_exists($path))
				{
					mkdir($path);
				}
				$file = $path . DIRECTORY_SEPARATOR . date("Y-m-d H-i", (int) ($time / 1000));
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
			'/update_snaps',
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

		$mime = mime_content_type($media);
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

	// NEED TO FINISH
	public function sendTyping($recipients)
	{
		if(!$this->auth_token || !$this->username)
		{
			return FALSE;
		}

		if (!is_array($recipients)) {
				$recipients = array($recipients);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/chat_typing',
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

		$mime = mime_content_type($media);
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
				text($media, $text);
				$media = file_get_contents(__DIR__ . '/cache/image.jpg');
				unlink(__DIR__ . '/cache/image.jpg');
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
				'camera_front_facing' => rand(0,1),
				'caption_text_display' => $text,
				'country_code' => 'US',
				'media_id' => $media_id,
				'client_id' => $media_id,
				'timestamp' => $timestamp,
				'story_timestamp' => ($timestamp - 1234),
				'time' => $time,
				'type' => $type,
				'username' => strtolower($this->username),
				'zipped' => '0',
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
	public function getStory($media_id, $key, $iv, $from, $save = FALSE)
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
					$path = __DIR__ . DIRECTORY_SEPARATOR . "stories" . DIRECTORY_SEPARATOR .  $from;
					if(!file_exists($path))
					{
						mkdir($path);
					}
					$file = $path . DIRECTORY_SEPARATOR . "story-" . $media_id;
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
		$blob = parent::get('/story_thumbnail?story_id=' . $media_id);

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
			'/bests',
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
			'/settings',
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
			'/settings',
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
}
